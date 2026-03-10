#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::{net::TcpStream, sync::Arc};

use anyhow::{bail, Result};
use io_imap::{
    context::ImapContext,
    coroutines::{
        authenticate::*, authenticate_anonymous::ImapAuthenticateAnonymousParams,
        authenticate_plain::ImapAuthenticatePlainParams, capability::*,
        greeting_with_capability::*, login::ImapLoginParams, starttls::*,
    },
    types::{auth::AuthMechanism, response::Capability},
};
use io_stream::runtimes::std::handle;
use log::{debug, info};
#[cfg(feature = "native-tls")]
use native_tls::TlsConnector;
#[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
use rustls::{ClientConnection, StreamOwned};
#[cfg(windows)]
use uds_windows::UnixStream;
use url::Url;

use crate::{
    sasl::{Sasl, SaslMechanism},
    stream::{Stream, Tls, TlsProvider},
};

#[derive(Debug)]
pub struct ImapSession {
    pub context: ImapContext,
    pub stream: Stream,
}

impl ImapSession {
    pub fn new(url: Url, tls: Tls, starttls: bool, mut sasl: Sasl) -> Result<Self> {
        info!("connecting to IMAP server using {url}");

        let mut context = ImapContext::new();
        let host = url.host_str().unwrap_or("127.0.0.1");

        let (mut context, mut stream) = match url.scheme() {
            scheme if scheme.eq_ignore_ascii_case("imap") => {
                let port = url.port().unwrap_or(143);
                let mut stream = TcpStream::connect((host, port))?;

                let mut coroutine = GetImapGreetingWithCapability::new(context);
                let mut arg = None;

                loop {
                    match coroutine.resume(arg.take()) {
                        GetImapGreetingWithCapabilityResult::Io { io } => {
                            arg = Some(handle(&mut stream, io)?)
                        }
                        GetImapGreetingWithCapabilityResult::Ok { context: c } => {
                            break context = c
                        }
                        GetImapGreetingWithCapabilityResult::Err { err, .. } => Err(err)?,
                    }
                }

                (context, Stream::Tcp(stream))
            }
            scheme if scheme.eq_ignore_ascii_case("imaps") => {
                let port = url.port().unwrap_or(993);
                let mut stream = TcpStream::connect((host, port))?;

                if starttls {
                    let mut coroutine = ImapStartTls::new(context);
                    let mut arg = None;

                    loop {
                        match coroutine.resume(arg.take()) {
                            ImapStartTlsResult::Io { io } => arg = Some(handle(&mut stream, io)?),
                            ImapStartTlsResult::Ok { context: c } => break context = c,
                            ImapStartTlsResult::Err { err, .. } => Err(err)?,
                        }
                    }
                }

                let mut stream = match tls.provider()? {
                    #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
                    TlsProvider::Rustls => {
                        let mut config = tls.build_rustls_client_config()?;
                        config.alpn_protocols = vec![b"imap".to_vec()];
                        let server_name = host.to_string().try_into()?;
                        let conn = ClientConnection::new(Arc::new(config), server_name)?;
                        Stream::Rustls(StreamOwned::new(conn, stream))
                    }
                    #[cfg(feature = "native-tls")]
                    TlsProvider::NativeTls => {
                        let mut builder = TlsConnector::builder();

                        if let Some(pem_path) = &tls.cert {
                            debug!("using TLS cert at {}", pem_path.display());
                            let pem = std::fs::read(pem_path)?;
                            let cert = native_tls::Certificate::from_pem(&pem)?;
                            builder.add_root_certificate(cert);
                        }

                        let connector = builder.build()?;
                        Stream::NativeTls(connector.connect(host, stream)?)
                    }
                    #[allow(unreachable_patterns)]
                    _ => unreachable!(),
                };

                if starttls {
                    let mut coroutine = GetImapCapability::new(context);
                    let mut arg = None;

                    loop {
                        match coroutine.resume(arg.take()) {
                            GetImapCapabilityResult::Io { io } => {
                                arg = Some(handle(&mut stream, io)?)
                            }
                            GetImapCapabilityResult::Ok { context: c } => break context = c,
                            GetImapCapabilityResult::Err { err, .. } => Err(err)?,
                        }
                    }
                } else {
                    let mut coroutine = GetImapGreetingWithCapability::new(context);
                    let mut arg = None;

                    loop {
                        match coroutine.resume(arg.take()) {
                            GetImapGreetingWithCapabilityResult::Io { io } => {
                                arg = Some(handle(&mut stream, io)?)
                            }
                            GetImapGreetingWithCapabilityResult::Ok { context: c } => {
                                break context = c
                            }
                            GetImapGreetingWithCapabilityResult::Err { err, .. } => Err(err)?,
                        }
                    }
                }

                (context, stream)
            }
            scheme if scheme.eq_ignore_ascii_case("unix") => {
                let sock_path = url.path();
                let mut stream = UnixStream::connect(&sock_path)?;

                let mut coroutine = GetImapGreetingWithCapability::new(context);
                let mut arg = None;

                loop {
                    match coroutine.resume(arg.take()) {
                        GetImapGreetingWithCapabilityResult::Io { io } => {
                            arg = Some(handle(&mut stream, io)?)
                        }
                        GetImapGreetingWithCapabilityResult::Ok { context: c } => {
                            break context = c
                        }
                        GetImapGreetingWithCapabilityResult::Err { err, .. } => Err(err)?,
                    }
                }

                (context, Stream::Unix(stream))
            }
            scheme => {
                bail!("Unknown scheme {scheme}, expected imap, imaps or unix");
            }
        };

        if !context.authenticated {
            let mut candidates = vec![];

            let ir = context.capability.contains(&Capability::SaslIr);

            for mechanism in sasl.mechanisms {
                match mechanism {
                    SaslMechanism::Login => {
                        let Some(auth) = sasl.login.take() else {
                            debug!("missing SASL LOGIN configuration, skipping it");
                            continue;
                        };

                        if context.capability.contains(&Capability::LoginDisabled) {
                            debug!("SASL LOGIN disabled by the server, skipping it");
                            continue;
                        }

                        let login = Capability::Auth(AuthMechanism::Login);
                        if !context.capability.contains(&login) {
                            debug!("SASL LOGIN disabled by the server, skipping it");
                            continue;
                        }

                        candidates.push(ImapAuthenticateCandidate::Login(ImapLoginParams::new(
                            auth.username,
                            auth.password,
                        )?));
                    }
                    SaslMechanism::Plain => {
                        let Some(auth) = sasl.plain.take() else {
                            debug!("missing SASL PLAIN configuration, skipping it");
                            continue;
                        };

                        let plain = Capability::Auth(AuthMechanism::Plain);
                        if !context.capability.contains(&plain) {
                            debug!("SASL PLAIN disabled by the server, skipping it");
                            continue;
                        }

                        candidates.push(ImapAuthenticateCandidate::Plain(
                            ImapAuthenticatePlainParams::new(
                                auth.authzid,
                                auth.authcid,
                                auth.passwd,
                                ir,
                            ),
                        ));
                    }
                    SaslMechanism::Anonymous => {
                        // TODO: check if capability available

                        let message = sasl
                            .anonymous
                            .take()
                            .and_then(|auth| auth.message)
                            .unwrap_or_default();

                        candidates.push(ImapAuthenticateCandidate::Anonymous(
                            ImapAuthenticateAnonymousParams::new(message, ir),
                        ));
                    }
                };
            }

            let mut arg = None;
            let mut coroutine = ImapAuthenticate::new(context, candidates);

            loop {
                match coroutine.resume(arg.take()) {
                    ImapAuthenticateResult::Io { io } => arg = Some(handle(&mut stream, io)?),
                    ImapAuthenticateResult::Ok { context: c, .. } => break context = c,
                    ImapAuthenticateResult::Err { err, .. } => bail!(err),
                }
            }
        }

        Ok(Self { context, stream })
    }
}
