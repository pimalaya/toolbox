#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::{net::TcpStream, sync::Arc};

use anyhow::{bail, Result};
use io_imap::{
    context::ImapContext,
    rfc3501::{capability::*, greeting_with_capability::*, login::*, starttls::*},
    sasl::authenticate_plain::*,
    types::response::Capability,
};
use io_socket::runtimes::std_stream::handle;
use log::info;
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

                let mut coroutine = ImapGreetingWithCapabilityGet::new(context);
                let mut arg = None;

                loop {
                    match coroutine.resume(arg.take()) {
                        ImapGreetingWithCapabilityGetResult::Io { input } => {
                            arg = Some(handle(&mut stream, input)?)
                        }
                        ImapGreetingWithCapabilityGetResult::Ok { context: c } => {
                            break context = c
                        }
                        ImapGreetingWithCapabilityGetResult::Err { err, .. } => Err(err)?,
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
                            ImapStartTlsResult::Io { input } => {
                                arg = Some(handle(&mut stream, input)?)
                            }
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
                    let mut coroutine = ImapCapabilityGet::new(context);
                    let mut arg = None;

                    loop {
                        match coroutine.resume(arg.take()) {
                            ImapCapabilityGetResult::Io { input } => {
                                arg = Some(handle(&mut stream, input)?)
                            }
                            ImapCapabilityGetResult::Ok { context: c } => break context = c,
                            ImapCapabilityGetResult::Err { err, .. } => Err(err)?,
                        }
                    }
                } else {
                    let mut coroutine = ImapGreetingWithCapabilityGet::new(context);
                    let mut arg = None;

                    loop {
                        match coroutine.resume(arg.take()) {
                            ImapGreetingWithCapabilityGetResult::Io { input } => {
                                arg = Some(handle(&mut stream, input)?)
                            }
                            ImapGreetingWithCapabilityGetResult::Ok { context: c } => {
                                break context = c
                            }
                            ImapGreetingWithCapabilityGetResult::Err { err, .. } => Err(err)?,
                        }
                    }
                }

                (context, stream)
            }
            scheme if scheme.eq_ignore_ascii_case("unix") => {
                let sock_path = url.path();
                let mut stream = UnixStream::connect(&sock_path)?;

                let mut coroutine = ImapGreetingWithCapabilityGet::new(context);
                let mut arg = None;

                loop {
                    match coroutine.resume(arg.take()) {
                        ImapGreetingWithCapabilityGetResult::Io { input } => {
                            arg = Some(handle(&mut stream, input)?)
                        }
                        ImapGreetingWithCapabilityGetResult::Ok { context: c } => {
                            break context = c
                        }
                        ImapGreetingWithCapabilityGetResult::Err { err, .. } => Err(err)?,
                    }
                }

                (context, Stream::Unix(stream))
            }
            scheme => {
                bail!("Unknown scheme {scheme}, expected imap, imaps or unix");
            }
        };

        if !context.authenticated {
            let ir = context.capability.contains(&Capability::SaslIr);

            let mechanism = sasl
                .mechanism
                .or(Some(SaslMechanism::Plain).filter(|_| sasl.plain.is_some()))
                .or(Some(SaslMechanism::Login).filter(|_| sasl.login.is_some()));

            match mechanism {
                None => bail!("no SASL mechanism configured"),
                Some(SaslMechanism::Login) => {
                    let Some(auth) = sasl.login.take() else {
                        bail!("missing SASL LOGIN configuration");
                    };

                    let mut arg = None;
                    let mut coroutine = ImapSessionLogin::new(
                        context,
                        ImapSessionLoginParams::new(auth.username, auth.password)?,
                    );

                    context = loop {
                        match coroutine.resume(arg.take()) {
                            ImapSessionLoginResult::Io { input } => {
                                arg = Some(handle(&mut stream, input)?)
                            }
                            ImapSessionLoginResult::Ok { context } => break context,
                            ImapSessionLoginResult::Err { err, .. } => bail!(err),
                        }
                    };
                }
                Some(SaslMechanism::Plain) => {
                    let Some(auth) = sasl.plain.take() else {
                        bail!("missing SASL PLAIN configuration");
                    };

                    let mut arg = None;
                    let mut coroutine = ImapSessionAuthenticatePlain::new(
                        context,
                        ImapSessionAuthenticatePlainParams::new(
                            auth.authzid,
                            auth.authcid,
                            auth.passwd,
                            ir,
                        ),
                    );

                    context = loop {
                        match coroutine.resume(arg.take()) {
                            ImapSessionAuthenticatePlainResult::Io { input } => {
                                arg = Some(handle(&mut stream, input)?)
                            }
                            ImapSessionAuthenticatePlainResult::Ok { context } => break context,
                            ImapSessionAuthenticatePlainResult::Err { err, .. } => bail!(err),
                        }
                    };
                }
                Some(SaslMechanism::Anonymous) => {
                    unimplemented!("ANONYMOUS SASL mechanism not yet implemented")
                }
            }
        }

        Ok(Self { context, stream })
    }
}
