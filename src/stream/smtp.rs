#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::{borrow::Cow, net::TcpStream, sync::Arc};

use anyhow::{bail, Result};
use io_smtp::{
    rfc3207::starttls::*,
    rfc4954::{authenticate::*, types::auth_mechanism::AuthMechanism},
    rfc5321::{
        ehlo::*,
        greeting::*,
        types::{domain::Domain, ehlo_domain::EhloDomain, ehlo_response::Capability},
    },
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
pub struct SmtpSession {
    pub stream: Stream,
}

impl SmtpSession {
    pub fn new(url: Url, tls: Tls, starttls: bool, mut sasl: Sasl) -> Result<Self> {
        info!("connecting to SMTP server using {url}");

        let host = url.host_str().unwrap_or("127.0.0.1");
        let domain = EhloDomain::Domain(Domain(Cow::Borrowed("127.0.0.1")));

        let (capabilities, mut stream) = match url.scheme() {
            scheme if scheme.eq_ignore_ascii_case("smtp") => {
                let port = url.port().unwrap_or(25);
                let mut stream = TcpStream::connect((host, port))?;

                let mut coroutine = GetSmtpGreeting::new();
                let mut arg = None;
                loop {
                    match coroutine.resume(arg.take()) {
                        GetSmtpGreetingResult::Io { io } => arg = Some(handle(&mut stream, io)?),
                        GetSmtpGreetingResult::Ok { .. } => break,
                        GetSmtpGreetingResult::Err { err } => Err(err)?,
                    }
                }

                let mut coroutine = SmtpEhlo::new(domain.clone());
                let mut arg = None;
                let capabilities = loop {
                    match coroutine.resume(arg.take()) {
                        SmtpEhloResult::Io { io } => arg = Some(handle(&mut stream, io)?),
                        SmtpEhloResult::Ok { capabilities } => break capabilities,
                        SmtpEhloResult::Err { err } => Err(err)?,
                    }
                };

                (capabilities, Stream::Tcp(stream))
            }
            scheme if scheme.eq_ignore_ascii_case("smtps") => {
                let default_port = if starttls { 587 } else { 465 };
                let port = url.port().unwrap_or(default_port);
                let mut stream = TcpStream::connect((host, port))?;

                if starttls {
                    let mut coroutine = SmtpStartTls::new();
                    let mut arg = None;

                    loop {
                        match coroutine.resume(arg.take()) {
                            SmtpStartTlsResult::Io { io } => arg = Some(handle(&mut stream, io)?),
                            SmtpStartTlsResult::Ok => break,
                            SmtpStartTlsResult::Err { err } => Err(err)?,
                        }
                    }
                }

                let mut stream = match tls.provider()? {
                    #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
                    TlsProvider::Rustls => {
                        let mut config = tls.build_rustls_client_config()?;
                        config.alpn_protocols = vec![b"smtp".to_vec()];
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

                let capabilities = if starttls {
                    let mut coroutine = SmtpEhlo::new(domain.clone());
                    let mut arg = None;

                    loop {
                        match coroutine.resume(arg.take()) {
                            SmtpEhloResult::Io { io } => arg = Some(handle(&mut stream, io)?),
                            SmtpEhloResult::Ok { capabilities } => break capabilities,
                            SmtpEhloResult::Err { err } => Err(err)?,
                        }
                    }
                } else {
                    let mut coroutine = GetSmtpGreeting::new();
                    let mut arg = None;
                    loop {
                        match coroutine.resume(arg.take()) {
                            GetSmtpGreetingResult::Io { io } => {
                                arg = Some(handle(&mut stream, io)?)
                            }
                            GetSmtpGreetingResult::Ok { .. } => break,
                            GetSmtpGreetingResult::Err { err } => Err(err)?,
                        }
                    }

                    let mut coroutine = SmtpEhlo::new(domain.clone());
                    let mut arg = None;

                    loop {
                        match coroutine.resume(arg.take()) {
                            SmtpEhloResult::Io { io } => arg = Some(handle(&mut stream, io)?),
                            SmtpEhloResult::Ok { capabilities } => break capabilities,
                            SmtpEhloResult::Err { err } => Err(err)?,
                        }
                    }
                };

                (capabilities, stream)
            }
            scheme if scheme.eq_ignore_ascii_case("unix") => {
                let sock_path = url.path();
                let mut stream = UnixStream::connect(&sock_path)?;

                let mut coroutine = GetSmtpGreeting::new();
                let mut arg = None;
                loop {
                    match coroutine.resume(arg.take()) {
                        GetSmtpGreetingResult::Io { io } => arg = Some(handle(&mut stream, io)?),
                        GetSmtpGreetingResult::Ok { .. } => break,
                        GetSmtpGreetingResult::Err { err } => Err(err)?,
                    }
                }

                let mut coroutine = SmtpEhlo::new(domain.clone());
                let mut arg = None;
                let capabilities = loop {
                    match coroutine.resume(arg.take()) {
                        SmtpEhloResult::Io { io } => arg = Some(handle(&mut stream, io)?),
                        SmtpEhloResult::Ok { capabilities } => break capabilities,
                        SmtpEhloResult::Err { err } => Err(err)?,
                    }
                };

                (capabilities, Stream::Unix(stream))
            }
            scheme => {
                bail!("Unknown scheme {scheme}, expected smtp, smtps or unix");
            }
        };

        let mut candidates = vec![];

        for mechanism in sasl.mechanisms {
            match mechanism {
                SaslMechanism::Login => {
                    let Some(auth) = sasl.login.take() else {
                        debug!("missing SASL LOGIN configuration, skipping it");
                        continue;
                    };

                    for capability in &capabilities {
                        match capability {
                            Capability::Auth(mechanisms) => {
                                for m in mechanisms {
                                    match m {
                                        AuthMechanism::Login => {
                                            candidates.push(SmtpAuthenticateCandidate::Login {
                                                login: auth.username.clone(),
                                                password: auth.password.clone(),
                                                domain: domain.clone(),
                                            });
                                            break;
                                        }
                                        _ => continue,
                                    }
                                }
                            }
                            _ => continue,
                        }
                    }

                    debug!("SASL LOGIN disabled by the server, skipping it");
                    continue;
                }
                SaslMechanism::Plain => {
                    let Some(auth) = sasl.plain.take() else {
                        debug!("missing SASL PLAIN configuration, skipping it");
                        continue;
                    };

                    for capability in &capabilities {
                        match capability {
                            Capability::Auth(mechanisms) => {
                                for m in mechanisms {
                                    match m {
                                        AuthMechanism::Plain => {
                                            candidates.push(SmtpAuthenticateCandidate::Plain {
                                                login: auth.authcid.clone(),
                                                password: auth.passwd.clone(),
                                                domain: domain.clone(),
                                            });
                                            break;
                                        }
                                        _ => continue,
                                    }
                                }
                            }
                            _ => continue,
                        }
                    }

                    debug!("SASL PLAIN disabled by the server, skipping it");
                    continue;
                }
                SaslMechanism::Anonymous => {
                    unimplemented!("ANONYMOUS SASL mechanism not yet implemented")
                }
            };
        }

        if !candidates.is_empty() {
            let mut arg = None;
            let mut coroutine = SmtpAuthenticate::new(candidates);

            loop {
                match coroutine.resume(arg.take()) {
                    SmtpAuthenticateResult::Io { io } => arg = Some(handle(&mut stream, io)?),
                    SmtpAuthenticateResult::Ok => break,
                    SmtpAuthenticateResult::Err { err } => bail!(err),
                }
            }
        }

        Ok(Self { stream })
    }
}
