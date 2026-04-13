#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::{
    borrow::Cow,
    net::{Ipv4Addr, TcpStream},
    sync::Arc,
};

use anyhow::{bail, Result};
use io_smtp::{
    login::*,
    rfc3207::starttls::*,
    rfc4616::plain::*,
    rfc5321::{
        ehlo::*,
        greeting::*,
        types::{domain::Domain, ehlo_domain::EhloDomain},
    },
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
pub struct SmtpSession {
    pub stream: Stream,
}

impl SmtpSession {
    pub fn new(url: Url, tls: Tls, starttls: bool, mut sasl: Sasl) -> Result<Self> {
        info!("connecting to SMTP server using {url}");

        let host = url.host_str().unwrap_or("127.0.0.1");
        let domain = EhloDomain::Domain(Domain(Cow::Borrowed("127.0.0.1")));

        let (_capabilities, mut stream) = match url.scheme() {
            scheme if scheme.eq_ignore_ascii_case("smtp") => {
                let port = url.port().unwrap_or(25);
                let mut stream = TcpStream::connect((host, port))?;

                let mut coroutine = GetSmtpGreeting::new();
                let mut arg = None;
                loop {
                    match coroutine.resume(arg.take()) {
                        GetSmtpGreetingResult::Io { input } => {
                            arg = Some(handle(&mut stream, input)?)
                        }
                        GetSmtpGreetingResult::Ok { .. } => break,
                        GetSmtpGreetingResult::Err { err } => Err(err)?,
                    }
                }

                let mut coroutine = SmtpEhlo::new(domain.clone());
                let mut arg = None;
                let capabilities = loop {
                    match coroutine.resume(arg.take()) {
                        SmtpEhloResult::Io { input } => arg = Some(handle(&mut stream, input)?),
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
                            SmtpStartTlsResult::Io { input } => {
                                arg = Some(handle(&mut stream, input)?)
                            }
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
                            SmtpEhloResult::Io { input } => arg = Some(handle(&mut stream, input)?),
                            SmtpEhloResult::Ok { capabilities } => break capabilities,
                            SmtpEhloResult::Err { err } => Err(err)?,
                        }
                    }
                } else {
                    let mut coroutine = GetSmtpGreeting::new();
                    let mut arg = None;
                    loop {
                        match coroutine.resume(arg.take()) {
                            GetSmtpGreetingResult::Io { input } => {
                                arg = Some(handle(&mut stream, input)?)
                            }
                            GetSmtpGreetingResult::Ok { .. } => break,
                            GetSmtpGreetingResult::Err { err } => Err(err)?,
                        }
                    }

                    let mut coroutine = SmtpEhlo::new(domain.clone());
                    let mut arg = None;

                    loop {
                        match coroutine.resume(arg.take()) {
                            SmtpEhloResult::Io { input } => arg = Some(handle(&mut stream, input)?),
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
                        GetSmtpGreetingResult::Io { input } => {
                            arg = Some(handle(&mut stream, input)?)
                        }
                        GetSmtpGreetingResult::Ok { .. } => break,
                        GetSmtpGreetingResult::Err { err } => Err(err)?,
                    }
                }

                let mut coroutine = SmtpEhlo::new(domain.clone());
                let mut arg = None;
                let capabilities = loop {
                    match coroutine.resume(arg.take()) {
                        SmtpEhloResult::Io { input } => arg = Some(handle(&mut stream, input)?),
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
                let mut coroutine = SmtpLogin::new(
                    &auth.username,
                    &auth.password,
                    Ipv4Addr::new(127, 0, 0, 1).into(),
                );

                loop {
                    match coroutine.resume(arg.take()) {
                        SmtpLoginResult::Io { input } => arg = Some(handle(&mut stream, input)?),
                        SmtpLoginResult::Ok => break,
                        SmtpLoginResult::Err { err } => bail!(err),
                    }
                }
            }
            Some(SaslMechanism::Plain) => {
                let Some(auth) = sasl.plain.take() else {
                    bail!("missing SASL PLAIN configuration");
                };

                let mut arg = None;
                let mut coroutine = SmtpPlain::new(
                    &auth.authcid,
                    &auth.passwd,
                    Ipv4Addr::new(127, 0, 0, 1).into(),
                );

                loop {
                    match coroutine.resume(arg.take()) {
                        SmtpPlainResult::Io { input } => arg = Some(handle(&mut stream, input)?),
                        SmtpPlainResult::Ok => break,
                        SmtpPlainResult::Err { err } => bail!(err),
                    }
                }
            }
            Some(SaslMechanism::Anonymous) => {
                unimplemented!("ANONYMOUS SASL mechanism not yet implemented")
            }
        }

        Ok(Self { stream })
    }
}
