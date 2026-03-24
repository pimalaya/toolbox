use std::{net::TcpStream, sync::Arc};

use anyhow::{bail, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use io_jmap::{
    context::JmapContext,
    coroutines::get_session::{GetJmapSession, GetJmapSessionResult},
};
use io_stream::runtimes::std::handle;
use log::info;
#[cfg(feature = "native-tls")]
use native_tls::TlsConnector;
#[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
use rustls::{ClientConnection, StreamOwned};
use secrecy::{ExposeSecret, SecretString};
use url::Url;

use crate::stream::{Stream, Tls, TlsProvider};

/// Authentication for a JMAP session.
// https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml#authschemes
#[derive(Clone, Debug)]
pub enum JmapAuth {
    /// Bearer token (OAuth 2.0).
    Bearer(SecretString),
    /// HTTP Basic authentication.
    Basic {
        username: String,
        password: SecretString,
    },
}

impl From<JmapAuth> for SecretString {
    fn from(auth: JmapAuth) -> SecretString {
        match auth {
            JmapAuth::Bearer(token) => {
                let token = token.expose_secret();
                format!("Bearer {token}").into()
            }
            JmapAuth::Basic { username, password } => {
                let creds = format!("{}:{}", username, password.expose_secret());
                let creds = BASE64_STANDARD.encode(creds.into_bytes());
                format!("Basic {creds}").into()
            }
        }
    }
}

/// A live JMAP session over a TLS connection.
///
/// Created by [`JmapSession::new`]. Holds the discovered session
/// context and the open TLS stream to the JMAP server.
///
/// JMAP always requires TLS — plain HTTP connections are not
/// supported by this session type.
#[derive(Debug)]
pub struct JmapSession {
    pub context: JmapContext,
    pub stream: Stream,
}

fn new_stream(host: impl ToString, tcp: TcpStream, tls: &Tls) -> Result<Stream> {
    let stream = match tls.provider()? {
        #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
        TlsProvider::Rustls => {
            let config = tls.build_rustls_client_config()?;
            let server_name = host.to_string().try_into()?;
            let conn = ClientConnection::new(Arc::new(config), server_name)?;
            Stream::Rustls(StreamOwned::new(conn, tcp))
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
            Stream::NativeTls(connector.connect(host, tcp)?)
        }
        #[allow(unreachable_patterns)]
        _ => unreachable!(),
    };

    Ok(stream)
}

impl JmapSession {
    /// Establishes a JMAP session.
    ///
    /// Connects to `url.host():443` (or the port in the URL), performs
    /// TLS handshake, and runs `GET /.well-known/jmap` to discover the
    /// server's session object. The session's `api_url` and
    /// `primary_accounts` are stored in the returned context.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The URL scheme is not `https` or `jmap`
    /// - TLS connection fails
    /// - Session discovery fails (network error or bad response)
    pub fn new(url: Url, tls: Tls, auth: JmapAuth) -> Result<Self> {
        info!("connecting to JMAP server using {url}");

        let host = url.host_str().unwrap_or("localhost");

        match url.scheme() {
            scheme
                if scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("jmap") =>
            {
                let port = url.port().unwrap_or(443);
                let tcp = TcpStream::connect((host, port))?;

                let mut stream = new_stream(host, tcp, &tls)?;

                let context = JmapContext::with_http_auth(auth);
                let mut coroutine = GetJmapSession::new(context, &url)?;
                let mut arg = None;

                let context = loop {
                    match coroutine.resume(arg.take()) {
                        GetJmapSessionResult::Io(io) => arg = Some(handle(&mut stream, io)?),
                        GetJmapSessionResult::Ok { context, .. } => break context,
                        GetJmapSessionResult::Reset(uri) => {
                            let host = uri.host().unwrap_or(host);
                            let port = uri.port_u16().unwrap_or(443);
                            let tcp = TcpStream::connect((host, port))?;
                            stream = new_stream(host, tcp, &tls)?;
                        }
                        GetJmapSessionResult::Err(err) => return Err(err.into()),
                    }
                };

                Ok(Self { context, stream })
            }
            scheme => {
                bail!("Unknown JMAP scheme `{scheme}`, expected `https` or `jmap`")
            }
        }
    }
}
