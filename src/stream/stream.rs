#[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
use std::sync::Arc;
use std::{
    io::{self, Read, Write},
    net::TcpStream,
};

use anyhow::Result;
#[cfg(feature = "native-tls")]
use native_tls::TlsConnector;
#[cfg(feature = "rustls-aws")]
use rustls::crypto::aws_lc_rs;
#[cfg(feature = "rustls-ring")]
use rustls::crypto::ring;
#[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
use rustls::{ClientConfig, ClientConnection, StreamOwned};
#[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
use rustls_platform_verifier::ConfigVerifierExt;
use serde::{Deserialize, Serialize};

use super::de;

#[derive(Debug)]
pub enum Stream {
    Plain(TcpStream),
    #[cfg(feature = "native-tls")]
    NativeTls(native_tls::TlsStream<TcpStream>),
    #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
    Rustls(StreamOwned<ClientConnection, TcpStream>),
}

impl Stream {
    pub fn connect(host: &str, port: u16, tls: &Tls) -> Result<Self> {
        match tls {
            Tls::Plain => {
                let tcp = TcpStream::connect((host, port))?;
                Ok(Stream::Plain(tcp))
            }
            #[cfg(feature = "rustls-aws")]
            Tls::RustlsAws => {
                let _ = aws_lc_rs::default_provider().install_default();
                let tls = Self::connect_rustls(host, port)?;
                Ok(Stream::Rustls(tls))
            }
            #[cfg(feature = "rustls-ring")]
            Tls::RustlsRing => {
                let _ = ring::default_provider().install_default();
                let tls = Self::connect_rustls(host, port)?;
                Ok(Stream::Rustls(tls))
            }
            #[cfg(feature = "native-tls")]
            Tls::NativeTls => {
                let connector = TlsConnector::new()?;
                let tcp = TcpStream::connect((host, port))?;
                let tls = connector.connect(host, tcp)?;
                Ok(Stream::NativeTls(tls))
            }
        }
    }

    #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
    fn connect_rustls(host: &str, port: u16) -> Result<StreamOwned<ClientConnection, TcpStream>> {
        let config = Arc::new(ClientConfig::with_platform_verifier());
        let server_name = host.to_owned().try_into()?;
        let conn = ClientConnection::new(config, server_name)?;
        let tcp = TcpStream::connect((host, port))?;
        Ok(StreamOwned::new(conn, tcp))
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buf),
            #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
            Self::Rustls(stream) => stream.read(buf),
            #[cfg(feature = "native-tls")]
            Self::NativeTls(stream) => stream.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buf),
            #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
            Self::Rustls(stream) => stream.write(buf),
            #[cfg(feature = "native-tls")]
            Self::NativeTls(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
            Self::Rustls(stream) => stream.flush(),
            #[cfg(feature = "native-tls")]
            Self::NativeTls(stream) => stream.flush(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "de::Tls")]
pub enum Tls {
    Plain,
    #[cfg(feature = "native-tls")]
    NativeTls,
    #[cfg(feature = "rustls-aws")]
    RustlsAws,
    #[cfg(feature = "rustls-ring")]
    RustlsRing,
}

#[cfg(not(feature = "native-tls"))]
#[cfg(not(feature = "rustls-aws"))]
#[cfg(not(feature = "rustls-ring"))]
impl Default for Tls {
    fn default() -> Self {
        Self::Plain
    }
}

#[cfg(feature = "native-tls")]
#[cfg(not(feature = "rustls-aws"))]
#[cfg(not(feature = "rustls-ring"))]
impl Default for Tls {
    fn default() -> Self {
        Self::NativeTls
    }
}

#[cfg(feature = "rustls-aws")]
impl Default for Tls {
    fn default() -> Self {
        Self::RustlsAws
    }
}

#[cfg(not(feature = "rustls-aws"))]
#[cfg(feature = "rustls-ring")]
impl Default for Tls {
    fn default() -> Self {
        Self::RustlsRing
    }
}
