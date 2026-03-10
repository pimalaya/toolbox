#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::{
    fs,
    io::{self, Read, Write},
    net::TcpStream,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::{bail, Result};
use log::debug;
#[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
use rustls::{
    crypto::{self, CryptoProvider},
    pki_types::{pem::PemObject, CertificateDer},
    ClientConfig, ClientConnection, StreamOwned,
};
#[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
use rustls_platform_verifier::{ConfigVerifierExt, Verifier};
#[cfg(windows)]
use uds_windows::UnixStream;

#[derive(Debug)]
pub enum Stream {
    Tcp(TcpStream),
    Unix(UnixStream),
    #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
    Rustls(StreamOwned<ClientConnection, TcpStream>),
    #[cfg(feature = "native-tls")]
    NativeTls(native_tls::TlsStream<TcpStream>),
}

impl Stream {
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Tcp(s) => s.set_read_timeout(timeout),
            Self::Unix(s) => s.set_read_timeout(timeout),
            #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
            Self::Rustls(s) => s.sock.set_read_timeout(timeout),
            #[cfg(feature = "native-tls")]
            Self::NativeTls(s) => s.get_ref().set_read_timeout(timeout),
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(s) => s.read(buf),
            Self::Unix(s) => s.read(buf),
            #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
            Self::Rustls(s) => s.read(buf),
            #[cfg(feature = "native-tls")]
            Self::NativeTls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(s) => s.write(buf),
            Self::Unix(s) => s.write(buf),
            #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
            Self::Rustls(s) => s.write(buf),
            #[cfg(feature = "native-tls")]
            Self::NativeTls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(s) => s.flush(),
            Self::Unix(s) => s.flush(),
            #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
            Self::Rustls(s) => s.flush(),
            #[cfg(feature = "native-tls")]
            Self::NativeTls(s) => s.flush(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Tls {
    pub provider: Option<TlsProvider>,
    pub rustls: Rustls,
    pub cert: Option<PathBuf>,
}

impl Tls {
    pub fn provider(&self) -> Result<TlsProvider> {
        let provider = match &self.provider {
            #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
            Some(TlsProvider::Rustls) => TlsProvider::Rustls,
            #[cfg(not(feature = "rustls-aws"))]
            #[cfg(not(feature = "rustls-ring"))]
            Some(TlsProvider::Rustls) => {
                bail!("Missing cargo feature: `rustls-aws` or `rustls-ring`")
            }
            #[cfg(feature = "native-tls")]
            Some(TlsProvider::NativeTls) => TlsProvider::NativeTls,
            #[cfg(not(feature = "native-tls"))]
            Some(TlsProvider::NativeTls) => {
                bail!("Missing cargo feature: `native-tls`")
            }
            #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
            None => TlsProvider::Rustls,
            #[cfg(not(feature = "rustls-aws"))]
            #[cfg(not(feature = "rustls-ring"))]
            #[cfg(feature = "native-tls")]
            None => TlsProvider::NativeTls,
            #[cfg(not(feature = "rustls-aws"))]
            #[cfg(not(feature = "rustls-ring"))]
            #[cfg(not(feature = "native-tls"))]
            None => {
                bail!("Missing cargo feature: `rustls-aws`, `rustls-ring` or `native-tls`")
            }
        };
        debug!("using TLS provider: {provider:?}");
        Ok(provider)
    }

    #[cfg(any(feature = "rustls-aws", feature = "rustls-ring"))]
    pub fn build_rustls_client_config(&self) -> Result<ClientConfig> {
        let crypto_provider = match &self.rustls.crypto {
            #[cfg(feature = "rustls-aws")]
            Some(RustlsCrypto::Aws) => RustlsCrypto::Aws,
            #[cfg(not(feature = "rustls-aws"))]
            Some(RustlsCrypto::Aws) => {
                bail!("Missing cargo feature: `rustls-aws`");
            }
            #[cfg(feature = "rustls-ring")]
            Some(RustlsCrypto::Ring) => RustlsCrypto::Ring,
            #[cfg(not(feature = "rustls-ring"))]
            Some(RustlsCrypto::Ring) => {
                bail!("Missing cargo feature: `rustls-ring`");
            }
            #[cfg(feature = "rustls-ring")]
            None => RustlsCrypto::Ring,
            #[cfg(not(feature = "rustls-ring"))]
            #[cfg(feature = "rustls-aws")]
            None => RustlsCrypto::Aws,
            #[cfg(not(feature = "rustls-aws"))]
            #[cfg(not(feature = "rustls-ring"))]
            None => {
                bail!("Missing cargo feature: `rustls-aws` or `rustls-ring`");
            }
        };

        debug!("using rustls crypto provider: {crypto_provider:?}");

        let crypto_provider = match crypto_provider {
            #[cfg(feature = "rustls-aws")]
            RustlsCrypto::Aws => crypto::aws_lc_rs::default_provider(),
            #[cfg(feature = "rustls-ring")]
            RustlsCrypto::Ring => crypto::ring::default_provider(),
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        };

        let crypto_provider = match crypto_provider.install_default() {
            Ok(()) => CryptoProvider::get_default().unwrap().clone(),
            Err(crypto_provider) => crypto_provider,
        };

        let config = if let Some(pem_path) = &self.cert {
            debug!("using TLS cert at {}", pem_path.display());
            let pem = fs::read(pem_path)?;

            let Some(cert) = CertificateDer::pem_slice_iter(&pem).next() else {
                bail!("empty TLS cert at {}", pem_path.display())
            };

            let verifier = Verifier::new_with_extra_roots(vec![cert?], crypto_provider)?;

            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth()
        } else {
            debug!("using OS TLS certs");
            ClientConfig::with_platform_verifier()?
        };

        Ok(config)
    }
}

#[derive(Clone, Debug)]
pub enum TlsProvider {
    Rustls,
    NativeTls,
}

#[derive(Clone, Debug, Default)]
pub struct Rustls {
    pub crypto: Option<RustlsCrypto>,
}

#[derive(Clone, Debug)]
pub enum RustlsCrypto {
    Aws,
    Ring,
}
