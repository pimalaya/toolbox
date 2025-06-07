#[allow(unused)]
use anyhow::{bail, Error, Result};
use serde::Deserialize;

#[allow(unused)]
use crate::feat;

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tls {
    Plain,
    NativeTls,
    RustlsAws,
    RustlsRing,
}

impl TryFrom<Tls> for super::Tls {
    type Error = Error;

    fn try_from(tls: Tls) -> Result<Self, Self::Error> {
        match tls {
            Tls::Plain => Ok(Self::Plain),
            #[cfg(feature = "native-tls")]
            Tls::NativeTls => Ok(Self::NativeTls),
            #[cfg(not(feature = "native-tls"))]
            Tls::NativeTls => bail!(feat!("native-tls")),
            #[cfg(feature = "rustls-aws")]
            Tls::RustlsAws => Ok(Self::RustlsAws),
            #[cfg(not(feature = "rustls-aws"))]
            Tls::RustlsAws => bail!(feat!("native-tls")),
            #[cfg(feature = "rustls-ring")]
            Tls::RustlsRing => Ok(Self::RustlsRing),
            #[cfg(not(feature = "rustls-ring"))]
            Tls::RustlsRing => bail!(feat!("native-tls")),
        }
    }
}
