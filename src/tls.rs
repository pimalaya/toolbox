use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Tls {
    pub provider: Option<TlsProvider>,
    pub cert: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TlsProvider {
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws"))]
    Rustls(Rustls),
    #[cfg(feature = "native-tls")]
    NativeTls,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Rustls {
    pub crypto: Option<RustlsCrypto>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RustlsCrypto {
    Aws,
    Ring,
}
