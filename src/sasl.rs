use secrecy::SecretString;

#[derive(Clone, Debug, Default)]
pub struct Sasl {
    pub mechanisms: Vec<SaslMechanism>,
    pub login: Option<SaslLogin>,
    pub plain: Option<SaslPlain>,
    pub anonymous: Option<SaslAnonymous>,
}

#[derive(Clone, Debug)]
pub enum SaslMechanism {
    Login,
    Plain,
    Anonymous,
}

pub fn sasl_default_mechanisms() -> Vec<SaslMechanism> {
    vec![SaslMechanism::Plain, SaslMechanism::Login]
}

#[derive(Clone, Debug)]
pub struct SaslLogin {
    pub username: String,
    pub password: SecretString,
}

#[derive(Clone, Debug)]
pub struct SaslPlain {
    pub authzid: Option<String>,
    pub authcid: String,
    pub passwd: SecretString,
}

#[derive(Clone, Debug)]
pub struct SaslAnonymous {
    pub message: Option<String>,
}
