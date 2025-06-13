use inquire::{Confirm, InquireError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PromptError {
    #[error("Prompt bool error")]
    Bool(#[source] InquireError),
}

pub fn bool(message: impl AsRef<str>, default: bool) -> Result<bool, PromptError> {
    Confirm::new(message.as_ref())
        .with_default(default)
        .prompt()
        .map_err(PromptError::Bool)
}
