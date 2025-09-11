#[cfg(feature = "command")]
use std::process::Output;

#[allow(unused)]
use anyhow::{anyhow, Result};
#[cfg(feature = "keyring")]
use io_keyring::{
    coroutines::read::{ReadSecret, ReadSecretResult},
    entry::KeyringEntry,
    runtimes::std::handle as handle_keyring,
};
#[cfg(feature = "command")]
use io_process::{
    command::Command,
    coroutines::spawn_then_wait_with_output::{
        SpawnThenWaitWithOutput, SpawnThenWaitWithOutputResult,
    },
    runtimes::std::handle as handle_process,
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use super::{de, ser};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "de::Secret", into = "ser::Secret")]
pub enum Secret {
    Raw(SecretString),
    #[cfg(feature = "command")]
    Command(Command),
    #[cfg(feature = "keyring")]
    Keyring(KeyringEntry),
}

impl Secret {
    pub fn get(&self) -> Result<SecretString> {
        match self {
            Self::Raw(secret) => Ok(secret.clone()),
            #[cfg(feature = "command")]
            Self::Command(cmd) => {
                let mut spawn = SpawnThenWaitWithOutput::new(cmd.clone());
                let mut arg = None;

                let Output {
                    status,
                    stdout,
                    stderr,
                } = loop {
                    match spawn.resume(arg.take()) {
                        SpawnThenWaitWithOutputResult::Ok(output) => break output,
                        SpawnThenWaitWithOutputResult::Io(io) => arg = Some(handle_process(io)?),
                        SpawnThenWaitWithOutputResult::Err(err) => {
                            let err = anyhow!("{err}");
                            return Err(err.context("Spawn command to get secret error"));
                        }
                    }
                };

                if !status.success() {
                    let bytes = if stdout.is_empty() { stderr } else { stdout };
                    let err = anyhow!("{}", String::from_utf8_lossy(&bytes));
                    return Err(err.context("Read secret via command error"));
                };

                let secret = String::from_utf8_lossy(&stdout)
                    .lines()
                    .next()
                    .unwrap()
                    .into();

                Ok(secret)
            }
            #[cfg(feature = "keyring")]
            Self::Keyring(entry) => {
                let mut spawn = ReadSecret::new(entry.clone());
                let mut arg = None;

                loop {
                    match spawn.resume(arg.take()) {
                        ReadSecretResult::Ok(secret) => break Ok(secret),
                        ReadSecretResult::Io(io) => arg = Some(handle_keyring(io)?),
                        ReadSecretResult::Err(err) => {
                            let err = anyhow!("{err}");
                            return Err(err.context("Read keyring entry to get secret error"));
                        }
                    }
                }
            }
        }
    }
}
