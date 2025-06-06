use std::path::PathBuf;

use clap::Parser;

/// The config path flag parser.
#[derive(Debug, Default, Parser)]
pub struct ConfigPathsFlag {
    /// Override the default configuration file path.
    ///
    /// The given paths are shell-expanded then canonicalized (if
    /// applicable). If the first path does not point to a valid file,
    /// the wizard will propose to assist you in the creation of the
    /// configuration file. Other paths are merged with the first one,
    /// which allows you to separate your public config from your
    /// private(s) one(s).
    #[arg(short, long = "config", global = true)]
    #[arg(name = "config_paths", value_name = "PATH", value_parser = path_parser)]
    pub paths: Vec<PathBuf>,
}

/// The account name flag parser.
#[derive(Debug, Default, Parser)]
pub struct AccountFlag {
    /// Override the default account.
    ///
    /// An account name corresponds to an entry in the table at the
    /// root level of your TOML configuration file.
    #[arg(long = "account", short = 'a', global = true)]
    #[arg(name = "account_name", value_name = "NAME")]
    pub name: Option<String>,
}

/// The JSON output flag parser.
#[derive(Debug, Default, Parser)]
pub struct JsonFlag {
    /// Enable JSON output.
    ///
    /// When set, command output (data or errors) is displayed as JSON
    /// string.
    #[arg(long = "json", name = "json", global = true)]
    pub enabled: bool,
}

/// The quiet, debug and trace flag parsers.
#[derive(Debug, Default, Parser)]
pub struct LogFlags {
    /// Disable all logs.
    ///
    /// Same as running command with `RUST_LOG=off` environment
    /// variable.
    #[arg(long, alias = "silent", global = true)]
    #[arg(conflicts_with = "debug")]
    #[arg(conflicts_with = "trace")]
    pub quiet: bool,

    /// Enable debug logs.
    ///
    /// Same as running command with `RUST_LOG=debug` environment
    /// variable.
    #[arg(long, global = true)]
    #[arg(conflicts_with = "quiet")]
    #[arg(conflicts_with = "trace")]
    pub debug: bool,

    /// Enable verbose trace logs with backtrace.
    ///
    /// Same as running command with `RUST_LOG=trace` and
    /// `RUST_BACKTRACE=1` environment variables.
    #[arg(long, alias = "verbose", global = true)]
    #[arg(conflicts_with = "quiet")]
    #[arg(conflicts_with = "debug")]
    pub trace: bool,
}

pub fn path_parser(path: &str) -> Result<PathBuf, String> {
    match shellexpand::full(path) {
        Ok(path) => {
            let path = PathBuf::from(&*path);
            Ok(path.canonicalize().unwrap_or(path))
        }
        Err(err) => Err(err.to_string()),
    }
}

#[macro_export]
macro_rules! long_version {
    () => {
        concat!(
            "v",
            env!("CARGO_PKG_VERSION"),
            " ",
            env!("CARGO_FEATURES"),
            "\nbuild: ",
            env!("CARGO_CFG_TARGET_OS"),
            " ",
            env!("CARGO_CFG_TARGET_ENV"),
            " ",
            env!("CARGO_CFG_TARGET_ARCH"),
            "\ngit: ",
            env!("GIT_DESCRIBE"),
            ", rev ",
            env!("GIT_REV"),
        )
    };
}
