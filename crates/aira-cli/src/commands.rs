//! CLI command parsing (/add, /file, /me, /verify, etc.).
//!
//! Parses user input text into structured `CliCommand` variants.
//! Supports Tab-completion for command names and contacts.
//! See SPEC.md §9 for the full command list.

use std::path::PathBuf;

/// All slash commands and plain message input.
#[derive(Debug, PartialEq)]
pub enum CliCommand {
    /// `/add <pubkey> [alias]` — add a contact by public key.
    Add {
        pubkey: String,
        alias: Option<String>,
    },
    /// `/file <path>` — send a file to the current contact.
    File { path: PathBuf },
    /// `/me <action>` — action message (third-person emote).
    Me { action: String },
    /// `/mykey` — display our own public key.
    MyKey,
    /// `/info` — show version, network status, relay info.
    Info,
    /// `/verify [contact]` — display Safety Number for verification.
    Verify { contact: Option<String> },
    /// `/disappear <time>` — set auto-delete timer (30s/5m/1h/1d/7d/off).
    Disappear { time: String },
    /// `/export [path]` — export encrypted backup.
    Export { path: Option<PathBuf> },
    /// `/import <path>` — import backup.
    Import { path: PathBuf },
    /// `/transport <mode>` — switch transport mode.
    Transport { mode: String },
    /// `/mute <contact> [duration]` — mute contact notifications.
    Mute {
        contact: String,
        duration: Option<String>,
    },
    /// `/block <contact>` — block contact.
    Block { contact: String },
    /// `/unblock <contact>` — unblock contact.
    Unblock { contact: String },
    /// `/profile [field]` — edit profile (name/avatar/status).
    Profile { field: Option<String> },
    /// `/delete-account` — permanent account deletion.
    DeleteAccount,
    /// `/lang <code>` — change UI language.
    Lang { code: String },
    /// `/search <query>` — search message history.
    Search { query: String },
    /// Plain text message to send to the current contact.
    Message(String),
}

/// All known slash-command names (without the leading `/`).
const COMMAND_NAMES: &[&str] = &[
    "add",
    "block",
    "delete-account",
    "disappear",
    "export",
    "file",
    "import",
    "info",
    "lang",
    "me",
    "mute",
    "mykey",
    "profile",
    "search",
    "transport",
    "unblock",
    "verify",
];

/// Parse user input into a `CliCommand`.
///
/// Input starting with `/` is treated as a slash command.
/// Anything else is a plain text message.
///
/// # Errors
///
/// Returns an error string if a command is malformed (missing required argument).
///
/// # Example
///
/// ```
/// use aira_cli::commands::parse;
///
/// let cmd = parse("/add abc123 Alice").unwrap();
/// // cmd is CliCommand::Add { pubkey: "abc123", alias: Some("Alice") }
/// ```
#[allow(clippy::too_many_lines)]
pub fn parse(input: &str) -> Result<CliCommand, String> {
    let trimmed = input.trim();

    if trimmed.is_empty() {
        return Err("empty input".into());
    }

    if !trimmed.starts_with('/') {
        return Ok(CliCommand::Message(trimmed.to_string()));
    }

    let mut parts = trimmed[1..].splitn(2, ' ');
    let cmd = parts.next().unwrap_or("");
    let args = parts.next().unwrap_or("").trim();

    match cmd {
        "add" => {
            if args.is_empty() {
                return Err("usage: /add <pubkey> [alias]".into());
            }
            let mut parts = args.splitn(2, ' ');
            let pubkey = parts.next().unwrap_or("").to_string();
            let alias = parts
                .next()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            Ok(CliCommand::Add { pubkey, alias })
        }
        "file" => {
            if args.is_empty() {
                return Err("usage: /file <path>".into());
            }
            Ok(CliCommand::File {
                path: PathBuf::from(args),
            })
        }
        "me" => {
            if args.is_empty() {
                return Err("usage: /me <action>".into());
            }
            Ok(CliCommand::Me {
                action: args.to_string(),
            })
        }
        "mykey" => Ok(CliCommand::MyKey),
        "info" => Ok(CliCommand::Info),
        "verify" => Ok(CliCommand::Verify {
            contact: if args.is_empty() {
                None
            } else {
                Some(args.to_string())
            },
        }),
        "disappear" => {
            if args.is_empty() {
                return Err("usage: /disappear <30s|5m|1h|1d|7d|off>".into());
            }
            Ok(CliCommand::Disappear {
                time: args.to_string(),
            })
        }
        "export" => Ok(CliCommand::Export {
            path: if args.is_empty() {
                None
            } else {
                Some(PathBuf::from(args))
            },
        }),
        "import" => {
            if args.is_empty() {
                return Err("usage: /import <path>".into());
            }
            Ok(CliCommand::Import {
                path: PathBuf::from(args),
            })
        }
        "transport" => {
            if args.is_empty() {
                return Err("usage: /transport <direct|obfs4|mimicry|reality|tor>".into());
            }
            Ok(CliCommand::Transport {
                mode: args.to_string(),
            })
        }
        "mute" => {
            if args.is_empty() {
                return Err("usage: /mute <contact> [duration]".into());
            }
            let mut parts = args.splitn(2, ' ');
            let contact = parts.next().unwrap_or("").to_string();
            let duration = parts
                .next()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            Ok(CliCommand::Mute { contact, duration })
        }
        "block" => {
            if args.is_empty() {
                return Err("usage: /block <contact>".into());
            }
            Ok(CliCommand::Block {
                contact: args.to_string(),
            })
        }
        "unblock" => {
            if args.is_empty() {
                return Err("usage: /unblock <contact>".into());
            }
            Ok(CliCommand::Unblock {
                contact: args.to_string(),
            })
        }
        "profile" => Ok(CliCommand::Profile {
            field: if args.is_empty() {
                None
            } else {
                Some(args.to_string())
            },
        }),
        "delete-account" => Ok(CliCommand::DeleteAccount),
        "lang" => {
            if args.is_empty() {
                return Err("usage: /lang <en|ru|es|zh|ar|de|fr|ja|pt|hi>".into());
            }
            Ok(CliCommand::Lang {
                code: args.to_string(),
            })
        }
        "search" => {
            if args.is_empty() {
                return Err("usage: /search <query>".into());
            }
            Ok(CliCommand::Search {
                query: args.to_string(),
            })
        }
        _ => Err(format!("unknown command: /{cmd}")),
    }
}

/// Return Tab-completion candidates for a partial input.
///
/// If the input starts with `/`, completes command names.
/// Returns a list of full command strings (e.g., `"/file"`, `"/find"`).
#[must_use]
pub fn completions(prefix: &str) -> Vec<String> {
    if !prefix.starts_with('/') {
        return vec![];
    }

    let partial = &prefix[1..];
    COMMAND_NAMES
        .iter()
        .filter(|name| name.starts_with(partial))
        .map(|name| format!("/{name}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain_message() {
        assert_eq!(
            parse("hello world").unwrap(),
            CliCommand::Message("hello world".into())
        );
    }

    #[test]
    fn parse_add_with_alias() {
        let cmd = parse("/add abc123 Alice").unwrap();
        assert_eq!(
            cmd,
            CliCommand::Add {
                pubkey: "abc123".into(),
                alias: Some("Alice".into()),
            }
        );
    }

    #[test]
    fn parse_add_without_alias() {
        let cmd = parse("/add abc123").unwrap();
        assert_eq!(
            cmd,
            CliCommand::Add {
                pubkey: "abc123".into(),
                alias: None,
            }
        );
    }

    #[test]
    fn parse_add_missing_args() {
        assert!(parse("/add").is_err());
    }

    #[test]
    fn parse_file() {
        let cmd = parse("/file /tmp/photo.jpg").unwrap();
        assert_eq!(
            cmd,
            CliCommand::File {
                path: PathBuf::from("/tmp/photo.jpg"),
            }
        );
    }

    #[test]
    fn parse_me() {
        let cmd = parse("/me waves hello").unwrap();
        assert_eq!(
            cmd,
            CliCommand::Me {
                action: "waves hello".into(),
            }
        );
    }

    #[test]
    fn parse_mykey() {
        assert_eq!(parse("/mykey").unwrap(), CliCommand::MyKey);
    }

    #[test]
    fn parse_info() {
        assert_eq!(parse("/info").unwrap(), CliCommand::Info);
    }

    #[test]
    fn parse_verify_with_contact() {
        let cmd = parse("/verify Alice").unwrap();
        assert_eq!(
            cmd,
            CliCommand::Verify {
                contact: Some("Alice".into()),
            }
        );
    }

    #[test]
    fn parse_verify_current_contact() {
        let cmd = parse("/verify").unwrap();
        assert_eq!(cmd, CliCommand::Verify { contact: None });
    }

    #[test]
    fn parse_disappear() {
        let cmd = parse("/disappear 5m").unwrap();
        assert_eq!(cmd, CliCommand::Disappear { time: "5m".into() });
    }

    #[test]
    fn parse_export_with_path() {
        let cmd = parse("/export /tmp/backup.aira").unwrap();
        assert_eq!(
            cmd,
            CliCommand::Export {
                path: Some(PathBuf::from("/tmp/backup.aira")),
            }
        );
    }

    #[test]
    fn parse_export_no_path() {
        let cmd = parse("/export").unwrap();
        assert_eq!(cmd, CliCommand::Export { path: None });
    }

    #[test]
    fn parse_import() {
        let cmd = parse("/import /tmp/backup.aira").unwrap();
        assert_eq!(
            cmd,
            CliCommand::Import {
                path: PathBuf::from("/tmp/backup.aira"),
            }
        );
    }

    #[test]
    fn parse_block() {
        let cmd = parse("/block Alice").unwrap();
        assert_eq!(
            cmd,
            CliCommand::Block {
                contact: "Alice".into(),
            }
        );
    }

    #[test]
    fn parse_unblock() {
        let cmd = parse("/unblock Alice").unwrap();
        assert_eq!(
            cmd,
            CliCommand::Unblock {
                contact: "Alice".into(),
            }
        );
    }

    #[test]
    fn parse_delete_account() {
        assert_eq!(parse("/delete-account").unwrap(), CliCommand::DeleteAccount);
    }

    #[test]
    fn parse_lang() {
        let cmd = parse("/lang ru").unwrap();
        assert_eq!(cmd, CliCommand::Lang { code: "ru".into() });
    }

    #[test]
    fn parse_search() {
        let cmd = parse("/search crypto").unwrap();
        assert_eq!(
            cmd,
            CliCommand::Search {
                query: "crypto".into(),
            }
        );
    }

    #[test]
    fn parse_mute_with_duration() {
        let cmd = parse("/mute Alice 2h").unwrap();
        assert_eq!(
            cmd,
            CliCommand::Mute {
                contact: "Alice".into(),
                duration: Some("2h".into()),
            }
        );
    }

    #[test]
    fn parse_unknown_command() {
        assert!(parse("/foobar").is_err());
    }

    #[test]
    fn parse_empty_input() {
        assert!(parse("").is_err());
    }

    #[test]
    fn parse_whitespace_only() {
        assert!(parse("   ").is_err());
    }

    #[test]
    fn completions_for_slash_f() {
        let comps = completions("/f");
        assert!(comps.contains(&"/file".to_string()));
        assert!(!comps.contains(&"/add".to_string()));
    }

    #[test]
    fn completions_for_full_command() {
        let comps = completions("/mykey");
        assert_eq!(comps, vec!["/mykey"]);
    }

    #[test]
    fn completions_empty_slash() {
        let comps = completions("/");
        assert_eq!(comps.len(), COMMAND_NAMES.len());
    }

    #[test]
    fn completions_no_slash() {
        let comps = completions("hello");
        assert!(comps.is_empty());
    }

    #[test]
    fn parse_transport() {
        let cmd = parse("/transport obfs4").unwrap();
        assert_eq!(
            cmd,
            CliCommand::Transport {
                mode: "obfs4".into(),
            }
        );
    }

    #[test]
    fn parse_profile_with_field() {
        let cmd = parse("/profile name John").unwrap();
        assert_eq!(
            cmd,
            CliCommand::Profile {
                field: Some("name John".into()),
            }
        );
    }

    #[test]
    fn parse_profile_no_field() {
        let cmd = parse("/profile").unwrap();
        assert_eq!(cmd, CliCommand::Profile { field: None });
    }
}
