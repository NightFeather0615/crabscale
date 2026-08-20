//! Admin command-line client for interactive registration approval.
//!
//! The CLI operates on a local [`ControlPlane`] and lets an administrator
//! approve or reject a pending interactive registration by its auth id.
//!
//! Usage:
//! ```text
//! crabscale auth approve --auth-id <id> --user <name>
//! crabscale auth reject --auth-id <id>
//! ```

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use crabscale_control::{ControlConfig, ControlError, ControlPlane};

/// Admin command-line client for crabscale.
#[derive(Parser)]
#[command(name = "crabscale", about = "crabscale admin CLI")]
struct Cli {
    /// Path to the SQLite database file used by the control server.
    #[arg(long, global = true)]
    store: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Approve or reject a pending interactive registration.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
}

#[derive(Subcommand)]
enum AuthCommand {
    /// Approve a pending interactive registration.
    Approve {
        /// The auth id from the registration AuthURL.
        #[arg(long)]
        auth_id: String,
        /// The login name of the user that owns the node.
        #[arg(long)]
        user: String,
    },
    /// Reject a pending interactive registration.
    Reject {
        /// The auth id from the registration AuthURL.
        #[arg(long)]
        auth_id: String,
    },
}

/// Run an auth command against the given control plane.
fn run_auth_command(plane: &ControlPlane, command: AuthCommand) -> Result<String, ControlError> {
    match command {
        AuthCommand::Approve { auth_id, user } => {
            plane.approve_pending(&auth_id, &user)?;
            Ok(format!(
                "approved pending registration {auth_id} for user {user}"
            ))
        }
        AuthCommand::Reject { auth_id } => {
            plane.reject_pending(&auth_id)?;
            Ok(format!("rejected pending registration {auth_id}"))
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let Command::Auth { command } = cli.command;
    let plane = match &cli.store {
        Some(path) => match ControlPlane::open_sqlite(ControlConfig::default(), path) {
            Ok(plane) => plane,
            Err(e) => {
                eprintln!("error: failed to open store {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
        },
        None => ControlPlane::new(ControlConfig::default()),
    };
    match run_auth_command(&plane, command) {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crabscale_control::{ControlConfig, ControlPlane};
    use crabscale_proto::{Hostinfo, MachineKey, NodeKey, RegisterAuth, RegisterRequest};

    fn test_plane() -> ControlPlane {
        ControlPlane::new(ControlConfig::default())
    }

    fn start_pending(plane: &ControlPlane) -> String {
        let request = RegisterRequest {
            version: 130,
            node_key: NodeKey::from_bytes([0x22; 32]),
            auth: Some(RegisterAuth {
                auth_key: "wrong".to_string(),
            }),
            hostinfo: Some(Hostinfo {
                hostname: "node1".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let response = plane
            .register(MachineKey::from_bytes([0x11; 32]), request)
            .unwrap();
        assert!(!response.machine_authorized);
        assert!(!response.auth_url.is_empty());
        crabscale_control::auth_id_from_followup(&response.auth_url).unwrap()
    }

    #[test]
    fn parses_approve_command() {
        let cli = Cli::try_parse_from([
            "crabscale",
            "auth",
            "approve",
            "--auth-id",
            "abc123",
            "--user",
            "alice",
        ])
        .unwrap();
        let Command::Auth { command } = cli.command;
        assert!(matches!(
            command,
            AuthCommand::Approve {
                auth_id,
                user
            } if auth_id == "abc123" && user == "alice"
        ));
    }

    #[test]
    fn parses_reject_command() {
        let cli = Cli::try_parse_from(["crabscale", "auth", "reject", "--auth-id", "abc"]).unwrap();
        let Command::Auth { command } = cli.command;
        assert!(matches!(
            command,
            AuthCommand::Reject { auth_id } if auth_id == "abc"
        ));
    }

    #[test]
    fn approve_authorizes_pending_registration() {
        let plane = test_plane();
        let auth_id = start_pending(&plane);
        let message = run_auth_command(
            &plane,
            AuthCommand::Approve {
                auth_id: auth_id.clone(),
                user: "alice".to_string(),
            },
        )
        .unwrap();
        assert!(message.contains("approved"));

        // The followup now authorizes the same machine key.
        let followup = RegisterRequest {
            version: 130,
            node_key: NodeKey::from_bytes([0x22; 32]),
            followup: format!("https://tailnet.example/register/{auth_id}"),
            ..Default::default()
        };
        let response = plane
            .register(MachineKey::from_bytes([0x11; 32]), followup)
            .unwrap();
        assert!(response.machine_authorized);
    }

    #[test]
    fn reject_denies_pending_registration() {
        let plane = test_plane();
        let auth_id = start_pending(&plane);
        run_auth_command(
            &plane,
            AuthCommand::Reject {
                auth_id: auth_id.clone(),
            },
        )
        .unwrap();

        let followup = RegisterRequest {
            version: 130,
            node_key: NodeKey::from_bytes([0x22; 32]),
            followup: format!("https://tailnet.example/register/{auth_id}"),
            ..Default::default()
        };
        let response = plane
            .register(MachineKey::from_bytes([0x11; 32]), followup)
            .unwrap();
        assert!(!response.machine_authorized);
        assert!(!response.error.is_empty());
    }

    #[test]
    fn approve_unknown_auth_id_errors() {
        let plane = test_plane();
        let err = run_auth_command(
            &plane,
            AuthCommand::Approve {
                auth_id: "does-not-exist".to_string(),
                user: "alice".to_string(),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ControlError::NotFound));
    }

    #[test]
    fn separate_process_can_approve_via_shared_sqlite_file() {
        // A pending registration started by one control plane (the server)
        // must be approvable by a second plane (the CLI) opening the same
        // SQLite database file.
        let dir = std::env::temp_dir();
        let db_path = dir.join(format!("crabscale-cli-test-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&db_path);

        let server = ControlPlane::open_sqlite(ControlConfig::default(), &db_path).unwrap();
        let auth_id = start_pending(&server);

        let cli = ControlPlane::open_sqlite(ControlConfig::default(), &db_path).unwrap();
        run_auth_command(
            &cli,
            AuthCommand::Approve {
                auth_id: auth_id.clone(),
                user: "alice".to_string(),
            },
        )
        .unwrap();

        // The server now sees the approval from the separate process.
        let followup = RegisterRequest {
            version: 130,
            node_key: NodeKey::from_bytes([0x22; 32]),
            followup: format!("https://tailnet.example/register/{auth_id}"),
            ..Default::default()
        };
        let response = server
            .register(MachineKey::from_bytes([0x11; 32]), followup)
            .unwrap();
        assert!(response.machine_authorized);

        let _ = std::fs::remove_file(&db_path);
    }
}
