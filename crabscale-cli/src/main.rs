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

use std::process::ExitCode;

use crabscale_control::{ControlConfig, ControlError, ControlPlane};

/// A parsed `crabscale auth` subcommand.
#[derive(Debug, PartialEq, Eq)]
enum AuthCommand {
    Approve { auth_id: String, user: String },
    Reject { auth_id: String },
}

/// Parse the `crabscale auth ...` argument vector.
fn parse_auth_command(args: &[String]) -> Result<AuthCommand, String> {
    if args.is_empty() {
        return Err("missing auth subcommand (expected `approve` or `reject`)".to_string());
    }
    match args[0].as_str() {
        "approve" => {
            let mut auth_id = None;
            let mut user = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--auth-id" => {
                        i += 1;
                        auth_id = Some(
                            args.get(i)
                                .ok_or_else(|| "--auth-id requires a value".to_string())?
                                .clone(),
                        );
                    }
                    "--user" => {
                        i += 1;
                        user = Some(
                            args.get(i)
                                .ok_or_else(|| "--user requires a value".to_string())?
                                .clone(),
                        );
                    }
                    other => return Err(format!("unknown approve argument: {other}")),
                }
                i += 1;
            }
            let auth_id = auth_id.ok_or_else(|| "approve requires --auth-id".to_string())?;
            let user = user.ok_or_else(|| "approve requires --user".to_string())?;
            Ok(AuthCommand::Approve { auth_id, user })
        }
        "reject" => {
            let mut auth_id = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--auth-id" => {
                        i += 1;
                        auth_id = Some(
                            args.get(i)
                                .ok_or_else(|| "--auth-id requires a value".to_string())?
                                .clone(),
                        );
                    }
                    other => return Err(format!("unknown reject argument: {other}")),
                }
                i += 1;
            }
            let auth_id = auth_id.ok_or_else(|| "reject requires --auth-id".to_string())?;
            Ok(AuthCommand::Reject { auth_id })
        }
        other => Err(format!("unknown auth subcommand: {other}")),
    }
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
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some("auth") {
        eprintln!(
            "usage: crabscale auth approve --auth-id <id> --user <name> | crabscale auth reject --auth-id <id>"
        );
        return ExitCode::FAILURE;
    }
    let command = match parse_auth_command(&args[1..]) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let plane = ControlPlane::new(ControlConfig::default());
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
        let args = vec![
            "approve".to_string(),
            "--auth-id".to_string(),
            "abc123".to_string(),
            "--user".to_string(),
            "alice".to_string(),
        ];
        assert_eq!(
            parse_auth_command(&args).unwrap(),
            AuthCommand::Approve {
                auth_id: "abc123".to_string(),
                user: "alice".to_string(),
            }
        );
    }

    #[test]
    fn parses_reject_command() {
        let args = vec![
            "reject".to_string(),
            "--auth-id".to_string(),
            "abc".to_string(),
        ];
        assert_eq!(
            parse_auth_command(&args).unwrap(),
            AuthCommand::Reject {
                auth_id: "abc".to_string()
            }
        );
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
}
