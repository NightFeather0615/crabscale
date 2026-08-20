//! Admin command-line client for registration and route administration.
//!
//! The CLI operates on a local [`ControlPlane`] and lets an administrator
//! approve or reject a pending interactive registration by its auth id, and
//! approve or disapprove subnet/exit routes a node advertises.
//!
//! Usage:
//! ```text
//! crabscale auth approve --auth-id <id> --user <name>
//! crabscale auth reject --auth-id <id>
//! crabscale route approve --node <nodekey> --route <cidr>
//! crabscale route disapprove --node <nodekey> --route <cidr>
//! crabscale route list --node <nodekey>
//! crabscale ssh approve --auth-id <id>
//! crabscale ssh reject --auth-id <id>
//! crabscale ssh list
//! ```

use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;

use clap::{Parser, Subcommand};
use crabscale_control::{ControlConfig, ControlError, ControlPlane};
use crabscale_proto::NodeKey;

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
    /// Approve, disapprove, or list subnet/exit routes.
    Route {
        #[command(subcommand)]
        command: RouteCommand,
    },
    /// Approve or reject a pending Tailscale SSH check-mode request.
    Ssh {
        #[command(subcommand)]
        command: SshCommand,
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

#[derive(Subcommand)]
enum SshCommand {
    /// Approve a pending SSH check-mode request.
    Approve {
        /// The auth id from the SSH check-mode followup URL.
        #[arg(long)]
        auth_id: String,
    },
    /// Reject a pending SSH check-mode request.
    Reject {
        /// The auth id from the SSH check-mode followup URL.
        #[arg(long)]
        auth_id: String,
    },
    /// List pending SSH check-mode requests.
    List,
}

#[derive(Subcommand)]
enum RouteCommand {
    /// Approve a route a node advertises.
    Approve {
        /// The node key (`nodekey:` prefixed) that advertises the route.
        #[arg(long)]
        node: String,
        /// The route to approve, as an IP or CIDR.
        #[arg(long)]
        route: String,
    },
    /// Remove an approval for a route.
    Disapprove {
        /// The node key (`nodekey:` prefixed) that advertises the route.
        #[arg(long)]
        node: String,
        /// The route to disapprove, as an IP or CIDR.
        #[arg(long)]
        route: String,
    },
    /// List the routes a node advertises and the approved subset.
    List {
        /// The node key (`nodekey:` prefixed) to list routes for.
        #[arg(long)]
        node: String,
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

/// Parse a `nodekey:` argument into a [`NodeKey`].
fn parse_node_key(node: &str) -> Result<NodeKey, ControlError> {
    NodeKey::from_str(node).map_err(|e| ControlError::Policy(format!("invalid node key: {e}")))
}

/// Run a route command against the given control plane.
fn run_route_command(plane: &ControlPlane, command: RouteCommand) -> Result<String, ControlError> {
    match command {
        RouteCommand::Approve { node, route } => {
            let node_key = parse_node_key(&node)?;
            plane.approve_route(&node_key, &route)?;
            Ok(format!("approved route {route} for {node}"))
        }
        RouteCommand::Disapprove { node, route } => {
            let node_key = parse_node_key(&node)?;
            plane.disapprove_route(&node_key, &route)?;
            Ok(format!("disapproved route {route} for {node}"))
        }
        RouteCommand::List { node } => {
            let node_key = parse_node_key(&node)?;
            let stored = plane
                .node_by_key(&node_key)?
                .ok_or(ControlError::NotFound)?;
            let advertised = if stored.advertised_routes.is_empty() {
                "(none)".to_string()
            } else {
                stored.advertised_routes.join(", ")
            };
            let approved = if stored.approved_routes.is_empty() {
                "(none)".to_string()
            } else {
                stored.approved_routes.join(", ")
            };
            Ok(format!(
                "node {} ({})\nadvertised: {}\napproved: {}",
                stored.stable_id, stored.name, advertised, approved
            ))
        }
    }
}

/// Run an SSH command against the given control plane.
fn run_ssh_command(plane: &ControlPlane, command: SshCommand) -> Result<String, ControlError> {
    match command {
        SshCommand::Approve { auth_id } => {
            plane.approve_ssh(&auth_id)?;
            Ok(format!("approved SSH auth {auth_id}"))
        }
        SshCommand::Reject { auth_id } => {
            plane.reject_ssh(&auth_id)?;
            Ok(format!("rejected SSH auth {auth_id}"))
        }
        SshCommand::List => {
            let auths = plane.list_ssh_auths()?;
            if auths.is_empty() {
                return Ok("no SSH auth records".to_string());
            }
            let mut lines = Vec::new();
            for auth in auths {
                let status = match auth.verdict {
                    crabscale_control::SshVerdict::Pending => "pending".to_string(),
                    crabscale_control::SshVerdict::Accepted { .. } => "accepted".to_string(),
                    crabscale_control::SshVerdict::Rejected => "rejected".to_string(),
                };
                lines.push(format!(
                    "{} {}->{} {status}",
                    auth.auth_id, auth.src_node_id, auth.dst_node_id
                ));
            }
            Ok(lines.join(
                "
",
            ))
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
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

    let result = match cli.command {
        Command::Auth { command } => run_auth_command(&plane, command),
        Command::Route { command } => run_route_command(&plane, command),
        Command::Ssh { command } => run_ssh_command(&plane, command),
    };

    match result {
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
        let response = plane.register(MachineKey::from_bytes([0x11; 32]), request);
        assert!(!response.machine_authorized);
        assert!(!response.auth_url.is_empty());
        crabscale_control::auth_id_from_followup(&response.auth_url).unwrap()
    }

    /// Register a node and return its node key string.
    fn registered_node_key(plane: &ControlPlane) -> String {
        let request = RegisterRequest {
            version: 130,
            node_key: NodeKey::from_bytes([0x22; 32]),
            auth: Some(RegisterAuth {
                auth_key: "hskey-auth-test-secret".to_string(),
            }),
            hostinfo: Some(Hostinfo {
                hostname: "router".to_string(),
                routable_ips: Some(vec!["10.99.0.0/16".to_string()]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let response = plane.register(MachineKey::from_bytes([0x11; 32]), request);
        assert!(response.machine_authorized);
        NodeKey::from_bytes([0x22; 32]).to_string()
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
        match cli.command {
            Command::Auth { command } => assert!(matches!(
                command,
                AuthCommand::Approve { auth_id, user }
                    if auth_id == "abc123" && user == "alice"
            )),
            _ => panic!("expected auth approve"),
        }
    }

    #[test]
    fn parses_reject_command() {
        let cli = Cli::try_parse_from(["crabscale", "auth", "reject", "--auth-id", "abc"]).unwrap();
        match cli.command {
            Command::Auth { command } => assert!(matches!(
                command,
                AuthCommand::Reject { auth_id } if auth_id == "abc"
            )),
            _ => panic!("expected auth reject"),
        }
    }

    #[test]
    fn parses_route_commands() {
        let cli = Cli::try_parse_from([
            "crabscale",
            "route",
            "approve",
            "--node",
            "nodekey:aa",
            "--route",
            "10.0.0.0/8",
        ])
        .unwrap();
        match cli.command {
            Command::Route { command } => assert!(matches!(
                command,
                RouteCommand::Approve { node, route }
                    if node == "nodekey:aa" && route == "10.0.0.0/8"
            )),
            _ => panic!("expected route approve"),
        }

        let cli = Cli::try_parse_from([
            "crabscale",
            "route",
            "disapprove",
            "--node",
            "nodekey:aa",
            "--route",
            "10.0.0.0/8",
        ])
        .unwrap();
        match cli.command {
            Command::Route { command } => assert!(matches!(
                command,
                RouteCommand::Disapprove { node, route }
                    if node == "nodekey:aa" && route == "10.0.0.0/8"
            )),
            _ => panic!("expected route disapprove"),
        }

        let cli =
            Cli::try_parse_from(["crabscale", "route", "list", "--node", "nodekey:aa"]).unwrap();
        match cli.command {
            Command::Route { command } => assert!(matches!(
                command,
                RouteCommand::List { node } if node == "nodekey:aa"
            )),
            _ => panic!("expected route list"),
        }
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
        let response = plane.register(MachineKey::from_bytes([0x11; 32]), followup);
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
        let response = plane.register(MachineKey::from_bytes([0x11; 32]), followup);
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
    fn route_commands_approve_disapprove_and_list() {
        let plane = test_plane();
        let node = registered_node_key(&plane);
        let node_key = NodeKey::from_str(&node).unwrap();

        let message = run_route_command(
            &plane,
            RouteCommand::Approve {
                node: node.clone(),
                route: "10.99.0.0/16".to_string(),
            },
        )
        .unwrap();
        assert!(message.contains("approved"));

        let listed = run_route_command(&plane, RouteCommand::List { node: node.clone() }).unwrap();
        assert!(listed.contains("10.99.0.0/16"));
        assert!(listed.contains("advertised"));

        let message = run_route_command(
            &plane,
            RouteCommand::Disapprove {
                node: node.clone(),
                route: "10.99.0.0/16".to_string(),
            },
        )
        .unwrap();
        assert!(message.contains("disapproved"));

        let after = plane.node_by_key(&node_key).unwrap().unwrap();
        assert!(after.approved_routes.is_empty());
    }

    #[test]
    fn route_command_rejects_bad_node_key() {
        let plane = test_plane();
        let err = run_route_command(
            &plane,
            RouteCommand::Approve {
                node: "not-a-key".to_string(),
                route: "10.0.0.0/8".to_string(),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ControlError::Policy(_)));
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
        let response = server.register(MachineKey::from_bytes([0x11; 32]), followup);
        assert!(response.machine_authorized);

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn parses_ssh_commands() {
        let cli =
            Cli::try_parse_from(["crabscale", "ssh", "approve", "--auth-id", "abc123"]).unwrap();
        match cli.command {
            Command::Ssh { command } => assert!(matches!(
                command,
                SshCommand::Approve { auth_id } if auth_id == "abc123"
            )),
            _ => panic!("expected ssh approve"),
        }

        let cli = Cli::try_parse_from(["crabscale", "ssh", "reject", "--auth-id", "abc"]).unwrap();
        match cli.command {
            Command::Ssh { command } => assert!(matches!(
                command,
                SshCommand::Reject { auth_id } if auth_id == "abc"
            )),
            _ => panic!("expected ssh reject"),
        }

        let cli = Cli::try_parse_from(["crabscale", "ssh", "list"]).unwrap();
        match cli.command {
            Command::Ssh { command } => assert!(matches!(command, SshCommand::List)),
            _ => panic!("expected ssh list"),
        }
    }

    #[test]
    fn ssh_approve_unknown_auth_id_errors() {
        let plane = test_plane();
        let err = run_ssh_command(
            &plane,
            SshCommand::Approve {
                auth_id: "does-not-exist".to_string(),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ControlError::NotFound));
    }

    #[test]
    fn ssh_list_empty_reports_no_records() {
        let plane = test_plane();
        let message = run_ssh_command(&plane, SshCommand::List).unwrap();
        assert!(message.contains("no SSH auth records"));
    }
}
