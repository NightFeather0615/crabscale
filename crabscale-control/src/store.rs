//! Durable store trait and SQLite implementation for the control plane.
//!
//! The [`Store`] trait is the single seam through which the control plane
//! persists its domain model. The default implementation is [`SqliteStore`],
//! which stores all entities in a SQLite database and can be opened either
//! from a file (for restart persistence) or in memory (for tests).

use std::path::Path;
use std::str::FromStr;
use std::sync::Mutex;

use crabscale_proto::{DiscoKey, MachineKey, NodeKey};
use rusqlite::{Connection, OptionalExtension, params};

use crate::model::{Login, Node, Policy, PreAuthKey, Session, User};
use crate::pending::PendingRegistration;

/// Errors returned by a [`Store`] implementation.
#[derive(Debug)]
pub enum StoreError {
    /// The requested entity does not exist.
    NotFound,
    /// An entity with the same unique key already exists.
    AlreadyExists,
    /// A SQLite operation failed.
    Sqlite(rusqlite::Error),
    /// JSON serialization or deserialization failed.
    Json(serde_json::Error),
    /// An I/O operation failed.
    Io(std::io::Error),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "entity not found"),
            Self::AlreadyExists => write!(f, "entity already exists"),
            Self::Sqlite(e) => write!(f, "sqlite error: {e}"),
            Self::Json(e) => write!(f, "json error: {e}"),
            Self::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// The persistence seam used by the control plane.
pub trait Store: Send + Sync {
    /// Create a user and return the stored entity with its assigned id.
    fn create_user(&self, user: &User) -> Result<User, StoreError>;
    /// Fetch a user by id.
    fn get_user(&self, id: i64) -> Result<Option<User>, StoreError>;
    /// Fetch a user by login name.
    fn get_user_by_login_name(&self, login_name: &str) -> Result<Option<User>, StoreError>;
    /// Create a login and return the stored entity with its assigned id.
    fn create_login(&self, login: &Login) -> Result<Login, StoreError>;
    /// Fetch a login by id.
    fn get_login(&self, id: i64) -> Result<Option<Login>, StoreError>;
    /// Insert or update a node and return the stored entity.
    fn upsert_node(&self, node: &Node) -> Result<Node, StoreError>;
    /// Fetch a node by its node key.
    fn get_node_by_node_key(&self, node_key: &NodeKey) -> Result<Option<Node>, StoreError>;
    /// Fetch a node by its machine key.
    fn get_node_by_machine_key(&self, machine_key: &MachineKey)
    -> Result<Option<Node>, StoreError>;
    /// List all registered nodes.
    fn list_nodes(&self) -> Result<Vec<Node>, StoreError>;
    /// Delete a node by its node key.
    fn delete_node(&self, node_key: &NodeKey) -> Result<(), StoreError>;
    /// Create a pre-auth key and return the stored entity.
    fn create_pre_auth_key(&self, key: &PreAuthKey) -> Result<PreAuthKey, StoreError>;
    /// Fetch a pre-auth key by its prefix.
    fn get_pre_auth_key(&self, prefix: &str) -> Result<Option<PreAuthKey>, StoreError>;
    /// Mark a pre-auth key as used.
    fn mark_pre_auth_key_used(&self, id: i64) -> Result<(), StoreError>;
    /// List all pre-auth keys.
    fn list_pre_auth_keys(&self) -> Result<Vec<PreAuthKey>, StoreError>;
    /// Revoke a pre-auth key by prefix.
    fn revoke_pre_auth_key(&self, prefix: &str) -> Result<(), StoreError>;
    /// Save a policy document and return the stored entity.
    fn save_policy(&self, policy: &Policy) -> Result<Policy, StoreError>;
    /// Fetch a policy document by name.
    fn get_policy(&self, name: &str) -> Result<Option<Policy>, StoreError>;
    /// Create a session and return the stored entity.
    fn create_session(&self, session: &Session) -> Result<Session, StoreError>;
    /// Fetch a session by id.
    fn get_session(&self, id: i64) -> Result<Option<Session>, StoreError>;
    /// Delete a session by id.
    fn delete_session(&self, id: i64) -> Result<(), StoreError>;
    /// Insert or update a pending interactive registration.
    fn save_pending(&self, pending: &PendingRegistration) -> Result<(), StoreError>;
    /// Fetch a pending interactive registration by auth id.
    fn get_pending(&self, auth_id: &str) -> Result<Option<PendingRegistration>, StoreError>;
    /// Delete a pending interactive registration by auth id.
    fn delete_pending(&self, auth_id: &str) -> Result<(), StoreError>;
    /// List all pending interactive registrations.
    fn list_pending(&self) -> Result<Vec<PendingRegistration>, StoreError>;
}

/// A [`Store`] backed by SQLite.
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    /// Open (or create) a SQLite database at `path` and run migrations.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        Self::from_connection(conn)
    }

    /// Open an in-memory SQLite database and run migrations.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: Connection) -> Result<Self, StoreError> {
        conn.pragma_update(None, "foreign_keys", "ON")?;
        run_migrations(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

impl Store for SqliteStore {
    fn create_user(&self, user: &User) -> Result<User, StoreError> {
        let conn = self.conn.lock().unwrap();
        let id_param: Option<i64> = if user.id == 0 { None } else { Some(user.id) };
        conn.execute(
            "INSERT INTO users (id, login_name, display_name, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![
                id_param,
                user.login_name,
                user.display_name,
                user.created_at
            ],
        )?;
        let id = if user.id == 0 {
            conn.last_insert_rowid()
        } else {
            user.id
        };
        Ok(User {
            id,
            login_name: user.login_name.clone(),
            display_name: user.display_name.clone(),
            created_at: user.created_at.clone(),
        })
    }

    fn get_user(&self, id: i64) -> Result<Option<User>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let user = conn
            .query_row(
                "SELECT id, login_name, display_name, created_at FROM users WHERE id = ?1",
                params![id],
                |row| {
                    Ok(User {
                        id: row.get(0)?,
                        login_name: row.get(1)?,
                        display_name: row.get(2)?,
                        created_at: row.get(3)?,
                    })
                },
            )
            .optional()?;
        Ok(user)
    }

    fn get_user_by_login_name(&self, login_name: &str) -> Result<Option<User>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let user = conn
            .query_row(
                "SELECT id, login_name, display_name, created_at FROM users WHERE login_name = ?1",
                params![login_name],
                |row| {
                    Ok(User {
                        id: row.get(0)?,
                        login_name: row.get(1)?,
                        display_name: row.get(2)?,
                        created_at: row.get(3)?,
                    })
                },
            )
            .optional()?;
        Ok(user)
    }

    fn create_login(&self, login: &Login) -> Result<Login, StoreError> {
        let conn = self.conn.lock().unwrap();
        let id_param: Option<i64> = if login.id == 0 { None } else { Some(login.id) };
        conn.execute(
            "INSERT INTO logins (id, user_id, provider, login_name, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                id_param,
                login.user_id,
                login.provider,
                login.login_name,
                login.created_at
            ],
        )?;
        let id = if login.id == 0 {
            conn.last_insert_rowid()
        } else {
            login.id
        };
        Ok(Login {
            id,
            user_id: login.user_id,
            provider: login.provider.clone(),
            login_name: login.login_name.clone(),
            created_at: login.created_at.clone(),
        })
    }

    fn get_login(&self, id: i64) -> Result<Option<Login>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let login = conn
            .query_row(
                "SELECT id, user_id, provider, login_name, created_at FROM logins WHERE id = ?1",
                params![id],
                |row| {
                    Ok(Login {
                        id: row.get(0)?,
                        user_id: row.get(1)?,
                        provider: row.get(2)?,
                        login_name: row.get(3)?,
                        created_at: row.get(4)?,
                    })
                },
            )
            .optional()?;
        Ok(login)
    }

    fn upsert_node(&self, node: &Node) -> Result<Node, StoreError> {
        let conn = self.conn.lock().unwrap();
        let addresses = serde_json::to_string(&node.addresses)?;
        let allowed_ips = node
            .allowed_ips
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let hostinfo = node
            .hostinfo
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let tags = node.tags.as_ref().map(serde_json::to_string).transpose()?;

        conn.execute(
            "INSERT INTO nodes (
                stable_id, name, user_id, node_key, machine_key, disco_key,
                addresses, allowed_ips, endpoints, endpoint_types, home_derp, hostinfo, created,
                cap, tags, machine_authorized, ephemeral
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
            ON CONFLICT(node_key) DO UPDATE SET
                stable_id = excluded.stable_id,
                name = excluded.name,
                user_id = excluded.user_id,
                machine_key = excluded.machine_key,
                disco_key = excluded.disco_key,
                addresses = excluded.addresses,
                allowed_ips = excluded.allowed_ips,
                endpoints = excluded.endpoints,
                endpoint_types = excluded.endpoint_types,
                home_derp = excluded.home_derp,
                hostinfo = excluded.hostinfo,
                created = excluded.created,
                cap = excluded.cap,
                tags = excluded.tags,
                machine_authorized = excluded.machine_authorized,
                ephemeral = excluded.ephemeral",
            params![
                node.stable_id,
                node.name,
                node.user_id,
                node.node_key.to_string(),
                node.machine_key.to_string(),
                node.disco_key.to_string(),
                addresses,
                allowed_ips,
                serde_json::to_string(&node.endpoints)?,
                serde_json::to_string(&node.endpoint_types)?,
                node.home_derp as i64,
                hostinfo,
                node.created,
                node.cap as i64,
                tags,
                node.machine_authorized as i64,
                node.ephemeral as i64,
            ],
        )?;
        let id = if node.id == 0 {
            conn.last_insert_rowid()
        } else {
            node.id
        };
        let stable_id = if node.stable_id.is_empty() {
            let sid = format!("n{id:023}");
            conn.execute(
                "UPDATE nodes SET stable_id = ?1 WHERE id = ?2",
                params![sid, id],
            )?;
            sid
        } else {
            node.stable_id.clone()
        };
        Ok(Node {
            id,
            stable_id,
            name: node.name.clone(),
            user_id: node.user_id,
            node_key: node.node_key,
            machine_key: node.machine_key,
            disco_key: node.disco_key,
            addresses: node.addresses.clone(),
            allowed_ips: node.allowed_ips.clone(),
            endpoints: node.endpoints.clone(),
            endpoint_types: node.endpoint_types.clone(),
            home_derp: node.home_derp,
            hostinfo: node.hostinfo.clone(),
            created: node.created.clone(),
            cap: node.cap,
            tags: node.tags.clone(),
            machine_authorized: node.machine_authorized,
            ephemeral: node.ephemeral,
        })
    }

    fn get_node_by_node_key(&self, node_key: &NodeKey) -> Result<Option<Node>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let node = conn
            .query_row(
                "SELECT id, stable_id, name, user_id, node_key, machine_key, disco_key,
                        addresses, allowed_ips, endpoints, endpoint_types, home_derp, hostinfo, created,
                        cap, tags, machine_authorized, ephemeral
                 FROM nodes WHERE node_key = ?1",
                params![node_key.to_string()],
                row_to_node,
            )
            .optional()?;
        Ok(node)
    }

    fn get_node_by_machine_key(
        &self,
        machine_key: &MachineKey,
    ) -> Result<Option<Node>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let node = conn
            .query_row(
                "SELECT id, stable_id, name, user_id, node_key, machine_key, disco_key,
                        addresses, allowed_ips, endpoints, endpoint_types, home_derp, hostinfo, created,
                        cap, tags, machine_authorized, ephemeral
                 FROM nodes WHERE machine_key = ?1",
                params![machine_key.to_string()],
                row_to_node,
            )
            .optional()?;
        Ok(node)
    }

    fn list_nodes(&self) -> Result<Vec<Node>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, stable_id, name, user_id, node_key, machine_key, disco_key,
                    addresses, allowed_ips, endpoints, endpoint_types, home_derp, hostinfo, created,
                    cap, tags, machine_authorized, ephemeral
             FROM nodes ORDER BY id",
        )?;
        let rows = stmt.query_map([], row_to_node)?;
        let mut nodes = Vec::new();
        for row in rows {
            nodes.push(row?);
        }
        Ok(nodes)
    }

    fn delete_node(&self, node_key: &NodeKey) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute(
            "DELETE FROM nodes WHERE node_key = ?1",
            params![node_key.to_string()],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    fn create_pre_auth_key(&self, key: &PreAuthKey) -> Result<PreAuthKey, StoreError> {
        let conn = self.conn.lock().unwrap();
        let tags = key.tags.as_ref().map(serde_json::to_string).transpose()?;
        conn.execute(
            "INSERT INTO pre_auth_keys (
                prefix, secret_hash, reusable, ephemeral, expiration, revoked,
                used, tags, user_id, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                key.prefix,
                key.secret_hash,
                key.reusable as i64,
                key.ephemeral as i64,
                key.expiration,
                key.revoked as i64,
                key.used as i64,
                tags,
                key.user_id,
                key.created_at,
            ],
        )?;
        let id = conn.last_insert_rowid();
        Ok(PreAuthKey {
            id,
            prefix: key.prefix.clone(),
            secret_hash: key.secret_hash.clone(),
            reusable: key.reusable,
            ephemeral: key.ephemeral,
            expiration: key.expiration.clone(),
            revoked: key.revoked,
            used: key.used,
            tags: key.tags.clone(),
            user_id: key.user_id,
            created_at: key.created_at.clone(),
        })
    }

    fn get_pre_auth_key(&self, prefix: &str) -> Result<Option<PreAuthKey>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let key = conn
            .query_row(
                "SELECT id, prefix, secret_hash, reusable, ephemeral, expiration, revoked,
                        used, tags, user_id, created_at
                 FROM pre_auth_keys WHERE prefix = ?1",
                params![prefix],
                |row| {
                    let tags: Option<String> = row.get(8)?;
                    Ok(PreAuthKey {
                        id: row.get(0)?,
                        prefix: row.get(1)?,
                        secret_hash: row.get(2)?,
                        reusable: row.get::<_, i64>(3)? != 0,
                        ephemeral: row.get::<_, i64>(4)? != 0,
                        expiration: row.get(5)?,
                        revoked: row.get::<_, i64>(6)? != 0,
                        used: row.get::<_, i64>(7)? != 0,
                        tags: tags
                            .map(|s| {
                                serde_json::from_str(&s).map_err(|e| {
                                    rusqlite::Error::FromSqlConversionFailure(
                                        8,
                                        rusqlite::types::Type::Text,
                                        Box::new(e),
                                    )
                                })
                            })
                            .transpose()?,
                        user_id: row.get(9)?,
                        created_at: row.get(10)?,
                    })
                },
            )
            .optional()?;
        Ok(key)
    }

    fn mark_pre_auth_key_used(&self, id: i64) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute(
            "UPDATE pre_auth_keys SET used = 1 WHERE id = ?1",
            params![id],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    fn list_pre_auth_keys(&self) -> Result<Vec<PreAuthKey>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, prefix, secret_hash, reusable, ephemeral, expiration, revoked,
                    used, tags, user_id, created_at
             FROM pre_auth_keys ORDER BY id",
        )?;
        let rows = stmt.query_map([], |row| {
            let tags: Option<String> = row.get(8)?;
            Ok(PreAuthKey {
                id: row.get(0)?,
                prefix: row.get(1)?,
                secret_hash: row.get(2)?,
                reusable: row.get::<_, i64>(3)? != 0,
                ephemeral: row.get::<_, i64>(4)? != 0,
                expiration: row.get(5)?,
                revoked: row.get::<_, i64>(6)? != 0,
                used: row.get::<_, i64>(7)? != 0,
                tags: tags
                    .map(|s| {
                        serde_json::from_str(&s).map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                8,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        })
                    })
                    .transpose()?,
                user_id: row.get(9)?,
                created_at: row.get(10)?,
            })
        })?;
        let mut keys = Vec::new();
        for row in rows {
            keys.push(row?);
        }
        Ok(keys)
    }

    fn revoke_pre_auth_key(&self, prefix: &str) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute(
            "UPDATE pre_auth_keys SET revoked = 1 WHERE prefix = ?1",
            params![prefix],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    fn save_policy(&self, policy: &Policy) -> Result<Policy, StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO policies (name, body, created_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(name) DO UPDATE SET body = excluded.body, created_at = excluded.created_at",
            params![policy.name, policy.body, policy.created_at],
        )?;
        let id = if policy.id == 0 {
            conn.last_insert_rowid()
        } else {
            policy.id
        };
        Ok(Policy {
            id,
            name: policy.name.clone(),
            body: policy.body.clone(),
            created_at: policy.created_at.clone(),
        })
    }

    fn get_policy(&self, name: &str) -> Result<Option<Policy>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let policy = conn
            .query_row(
                "SELECT id, name, body, created_at FROM policies WHERE name = ?1",
                params![name],
                |row| {
                    Ok(Policy {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        body: row.get(2)?,
                        created_at: row.get(3)?,
                    })
                },
            )
            .optional()?;
        Ok(policy)
    }

    fn create_session(&self, session: &Session) -> Result<Session, StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO sessions (node_id, machine_key, created_at, last_seen, closed_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                session.node_id,
                session.machine_key.to_string(),
                session.created_at,
                session.last_seen,
                session.closed_at,
            ],
        )?;
        let id = conn.last_insert_rowid();
        Ok(Session {
            id,
            node_id: session.node_id,
            machine_key: session.machine_key,
            created_at: session.created_at.clone(),
            last_seen: session.last_seen.clone(),
            closed_at: session.closed_at.clone(),
        })
    }

    fn get_session(&self, id: i64) -> Result<Option<Session>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let session = conn
            .query_row(
                "SELECT id, node_id, machine_key, created_at, last_seen, closed_at
                 FROM sessions WHERE id = ?1",
                params![id],
                |row| {
                    Ok(Session {
                        id: row.get(0)?,
                        node_id: row.get(1)?,
                        machine_key: MachineKey::from_str(&row.get::<_, String>(2)?).map_err(
                            |_| {
                                rusqlite::Error::InvalidColumnType(
                                    2,
                                    "machine key".to_string(),
                                    rusqlite::types::Type::Text,
                                )
                            },
                        )?,
                        created_at: row.get(3)?,
                        last_seen: row.get(4)?,
                        closed_at: row.get(5)?,
                    })
                },
            )
            .optional()?;
        Ok(session)
    }

    fn delete_session(&self, id: i64) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute("DELETE FROM sessions WHERE id = ?1", params![id])?;
        if changed == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    fn save_pending(&self, pending: &PendingRegistration) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        let hostinfo = pending
            .hostinfo
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let verdict = serde_json::to_string(&pending.verdict)?;
        conn.execute(
            "INSERT INTO pending_registrations (
                auth_id, machine_key, node_key, hostinfo, expiry, version, ephemeral,
                created_at, expires_at, verdict
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            ON CONFLICT(auth_id) DO UPDATE SET
                machine_key = excluded.machine_key,
                node_key = excluded.node_key,
                hostinfo = excluded.hostinfo,
                expiry = excluded.expiry,
                version = excluded.version,
                ephemeral = excluded.ephemeral,
                created_at = excluded.created_at,
                expires_at = excluded.expires_at,
                verdict = excluded.verdict",
            params![
                pending.auth_id,
                pending.machine_key.to_string(),
                pending.node_key.to_string(),
                hostinfo,
                pending.expiry,
                pending.version as i64,
                pending.ephemeral as i64,
                pending.created_at,
                pending.expires_at,
                verdict,
            ],
        )?;
        Ok(())
    }

    fn get_pending(&self, auth_id: &str) -> Result<Option<PendingRegistration>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let pending = conn
            .query_row(
                "SELECT auth_id, machine_key, node_key, hostinfo, expiry, version, ephemeral,
                        created_at, expires_at, verdict
                 FROM pending_registrations WHERE auth_id = ?1",
                params![auth_id],
                row_to_pending,
            )
            .optional()?;
        Ok(pending)
    }

    fn delete_pending(&self, auth_id: &str) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM pending_registrations WHERE auth_id = ?1",
            params![auth_id],
        )?;
        Ok(())
    }

    fn list_pending(&self) -> Result<Vec<PendingRegistration>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT auth_id, machine_key, node_key, hostinfo, expiry, version, ephemeral,
                    created_at, expires_at, verdict
             FROM pending_registrations",
        )?;
        let rows = stmt
            .query_map([], row_to_pending)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

fn row_to_pending(row: &rusqlite::Row<'_>) -> rusqlite::Result<PendingRegistration> {
    let hostinfo: Option<String> = row.get(3)?;
    let verdict: String = row.get(9)?;
    Ok(PendingRegistration {
        auth_id: row.get(0)?,
        machine_key: MachineKey::from_str(&row.get::<_, String>(1)?).map_err(|_| {
            rusqlite::Error::InvalidColumnType(
                1,
                "machine key".to_string(),
                rusqlite::types::Type::Text,
            )
        })?,
        node_key: NodeKey::from_str(&row.get::<_, String>(2)?).map_err(|_| {
            rusqlite::Error::InvalidColumnType(
                2,
                "node key".to_string(),
                rusqlite::types::Type::Text,
            )
        })?,
        hostinfo: hostinfo
            .map(|s| serde_json::from_str(&s))
            .transpose()
            .map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    3,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?,
        expiry: row.get(4)?,
        version: row.get::<_, i64>(5)? as u32,
        ephemeral: row.get::<_, i64>(6)? != 0,
        created_at: row.get(7)?,
        expires_at: row.get(8)?,
        verdict: serde_json::from_str(&verdict).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(9, rusqlite::types::Type::Text, Box::new(e))
        })?,
    })
}

fn row_to_node(row: &rusqlite::Row<'_>) -> rusqlite::Result<Node> {
    let addresses: String = row.get(7)?;
    let allowed_ips: Option<String> = row.get(8)?;
    let endpoints: String = row.get(9)?;
    let endpoint_types: String = row.get(10)?;
    let hostinfo: Option<String> = row.get(12)?;
    let tags: Option<String> = row.get(15)?;
    Ok(Node {
        id: row.get(0)?,
        stable_id: row.get(1)?,
        name: row.get(2)?,
        user_id: row.get(3)?,
        node_key: NodeKey::from_str(&row.get::<_, String>(4)?).map_err(|_| {
            rusqlite::Error::InvalidColumnType(
                4,
                "node key".to_string(),
                rusqlite::types::Type::Text,
            )
        })?,
        machine_key: MachineKey::from_str(&row.get::<_, String>(5)?).map_err(|_| {
            rusqlite::Error::InvalidColumnType(
                5,
                "machine key".to_string(),
                rusqlite::types::Type::Text,
            )
        })?,
        disco_key: DiscoKey::from_str(&row.get::<_, String>(6)?).map_err(|_| {
            rusqlite::Error::InvalidColumnType(
                6,
                "disco key".to_string(),
                rusqlite::types::Type::Text,
            )
        })?,
        addresses: serde_json::from_str(&addresses).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(e))
        })?,
        allowed_ips: allowed_ips
            .map(|s| serde_json::from_str(&s))
            .transpose()
            .map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    8,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?,
        endpoints: serde_json::from_str(&endpoints).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(9, rusqlite::types::Type::Text, Box::new(e))
        })?,
        endpoint_types: serde_json::from_str(&endpoint_types).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(10, rusqlite::types::Type::Text, Box::new(e))
        })?,
        home_derp: row.get::<_, i64>(11)? as u64,
        hostinfo: hostinfo
            .map(|s| serde_json::from_str(&s))
            .transpose()
            .map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    12,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?,
        created: row.get(13)?,
        cap: row.get(14)?,
        tags: tags
            .map(|s| serde_json::from_str(&s))
            .transpose()
            .map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    15,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?,
        machine_authorized: row.get::<_, i64>(16)? != 0,
        ephemeral: row.get::<_, i64>(17)? != 0,
    })
}

/// Apply all pending schema migrations.
fn run_migrations(conn: &Connection) -> Result<(), StoreError> {
    let mut version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version < 1 {
        conn.execute_batch(
            "BEGIN;
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                login_name TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS logins (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                provider TEXT NOT NULL,
                login_name TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS nodes (
                id INTEGER PRIMARY KEY,
                stable_id TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                user_id INTEGER NOT NULL REFERENCES users(id),
                node_key TEXT NOT NULL UNIQUE,
                machine_key TEXT NOT NULL,
                disco_key TEXT NOT NULL,
                addresses TEXT NOT NULL,
                allowed_ips TEXT,
                endpoints TEXT NOT NULL,
                endpoint_types TEXT NOT NULL DEFAULT '[]',
                home_derp INTEGER NOT NULL,
                hostinfo TEXT,
                created TEXT NOT NULL,
                cap INTEGER NOT NULL,
                tags TEXT,
                machine_authorized INTEGER NOT NULL,
                ephemeral INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_nodes_machine_key ON nodes(machine_key);
            CREATE TABLE IF NOT EXISTS pre_auth_keys (
                id INTEGER PRIMARY KEY,
                prefix TEXT NOT NULL UNIQUE,
                secret_hash TEXT NOT NULL,
                reusable INTEGER NOT NULL,
                ephemeral INTEGER NOT NULL,
                expiration TEXT,
                revoked INTEGER NOT NULL,
                used INTEGER NOT NULL,
                tags TEXT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS policies (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY,
                node_id INTEGER NOT NULL REFERENCES nodes(id),
                machine_key TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                closed_at TEXT
            );
            PRAGMA user_version = 3;
            COMMIT;",
        )?;
        version = 3;
    }
    if version < 2 {
        conn.execute_batch(
            "ALTER TABLE nodes ADD COLUMN ephemeral INTEGER NOT NULL DEFAULT 0;
            PRAGMA user_version = 2;",
        )?;
    }
    if version < 3 {
        conn.execute_batch(
            "ALTER TABLE nodes ADD COLUMN endpoint_types TEXT NOT NULL DEFAULT '[]';
            PRAGMA user_version = 3;",
        )?;
    }
    if version < 4 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS pending_registrations (
                auth_id TEXT PRIMARY KEY,
                machine_key TEXT NOT NULL,
                node_key TEXT NOT NULL,
                hostinfo TEXT,
                expiry TEXT NOT NULL,
                version INTEGER NOT NULL,
                ephemeral INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                verdict TEXT NOT NULL
            );
            PRAGMA user_version = 4;",
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    fn test_store() -> SqliteStore {
        SqliteStore::open_in_memory().unwrap()
    }

    fn test_user() -> User {
        User {
            id: 0,
            login_name: "owner@example.com".to_string(),
            display_name: "Owner".to_string(),
            created_at: "2026-08-20T00:00:00Z".to_string(),
        }
    }

    fn test_node(user_id: i64) -> Node {
        Node {
            id: 0,
            stable_id: "n00000000000000000000001".to_string(),
            name: "node1.tailnet.example.".to_string(),
            user_id,
            node_key: NodeKey::from_bytes([0x22; 32]),
            machine_key: MachineKey::from_bytes([0x11; 32]),
            disco_key: DiscoKey::from_bytes([0x33; 32]),
            addresses: vec!["100.64.0.1/32".to_string()],
            allowed_ips: Some(vec!["100.64.0.1/32".to_string()]),
            endpoints: Vec::new(),
            endpoint_types: Vec::new(),
            home_derp: 1,
            hostinfo: None,
            created: "2026-08-20T00:00:00Z".to_string(),
            cap: 130,
            tags: None,
            machine_authorized: true,
            ephemeral: false,
        }
    }

    #[test]
    fn migrations_create_all_tables() {
        let store = test_store();
        let conn = store.conn.lock().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name IN
                 ('users', 'logins', 'nodes', 'pre_auth_keys', 'policies', 'sessions')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 6);
    }

    #[test]
    fn user_and_login_round_trip() {
        let store = test_store();
        let user = store.create_user(&test_user()).unwrap();
        assert!(user.id > 0);
        assert_eq!(store.get_user(user.id).unwrap(), Some(user.clone()));

        let login = store
            .create_login(&Login {
                id: 0,
                user_id: user.id,
                provider: "authkey".to_string(),
                login_name: user.login_name.clone(),
                created_at: user.created_at.clone(),
            })
            .unwrap();
        assert!(login.id > 0);
        assert_eq!(store.get_login(login.id).unwrap(), Some(login));
    }

    #[test]
    fn node_upsert_and_fetch_round_trip() {
        let store = test_store();
        let user = store.create_user(&test_user()).unwrap();
        let node = store.upsert_node(&test_node(user.id)).unwrap();
        assert!(node.id > 0);

        let fetched = store
            .get_node_by_node_key(&node.node_key)
            .unwrap()
            .expect("node should exist");
        assert_eq!(fetched, node);

        let by_machine = store
            .get_node_by_machine_key(&node.machine_key)
            .unwrap()
            .expect("node should exist by machine key");
        assert_eq!(by_machine, node);

        assert_eq!(store.list_nodes().unwrap(), vec![node.clone()]);
    }

    #[test]
    fn node_upsert_updates_existing() {
        let store = test_store();
        let user = store.create_user(&test_user()).unwrap();
        let mut node = store.upsert_node(&test_node(user.id)).unwrap();
        node.endpoints = vec!["1.2.3.4:41641".to_string()];
        let updated = store.upsert_node(&node).unwrap();
        assert_eq!(updated.id, node.id);
        assert_eq!(updated.endpoints, vec!["1.2.3.4:41641".to_string()]);
        assert_eq!(store.list_nodes().unwrap().len(), 1);
    }

    #[test]
    fn pre_auth_key_round_trip_and_use() {
        let store = test_store();
        let user = store.create_user(&test_user()).unwrap();
        let key = store
            .create_pre_auth_key(&PreAuthKey {
                id: 0,
                prefix: "test".to_string(),
                secret_hash: "hash".to_string(),
                reusable: false,
                ephemeral: false,
                expiration: None,
                revoked: false,
                used: false,
                tags: None,
                user_id: user.id,
                created_at: "2026-08-20T00:00:00Z".to_string(),
            })
            .unwrap();
        assert!(key.id > 0);
        assert_eq!(store.get_pre_auth_key("test").unwrap(), Some(key.clone()));
        store.mark_pre_auth_key_used(key.id).unwrap();
        let used = store.get_pre_auth_key("test").unwrap().unwrap();
        assert!(used.used);
    }

    #[test]
    fn policy_and_session_round_trip() {
        let store = test_store();
        let policy = store
            .save_policy(&Policy {
                id: 0,
                name: "default".to_string(),
                body: "{}".to_string(),
                created_at: "2026-08-20T00:00:00Z".to_string(),
            })
            .unwrap();
        assert!(policy.id > 0);
        assert_eq!(store.get_policy("default").unwrap(), Some(policy));

        let user = store.create_user(&test_user()).unwrap();
        let node = store.upsert_node(&test_node(user.id)).unwrap();
        let session = store
            .create_session(&Session {
                id: 0,
                node_id: node.id,
                machine_key: node.machine_key,
                created_at: "2026-08-20T00:00:00Z".to_string(),
                last_seen: "2026-08-20T00:00:00Z".to_string(),
                closed_at: None,
            })
            .unwrap();
        assert!(session.id > 0);
        assert_eq!(
            store.get_session(session.id).unwrap(),
            Some(session.clone())
        );
        store.delete_session(session.id).unwrap();
        assert_eq!(store.get_session(session.id).unwrap(), None);
    }

    #[test]
    fn restart_preserves_registered_node() {
        let dir = std::env::temp_dir().join(format!("crabscale-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("restart.sqlite");

        let node_key = NodeKey::from_bytes([0x22; 32]);
        let machine_key = MachineKey::from_bytes([0x11; 32]);

        {
            let store = SqliteStore::open(&db_path).unwrap();
            let user = store.create_user(&test_user()).unwrap();
            let node = store.upsert_node(&test_node(user.id)).unwrap();
            assert_eq!(node.node_key, node_key);
            assert_eq!(node.machine_key, machine_key);
        }

        // Reopen the same database file: the node must still be there.
        let store = SqliteStore::open(&db_path).unwrap();
        let node = store
            .get_node_by_node_key(&node_key)
            .unwrap()
            .expect("node should survive restart");
        assert_eq!(node.machine_key, machine_key);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
