//! Backup and restore for the SQLite store (M4-04, #27).
//!
//! A backup is a zstd-compressed JSON document containing only an explicit
//! allowlist of tables and columns. The allowlist deliberately excludes any
//! table or column that could carry plaintext secret material. Today the store
//! keeps only public key material and salted *hashes* of pre-auth key secrets,
//! so every domain table qualifies; if a future migration ever introduces a
//! plaintext secret column, that column must be added to the exclusion list
//! here *before* it is persisted, mirroring Architecture.md invariant 5
//! ("Secret material is never logged or serialized into backups in
//! plaintext").
//!
//! The format is versioned so that a restore can reject documents written by
//! an incompatible (future) exporter instead of silently writing wrong data.

use std::io::{Read, Write};

use rusqlite::Connection;
use serde_json::{Map, Value, json};

/// Version identifier embedded in every backup document.
pub const BACKUP_FORMAT: &str = "crabscale-backup/v1";

/// Tables allowed into a backup, with their exact column allowlist.
///
/// Anything not listed here is never serialized. Each row is stored as a JSON
/// object keyed by the allowlisted column name.
pub const BACKUP_TABLES: &[(&str, &[&str])] = &[
    ("users", &["id", "login_name", "display_name", "created_at"]),
    (
        "logins",
        &["id", "user_id", "provider", "login_name", "created_at"],
    ),
    (
        "nodes",
        &[
            "id",
            "stable_id",
            "name",
            "user_id",
            "node_key",
            "machine_key",
            "disco_key",
            "addresses",
            "allowed_ips",
            "endpoints",
            "endpoint_types",
            "home_derp",
            "hostinfo",
            "created",
            "cap",
            "tags",
            "machine_authorized",
            "ephemeral",
            "advertised_routes",
            "approved_routes",
            "last_seen",
            "key_expiry",
        ],
    ),
    (
        "pre_auth_keys",
        &[
            "id",
            "prefix",
            "secret_hash",
            "reusable",
            "ephemeral",
            "expiration",
            "revoked",
            "used",
            "tags",
            "user_id",
            "created_at",
        ],
    ),
    ("policies", &["id", "name", "body", "created_at"]),
    (
        "sessions",
        &[
            "id",
            "node_id",
            "machine_key",
            "created_at",
            "last_seen",
            "closed_at",
        ],
    ),
    (
        "pending_registrations",
        &[
            "auth_id",
            "machine_key",
            "node_key",
            "hostinfo",
            "expiry",
            "version",
            "ephemeral",
            "created_at",
            "expires_at",
            "verdict",
        ],
    ),
    (
        "ssh_auths",
        &[
            "auth_id",
            "src_node_id",
            "dst_node_id",
            "ssh_user",
            "local_user",
            "machine_key",
            "created_at",
            "expires_at",
            "verdict",
        ],
    ),
];

/// Errors produced by backup/restore.
#[derive(Debug)]
pub enum BackupError {
    /// The backup document format is not supported.
    Format(String),
    /// A table in the backup document is not on the export allowlist.
    UnknownTable(String),
    /// The backup contains a row whose type cannot be bound back to SQLite.
    UnsupportedValue(String),
    Sqlite(rusqlite::Error),
    Json(serde_json::Error),
    Io(std::io::Error),
}

impl std::fmt::Display for BackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Format(e) => write!(f, "backup format error: {e}"),
            Self::UnknownTable(t) => write!(f, "backup contains unsupported table `{t}`"),
            Self::UnsupportedValue(v) => write!(f, "backup contains unsupported value: {v}"),
            Self::Sqlite(e) => write!(f, "sqlite error: {e}"),
            Self::Json(e) => write!(f, "backup json error: {e}"),
            Self::Io(e) => write!(f, "backup io error: {e}"),
        }
    }
}

impl std::error::Error for BackupError {}

impl From<rusqlite::Error> for BackupError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}
impl From<serde_json::Error> for BackupError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}
impl From<std::io::Error> for BackupError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Serialize the allowed tables of `conn` into a zstd-compressed backup
/// written to `writer`.
pub fn write_backup<W: Write>(conn: &mut Connection, mut writer: W) -> Result<(), BackupError> {
    // Read everything inside one transaction so a concurrent writer cannot
    // produce a torn snapshot: the shared read lock is held until commit.
    let tx = conn.transaction()?;
    let mut tables = Map::new();
    for (table, columns) in BACKUP_TABLES {
        let rows = export_table(&tx, table, columns)?;
        tables.insert((*table).to_string(), Value::Array(rows));
    }
    tx.commit()?;

    let created_at = crate::time::now_rfc3339();
    let document = json!({
        "format": BACKUP_FORMAT,
        "created_at": created_at,
        "tables": Value::Object(tables),
    });

    let json = serde_json::to_vec(&document)?;
    let compressed = zstd::stream::encode_all(&json[..], 3)?;
    writer.write_all(&compressed)?;
    Ok(())
}

/// Read a zstd-compressed backup from `reader` and replace the allowed tables
/// in `conn` with its contents.
///
/// The restore runs inside a single transaction with foreign keys deferred so
/// that parent/child rows can be inserted in any order; the final state must
/// satisfy every foreign key at commit.
pub fn restore_backup<R: Read>(conn: &mut Connection, mut reader: R) -> Result<(), BackupError> {
    let mut compressed = Vec::new();
    reader.read_to_end(&mut compressed)?;
    let json = zstd::stream::decode_all(&compressed[..])?;
    let document: Value = serde_json::from_slice(&json)?;

    let format = document
        .get("format")
        .and_then(Value::as_str)
        .ok_or_else(|| BackupError::Format("missing `format` field".to_string()))?;
    if format != BACKUP_FORMAT {
        return Err(BackupError::Format(format!(
            "unsupported format `{format}` (expected `{BACKUP_FORMAT}`)"
        )));
    }

    let tables = document
        .get("tables")
        .and_then(Value::as_object)
        .ok_or_else(|| BackupError::Format("missing `tables` object".to_string()))?;

    for table in tables.keys() {
        if !BACKUP_TABLES.iter().any(|(name, _)| *name == table) {
            return Err(BackupError::UnknownTable(table.clone()));
        }
    }

    let tx = conn.transaction()?;
    // Defer FK enforcement until commit so we can clear and repopulate tables
    // without depending on insert order (see module docs).
    tx.pragma_update(None, "defer_foreign_keys", "ON")?;
    for (table, _columns) in BACKUP_TABLES.iter().rev() {
        tx.execute(&format!("DELETE FROM {table}"), [])?;
    }
    for (table, columns) in BACKUP_TABLES {
        let rows = tables
            .get(*table)
            .and_then(Value::as_array)
            .ok_or_else(|| BackupError::Format(format!("backup is missing table `{table}`")))?;
        import_table(&tx, table, columns, rows)?;
    }
    tx.commit()?;
    Ok(())
}

/// Read every row of `table` as a JSON object of the allowlisted columns.
fn export_table(
    conn: &Connection,
    table: &str,
    columns: &[&str],
) -> Result<Vec<Value>, BackupError> {
    let column_list = columns.join(", ");
    let sql = format!("SELECT {column_list} FROM {table}");
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let mut obj = Map::new();
        for (idx, column) in columns.iter().enumerate() {
            let value = sqlite_to_json(row.get_ref(idx)?);
            obj.insert((*column).to_string(), value);
        }
        out.push(Value::Object(obj));
    }
    Ok(out)
}

/// Insert `rows` into `table` using the allowlisted `columns`.
fn import_table(
    tx: &rusqlite::Transaction,
    table: &str,
    columns: &[&str],
    rows: &[Value],
) -> Result<(), BackupError> {
    if rows.is_empty() {
        return Ok(());
    }
    let placeholders = (1..=columns.len())
        .map(|i| format!("?{i}"))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "INSERT INTO {table} ({}) VALUES ({placeholders})",
        columns.join(", ")
    );
    let mut stmt = tx.prepare(&sql)?;
    for row in rows {
        let obj = row
            .as_object()
            .ok_or_else(|| BackupError::Format("backup table row is not an object".to_string()))?;
        let mut params = Vec::with_capacity(columns.len());
        for column in columns {
            let value = obj.get(*column).ok_or_else(|| {
                BackupError::Format(format!(
                    "backup row for `{table}` is missing column `{column}`"
                ))
            })?;
            params.push(json_to_sqlite(value).map_err(BackupError::UnsupportedValue)?);
        }
        stmt.execute(rusqlite::params_from_iter(params.iter()))?;
    }
    Ok(())
}

/// Convert a SQLite cell to a JSON value (blobs are hex-encoded).
fn sqlite_to_json(value: rusqlite::types::ValueRef<'_>) -> Value {
    match value {
        rusqlite::types::ValueRef::Null => Value::Null,
        rusqlite::types::ValueRef::Integer(i) => Value::Number(i.into()),
        rusqlite::types::ValueRef::Real(r) => json!(r),
        rusqlite::types::ValueRef::Text(t) => {
            Value::String(std::str::from_utf8(t).unwrap_or("").to_string())
        }
        rusqlite::types::ValueRef::Blob(b) => Value::String(hex::encode(b)),
    }
}

/// Convert a JSON value back into a SQLite value for binding.
///
/// Only the types our schema uses (`null`, integer, text) are accepted.
fn json_to_sqlite(value: &Value) -> Result<rusqlite::types::Value, String> {
    match value {
        Value::Null => Ok(rusqlite::types::Value::Null),
        Value::Bool(b) => Ok(rusqlite::types::Value::Integer(*b as i64)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(rusqlite::types::Value::Integer(i))
            } else if let Some(f) = n.as_f64() {
                Ok(rusqlite::types::Value::Real(f))
            } else {
                Err(format!("unsupported JSON number {n}"))
            }
        }
        Value::String(s) => Ok(rusqlite::types::Value::Text(s.clone())),
        other => Err(format!("unsupported JSON type {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{SqliteStore, Store};
    use crate::{ControlConfig, ControlPlane};
    use crabscale_proto::{Hostinfo, MachineKey, NodeKey, RegisterAuth, RegisterRequest};

    #[test]
    fn write_and_restore_round_trip_preserves_state() {
        // Build a control plane persisted to a temp SQLite file with a node
        // already authorized (so "existing nodes can relogin" after restore).
        let mut dir = std::env::temp_dir();
        dir.push(format!("crabscale-backup-test-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&dir);

        let plane = ControlPlane::open_sqlite(ControlConfig::default(), &dir).unwrap();
        let request = RegisterRequest {
            version: 130,
            node_key: NodeKey::from_bytes([0x22; 32]),
            auth: Some(RegisterAuth {
                auth_key: "hskey-auth-test-secret".to_string(),
            }),
            hostinfo: Some(Hostinfo {
                hostname: "node1".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(
            plane
                .register(MachineKey::from_bytes([0x11; 32]), request)
                .machine_authorized
        );

        // Serialize a backup.
        let conn = SqliteStore::open(&dir).unwrap();
        let mut bytes = Vec::new();
        write_backup(&mut conn.conn.lock().unwrap(), &mut bytes).unwrap();

        // Restore into a fresh database.
        let restored_path = dir.with_extension("restored.db");
        let _ = std::fs::remove_file(&restored_path);
        let restored = SqliteStore::open(&restored_path).unwrap();
        restore_backup(&mut restored.conn.lock().unwrap(), &bytes[..]).unwrap();

        // The restored store still authorizes the same node (relogin).
        let node = restored
            .get_node_by_node_key(&NodeKey::from_bytes([0x22; 32]))
            .unwrap()
            .expect("node restored");
        assert!(node.machine_authorized);
        assert_eq!(node.machine_key, MachineKey::from_bytes([0x11; 32]));
        assert_eq!(node.name, "node1.tailnet.example.");

        let _ = std::fs::remove_file(&dir);
        let _ = std::fs::remove_file(&restored_path);
    }

    #[test]
    fn restore_rejects_unknown_table() {
        let document = json!({
            "format": BACKUP_FORMAT,
            "created_at": "2026-08-20T00:00:00Z",
            "tables": { "secret_table": [] }
        });
        let bytes =
            zstd::stream::encode_all(serde_json::to_vec(&document).unwrap().as_slice(), 3).unwrap();
        let conn = SqliteStore::open_in_memory().unwrap();
        let err = restore_backup(&mut conn.conn.lock().unwrap(), &bytes[..]).unwrap_err();
        assert!(matches!(err, BackupError::UnknownTable(ref t) if t == "secret_table"));
    }

    #[test]
    fn restore_rejects_unsupported_format() {
        let document = json!({ "format": "crabscale-backup/v999", "tables": {} });
        let bytes =
            zstd::stream::encode_all(serde_json::to_vec(&document).unwrap().as_slice(), 3).unwrap();
        let conn = SqliteStore::open_in_memory().unwrap();
        let err = restore_backup(&mut conn.conn.lock().unwrap(), &bytes[..]).unwrap_err();
        assert!(matches!(err, BackupError::Format(_)));
    }
}
