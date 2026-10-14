//! SQLite persistence for scans.
//!
//! We store the raw nmap XML verbatim as the source of truth, plus a few
//! denormalized summary columns so the history list can render without
//! re-parsing every row. A saved scan is re-materialized by re-parsing its
//! stored XML (see `commands::get_scan`).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

use crate::cmdline;
use crate::identify::HostIdentity;
use crate::scan::{self, ScanResult};

/// Tauri-managed database handle. `Connection` is `Send` but not `Sync`, so we
/// guard it with a `Mutex` to make the state `Send + Sync`.
pub struct Db(pub Mutex<Connection>);

/// A row in the scan-history list (no raw XML — that is fetched on demand).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredScan {
    pub id: i64,
    pub target: String,
    /// The command line nmap recorded for the run.
    pub args: String,
    /// The command to run this scan again: what the user ran (incl. `sudo`),
    /// or for imported / older scans, rebuilt from `args`.
    pub command: String,
    /// Unix epoch (seconds) when the scan was saved.
    pub created_at: i64,
    pub hosts_up: i64,
    pub open_ports: i64,
    pub elapsed_secs: Option<f64>,
}

/// Move a database left at `old` (e.g. under the app's previous name) to
/// `new`, unless `new` already exists. Returns whether anything was moved.
pub fn adopt_legacy(old: &Path, new: &Path) -> std::io::Result<bool> {
    if new.exists() || !old.is_file() {
        return Ok(false);
    }
    // rename can't cross filesystems; copy then remove the old one instead.
    if std::fs::rename(old, new).is_err() {
        std::fs::copy(old, new)?;
        std::fs::remove_file(old)?;
    }
    Ok(true)
}

/// Open (creating if needed) the database at `path` and ensure the schema.
pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS scans (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            target       TEXT    NOT NULL,
            args         TEXT    NOT NULL,
            created_at   INTEGER NOT NULL,
            raw_xml      TEXT    NOT NULL,
            hosts_up     INTEGER NOT NULL,
            open_ports   INTEGER NOT NULL,
            elapsed_secs REAL
        );
        CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
        CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
        -- Identity gathered after a scan (mDNS / ARP). Not in the XML, so it
        -- lives beside it; IF NOT EXISTS migrates older databases in place.
        CREATE TABLE IF NOT EXISTS host_identity (
            scan_id        INTEGER NOT NULL REFERENCES scans(id),
            addr           TEXT    NOT NULL,
            mdns_name      TEXT,
            mac            TEXT,
            vendor         TEXT,
            mac_randomized INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (scan_id, addr)
        );
        -- Saved scan profiles: just the options (no targets), as typed.
        CREATE TABLE IF NOT EXISTS profiles (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL UNIQUE,
            description TEXT    NOT NULL DEFAULT '',
            command     TEXT    NOT NULL,
            created_at  INTEGER NOT NULL,
            updated_at  INTEGER NOT NULL
        );",
    )?;
    // The command as the user ran it. NULL for scans saved before it was
    // recorded, and for imported ones.
    add_column_if_missing(&conn, "scans", "command", "TEXT")?;
    Ok(conn)
}

fn add_column_if_missing(
    conn: &Connection,
    table: &str,
    column: &str,
    decl: &str,
) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let exists = stmt
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?
        .iter()
        .any(|c| c == column);
    if !exists {
        conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"))?;
    }
    Ok(())
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Insert a completed scan saved at `created_at` (unix seconds). `command` is
/// the command as the user ran it, when known. Returns the new row id.
pub fn insert_scan(
    conn: &Connection,
    target: &str,
    command: Option<&str>,
    created_at: i64,
    result: &ScanResult,
    raw_xml: &str,
) -> rusqlite::Result<i64> {
    let hosts_up = result
        .summary
        .as_ref()
        .map(|s| s.hosts_up as i64)
        .unwrap_or_else(|| result.hosts.iter().filter(|h| h.state == "up").count() as i64);

    let open_ports = result
        .hosts
        .iter()
        .flat_map(|h| &h.ports)
        .filter(|p| p.state == "open")
        .count() as i64;

    let elapsed = result.summary.as_ref().and_then(|s| s.elapsed_secs);

    conn.execute(
        "INSERT INTO scans
         (target, args, created_at, raw_xml, hosts_up, open_ports, elapsed_secs, command)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            target,
            result.args,
            created_at,
            raw_xml,
            hosts_up,
            open_ports,
            elapsed,
            command
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

const SCAN_COLUMNS: &str =
    "id, target, args, created_at, hosts_up, open_ports, elapsed_secs, command";

fn stored_scan(r: &rusqlite::Row) -> rusqlite::Result<StoredScan> {
    let args: String = r.get(2)?;
    let command = r
        .get::<_, Option<String>>(7)?
        .unwrap_or_else(|| cmdline::command_from_args(&args));
    Ok(StoredScan {
        id: r.get(0)?,
        target: r.get(1)?,
        args,
        command,
        created_at: r.get(3)?,
        hosts_up: r.get(4)?,
        open_ports: r.get(5)?,
        elapsed_secs: r.get(6)?,
    })
}

/// All saved scans, newest first.
pub fn list_scans(conn: &Connection) -> rusqlite::Result<Vec<StoredScan>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {SCAN_COLUMNS} FROM scans ORDER BY created_at DESC, id DESC"
    ))?;
    let rows = stmt.query_map([], stored_scan)?;
    rows.collect()
}

/// One saved scan's history row.
pub fn get_scan(conn: &Connection, id: i64) -> rusqlite::Result<Option<StoredScan>> {
    conn.query_row(
        &format!("SELECT {SCAN_COLUMNS} FROM scans WHERE id = ?1"),
        [id],
        stored_scan,
    )
    .optional()
}

/// Why an XML file couldn't be imported.
#[derive(Debug)]
pub enum ImportError {
    Parse(scan::ParseError),
    Db(rusqlite::Error),
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportError::Parse(e) => write!(f, "not nmap XML output ({e})"),
            ImportError::Db(e) => write!(f, "database error: {e}"),
        }
    }
}

/// Import nmap `-oX` output produced elsewhere (a CLI run, another machine)
/// into history, dated by when nmap started it. Returns the new row id, or
/// `None` when the identical XML is already in history.
pub fn import_scan(conn: &Connection, xml: &str) -> Result<Option<i64>, ImportError> {
    let result = scan::parse_nmap_xml(xml).map_err(ImportError::Parse)?;
    let existing: Option<i64> = conn
        .query_row("SELECT id FROM scans WHERE raw_xml = ?1", [xml], |r| {
            r.get(0)
        })
        .optional()
        .map_err(ImportError::Db)?;
    if existing.is_some() {
        return Ok(None);
    }
    let command = cmdline::command_from_args(&result.args);
    let mut label = cmdline::analyze_text(&command).target_label();
    if label.is_empty() {
        label = result
            .hosts
            .iter()
            .find_map(|h| h.addresses.first())
            .map(|a| a.addr.clone())
            .unwrap_or_else(|| "imported scan".into());
    }
    let created_at = result.start.unwrap_or_else(now_unix);
    insert_scan(conn, &label, None, created_at, &result, xml)
        .map(Some)
        .map_err(ImportError::Db)
}

/// A saved scan profile (see `commands::Profile` for what the UI gets).
#[derive(Debug, Clone, PartialEq)]
pub struct StoredProfile {
    pub id: i64,
    pub name: String,
    pub description: String,
    /// The options, as typed after `nmap` (no targets).
    pub command: String,
}

/// All saved profiles, by name.
pub fn list_profiles(conn: &Connection) -> rusqlite::Result<Vec<StoredProfile>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, description, command FROM profiles ORDER BY name COLLATE NOCASE",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(StoredProfile {
            id: r.get(0)?,
            name: r.get(1)?,
            description: r.get(2)?,
            command: r.get(3)?,
        })
    })?;
    rows.collect()
}

/// Create (`id: None`) or update a profile. Returns its id. Fails with a
/// constraint error if another profile already has `name`.
pub fn save_profile(
    conn: &Connection,
    id: Option<i64>,
    name: &str,
    description: &str,
    command: &str,
) -> rusqlite::Result<i64> {
    let now = now_unix();
    match id {
        Some(id) => {
            let n = conn.execute(
                "UPDATE profiles SET name = ?2, description = ?3, command = ?4, updated_at = ?5
                 WHERE id = ?1",
                params![id, name, description, command, now],
            )?;
            if n == 0 {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
            Ok(id)
        }
        None => {
            conn.execute(
                "INSERT INTO profiles (name, description, command, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?4)",
                params![name, description, command, now],
            )?;
            Ok(conn.last_insert_rowid())
        }
    }
}

/// Add a profile unless one with that name exists. True if it was added.
pub fn insert_profile_if_new(
    conn: &Connection,
    name: &str,
    description: &str,
    command: &str,
) -> rusqlite::Result<bool> {
    let n = conn.execute(
        "INSERT OR IGNORE INTO profiles (name, description, command, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?4)",
        params![name, description, command, now_unix()],
    )?;
    Ok(n == 1)
}

pub fn delete_profile(conn: &Connection, id: i64) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM profiles WHERE id = ?1", [id])?;
    Ok(())
}

/// Fetch the raw XML for one saved scan, if it exists.
pub fn get_scan_xml(conn: &Connection, id: i64) -> rusqlite::Result<Option<String>> {
    conn.query_row("SELECT raw_xml FROM scans WHERE id = ?1", [id], |r| {
        r.get(0)
    })
    .optional()
}

/// Save the identities found for a scan.
pub fn insert_identities(
    conn: &Connection,
    scan_id: i64,
    ids: &HashMap<Ipv4Addr, HostIdentity>,
) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare(
        "INSERT OR REPLACE INTO host_identity
         (scan_id, addr, mdns_name, mac, vendor, mac_randomized)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    for (ip, id) in ids {
        stmt.execute(params![
            scan_id,
            ip.to_string(),
            id.mdns_name,
            id.mac,
            id.vendor,
            id.mac_randomized
        ])?;
    }
    Ok(())
}

/// Identities saved for a scan, keyed by IPv4 address.
pub fn get_identities(
    conn: &Connection,
    scan_id: i64,
) -> rusqlite::Result<HashMap<Ipv4Addr, HostIdentity>> {
    let mut stmt = conn.prepare(
        "SELECT addr, mdns_name, mac, vendor, mac_randomized
         FROM host_identity WHERE scan_id = ?1",
    )?;
    let rows = stmt.query_map([scan_id], |r| {
        Ok((
            r.get::<_, String>(0)?,
            HostIdentity {
                mdns_name: r.get(1)?,
                mac: r.get(2)?,
                vendor: r.get(3)?,
                mac_randomized: r.get(4)?,
            },
        ))
    })?;
    let mut out = HashMap::new();
    for row in rows {
        let (addr, id) = row?;
        if let Ok(ip) = addr.parse() {
            out.insert(ip, id);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::parse_nmap_xml;

    const SAMPLE: &str = include_str!("../tests/fixtures/multi-host-version.xml");

    fn mem_db() -> Connection {
        open(":memory:").unwrap()
    }

    fn insert(conn: &Connection, target: &str, result: &ScanResult) -> i64 {
        insert_scan(conn, target, None, now_unix(), result, SAMPLE).unwrap()
    }

    #[test]
    fn insert_list_and_fetch_roundtrip() {
        let conn = mem_db();
        let result = parse_nmap_xml(SAMPLE).unwrap();

        let id = insert(&conn, "192.168.1.10", &result);
        assert!(id > 0);

        let scans = list_scans(&conn).unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].target, "192.168.1.10");
        assert_eq!(scans[0].hosts_up, 1); // one up, one down in the fixture
        assert_eq!(scans[0].open_ports, 2); // ssh + http

        // The stored XML round-trips back through the parser unchanged.
        let xml = get_scan_xml(&conn, id).unwrap().unwrap();
        let reparsed = parse_nmap_xml(&xml).unwrap();
        assert_eq!(reparsed, result);

        assert!(get_scan_xml(&conn, 9999).unwrap().is_none());
    }

    #[test]
    fn identities_roundtrip_per_scan() {
        let conn = open(":memory:").unwrap(); // real schema incl. host_identity
        let result = parse_nmap_xml(SAMPLE).unwrap();
        let a = insert(&conn, "lan", &result);
        let b = insert(&conn, "lan", &result);

        let id = HostIdentity {
            mdns_name: Some("Pixel-7.local".into()),
            mac: Some("DA:A1:19:00:00:01".into()),
            vendor: None,
            mac_randomized: true,
        };
        let ip: Ipv4Addr = "192.168.1.148".parse().unwrap();
        insert_identities(&conn, a, &HashMap::from([(ip, id.clone())])).unwrap();

        assert_eq!(get_identities(&conn, a).unwrap(), HashMap::from([(ip, id)]));
        assert!(get_identities(&conn, b).unwrap().is_empty()); // scoped per scan
    }

    #[test]
    fn persists_across_reopen() {
        // Proves the M3 acceptance ("past scans survive a restart") at the
        // storage layer: write with one connection, drop it (= app close),
        // reopen the same file (= app restart), data is still there.
        let dir = std::env::temp_dir().join(format!("wardmap-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("persist.sqlite3");
        let _ = std::fs::remove_file(&path);

        let result = parse_nmap_xml(SAMPLE).unwrap();
        {
            let conn = open(&path).unwrap(); // real schema + indexes on a real file
            insert(&conn, "persist-target", &result);
        } // connection dropped — simulates the app closing
        {
            let conn = open(&path).unwrap(); // reopen — simulates app restart
            let scans = list_scans(&conn).unwrap();
            assert_eq!(scans.len(), 1);
            assert_eq!(scans[0].target, "persist-target");
        }

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn adopts_legacy_database_once() {
        let dir = std::env::temp_dir().join(format!("wardmap-adopt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (old, new) = (dir.join("old.sqlite3"), dir.join("new.sqlite3"));
        let _ = std::fs::remove_file(&new);

        let result = parse_nmap_xml(SAMPLE).unwrap();
        insert(&open(&old).unwrap(), "legacy-target", &result);

        assert!(adopt_legacy(&old, &new).unwrap());
        assert!(!old.exists());
        assert_eq!(
            list_scans(&open(&new).unwrap()).unwrap()[0].target,
            "legacy-target"
        );

        // Never overwrites a database that's already there.
        insert(&open(&old).unwrap(), "stale", &result);
        assert!(!adopt_legacy(&old, &new).unwrap());
        assert!(old.exists());
        assert_eq!(list_scans(&open(&new).unwrap()).unwrap().len(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn list_is_newest_first() {
        let conn = mem_db();
        let result = parse_nmap_xml(SAMPLE).unwrap();
        let first = insert(&conn, "a", &result);
        let second = insert(&conn, "b", &result);
        let scans = list_scans(&conn).unwrap();
        // Newest (highest id) first.
        assert_eq!(scans[0].id, second);
        assert_eq!(scans[1].id, first);
    }

    #[test]
    fn command_is_stored_or_rebuilt_from_args() {
        let conn = mem_db();
        let result = parse_nmap_xml(SAMPLE).unwrap();
        let ran = insert_scan(
            &conn,
            "h",
            Some("sudo nmap -sS h"),
            now_unix(),
            &result,
            SAMPLE,
        )
        .unwrap();
        let old = insert(&conn, "h", &result);
        assert_eq!(
            get_scan(&conn, ran).unwrap().unwrap().command,
            "sudo nmap -sS h"
        );
        // No stored command: rebuilt from nmap's recorded args.
        let rebuilt = get_scan(&conn, old).unwrap().unwrap().command;
        assert_eq!(rebuilt, cmdline::command_from_args(&result.args));
        assert!(!rebuilt.contains("-oX"), "{rebuilt}");
    }

    #[test]
    fn import_dates_by_scan_start_and_skips_duplicates() {
        let conn = mem_db();
        let result = parse_nmap_xml(SAMPLE).unwrap();
        let id = import_scan(&conn, SAMPLE).unwrap().expect("imported");
        let row = get_scan(&conn, id).unwrap().unwrap();
        assert_eq!(Some(row.created_at), result.start);
        assert!(!row.target.is_empty());
        assert!(import_scan(&conn, SAMPLE).unwrap().is_none()); // already there
        assert!(matches!(
            import_scan(&conn, "<html/>"),
            Err(ImportError::Parse(_))
        ));
        assert_eq!(list_scans(&conn).unwrap().len(), 1);
    }

    #[test]
    fn profiles_crud_and_unique_names() {
        let conn = mem_db();
        let a = save_profile(&conn, None, "Web", "web ports", "-p 80,443 -sV").unwrap();
        assert!(save_profile(&conn, None, "Web", "", "-F").is_err()); // name taken
        save_profile(&conn, Some(a), "Web", "web ports", "-p 80,443,8080 -sV").unwrap();
        assert!(!insert_profile_if_new(&conn, "Web", "", "-F").unwrap());
        assert!(insert_profile_if_new(&conn, "Another", "", "-F").unwrap());

        let all = list_profiles(&conn).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].name, "Another"); // by name
        assert_eq!(all[1].command, "-p 80,443,8080 -sV");

        delete_profile(&conn, a).unwrap();
        assert_eq!(list_profiles(&conn).unwrap().len(), 1);
        assert!(save_profile(&conn, Some(a), "Gone", "", "").is_err());
    }

    #[test]
    fn open_migrates_a_database_without_the_command_column() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, args TEXT NOT NULL,
                created_at INTEGER NOT NULL, raw_xml TEXT NOT NULL, hosts_up INTEGER NOT NULL,
                open_ports INTEGER NOT NULL, elapsed_secs REAL);
             INSERT INTO scans (target, args, created_at, raw_xml, hosts_up, open_ports)
             VALUES ('h', 'nmap -oX - -F h', 1, '', 1, 0);",
        )
        .unwrap();
        // Run the same migration `open` runs, twice (idempotent).
        add_column_if_missing(&conn, "scans", "command", "TEXT").unwrap();
        add_column_if_missing(&conn, "scans", "command", "TEXT").unwrap();
        assert_eq!(list_scans(&conn).unwrap()[0].command, "nmap -F h");
    }
}
