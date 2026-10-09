//! SQLite persistence for scans.
//!
//! We store the raw nmap XML verbatim as the source of truth, plus a few
//! denormalized summary columns so the history list can render without
//! re-parsing every row. A saved scan is re-materialized by re-parsing its
//! stored XML (see `commands::get_scan`).

use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

use crate::scan::ScanResult;

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
    /// Unix epoch (seconds) when the scan was saved.
    pub created_at: i64,
    pub hosts_up: i64,
    pub open_ports: i64,
    pub elapsed_secs: Option<f64>,
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
        CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);",
    )?;
    Ok(conn)
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Insert a completed scan. Returns the new row id.
pub fn insert_scan(
    conn: &Connection,
    target: &str,
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
        "INSERT INTO scans (target, args, created_at, raw_xml, hosts_up, open_ports, elapsed_secs)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            target,
            result.args,
            now_unix(),
            raw_xml,
            hosts_up,
            open_ports,
            elapsed
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// All saved scans, newest first.
pub fn list_scans(conn: &Connection) -> rusqlite::Result<Vec<StoredScan>> {
    let mut stmt = conn.prepare(
        "SELECT id, target, args, created_at, hosts_up, open_ports, elapsed_secs
         FROM scans ORDER BY created_at DESC, id DESC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(StoredScan {
            id: r.get(0)?,
            target: r.get(1)?,
            args: r.get(2)?,
            created_at: r.get(3)?,
            hosts_up: r.get(4)?,
            open_ports: r.get(5)?,
            elapsed_secs: r.get(6)?,
        })
    })?;
    rows.collect()
}

/// Fetch the raw XML for one saved scan, if it exists.
pub fn get_scan_xml(conn: &Connection, id: i64) -> rusqlite::Result<Option<String>> {
    conn.query_row("SELECT raw_xml FROM scans WHERE id = ?1", [id], |r| {
        r.get(0)
    })
    .optional()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::parse_nmap_xml;

    const SAMPLE: &str = include_str!("../tests/fixtures/multi-host-version.xml");

    fn mem_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, args TEXT NOT NULL,
                created_at INTEGER NOT NULL, raw_xml TEXT NOT NULL, hosts_up INTEGER NOT NULL,
                open_ports INTEGER NOT NULL, elapsed_secs REAL);",
        )
        .unwrap();
        conn
    }

    #[test]
    fn insert_list_and_fetch_roundtrip() {
        let conn = mem_db();
        let result = parse_nmap_xml(SAMPLE).unwrap();

        let id = insert_scan(&conn, "192.168.1.10", &result, SAMPLE).unwrap();
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
    fn persists_across_reopen() {
        // Proves the M3 acceptance ("past scans survive a restart") at the
        // storage layer: write with one connection, drop it (= app close),
        // reopen the same file (= app restart), data is still there.
        let dir = std::env::temp_dir().join(format!("cartograph-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("persist.sqlite3");
        let _ = std::fs::remove_file(&path);

        let result = parse_nmap_xml(SAMPLE).unwrap();
        {
            let conn = open(&path).unwrap(); // real schema + indexes on a real file
            insert_scan(&conn, "persist-target", &result, SAMPLE).unwrap();
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
    fn list_is_newest_first() {
        let conn = mem_db();
        let result = parse_nmap_xml(SAMPLE).unwrap();
        let first = insert_scan(&conn, "a", &result, SAMPLE).unwrap();
        let second = insert_scan(&conn, "b", &result, SAMPLE).unwrap();
        let scans = list_scans(&conn).unwrap();
        // Newest (highest id) first.
        assert_eq!(scans[0].id, second);
        assert_eq!(scans[1].id, first);
    }
}
