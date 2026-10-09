//! Tauri commands exposed to the frontend. These are the only DB-aware layer;
//! `scan` and `db` stay free of Tauri types.

use tauri::ipc::Channel;
use tauri::{AppHandle, Manager, State};

use crate::cmdline::{self, Analysis};
use crate::db::{self, Db, StoredScan};
use crate::diff::{self, ScanDiff};
use crate::identify;
use crate::nse::{self, NseScript};
use crate::runner::{self, Runs, ScanProgress};
use crate::scan::{self, ScanResult};

/// Run a scan, streaming progress over `on_progress`, then persist it and
/// return the parsed result. `command` is the full command as shown to the
/// user (a leading `nmap` is optional); it is analyzed here — the frontend's
/// own view of it is never trusted — and refused if it fails the checks in
/// `cmdline`. Async + `spawn_blocking` so a long scan never ties up the main
/// thread; `run_id` (chosen by the frontend) is what `cancel_scan` takes. A
/// cancelled scan rejects with "scan cancelled" and is not saved.
#[tauri::command]
pub async fn run_nmap_scan(
    run_id: String,
    command: String,
    on_progress: Channel<ScanProgress>,
    app: AppHandle,
) -> Result<ScanResult, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let analysis = cmdline::analyze_text(&command);
        // History is keyed by target; a list-file scan is labelled by it.
        let label = {
            let targets: Vec<&str> = analysis.targets().collect();
            if targets.is_empty() {
                analysis
                    .items
                    .iter()
                    .find(|i| i.name == "-iL")
                    .and_then(|i| i.value.as_deref())
                    .map(|f| format!("-iL {f}"))
                    .unwrap_or_default()
            } else {
                targets.join(" ")
            }
        };

        // Capture the raw XML so we can both parse it now and store it verbatim.
        let xml = runner::run(&app.state::<Runs>(), &run_id, &analysis, |p| {
            let _ = on_progress.send(p);
        })
        .map_err(|e| e.to_string())?;
        let mut result = scan::parse_nmap_xml(&xml).map_err(|e| e.to_string())?;

        // Name/MAC identification for LAN hosts the scan found up (~1.5s of
        // mDNS listening when there are any). Done before taking the DB lock.
        let ids = identify::identify(&identify::up_ipv4s(&result));
        identify::attach(&mut result, &ids);

        let db = app.state::<Db>();
        let conn =
            db.0.lock()
                .map_err(|_| "database lock poisoned".to_string())?;
        let scan_id = db::insert_scan(&conn, &label, &result, &xml).map_err(|e| e.to_string())?;
        db::insert_identities(&conn, scan_id, &ids).map_err(|e| e.to_string())?;

        Ok(result)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Parse a command the way nmap would and report Cartograph's checks — the
/// live feedback behind the editable command line and the option builder.
#[tauri::command]
pub fn analyze_command(command: String) -> Analysis {
    cmdline::analyze_text(&command)
}

/// Cancel a running scan. False if it already finished.
#[tauri::command]
pub fn cancel_scan(run_id: String, runs: State<Runs>) -> bool {
    runs.cancel(&run_id)
}

/// Startup preflight: the installed nmap's version, or why it can't run.
#[tauri::command]
pub fn nmap_version() -> Result<String, String> {
    scan::nmap_version().map_err(|e| e.to_string())
}

/// List saved scans, newest first, for the history panel.
#[tauri::command]
pub fn list_scans(db: State<Db>) -> Result<Vec<StoredScan>, String> {
    let conn =
        db.0.lock()
            .map_err(|_| "database lock poisoned".to_string())?;
    db::list_scans(&conn).map_err(|e| e.to_string())
}

/// Re-materialize a saved scan by re-parsing its stored XML.
#[tauri::command]
pub fn get_scan(id: i64, db: State<Db>) -> Result<ScanResult, String> {
    let conn =
        db.0.lock()
            .map_err(|_| "database lock poisoned".to_string())?;
    let xml = db::get_scan_xml(&conn, id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("scan {id} not found"))?;
    let mut result = scan::parse_nmap_xml(&xml).map_err(|e| e.to_string())?;
    let ids = db::get_identities(&conn, id).map_err(|e| e.to_string())?;
    identify::attach(&mut result, &ids);
    Ok(result)
}

/// Diff two saved scans (old vs new), each re-parsed from its stored XML.
#[tauri::command]
pub fn diff_scans(old_id: i64, new_id: i64, db: State<Db>) -> Result<ScanDiff, String> {
    let conn =
        db.0.lock()
            .map_err(|_| "database lock poisoned".to_string())?;
    let load = |id: i64| -> Result<ScanResult, String> {
        let xml = db::get_scan_xml(&conn, id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("scan {id} not found"))?;
        scan::parse_nmap_xml(&xml).map_err(|e| e.to_string())
    };
    let old = load(old_id)?;
    let new = load(new_id)?;
    Ok(diff::diff_scans(&old, &new))
}

/// The installed nmap's NSE script catalogue, for the script browser.
#[tauri::command]
pub fn list_nse_scripts() -> Result<Vec<NseScript>, String> {
    nse::list_scripts().map_err(|e| e.to_string())
}
