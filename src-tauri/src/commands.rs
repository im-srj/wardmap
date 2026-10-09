//! Tauri commands exposed to the frontend. These are the only DB-aware layer;
//! `scan` and `db` stay free of Tauri types.

use std::path::PathBuf;

use serde::Serialize;
use tauri::ipc::Channel;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::DialogExt;

use crate::cmdline::{self, Analysis, Item, Kind};
use crate::db::{self, Db, StoredProfile, StoredScan};
use crate::diff::{self, ScanDiff};
use crate::export::{self, Format};
use crate::identify;
use crate::nse::{self, NseScript};
use crate::profiles;
use crate::runner::{self, Runs, ScanProgress};
use crate::scan::{self, ScanResult};

fn lock(db: &Db) -> Result<std::sync::MutexGuard<'_, rusqlite::Connection>, String> {
    db.0.lock()
        .map_err(|_| "database lock poisoned".to_string())
}

/// A finished scan: its history id (for diffing / exporting it) and result.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanOutcome {
    pub scan_id: i64,
    pub result: ScanResult,
}

/// Run a scan, streaming progress over `on_progress`, then persist it and
/// return the parsed result. `command` is the full command as shown to the
/// user (a leading `nmap` is optional); it is analyzed here — the frontend's
/// own view of it is never trusted — and refused if it fails the checks in
/// `cmdline`. Async + `spawn_blocking` so a long scan never ties up the main
/// thread; `run_id` (chosen by the frontend) is what `cancel_scan` takes. A
/// cancelled scan rejects with "scan cancelled" and is not saved. Several
/// scans may run at once, each under its own `run_id`.
#[tauri::command]
pub async fn run_nmap_scan(
    run_id: String,
    command: String,
    on_progress: Channel<ScanProgress>,
    app: AppHandle,
) -> Result<ScanOutcome, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let analysis = cmdline::analyze_text(&command);
        // History is keyed by target; a list-file scan is labelled by it.
        let label = analysis.target_label();

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

        let conn = lock(&db)?;
        let scan_id = db::insert_scan(
            &conn,
            &label,
            Some(command.trim()),
            db::now_unix(),
            &result,
            &xml,
        )
        .map_err(|e| e.to_string())?;
        db::insert_identities(&conn, scan_id, &ids).map_err(|e| e.to_string())?;

        Ok(ScanOutcome { scan_id, result })
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
    let conn = lock(&db)?;
    db::list_scans(&conn).map_err(|e| e.to_string())
}

/// Re-materialize a saved scan by re-parsing its stored XML.
#[tauri::command]
pub fn get_scan(id: i64, db: State<Db>) -> Result<ScanResult, String> {
    let conn = lock(&db)?;
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
    let conn = lock(&db)?;
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

/// A saved profile as the UI uses it: `items` is the backend's reading of
/// `command`, so applying a profile never re-parses on the frontend.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub command: String,
    pub items: Vec<Item>,
}

impl From<StoredProfile> for Profile {
    fn from(p: StoredProfile) -> Self {
        let items = cmdline::analyze_text(&format!("nmap {}", p.command))
            .items
            .into_iter()
            .filter(|i| i.kind != Kind::Target)
            .collect();
        Profile {
            id: p.id,
            name: p.name,
            description: p.description,
            command: p.command,
            items,
        }
    }
}

#[tauri::command]
pub fn list_profiles(db: State<Db>) -> Result<Vec<Profile>, String> {
    let conn = lock(&db)?;
    let all = db::list_profiles(&conn).map_err(|e| e.to_string())?;
    Ok(all.into_iter().map(Profile::from).collect())
}

/// Create (`id` null) or update a profile. `command` may be a whole command
/// line; only its options are kept (never targets — see `options_only`).
#[tauri::command]
pub fn save_profile(
    id: Option<i64>,
    name: String,
    description: String,
    command: String,
    db: State<Db>,
) -> Result<Profile, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("Give the profile a name.".into());
    }
    if name.chars().count() > 80 {
        return Err("Keep the profile name under 80 characters.".into());
    }
    let command = cmdline::options_only(&command);
    let description = description.trim();
    let conn = lock(&db)?;
    let id = db::save_profile(&conn, id, name, description, &command).map_err(|e| match e {
        rusqlite::Error::SqliteFailure(f, _)
            if f.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            format!("A profile named “{name}” already exists.")
        }
        rusqlite::Error::QueryReturnedNoRows => "That profile no longer exists.".into(),
        e => e.to_string(),
    })?;
    Ok(Profile::from(StoredProfile {
        id,
        name: name.into(),
        description: description.into(),
        command,
    }))
}

#[tauri::command]
pub fn delete_profile(id: i64, db: State<Db>) -> Result<(), String> {
    db::delete_profile(&*lock(&db)?, id).map_err(|e| e.to_string())
}

/// What an import did. `errors` holds one "file: reason" line per failure.
#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ImportReport {
    pub imported: u32,
    pub skipped: u32,
    pub errors: Vec<String>,
}

fn file_label(path: &std::path::Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// Files nmap XML imports may be at most this big (a /16 with -sV is ~50 MB).
const MAX_IMPORT_BYTES: u64 = 256 * 1024 * 1024;

/// Ask for nmap XML files (native dialog) and add them to history. `None`
/// if the dialog was dismissed. The file choice happens here, in the
/// backend, so the webview can never name a path to read.
#[tauri::command]
pub async fn import_scans(app: AppHandle) -> Result<Option<ImportReport>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let Some(files) = app
            .dialog()
            .file()
            .set_title("Import nmap XML")
            .add_filter("nmap XML output", &["xml"])
            .blocking_pick_files()
        else {
            return Ok(None);
        };
        let mut report = ImportReport::default();
        for f in files {
            let path = f.into_path().map_err(|e| e.to_string())?;
            let name = file_label(&path);
            let xml = match std::fs::metadata(&path) {
                Ok(m) if m.len() > MAX_IMPORT_BYTES => Err("file is too large".to_string()),
                _ => std::fs::read_to_string(&path).map_err(|e| e.to_string()),
            };
            let outcome = xml.and_then(|xml| {
                let db = app.state::<Db>();
                let conn = lock(&db)?;
                db::import_scan(&conn, &xml).map_err(|e| e.to_string())
            });
            match outcome {
                Ok(Some(_)) => report.imported += 1,
                Ok(None) => report.skipped += 1,
                Err(e) => report.errors.push(format!("{name}: {e}")),
            }
        }
        Ok(Some(report))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Where Zenmap keeps its profiles, if that folder exists.
fn zenmap_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    let dir = PathBuf::from(home).join(".zenmap");
    dir.is_dir().then_some(dir)
}

/// Ask for a Zenmap `scan_profile.usp` and add its profiles. Profiles whose
/// name already exists are skipped (counted in `skipped`), never overwritten.
#[tauri::command]
pub async fn import_zenmap_profiles(app: AppHandle) -> Result<Option<ImportReport>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut dialog = app
            .dialog()
            .file()
            .set_title("Import Zenmap profiles (scan_profile.usp)")
            .add_filter("Zenmap profiles", &["usp"]);
        if let Some(dir) = zenmap_dir() {
            dialog = dialog.set_directory(dir);
        }
        let Some(file) = dialog.blocking_pick_file() else {
            return Ok(None);
        };
        let path = file.into_path().map_err(|e| e.to_string())?;
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", file_label(&path)))?;
        let found = profiles::parse_zenmap_usp(&text);
        if found.is_empty() {
            return Err(format!(
                "{} has no Zenmap profiles in it.",
                file_label(&path)
            ));
        }
        let db = app.state::<Db>();
        let conn = lock(&db)?;
        let mut report = ImportReport::default();
        for p in found {
            match db::insert_profile_if_new(&conn, &p.name, &p.description, &p.command) {
                Ok(true) => report.imported += 1,
                Ok(false) => report.skipped += 1,
                Err(e) => report.errors.push(format!("{}: {e}", p.name)),
            }
        }
        Ok(Some(report))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// A history label as a file-name stem: `cartograph-192.168.1.0_24`.
fn file_stem(label: &str) -> String {
    let safe: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-') {
                c
            } else {
                '_'
            }
        })
        .take(60)
        .collect();
    format!("cartograph-{}", safe.trim_matches('_'))
}

/// Export a saved scan: render it, ask where to save it (native dialog),
/// write it. Returns the saved path, or `None` if the dialog was dismissed.
#[tauri::command]
pub async fn export_scan(
    id: i64,
    format: Format,
    app: AppHandle,
) -> Result<Option<String>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let (row, contents) = {
            let db = app.state::<Db>();
            let conn = lock(&db)?;
            let row = db::get_scan(&conn, id)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("scan {id} not found"))?;
            let xml = db::get_scan_xml(&conn, id)
                .map_err(|e| e.to_string())?
                .unwrap_or_default();
            let mut result = scan::parse_nmap_xml(&xml).map_err(|e| e.to_string())?;
            let ids = db::get_identities(&conn, id).map_err(|e| e.to_string())?;
            identify::attach(&mut result, &ids);
            let contents = export::render(format, &row.target, &result, &xml);
            (row, contents)
        }; // DB unlocked before the dialog waits on the user
        let Some(file) = app
            .dialog()
            .file()
            .set_title(format!("Export as {}", format.label()))
            .add_filter(format.label(), &[format.extension()])
            .set_file_name(format!("{}.{}", file_stem(&row.target), format.extension()))
            .blocking_save_file()
        else {
            return Ok(None);
        };
        let path = file.into_path().map_err(|e| e.to_string())?;
        std::fs::write(&path, contents).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(Some(path.display().to_string()))
    })
    .await
    .map_err(|e| e.to_string())?
}
