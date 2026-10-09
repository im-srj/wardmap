pub mod scan;

/// Builds and runs the Tauri application.
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![scan::run_nmap_scan])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
