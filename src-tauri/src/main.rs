// M0: blank-window scaffold only. Nmap subprocess + XML parsing (M1)
// will add Tauri commands here — see CLAUDE.md for the milestone plan.
fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
