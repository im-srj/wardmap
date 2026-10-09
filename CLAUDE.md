# Project: Cartograph

## What this is
Cartograph is a modern, actively-maintained GUI for Nmap, filling the gap left by Zenmap
(unmaintained since 2019, no Apple Silicon build, Python 2/GTK). Full
rationale and competitive landscape: see `docs/BRIEF.md` (paste in the
project brief doc if you want it versioned alongside the code).

We are NOT reimplementing Nmap's scan engine. We wrap the real `nmap`
binary as a subprocess and parse its XML output. All novel value lives in:
diffing/history, topology visualization, NSE script browsing, and UX.

## Architecture decisions (do not relitigate without discussion)
- **Shell:** Tauri (Rust backend + web frontend). Chosen over Electron for
  binary size and native feel; chosen over pure Qt/PySide for easier
  cross-platform CI, including Apple Silicon.
- **Frontend:** React + TypeScript. Component library: keep minimal,
  prefer hand-rolled components over a heavy UI kit early on.
- **Backend (Rust, via Tauri commands):**
  - Spawns `nmap` as a subprocess, always with `-oX -` (XML to stdout).
  - Parses XML with a proper XML crate (e.g. `quick-xml` or `roxmltree`),
    never regex/string-matching on Nmap output.
  - Never re-implements scanning logic — if a feature needs raw packet
    manipulation, that's out of scope; shell out to nmap flags instead.
- **Persistence:** SQLite (via `rusqlite` or `sqlx`). Every completed scan
  is stored: target, timestamp, raw XML, parsed summary.
- **No telemetry, no phone-home.** This is a security tool; local-only by
  default, full stop.

## Coding conventions
- Rust: `cargo fmt` + `cargo clippy` clean before every commit.
- TypeScript: ESLint + Prettier, strict mode on.
- Commits: small, one logical change each, imperative mood
  ("Add XML parser for host/port blocks", not "added stuff").
- Every milestone ends with a short `## Status` update appended to this
  file's Progress Log (below) — one or two lines, what works, what's next.
- Write tests for the XML parser and the diff logic specifically — these
  are the two places silent bugs would be worst (wrong port status, wrong
  diff = wrong security conclusions).

## Working across machines
This project is developed from more than one machine. There is NO live sync
of a Claude Code conversation across machines — the git repo and this file
are the shared state, so treat them as such:
- **Before switching machines / ending a work session:** commit and push.
- **When starting on any machine:** `git pull` first.
- **Context travels via this file**, especially the Progress Log below — a
  fresh session on any machine reads CLAUDE.md on startup and picks up where
  the last one left off. Keep the Progress Log current at each milestone.
- Do NOT rely on resuming the same transcript elsewhere; start a fresh
  session and let git + this file carry the context.
(This is about the dev workflow. It does not change the "Cloud sync /
multi-device state" non-goal below, which is about the shipped app.)

## Milestones (build in this order; each should be runnable/demoable)

### M0 — Scaffold
- Tauri project initialized, builds and runs a blank window on your OS.
- Repo structure: `/src-tauri` (Rust backend), `/src` (frontend), `/docs`.
- CI: a GitHub Action that runs `cargo check` + frontend lint on every push.

### M1 — Nmap subprocess + XML parsing
- Rust function: given a target string + flag list, spawns nmap, captures
  stdout XML, returns a parsed Rust struct (hosts → ports → service info).
- Unit tests using a few saved sample XML files (don't require nmap
  installed to run the test suite).
- Acceptance: can call this from a temporary CLI test harness and get
  correct structured output for a scan against localhost.

### M2 — Minimal UI: run a scan, see results
- Target input field, a short list of scan-intensity presets (not every
  flag yet), a "Run" button.
- **Live command preview** — show the literal nmap command being built,
  updating as the user changes options. (This is a real differentiator —
  keep it visible at all times, not buried in a tooltip.)
- Results rendered as a sortable table (host, port, state, service).
- Acceptance: can run a real scan against a target you own and see
  correct results in the UI.

### M3 — SQLite persistence
- Every run is saved (raw XML + parsed summary) keyed by target + timestamp.
- Simple "Scan History" list view per target.
- Acceptance: close and reopen the app, past scans are still there.

### M4 — Diff view
- Pick any two past scans of the same target, show: new hosts, new/closed
  ports, changed service versions, newly-seen certs.
- Acceptance: run two scans with a deliberately changed open-port set
  (e.g. toggle a local test service), diff correctly shows the change.

### M5 — Topology view
- Interactive graph of hosts/subnets from the latest scan (or a merged
  view). Filterable by subnet/service. Start simple (force-directed graph
  of what you already have in M2 data) before adding clustering polish.

### M6 — NSE script browser
- Parse `nmap --script-help all` (or local NSE script directory) into a
  searchable, categorized picker with each script's description.
- Selecting scripts updates the live command preview from M2.

### M7 — Packaging
- Homebrew formula, apt package (or AppImage), winget manifest.
- Goal: `brew install <name>` / `winget install <name>` works from a
  clean machine.

## Non-goals (explicitly out of scope — push back if asked to add these)
- Reimplementing SYN scanning, OS fingerprinting, or any of Nmap's core
  engine logic.
- Any automated/scheduled scanning against hosts not explicitly entered
  by the user in that session (no "scan my whole subnet automatically on
  startup" type features without explicit, every-time user action).
- Cloud sync / multi-device state — local-first, no backend service.

## Progress Log
<!-- Append one short entry per milestone completed. Do not rewrite history. -->

### M0 — Scaffold (2026-10-09)
Hand-authored Tauri v2 + React/TypeScript scaffold committed (not generated
via `create-tauri-app`, since the authoring environment had no registry
access — written directly against the known v2 config/Cargo schema).
**Not yet verified to build** — next step is running `npm install` and
`npm run tauri dev` on a machine with normal network access and confirming
the window opens. `bundle.icon` was deliberately left out of
`tauri.conf.json`; icons need generating (`npm run tauri icon <source>`)
before `tauri build` works — tracked for M7. CI workflow added but likewise
unverified until it runs on a push.

### M0 — Verified building (2026-10-09)
M0 now compiles cleanly on Linux (Ubuntu 24.04). Frontend builds (tsc +
vite). Rust/Tauri builds (`cargo build` green, tauri 2.12.2, Rust 1.99 via
rustup). Env prep needed on this machine: apt Tauri libs
(libwebkit2gtk-4.1-dev et al.) + rustup (system Rust 1.75 was too old).
**Correction to the note above:** `tauri::generate_context!()` embeds the
app icon at COMPILE time, so icons are required even for `dev`, not just
`tauri build`. Generated a placeholder icon set via `tauri icon app-icon.png`
(source `app-icon.png` kept in repo root for regeneration; real icon design
still deferred to M7) and wired `bundle.icon` into `tauri.conf.json`. Mobile
(android/ios) icon dirs removed — desktop-only project. `gen/schemas` is
gitignored. **M0 DONE** — `npm run tauri dev` opens the window and the
frontend renders correctly.

**Dev note / known env quirk (older GPUs):** on older NVIDIA/Intel GPUs the
webkit2gtk WebView can render garbled scan-lines under its default DMABUF
path. Fix is to launch with `WEBKIT_DISABLE_DMABUF_RENDERER=1 npm run tauri
dev`. Confirmed needed on the GT 730 dev box; harmless/ignored on macOS and
Windows (no webkit2gtk there). Not baked into the default script so it
doesn't mask the var cross-platform — set it in your shell if your GPU needs
it. Revisit for the Linux package in M7.

### M1 — Nmap subprocess + XML parsing DONE (2026-10-09)
Restructured to the standard Tauri lib+thin-bin layout (`src/lib.rs` exposes
`run()` + `pub mod scan`; `src/main.rs` just calls `cartograph_lib::run()`),
so parsing code is shared by the app, tests, and the example harness.
- `src/scan.rs`: typed model (`ScanResult/Host/Address/Port/Service/RunStats`,
  serde camelCase for the frontend), `parse_nmap_xml` (roxmltree, no regex),
  `run_scan` (spawns `nmap -oX - <flags> <target>`), and `#[tauri::command]
  run_nmap_scan`. Registered in the Tauri builder (ready for M2's UI).
- Security: `run_scan` uses `Command` with explicit args (no shell), and
  rejects a target that is empty or starts with `-` (flag-injection guard).
  Had to set roxmltree `allow_dtd: true` for nmap's `<!DOCTYPE nmaprun>`
  (safe — no entities declared, no external-entity expansion).
- Tests: 8 unit tests, pass WITHOUT nmap installed, driven by two committed
  fixtures (`tests/fixtures/localhost-connect.xml` = a frozen real scan;
  `multi-host-version.xml` = crafted, exercises -sV versions, mac+vendor, a
  down host). Covers happy path, bad portid, malformed XML, non-nmap root,
  and both target-guard rejections.
- Live proof: `cargo run --example scan_demo -- localhost -F` returns correct
  structured JSON (8 open ports on 127.0.0.1). Harness is temporary (M2 UI
  supersedes it). `cargo fmt` + `cargo clippy --all-targets -D warnings` clean.
Next: M2 — minimal UI (target input, intensity presets, live command preview,
sortable results table) calling `run_nmap_scan`.

### M2 — Minimal UI DONE (2026-10-09)
React UI wired to `run_nmap_scan`, verified at runtime in the dev window
(localhost -sV → 9 open ports with versions, sortable table).
- `src/types.ts` mirrors the backend's camelCase shape; `src/api.ts` wraps
  `invoke("run_nmap_scan", { target, flags })` (import from
  `@tauri-apps/api/core`). Custom commands need NO capabilities/ACL entry in
  Tauri v2 — confirmed, invoke works without one.
- `src/presets.ts`: three root-free presets (Quick `-F`, Regular ``,
  Service+version `-sV`) — no `-sS/-O/-A` since the app runs unprivileged.
  `buildCommand()` shows the reproducible `nmap <flags> <target>` WITHOUT our
  internal `-oX -` so the user can paste it into a real terminal.
- Components: `ScanForm` (input + presets + preview), `CommandPreview`
  (always-visible live command, copy button — the signature "teaches while
  doing" feature), `ResultsTable` (flattens hosts→ports, client-side sort by
  any column, state pills, summary bar). `App` drives idle/scanning/error/done.
- Dark UI in the icon's slate/cyan palette (`src/App.css`).
- `npm run build` (tsc strict + vite) clean.
Next: M3 — SQLite persistence (store every run: target, timestamp, raw XML,
parsed summary) + a per-target scan-history list.

### M3 — SQLite persistence + history DONE (backend verified; GUI check pending)
- Added `rusqlite` (bundled — compiles SQLite from source, no system dep).
- `src/db.rs`: `Db(Mutex<Connection>)` Tauri state, schema (scans table: raw_xml
  stored verbatim as source of truth + denormalized target/args/created_at/
  hosts_up/open_ports/elapsed_secs, indexed on target & created_at), and
  `insert_scan` / `list_scans` / `get_scan_xml`.
- Refactored `scan.rs`: split out `run_nmap_raw` (returns raw XML) so the
  command path can persist it; `run_scan` (parse+run) kept for example/tests.
- `src/commands.rs`: the only Tauri/DB-aware layer — `run_nmap_scan` (now also
  persists), `list_scans`, `get_scan` (re-parses stored XML). `scan`/`db` stay
  free of Tauri types.
- `lib.rs` setup hook opens the DB at `app_data_dir()/cartograph.sqlite3`
  (under the bundle id) and manages it as state.
- Frontend: `HistoryList` sidebar (target · open count · time), click a row →
  `get_scan` loads it into the table with a "viewing a saved scan" banner;
  history refreshes after each run. Sidebar layout in `App.css`.
- Tests: 11 green without nmap. `persists_across_reopen` proves the acceptance
  at the storage layer (write → drop connection = close → reopen = restart →
  data present). `insert_list_and_fetch_roundtrip` proves stored XML re-parses
  identically. fmt + clippy clean; frontend tsc+vite clean.
- PENDING user GUI check: scan appears in sidebar, survives a real app
  close/reopen, and click-to-load works.
Next: M4 — diff view (pick two scans of the same target → new/closed ports,
changed service versions).
