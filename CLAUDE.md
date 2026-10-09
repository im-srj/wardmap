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
