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

**Branches:** `main` is always the latest merged state. Start each milestone
on a NEW branch off an up-to-date `main`, push it, merge it via a PR, then
delete the branch:
```sh
git checkout main && git pull && git checkout -b m7-packaging
```
Never stack a new milestone on an unmerged feature branch (that's how M8–M12
and the README all ended up on `ui-themes-map-device-id` once and had to be
split up). Check `git branch --show-current` before the first commit.

**First-time setup on a new machine** (Ubuntu/Debian; see README for others):
```sh
sudo apt install nmap libwebkit2gtk-4.1-dev libgtk-3-dev \
  libayatana-appindicator3-dev librsvg2-dev build-essential
curl https://sh.rustup.rs -sSf | sh   # distro Rust is too old
npm install
cd src-tauri && cargo test            # should be all green, no nmap needed
npm run tauri dev                     # add WEBKIT_DISABLE_DMABUF_RENDERER=1 on old GPUs
```
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

### M8+ — Full nmap coverage
Async engine/progress/cancel → full option catalogue + builder → custom
command mode → privileged scans → profiles/import/export; M7 moves after
these. Plan and rationale: `docs/ROADMAP.md`.

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

### M3 — SQLite persistence + history DONE (GUI confirmed 2026-10-09)
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
- GUI confirmed: scans appear in sidebar, survive app close/reopen, and
  click-to-load works.
Next: M4 — diff view (pick two scans of the same target → new/closed ports,
changed service versions).

### M4 — Diff view DONE (backend tested; GUI check pending)
- `src/diff.rs`: pure `diff_scans(old, new) -> ScanDiff`. Compares hosts by key
  (IPv4 preferred), surfaces only CHANGES: hosts added/removed, host up/down,
  ports opened/closed, and service (name/product/version) changes. Unchanged
  items omitted; `unchanged: true` when nothing differs.
- `commands::diff_scans(old_id, new_id)` loads both scans from the DB
  (re-parses stored XML) and diffs them. Registered in the builder.
- 4 diff unit tests (15 total, all green w/o nmap): identical→unchanged;
  opened + closed + service-version-change in one host; added/removed hosts;
  host up→down. fmt + clippy clean (had to add a test type alias + elide a
  lifetime).
- Frontend: `CompareBar` (two dropdowns of saved scans, defaults to the two
  newest, disabled when equal), `DiffView` (per-host cards, +/−/~ signed port
  rows color-coded by change kind). `App` refactored to a `View` union
  (idle/scanning/error/scan/diff). tsc+vite clean.
- DEFERRED: TLS cert diffing. Certs come from nmap NSE `<script>` output, which
  the parser doesn't read yet — deferred to M6 (NSE support). Noted in diff.rs.
- GUI confirmed: Compare renders the diff (opened port detected between two
  localhost scans). Two post-M4 CSS fixes also landed: focus-ring on selects/
  buttons, and `color-scheme: dark` so WebKitGTK stops painting native
  <select> controls white (light text was invisible on them).
Next: M5 — topology view (interactive host/subnet graph).

### M5 — Topology view DONE (frontend-only; GUI check pending)
- `src/components/TopologyView.tsx`: hand-rolled force-directed graph (no dep,
  per conventions). A pinned central "scan" root node with an edge to each
  up-host node; `computeLayout` runs ~320 iterations of repulsion + spring +
  center-gravity with cooling to a settled, deterministic layout. Nodes are
  draggable (pointer capture), hover shows a tooltip (addr · subnet · open
  count · services), size scales with open-port count, color by /24 subnet.
- Filters (the M5 "filterable by subnet/service"): subnet chips toggle each
  /24's visibility; a service `<select>` filters to hosts exposing it. Layout
  reflows when the visible node count changes.
- `App`: Table/Map toggle on scan results (`resultMode` state); both render
  from the same `ScanResult`, so no backend change was needed.
- tsc+vite clean. No Rust touched, so the 15 backend tests are unaffected.
- PENDING user GUI check: best seen with a MULTI-host scan — e.g. Quick scan
  of your own LAN `192.168.1.0/24` — then Map toggle shows the graph; localhost
  alone is just root→one node.
Next: M6 — NSE script browser (searchable/categorized picker; selecting
scripts updates the live command preview; also unlocks cert data for M4's
deferred cert diffing).

### M6 — NSE script browser DONE (backend tested; GUI check pending)
- `src/nse.rs`: catalogue from `nmap --script-help all -oX -` (XML, roxmltree —
  no scripts-dir guessing per OS; ~0.25s for 605 scripts on 7.94). Command
  `list_nse_scripts`. Fixture `script-help.xml` = 5 real entries.
- Frontend `ScriptBrowser` (in `ScanForm`, between presets and preview):
  lazy-loads on first open; search by name/description; category chips with
  counts; per-script "more" for the full NSEDoc. Selection → one
  `--script=a,b` arg via `buildFlags()` (presets.ts), so preview == actual run.
  Amber warning when an intrusive/brute/dos/exploit script is selected.
- Parser now reads `<script>` (ports) + `<hostscript>` (hosts) as
  `scripts: [{id, output}]`, and `ssl-cert`'s structured elems into
  `Port.cert: TlsCert` (sha1, subject/issuer CN, validity). Results table:
  "▸ N scripts" expands output inline; host scripts listed under the table.
  Fixture `localhost-scripts.xml` = real ssl-cert/http-title scan (hostname
  redacted to `devbox`, PEM/modulus stripped).
- M4's deferred cert diff DONE: `cert-changed` (SHA-1 differs) and `cert-new`
  (incl. newly opened ports / added hosts). Cert missing from the NEWER scan
  is intentionally NOT reported (usually = ssl-cert not run; "removed" would
  be a false conclusion).
- 26 tests green w/o nmap; fmt + clippy clean; tsc+vite clean. Live check via
  `scan_demo -- localhost -p 5432 --script=ssl-cert` → cert parsed correctly.
- Not done (possible follow-ups): `--script-args`, selecting a whole category
  as a script spec (e.g. `--script=vuln`), ESLint/Prettier aren't actually
  configured in the repo yet (CI only runs `tsc --noEmit`).
Next: M7 — packaging (Homebrew / AppImage-or-apt / winget; real icon).

### UI overhaul + themes (2026-10-09, between M6 and M7; GUI check pending)
- Redesigned shell: brand sidebar (New scan, filterable history w/ relative
  times), top bar per view, stat cards, filterable results table, terminal-style
  syntax-coloured command preview, radar empty/scanning states (elapsed timer),
  polished diff (summary stats + tinted rows). Scan options auto-collapse while
  results/diff are shown; command preview + intrusive-script warning never hide.
- Themes: tokens are `[data-theme="<id>"]` blocks in `App.css` (attribute, not
  :root-only, so Appearance-panel previews render each theme exactly). Six:
  Midnight (default), Graphite, Terminal, Arctic, Ember, Daylight. `src/themes.ts`
  persists choice in localStorage; applied in `main.tsx` before first paint.
  Derived tints use `color-mix()`. Topology colours come from `--viz-1..6`.
- Fonts bundled locally via `@fontsource-variable/inter` + `jetbrains-mono`
  (no runtime fetch — keeps the no-phone-home rule). Icons hand-rolled in
  `components/Icon.tsx` (no icon lib). Window default 1280×840, min 900×600.

### M5 rework — exposure map replaces force graph (2026-10-09; GUI check pending)
The M5 star graph ("scan" → hosts) conveyed nothing the table didn't, and its
edges implied a topology we can't see (real paths need `--traceroute` = root).
Replaced by `components/ExposureMap.tsx` + `src/exposure.ts`:
- Hosts grouped by /24 subnet as cards (no edges; footnote says why), each with
  a device-type GUESS (router/printer/Windows/NAS/DB/…, from services + MAC
  vendor; always labelled "guess" with its reason) and colour-coded service
  pills. Click → detail panel: services grouped by purpose (remote access,
  databases, file sharing…), plain-language note per service, review /
  unencrypted / TLS tags, cert summary. Filters: "Needs attention" + category.
- `exposure.ts` = offline catalogue (~55 services by nmap name, port fallback).
  Notes describe the KIND of service only — never version-specific vuln claims.
- Backend: `Service` now carries `tunnel` ("ssl") and `method` ("probed"/
  "table"). Needed so -sV's HTTPS (`http`+`ssl`) isn't flagged unencrypted, and
  so port-table guesses are shown as unconfirmed. Test added (27 green).
Possible follow-up: "changes since last scan" overlay on the map (ties to M4).

### Device identification (2026-10-09; GUI check pending)
Unprivileged nmap reports no MACs and its rDNS rarely names LAN devices, so
hosts were hard to tell apart. New `src-tauri/src/identify.rs` runs after every
scan (approved design: built-in, automatic, LAN-only):
- MAC from the OS ARP cache (`/proc/net/arp`; `arp -an`/`arp -a` elsewhere) +
  vendor from nmap's own `nmap-mac-prefixes` (longest-prefix; located via
  NMAPDIR / PATH / common dirs). Randomized (locally-administered) MACs flagged.
- mDNS reverse lookup = what `avahi-resolve-address` does: one-shot PTR query
  (multicast 224.0.0.251 + direct unicast to host:5353), ~1.5s, `simple-dns`
  crate for packets. Live-verified on the dev LAN: 24/24 names identical to avahi.
- Only up hosts in private/link-local IPv4 ranges; capped at 1024. Stored in a
  new `host_identity` table keyed by scan id (raw XML stays the source of
  truth); `Host.identity` is attached on run and on `get_scan`.
- Frontend `src/device.ts`: guess = what it IS (name patterns incl. Windows
  `DESKTOP-XXXXXXX` and Linux `<user>-<motherboard>` defaults, MAC vendor,
  randomized MAC) + what it DOES (role from services). Map detail shows
  DNS/mDNS names, MAC (tagged "ARP cache") and vendor. Table hostname falls
  back to the mDNS name. `examples/identify_demo.rs` = live debug harness.
- 37 Rust tests green (9 identify + 1 DB roundtrip new); fmt + clippy clean.

### M8 — Async scan engine: progress + cancel DONE (backend live-tested; GUI check pending)
- `src-tauri/src/runner.rs`: `run_nmap_scan` is now async (`spawn_blocking`),
  streams `ScanProgress {task, percent, remainingSecs}` over a Tauri `Channel`;
  `cancel_scan(run_id)` kills nmap (cancelled scans aren't saved); all running
  nmaps are killed on app exit. `nmap_version` preflight command.
- **Gotcha worth remembering:** nmap's `--stats-every` does NOTHING without a
  controlling terminal (piped = zero `<taskprogress>`). On Unix we give nmap a
  pty as stdin/ctty (`openpty`+`setsid`+`TIOCSCTTY`); stdout stays the XML
  pipe. Windows progress unverified (→ M7).
- Frontend: run state lives outside the view (scan continues while browsing
  history; sidebar row returns to it), progress bar with phase/ETA, Cancel,
  "nmap isn't installed" card, nmap version in the sidebar footer.
- 45 tests green w/o nmap + 2 `#[ignore]` live tests (`cargo test --lib runner
  -- --ignored`: real progress through the pty; cancel stops nmap) — both pass.
  fmt + clippy clean; tsc+vite clean.
- GUI check: run a slow scan (e.g. `localhost` with Service+version, or a /24)
  → bar fills with phase names; click History mid-scan → sidebar shows the
  running row; Cancel returns to idle and nothing is saved.
Next: M9 — option catalogue (`shared/nmap-options.json`) + visual builder.

### M9 + M10 — All nmap options + editable command line DONE (backend tested; GUI check pending)
- `src-tauri/src/cmdline.rs` mirrors nmap's own `getopt_long_only`
  (`long_options[]` + optstring transcribed from nmap.cc): abbreviations,
  `-top`-style single-dash longs, clusters, attached values, deprecated
  aliases. It is the trust boundary: `run_nmap_scan(run_id, command)`
  re-analyzes the text, and `runner::run` only takes an `Analysis` and refuses
  blocked ones (output flags in every spelling, `--stats-every`, `--resume`,
  `-iR`, `-iL -`, non-scan modes, ambiguous/malformed input). Tricky cases were
  checked against real nmap 7.94. New command `analyze_command` gives live
  feedback.
- `src/nmap-options.json` = UI catalogue (100+ options, nmap's sections, root/
  risk/exclusive-group metadata). The Rust test `ui_catalogue_matches_the_parser`
  keeps it consistent with the parser. `src/options.ts` = makeItem/setOption/
  quoting.
- UI: presets, NSE browser, new **All options** panel (`OptionsBuilder`) and
  the now-**editable command line** (`CommandPreview`) all edit one list of
  canonical option items. Backend issues + root/spoofing warnings are shown
  under the command. Run is enabled only when the backend has cleared the
  current command.
- 61 Rust tests green w/o nmap (+16 cmdline incl. catalogue check); live tests
  still pass; fmt + clippy clean; tsc+vite clean.
- GUI check: open "All options", tick e.g. -sV, set -p and -T4 → the command
  updates; click the command, paste `nmap -sSV -p- -oX out.xml host` → the
  options follow and a red "output file" issue disables Run; remove `-oX
  out.xml` → Run enables.
Next: M11 — privileged scans (pkexec/osascript/UAC per scan), then M12.

### M11 — Root scans, password every time DONE on Linux (backend tested; GUI check pending)
- User decision: per-scan password prompt (no setcap). `sudo` prefix in the
  command = run as root; "Run as root" checkbox toggles it (auto-ticks for
  root-only options, explicit choice wins).
- `runner.rs`: `pkexec --disable-internal-agent /usr/bin/nmap …` (desktop polkit
  dialog; 126 → "authentication cancelled", 127 → not authorized). Cancel
  writes Ctrl-C to nmap's pty (kernel SIGINT works on a root process we can't
  `kill`); verified live that ^C alone stops nmap.
- macOS/Windows elevation NOT implemented — `sudo` is blocked there with a
  message; deferred to M7 where it can be tested.
- 63 tests green + 3 live (`cargo test --lib runner -- --ignored`); fmt +
  clippy clean; tsc+vite clean.
- GUI check: tick -sS (or -O) → "Run as root" ticks and the command shows
  `sudo nmap …` → Run → password dialog → results. Also try Cancel on the
  dialog ("authentication cancelled") and Cancel mid-scan (stops the root nmap).
Next: M12 — profiles, re-run from history, import/export.

### M12 — Profiles, re-run, import/export, run queue DONE (backend tested; GUI check pending)
- Profiles: 8 built-ins (`presets.ts`) + saved ones (SQLite `profiles`, options
  only — never targets). Picking a profile now REPLACES all options (target
  kept). Save / update / delete in `ProfilePicker`; Zenmap `scan_profile.usp`
  import (`profiles.rs`).
- History: new `scans.command` column (migrated in place, verified on the real
  DB); rebuilt from nmap's args for imported/old scans. Saved-scan toolbar
  (`ScanActions`): Re-run (loads the command; result gets a "changed since…"
  banner + diff link), Copy command, Export (XML/JSON/CSV/-oN-/-oG-like/HTML,
  `export.rs`). Sidebar ↑ imports nmap XML files (deduped, dated by nmap start).
- File dialogs run in the BACKEND (`tauri-plugin-dialog` Rust API) — the
  webview never passes a path; no capability entries needed.
- Up to 2 concurrent scans, rest queued; `run_nmap_scan` returns
  `{scanId, result}`. `examples/export_demo.rs` compares exports with nmap's.
- 80 Rust tests green (+17); fmt + clippy clean; tsc+vite clean.
- GUI check: save a profile and reload it; Import from Zenmap; open a saved
  scan → Export each format, Re-run → Run → "changed since…" banner; start 3
  scans → third shows "queued" in the sidebar; import an `nmap -oX` file.
Next: M7 — packaging (incl. macOS/Windows elevation from M11).


### Repo housekeeping + README (2026-10-09)
- Added `README.md` (features, requirements, build, usage, architecture,
  layout, dev commands, roadmap). No LICENSE chosen yet — README says so.
- Branch cleanup: work from the UI overhaul through M12 had piled onto
  `ui-themes-map-device-id`. Split into per-milestone branches and merged
  into `main` in order via PRs #1–#7. **`main` now holds everything up to
  M12 + README**; the old feature branches are merged and can be deleted.
- Branch-per-milestone rule added under "Working across machines".
Next: on any machine, `git checkout main && git pull`, then clear the pending
GUI checks above (themes, exposure map, device ID, M8–M12), then start M7 —
packaging — on a fresh `m7-packaging` branch.
