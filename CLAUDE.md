# Project: Wardmap

## What this is
Wardmap is a modern desktop GUI for Nmap. Zenmap (the official Nmap GUI) is
actively maintained (Python 3 since Nmap 7.94, still updated in 7.991), so
never describe it as unmaintained; README's "Related projects" lists the other
front ends.

We do NOT reimplement Nmap's scan engine. We run the real `nmap` binary as a
subprocess and parse its XML output. All of Wardmap's value is in what sits
around that: history and diffing, the exposure map and device identification,
the NSE script browser, the full option builder with an editable live command
line, and UX.

## Architecture (do not relitigate without discussion)
- **Shell:** Tauri v2 (Rust backend + web frontend). Chosen over Electron for
  size and native feel, over Qt/PySide for easier cross-platform CI.
- **Frontend:** React 18 + TypeScript (strict). Hand-rolled components and
  icons; no UI kit, no icon library.
- **Backend:** spawns `nmap` with explicit argv (never a shell), always with
  `-oX -`; parses XML with `roxmltree`, never regex. Anything needing raw
  packets is out of scope: use nmap flags instead.
- **Persistence:** SQLite via `rusqlite` (bundled). `wardmap.sqlite3` in the
  app data dir (bundle id `io.github.im-srj.wardmap`). The raw XML of every
  scan is the source of truth; other columns are derived from it.
- **No telemetry, no phone-home.** Fonts are bundled, there is no auto-updater.
  The only network traffic is the user's own scans plus LAN mDNS lookups.

## Rules that must keep holding
- **`cmdline.rs` is the trust boundary.** The backend re-analyzes every
  command before running it; `runner::run` only accepts an `Analysis` and
  refuses blocked ones (output flags in any spelling, `--stats-every`,
  `--resume`, `-iR`, `-iL -`, non-scan modes, malformed input).
- **Never bundle nmap or its data files** in any package. Depend on the
  system's nmap (`.deb`/`.rpm` declare `Depends: nmap`). Wardmap is
  GPL-2.0-or-later because Nmap's NPSL §3 calls software "designed
  specifically to execute" Nmap a derivative work.
- **Only scan what the user entered** in that session (see Non-goals).
- File dialogs run in the backend; the webview never passes file paths.
- Profiles store options only, never targets.
- **Never overstate findings.** Device types are labelled "guess" with a
  reason; exposure notes describe the kind of service, never version-specific
  vulnerability claims; the diff never reports a TLS cert as "removed" (a
  missing cert usually means `ssl-cert` didn't run).
- Root scans ask for the password every scan (pkexec on Linux); no setcap.

## Non-goals (push back if asked to add these)
- Reimplementing SYN scanning, OS fingerprinting, or any of Nmap's engine.
- Automated or scheduled scanning of hosts the user didn't explicitly enter
  in that session (no "scan my subnet on startup").
- Cloud sync or multi-device state: local-first, no backend service.

## Code map
`src-tauri/src/` (Rust):
| File | What it does |
|---|---|
| `scan.rs` | XML → `ScanResult` (hosts, ports, services, scripts, TLS certs) |
| `cmdline.rs` | nmap's own option parser, mirrored; policy checks |
| `runner.rs` | runs nmap (pty for progress, pkexec for root), cancel, queue |
| `commands.rs` | the only Tauri-aware layer: every `#[tauri::command]` |
| `db.rs` | SQLite schema, migrations, scans/profiles/identities |
| `diff.rs` | `diff_scans(old, new)`: only what changed |
| `identify.rs` | MAC (ARP cache) + vendor (`nmap-mac-prefixes`) + mDNS names |
| `nse.rs` / `profiles.rs` / `export.rs` | NSE catalogue / Zenmap profile import / export formats |

`src/` (frontend): `App.tsx` (state, views), `api.ts` (invoke wrappers),
`types.ts` (mirrors Rust's camelCase types), `options.ts` +
`nmap-options.json` (option catalogue), `presets.ts` (8 built-in profiles),
`exposure.ts` / `device.ts` (offline service and device knowledge),
`themes.ts`, `components/`. Themes are `[data-theme]` blocks in `App.css`.

Tests run without nmap, against XML in `src-tauri/tests/fixtures/`.
`ui_catalogue_matches_the_parser` keeps `nmap-options.json` in sync with
`cmdline.rs`.

## Commands
```sh
# First-time setup (Ubuntu/Debian; README covers other OSes)
sudo apt install nmap libwebkit2gtk-4.1-dev libgtk-3-dev \
  libayatana-appindicator3-dev librsvg2-dev build-essential
curl https://sh.rustup.rs -sSf | sh      # distro Rust is too old
npm install

npm run tauri dev                         # run the app
cd src-tauri && cargo test                # all tests, no nmap needed
cargo test --lib runner -- --ignored      # live tests against real nmap
cargo fmt && cargo clippy --all-targets -- -D warnings
npm run build                             # tsc (strict) + vite
npm run tauri build                       # local installers → src-tauri/target/release/bundle/
cargo run --example scan_demo -- localhost -F   # also identify_demo, export_demo
```

## Conventions
- `cargo fmt` + `cargo clippy -D warnings` clean before every commit.
- TypeScript strict; follow Prettier's style (ESLint/Prettier aren't set up
  yet; CI runs `cargo check` + `tsc --noEmit`).
- Small commits, one logical change each, imperative mood ("Add XML parser
  for host/port blocks").
- **The XML parser and the diff need tests for every change**: a silent bug
  there means a wrong port state or a wrong diff, and wrong security
  conclusions.
- When something lands, update **Status** below in a line or two. Keep this
  file a current reference, not a diary: history lives in git and the PRs.

## Working across machines
Developed on more than one machine; there is no live sync of Claude Code
sessions, so git and this file carry the context.
- `git pull` before starting; commit and push before switching machines.
- **Branches:** `main` is always the merged state. Each piece of work gets a
  new branch off an up-to-date `main` → push → PR → merge → delete the
  branch. Never stack work on an unmerged branch. Check
  `git branch --show-current` before the first commit.

## Releasing
Bump the version in `package.json`, `src-tauri/Cargo.toml` and
`src-tauri/tauri.conf.json` (must match), merge to `main`, then
`git tag vX.Y.Z && git push origin vX.Y.Z`. `.github/workflows/release.yml`
checks the versions, builds Linux/macOS/Windows and creates a **draft**
release; test the installers, then publish. A failed run costs nothing:
delete the draft and the tag, fix, re-tag.

## Gotchas
- nmap's `--stats-every` prints nothing without a controlling terminal, so
  the runner gives nmap a pty (`openpty` + `setsid` + `TIOCSCTTY`); stdout
  stays the XML pipe.
- A root nmap can't be killed by us: Cancel writes Ctrl-C to its pty.
  pkexec exit 126 = authentication cancelled, 127 = not authorized.
- roxmltree needs `allow_dtd: true` for nmap's `<!DOCTYPE nmaprun>` (safe:
  no entities).
- `tauri::generate_context!()` embeds the icons at compile time, so they're
  needed even for `dev`. To change the logo: edit `app-icon.svg`, render a
  1024px `app-icon.png` with headless Chrome (ImageMagick drops gradients),
  run `npm run tauri icon app-icon.png`, delete the `android/` and `ios/`
  dirs it creates. The sidebar `BrandMark` is a simplified copy.
- WebKitGTK paints native `<select>`s white unless `color-scheme` is set; old
  GPUs may need `WEBKIT_DISABLE_DMABUF_RENDERER=1 npm run tauri dev`.
- Custom Tauri commands need no capability entries.
- `libc` differs per OS: `openpty`'s termios/winsize params are `*const` on
  Linux but `*mut` on macOS (pass `null_mut()`). Code that only compiles on
  Linux locally can still break the macOS/Windows release builds.
- `npm run tauri build`'s AppImage step downloads helpers from GitHub;
  `timeout: global` means retry (`-- --bundles appimage`).
- Windows `.msi` needs a purely numeric version: no `-rc` tags.
- The app was called Cartograph until 2026-10-14; `db::adopt_legacy` moves
  the old `com.cartograph.app/cartograph.sqlite3` on first launch.

## Status (2026-10-15)
| Area | State |
|---|---|
| M0–M3: scaffold, XML parsing, scan UI + live command, SQLite history | Done |
| M4: diff, incl. TLS cert changes | Done |
| M5: exposure map (replaced the force graph) + device identification | Done, GUI check pending |
| M6: NSE browser (one place for all script options) | Done, GUI check pending |
| UI overhaul + 6 themes | Done, GUI check pending |
| M8: async engine, progress, cancel | Done, GUI check pending |
| M9–M10: full option catalogue, editable command line | Done, GUI check pending |
| M11: root scans | Linux done; macOS/Windows not implemented (blocked with a message) |
| M12: profiles, re-run, import/export, queue | Done |
| Rename to Wardmap + new logo | Done |
| **M7: packaging** | **In progress** |

**M7 now:** license (GPL-2.0-or-later), release workflow, `.deb`/`.rpm`
nmap dependency and README Install/Releasing are merged; the Linux bundles
build locally. The first `v0.1.0` run failed to compile on macOS (openpty,
see Gotchas); fixed in `df9e80a` and `v0.1.0` re-tagged onto it. Check that
run and the draft (macOS/Windows installers still untested), then publish.

**Next:** Homebrew tap (`im-srj/homebrew-wardmap`, a cask depending on the
`nmap` formula) → winget manifest (PR to `microsoft/winget-pkgs`) → code
signing (Apple Developer ID; SignPath for Windows) → macOS/Windows root
scans → check scan progress on Windows. Also open: decide whether the Linux
packages should set `WEBKIT_DISABLE_DMABUF_RENDERER`; set up ESLint +
Prettier (add them to CI); clear the pending GUI checks above.
