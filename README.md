# Cartograph

**A modern desktop GUI for [Nmap](https://nmap.org).** Build scans visually or
type any nmap command, watch them run, and keep every result. You can compare
scans over time, see what a network exposes, and browse NSE scripts, all
locally.

Cartograph is meant to replace [Zenmap](https://nmap.org/zenmap/), which has
been unmaintained since 2019, is Python 2/GTK, and has no Apple Silicon build.
It does **not** reimplement Nmap: it runs the real `nmap` binary and parses
its XML output.

> **Status: pre-release (v0.1.0).** It works on Linux and is used day to day
> there. macOS and Windows builds aren't verified yet, and there are no
> packages yet (see [Roadmap](#roadmap)). Build from source for now.

---

## Features

- **Live command line.** The exact `nmap …` command is always on screen and
  updates as you change options. You can also edit it directly: type or paste
  any nmap command and the options panel follows. What you see is what runs.
- **Every nmap option.** An *All options* panel covers 100+ options in nmap's
  own sections, with search, plus badges for root-only and risky options and
  mutually-exclusive groups.
- **Profiles.** Eight built-ins (Quick, Regular, Service + version, Intense,
  Ping sweep, UDP top 100, Full TCP, Vuln scripts). You can save your own and
  import Zenmap's `scan_profile.usp`.
- **NSE script browser.** A searchable, categorised list of every installed
  script with its full documentation. It warns you when a selected script is
  intrusive, brute-force, DoS or exploit.
- **Progress and cancel.** A progress bar shows the scan phase and ETA, and you
  can cancel at any time. Up to two scans run at once and the rest are queued.
  You can keep browsing while scans run.
- **Root scans (Linux).** Tick *Run as root*, or start the command with `sudo`,
  for `-sS`, `-O`, `-A` and similar options. Cartograph asks for your password
  through the system (polkit) dialog **on every such scan** and never keeps
  elevated rights.
- **Scan history.** Every completed scan is saved to a local SQLite database:
  the raw XML plus a parsed summary. You can re-run any past scan or import
  existing `nmap -oX` files.
- **Diff.** Pick two scans to see added/removed hosts, hosts that went up or
  down, opened/closed ports, changed service versions, and new or changed TLS
  certificates.
- **Exposure map.** Hosts are grouped by subnet, with a device-type guess,
  colour-coded services, plain-language notes on what each service is, and a
  *Needs attention* filter.
- **Device identification.** On private LANs, Cartograph adds MAC address +
  vendor (from the OS ARP cache and nmap's own vendor database) and mDNS names
  to each host.
- **Export.** nmap XML, JSON, CSV, `-oN`-style text, `-oG`-style grepable, and
  a standalone HTML report.
- **Six themes**, with fonts and icons bundled in the app.
- **No telemetry, no network calls of its own.** The only traffic Cartograph
  sends is the scans you start, plus local mDNS lookups for hosts on your LAN.

## Requirements

| | |
|---|---|
| **nmap** | Installed and on your `PATH`. Developed against 7.94. Cartograph tells you if it can't find nmap. |
| **OS** | Linux (tested on Ubuntu 24.04). macOS and Windows should build but are untested. Root scans are Linux-only for now. |
| **To build** | Rust (recent stable, via [rustup](https://rustup.rs)), Node.js 20+, and the [Tauri v2 system prerequisites](https://v2.tauri.app/start/prerequisites/) for your OS. |

On Debian/Ubuntu, the Tauri prerequisites are:

```sh
sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev \
  libayatana-appindicator3-dev librsvg2-dev build-essential
```

> Distro-packaged Rust is often too old. Use rustup.

## Getting started

```sh
git clone git@github.com:im-srj/cartograph.git
cd cartograph
npm install
npm run tauri dev      # run in development mode
npm run tauri build    # build a release bundle (src-tauri/target/release/bundle/)
```

**Garbled or striped window on Linux?** Some older NVIDIA/Intel GPUs hit a
WebKitGTK rendering bug. Launch with:

```sh
WEBKIT_DISABLE_DMABUF_RENDERER=1 npm run tauri dev
```

## Using Cartograph

1. Enter a target (host, IP, CIDR range or list) that **you own or are
   authorised to scan**.
2. Pick a profile, open *All options* or *Scripts*, or edit the command line
   directly.
3. Press **Run**. Results appear as a sortable table or as the exposure map.
4. Open past scans from the sidebar. Use **Compare** to diff two scans, and
   **Re-run** / **Export** from a saved scan's toolbar.

Some flags are blocked on purpose, and the command line explains why when you
use one:

- **Output flags** (`-oX file`, `-oN`, …). Cartograph manages nmap's output
  itself. Use Export instead.
- **`--resume`, `--stats-every`, `-iL -`, and modes like `-h` / `-V`.** These
  conflict with how Cartograph runs nmap.
- **`-iR` (random internet targets).** Cartograph only scans hosts you typed
  in.

Your data lives in `cartograph.sqlite3` in the app data directory:

| OS | Path |
|---|---|
| Linux | `~/.local/share/com.cartograph.app/` |
| macOS | `~/Library/Application Support/com.cartograph.app/` |
| Windows | `%APPDATA%\com.cartograph.app\` |

## How it works

```
React UI (src/)  ──invoke──▶  Rust backend (src-tauri/src/)  ──spawn──▶  nmap -oX - …
                 ◀─progress──                                ◀──XML────
                                        │
                                        └──▶ SQLite (raw XML + summary)
```

- **No shell, ever.** Commands are tokenised and passed to nmap as an
  argument list.
- **The backend checks every command before it runs.** `cmdline.rs` parses
  the command the way nmap's own `getopt_long_only` does, including
  abbreviations, clusters and attached values, so a blocked flag can't slip
  through under a different spelling.
- **Progress needs a terminal.** nmap only reports progress when it has a
  controlling terminal, so on Unix it gets a pseudo-terminal as stdin. Stdout
  stays a clean XML pipe.
- **XML is parsed with `roxmltree`, never regex.** The raw XML is stored
  unchanged and is the source of truth: history views and exports are
  rebuilt from it.

### Project layout

```
src/                     React + TypeScript frontend
  components/            UI components (hand-rolled, no UI kit)
  nmap-options.json      Option catalogue for the builder (checked against the Rust parser by a test)
  presets.ts, options.ts Profiles and option/command helpers
  exposure.ts, device.ts Service catalogue and device-type guessing
src-tauri/src/           Rust backend
  commands.rs            Tauri command layer (the only module that knows Tauri + DB)
  cmdline.rs             nmap-compatible command parser and policy (trust boundary)
  runner.rs              Spawning, pty, progress, cancel, elevation, queue
  scan.rs                nmap XML → typed model
  diff.rs                Scan-to-scan diff
  db.rs                  SQLite schema and queries
  nse.rs, profiles.rs    NSE catalogue, Zenmap profile import
  identify.rs            ARP / MAC vendor / mDNS identification
  export.rs              Export formats
src-tauri/tests/fixtures Saved nmap XML used by the tests
src-tauri/examples/      Small CLI harnesses (scan_demo, identify_demo, export_demo)
docs/ROADMAP.md          Plan and design notes for the remaining milestones
```

## Development

```sh
# Backend tests (no nmap needed; they run against saved XML fixtures)
cd src-tauri && cargo test

# Live tests against a real nmap (progress through the pty, cancel)
cargo test --lib runner -- --ignored

# Lint and format, required before every commit
cargo fmt && cargo clippy --all-targets -- -D warnings

# Frontend type-check and build
npm run build
```

CLI harnesses, handy for debugging without the UI:

```sh
cargo run --example scan_demo -- localhost -F        # scan → JSON
cargo run --example identify_demo -- 192.168.1.10    # MAC / vendor / mDNS for an IP
cargo run --example export_demo -- scan.xml normal   # render an export format
```

CI (`.github/workflows/ci.yml`) runs `cargo check` and `tsc --noEmit` on every
push.

### Contributing

- Make small commits, one logical change each, with an imperative subject
  ("Add XML parser for host/port blocks").
- `cargo fmt` and `cargo clippy` must be clean. TypeScript runs in strict
  mode.
- **Changes to the XML parser (`scan.rs`) or the diff (`diff.rs`) need
  tests.** A silent bug there means a wrong port state or a wrong diff, and
  that leads to wrong security conclusions.
- Out of scope: reimplementing any part of nmap's engine, scanning anything
  the user didn't enter in that session (no automatic or scheduled scans),
  and cloud sync or any backend service.

## Roadmap

| Milestone | State |
|---|---|
| M0–M6: scaffold, XML parsing, UI, history, diff, map, NSE | Done |
| M8: async engine, progress, cancel | Done |
| M9–M10: full option catalogue, editable command line | Done |
| M11: root scans | Done on Linux; macOS/Windows pending |
| M12: profiles, re-run, import/export, queue | Done |
| **M7: packaging** (Homebrew, AppImage/deb, winget, real icon) | **Next** |

Details and open questions: [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Responsible use

Only scan networks and hosts that you own or have explicit permission to test.
Unauthorised scanning may be illegal where you live.

## License

No license has been chosen yet. Until one is added, all rights are reserved.
Nmap itself is distributed under the
[Nmap Public Source License](https://nmap.org/npsl/). Cartograph runs it as a
separate program and doesn't bundle it.
