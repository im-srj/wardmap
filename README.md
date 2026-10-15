# Wardmap

**A modern desktop GUI for [Nmap](https://nmap.org).** Build scans visually or
type any nmap command, watch them run, and keep every result. You can compare
scans over time, see what a network exposes, and browse NSE scripts, all
locally.

Wardmap is an independent project, not affiliated with Nmap. It does **not**
reimplement Nmap: it runs the real `nmap` binary and parses its XML output.

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
  for `-sS`, `-O`, `-A` and similar options. Wardmap asks for your password
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
- **Device identification.** On private LANs, Wardmap adds MAC address +
  vendor (from the OS ARP cache and nmap's own vendor database) and mDNS names
  to each host.
- **Export.** nmap XML, JSON, CSV, `-oN`-style text, `-oG`-style grepable, and
  a standalone HTML report.
- **Six themes**, with fonts and icons bundled in the app.
- **No telemetry, no network calls of its own.** The only traffic Wardmap
  sends is the scans you start, plus local mDNS lookups for hosts on your LAN.

## Install

Download an installer from the
[Releases page](https://github.com/im-srj/wardmap/releases) (none published
yet; the first one is being prepared). You also need **nmap**, which Wardmap
runs but doesn't include:

| OS | Wardmap | nmap |
|---|---|---|
| Debian, Ubuntu | `sudo apt install ./Wardmap_<version>_amd64.deb` | installed for you with the `.deb` |
| Fedora, openSUSE | `sudo dnf install ./Wardmap-<version>-1.x86_64.rpm` | installed for you with the `.rpm` |
| Any Linux | `chmod +x Wardmap_<version>_amd64.AppImage`, then run it | your distro's `nmap` package |
| macOS (Apple Silicon or Intel) | open the `.dmg`, drag Wardmap to Applications | `brew install nmap` |
| Windows | run `Wardmap_<version>_x64-setup.exe` | the installer from [nmap.org/download](https://nmap.org/download) (includes Npcap) |

The builds aren't code-signed yet, so the first launch needs one extra step:

- **macOS:** if it says Wardmap "can't be opened", right-click the app, choose
  **Open**, then **Open** again.
- **Windows:** on "Windows protected your PC", click **More info**, then
  **Run anyway**.

Homebrew and winget packages are planned.

## Requirements

| | |
|---|---|
| **nmap** | Installed and on your `PATH`. Developed against 7.94. Wardmap tells you if it can't find nmap. |
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
git clone git@github.com:im-srj/wardmap.git
cd wardmap
npm install
npm run tauri dev      # run in development mode
npm run tauri build    # build a release bundle (src-tauri/target/release/bundle/)
```

**Garbled or striped window on Linux?** Some older NVIDIA/Intel GPUs hit a
WebKitGTK rendering bug. Launch with:

```sh
WEBKIT_DISABLE_DMABUF_RENDERER=1 npm run tauri dev
```

## Using Wardmap

1. Enter a target (host, IP, CIDR range or list) that **you own or are
   authorised to scan**.
2. Pick a profile, open *All options* or *Scripts*, or edit the command line
   directly.
3. Press **Run**. Results appear as a sortable table or as the exposure map.
4. Open past scans from the sidebar. Use **Compare** to diff two scans, and
   **Re-run** / **Export** from a saved scan's toolbar.

Some flags are blocked on purpose, and the command line explains why when you
use one:

- **Output flags** (`-oX file`, `-oN`, …). Wardmap manages nmap's output
  itself. Use Export instead.
- **`--resume`, `--stats-every`, `-iL -`, and modes like `-h` / `-V`.** These
  conflict with how Wardmap runs nmap.
- **`-iR` (random internet targets).** Wardmap only scans hosts you typed
  in.

Your data lives in `wardmap.sqlite3` in the app data directory:

| OS | Path |
|---|---|
| Linux | `~/.local/share/io.github.im-srj.wardmap/` |
| macOS | `~/Library/Application Support/io.github.im-srj.wardmap/` |
| Windows | `%APPDATA%\io.github.im-srj.wardmap\` |

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

### Releasing

1. Set the new version in `package.json`, `src-tauri/Cargo.toml` and
   `src-tauri/tauri.conf.json` (all three must match), and merge to `main`.
2. Tag it and push the tag:
   ```sh
   git checkout main && git pull
   git tag v0.1.0 && git push origin v0.1.0
   ```
3. `.github/workflows/release.yml` checks the versions, builds on Linux,
   macOS and Windows, and attaches the installers to a **draft** release.
4. Download and try them, then press **Publish release** on GitHub.

Never bundle nmap or its data files into a package (see [License](#license)).

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
| **M7: packaging** (Homebrew, AppImage/deb, winget) | **In progress**: license and release builds done |

Details and open questions: [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Related projects

Wardmap is one of several front ends for Nmap. If it doesn't fit your needs,
one of these may:

| Project | Type | Notes |
|---|---|---|
| [Zenmap](https://nmap.org/zenmap/) | Desktop (Python 3, GTK) | The official Nmap GUI, shipped with Nmap. |
| [NmapSI4](https://github.com/nmapsi4/nmapsi4) | Desktop (Qt 6) | Long-running Qt front end that aims to cover the full set of Nmap options. Latest version is 0.5 alpha; packaged by Debian and other distros. |
| [Fnmap](https://github.com/gmckesey/fnmap) | Desktop (Flutter) | Flutter front end for Nmap. Available on [Flathub](https://flathub.org/apps/com.krioltech.fnmap) and Snap. |
| [WebMap](https://github.com/SECUREFOREST/WebMap) | Web (Docker) | Dashboard for Nmap XML reports: charts, host notes and labels, PDF reports. |
| [NmapWebUI](https://www.linuxlinks.com/nmapwebui-web-based-interface-nmap-network-scanner/) | Web (Docker) | Self-hosted web UI with user roles, scheduled scans and run history. |

**What Wardmap focuses on:** a live, editable command line that stays in sync
with the option builder (and is checked before it runs); scan-to-scan diffs
that include service-version and TLS-certificate changes; an exposure map
with plain-language service notes; LAN device identification (MAC vendor,
mDNS); and a local SQLite history that stores the raw XML. It is a desktop
app with no server and no scheduled scans.

## Responsible use

Only scan networks and hosts that you own or have explicit permission to test.
Unauthorised scanning may be illegal where you live.

## License

Wardmap is free software, licensed under the
[GNU General Public License, version 2 or (at your option) any later
version](LICENSE) (`GPL-2.0-or-later`).

**Nmap is not part of Wardmap.** Nmap is distributed under the
[Nmap Public Source License](https://nmap.org/npsl/) (NPSL), a GPLv2-based
license with extra terms. Wardmap never bundles or redistributes Nmap or any
of its files: you install nmap yourself, and Wardmap runs that copy as a
separate program and reads its output. It also reads one of your nmap
install's data files (`nmap-mac-prefixes`) to name network-card vendors.

Because the NPSL treats software "designed specifically to execute" Nmap and
parse its results as a derivative work, Wardmap is copyleft (like Nmap), and
the project has asked the Nmap project to confirm this arrangement. If you
package Wardmap, keep it that way: depend on the system's nmap rather than
shipping it.
