# Cartograph roadmap — full nmap coverage (post-M6)

Status as of 2026-10-09: M0–M6 done, plus the UI overhaul, exposure map and
device identification. M7 (packaging) has not started. This document plans the
next stretch: **every nmap option is reachable from the GUI, and a power user
can type or paste any nmap command and run it.**

## Where we are (the constraints this plan has to fix)

| Today | Why it blocks "all of nmap" |
|---|---|
| 3 hard-coded presets (`-F`, default, `-sV`) + NSE picker (`src/presets.ts`) | ~130 nmap options can't be reached at all |
| `run_nmap_raw(target, flags)` takes ONE target string; flags are "app-controlled, not free text" (`scan.rs`) | A custom command has many targets and arbitrary flags, so validation has to move to the backend |
| `Command::output()` blocks until nmap exits | Fine for `-F`. A `-p- -sV -A` scan runs for minutes with no progress and can't be cancelled |
| App runs unprivileged; nmap has no capabilities on the dev box | `-sS -sU -O -A --traceroute`, spoofing and most evasion options fail or quietly fall back to `-sT` |
| Saved scans store `args` as text | Fine, but "re-run / edit this scan" needs the structured argv |

## Design principles (apply to every milestone below)

1. **One option catalogue, and the backend enforces it.** A single
   `shared/nmap-options.json` describes every option: flag(s), value type,
   section, root requirement, which options exclude each other, risk tags and
   help text. The Rust side `include_str!`s it to validate; the frontend
   imports it to render the builder. The UI and the validator can't disagree.
2. **The argv is the source of truth.** Builder, presets, profiles and
   custom-command mode all produce the same `Vec<String>`. The live preview
   shows that argv, so what you see is exactly what runs (this already holds
   for scripts, and we extend it to everything).
3. **Still no shell.** Custom text is tokenized (POSIX-style quoting via the
   `shell-words` crate) and passed to `Command::args`. We never run `sh -c`.
4. **We own output.** We always append `-oX -`. User output flags are
   rejected or turned into an "export after scan" action (see M10).
5. **Non-goals still apply.** `-iR` (random internet targets) is refused
   outright, because those are hosts the user didn't enter. Nothing ever runs
   without the user clicking Run.

---

## M8 — Scan engine: async, progress, cancel  *(foundation; do first)*

A full option set makes long scans normal, so this has to come first.

- Spawn with `tokio::process` / a worker thread instead of `.output()`. A Tauri
  command `start_scan(argv) -> scan_id` returns immediately.
- **Progress:** add `--stats-every 2s`. nmap then writes `<taskbegin>`,
  `<taskprogress percent= remaining= task=>` and `<taskend>` into the XML
  stream. Read stdout incrementally with a **`quick-xml` streaming reader**
  (convention: no string matching) and emit Tauri events
  `scan://progress {id, task, percent, etc}`. Buffer the full bytes for the
  final `roxmltree` parse, unchanged from today.
- **Cancel:** `cancel_scan(id)` kills the child. Keep any partial XML if it
  parses, and mark the scan `cancelled`.
- DB: `scans.status` (`running|completed|cancelled|failed`) + `argv_json`.
  Store stderr warnings (e.g. "QUITTING!", "requires root").
- UI: progress bar + current phase ("SYN Stealth Scan 43%, ~1m left"),
  Cancel button, and a scan keeps running when you switch views.
- **nmap preflight:** on startup, `nmap --version` → version + compiled
  features (or a "nmap not found" onboarding screen with an install link for
  each OS). Packaging (M7) needs this too.
- Tests: feed a recorded `--stats-every` XML stream in chunks and assert the
  progress events. Cancel test uses a fake child (no nmap needed).

## M9 — Full option catalogue + visual builder

- Write `shared/nmap-options.json` by hand from the nmap man page (7.94),
  grouped into nmap's own 11 sections: Target spec · Host discovery · Scan
  techniques · Port spec & order · Service/version · Script scan · OS
  detection · Timing & performance · Firewall/IDS evasion & spoofing · Output
  (mostly reserved, see below) · Misc.
  Each entry: `flags`, `arg` (`none|int|float|time|ports|hostlist|string|enum|file`),
  `root: bool`, `exclusiveGroup` (e.g. one TCP scan type), `implies` (e.g.
  `-A` ⇒ `-sV -O -sC --traceroute`), `risk` (`noisy|intrusive|spoofing`),
  `summary`, `detail`.
- Builder UI, replacing the 3-button preset row (presets stay as one-click
  starting points that fill in the builder):
  - Collapsible sections in nmap's order, with search across all options
    ("what is -Pn"). Typed inputs per value kind: port-range editor,
    T0–T5 slider, time fields with units.
  - Every option explains itself inline. That is the "teaches while doing"
    feature applied to every flag.
  - Conflicts are resolved visibly ("-sT replaced -sS"). Root-only options get
    a badge and are disabled or warned about, depending on M11 status.
  - NSE: keep the browser, and add **`--script-args` editor** (key/values,
    using arg names parsed from NSEDoc `@args`), **category/expression specs**
    (`--script "vuln and not intrusive"`), and `--script-trace`.
- Tests: a catalogue schema test (every flag unique, every exclusive group
  valid), and argv round-trip (builder state → argv → builder state).

## M10 — Custom command mode (type/paste any nmap command)

- An editable command line above the preview. Toggle **Builder ⇄ Command**,
  with two-way sync:
  - Typing/pasting → backend `parse_command(text)` → tokens classified using
    the catalogue into `{options, targets, unknown}` → builder updates.
  - Unknown/new flags (newer nmap than the catalogue) are kept verbatim as
    "raw" chips rather than dropped. Power users are never blocked by an
    outdated catalogue.
  - Paste-friendly: strips a leading `nmap` / `sudo nmap`. `sudo` sets the
    "needs elevation" flag (M11).
- **Policy layer (Rust, `scan_policy.rs`). This is the trust boundary, test
  it hard:**
  - *Reserved* (we own them): `-oN -oX -oS -oG -oA`, `--append-output`,
    `--stylesheet`, `--webxml`, `--no-stylesheet`, `--resume`. Output flags
    become post-scan exports of the same type instead of errors.
  - *Refused:* `-iR` (non-goal), `--interactive`.
  - *File-taking options* (`-iL`, `--excludefile`, `--script-args-file`,
    `--datadir`, `--servicedb`, `--versiondb`, script paths): allowed, chosen
    via a native file picker and shown as full paths in the preview.
  - *Warnings, not blocks:* intrusive/brute/dos/exploit scripts (exists),
    spoofing (`-S -D --spoof-mac -e`), very aggressive timing on non-local
    ranges, and huge target expansions (e.g. a /8).
  - Targets: replace the single `target.starts_with('-')` guard with
    catalogue-aware classification (anything that's not a known option or its
    value is a target). Run `nmap -sL -n` as an optional "preview targets"
    check that lists hosts without sending a packet to them.
- Tests: a table of 50+ real-world commands (from the nmap book/man page) →
  expected classification and policy result. Fuzz the tokenizer with odd
  quoting.

## M11 — Privileged scans

Without this, half the catalogue is greyed out. Elevation is explicit and
per scan, matching the "explicit user action" rule.

- **Detect** at startup: euid; on Linux `getcap` on the nmap binary
  (`cap_net_raw,cap_net_admin+eip` ⇒ run with `--privileged`); on Windows,
  admin + Npcap present.
- **Elevate per scan** (only that nmap process; the app and DB stay
  unprivileged, and XML still comes back on stdout):
  Linux `pkexec nmap …` · macOS
  `osascript … with administrator privileges` · Windows UAC `runas`.
- **Optional one-time Linux setup** (setcap on nmap) offered from a settings
  screen, with an honest note on the tradeoff: any local user can then do raw
  packet scans.
- UI: root-requiring options show "will ask for your password". The preview
  shows `sudo nmap …` when elevation applies, so it stays copy-pasteable.

## M12 — Profiles, re-run, import/export  *(Zenmap parity and beyond)*

- **Profiles:** save/name/edit builder states (SQLite `profiles` table).
  Built-ins: Quick, Regular, Intense (`-T4 -A`), Ping sweep (`-sn`),
  UDP top-100, Full TCP (`-p-`), Vuln scripts. Import Zenmap's
  `scan_profile.usp` (INI) for migrating users.
- **Re-run / edit from history:** load a saved scan's argv into the builder.
  It only runs when the user presses Run (explicit action, per the non-goals),
  and the new result diffs against the old one automatically (ties to M4).
- **Import** existing nmap XML files (from CLI runs / other machines) into
  history. The parser already handles them.
- **Export:** raw XML, normal/grepable text (our own formatter over the
  saved XML, so no re-scan), JSON, CSV, a standalone HTML report, and
  "copy command".
- Multiple concurrent scans + a small run queue (each is explicit user action).

## M7 — Packaging  *(moved after M8–M11)*

Unchanged scope (Homebrew, AppImage/deb, winget, real icon). It needs M8's
nmap preflight and M11's elevation story per OS, which is why it moves after
them. Also decide `WEBKIT_DISABLE_DMABUF_RENDERER` for the Linux package.

## Housekeeping (do alongside, small commits)

- ESLint + Prettier are still not configured (CI runs only `tsc --noEmit`).
  Add them before the catalogue/builder code lands, since it's large.
- Several GUI checks are still marked pending in the Progress Log (M5 rework,
  device ID, themes). Clear them before starting M8.

## Order and rough size

| # | Milestone | Size | Depends on |
|---|---|---|---|
| 0 | Housekeeping (lint, pending GUI checks) | S | — |
| 8 | Async engine, progress, cancel, nmap preflight | M | — |
| 9 | Option catalogue + builder | L | 8 |
| 10 | Custom command + policy layer | M | 9 (catalogue) |
| 11 | Privileged scans | M | 9 (root flags known) |
| 12 | Profiles, re-run, import/export | M | 9, 10 |
| 7 | Packaging | M | 8, 11 |

## Open questions for the user

1. Elevation: is per-scan password prompting acceptable, or do you want the
   one-time `setcap` path as the default on Linux?
2. Should the catalogue track a specific nmap version (7.94 / 7.95), and how
   should we handle a user with an older nmap that lacks some flags (hide
   vs. warn)?
3. Anything from the earlier ChatGPT conversation that should change this
   order? Paste it (the share link is login-only) and I'll merge it in.
