# Wardmap roadmap — full nmap coverage (post-M6)

Status as of 2026-10-09: M0–M6 and M8–M12 done (M11 Linux-only), plus the UI overhaul, exposure map and
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

## M8 — Scan engine: async, progress, cancel  *(DONE 2026-10-09)*

What shipped, and where it differs from the original plan:

- `run_nmap_scan` is now an **async command + `spawn_blocking`**,
  streaming progress over a Tauri v2 `Channel` (not global events) and
  resolving with the result. `cancel_scan(run_id)` kills the child. Running
  nmaps are killed on app exit.
- **Finding: nmap only emits progress when it has a controlling terminal.**
  With a piped stdin, `--stats-every` silently produces nothing (verified
  on 7.94, both XML `<taskprogress>` and normal-output "Stats:" lines). So
  on Unix nmap gets a **pseudo-terminal** as stdin and controlling tty
  (`openpty` + `setsid` + `TIOCSCTTY`, `runner.rs`). Stdout stays our XML
  pipe, so the XML is unchanged apart from the progress elements. If the pty
  fails, the scan runs without progress. **Windows is unverified**, and may
  need ConPTY or may get no progress; check this in M7.
- Progress is read with a `quick-xml` streaming reader over a tee of stdout.
  The full bytes still go through the `roxmltree` parser.
- **Dropped (YAGNI for now):** saving partial XML of a cancelled scan (a
  killed nmap leaves unclosed XML, so it would need a repair pass), the
  `scans.status` column (only completed scans are stored), and `argv_json`
  (moves to M10/M12, where re-run needs it).
- nmap preflight: `nmap_version` on startup → version in the sidebar, or an
  install-instructions card.
- **Reserved for M10's policy layer:** `--stats-every` (we set it), alongside
  the output flags.

## M9 + M10 — All options + custom command  *(DONE 2026-10-09; built together)*

They shared one core, so they landed together. Where it differs from the
original plan:

- **The backend parses commands exactly like nmap.** `src-tauri/src/cmdline.rs`
  mirrors nmap's `getopt_long_only`, using its `long_options[]` table (101
  entries) and its short-option string, both transcribed from nmap.cc. That
  covers abbreviations (`--stats` = `--stats-every`), single-dash long options
  (`-top 10`), clusters (`-sSV`, `-nF`), attached values (`-p80`, and
  `-oXfoo` = `-o Xfoo`), and required values taken from the next token even
  when it starts with `-` (`--script-args -oX`). The tricky cases were
  checked against real nmap 7.94. Name-matching would have missed reserved
  options hidden behind abbreviations or old aliases (`-o`, `-m`, `-i`).
- **Two data sources instead of one shared JSON.** The parser's tables live in
  Rust; the UI catalogue is `src/nmap-options.json` (100+ options in nmap's
  section order, with summary, root, risk and exclusive group for each).
  The Rust test `ui_catalogue_matches_the_parser` checks that every catalogue
  entry parses back to exactly the tokens the UI builds, so they can't drift.
- **Trust boundary:** `run_nmap_scan` now takes the command text and
  re-analyzes it. `runner::run` only accepts an `Analysis` and refuses a
  blocked one. Blocked: output options in every spelling (we own `-oX -`),
  `--stats-every`, `--resume`, `-iR` (non-goal), `-iL -` (stdin is the pty),
  non-scan modes (`-h -V --iflist --script-help --script-updatedb`),
  ambiguous abbreviations, missing values, unknown letters inside a cluster,
  typographic dashes, targets starting with `-`, and no target at all.
  Unknown long options only warn, so a newer nmap's flags still run.
  A leading `sudo` is stripped with a warning (M11).
- UI: the options state is one list of canonical items, edited by presets,
  the script browser, the **All options** panel (search, sections,
  root/risk badges, exclusive groups, chips for anything set, including
  uncatalogued options) and the **editable command line** (type or paste
  any nmap command; issues show underneath; Run is enabled only once the
  backend has cleared the current command).
- **Not done (follow-ups):** native file pickers (paths are typed), a
  `--script-args` editor driven by NSEDoc `@args`, turning output flags into
  post-scan exports (they're blocked with an explanation for now), a
  `-sL -n` "preview targets" check, warnings for huge target ranges or
  aggressive timing, and a dedicated port-range editor or timing slider.

## M11 — Privileged scans  *(Linux DONE 2026-10-09; macOS/Windows pending)*

Decision (user, 2026-10-09): **ask for the password every scan**. No
standing `setcap` on nmap, so other local users don't get raw-socket scans.

- `sudo` at the start of the command means "run as root". The **Run as root**
  checkbox adds or removes it; it ticks itself when any root-only option is
  set, and an explicit choice (checkbox, or typing/removing `sudo`) overrides
  that. The preview therefore stays an exact, copy-pasteable command.
- Linux: `pkexec --disable-internal-agent /usr/bin/nmap …` shows the
  desktop's polkit password dialog. Using `--disable-internal-agent` matters:
  otherwise, with no GUI agent, pkexec would prompt on nmap's pty, where
  nobody can answer. Exit 126 (dialog dismissed) → "authentication
  cancelled"; 127 → "couldn't run nmap as root". Already root → no pkexec.
- **Cancel for a root nmap:** our unprivileged `kill` can't signal it, so
  Cancel first writes Ctrl-C to nmap's pty and the kernel delivers SIGINT
  regardless of owner. Verified live: ^C alone stops nmap; nmap's
  non-canonical tty mode keeps ISIG. `kill` remains the fallback.
- **macOS/Windows: not implemented, and blocked with a clear message.**
  macOS needs `osascript … with administrator privileges` (it goes through
  `sh`, so needs careful quoting, returns output only at the end, and has
  no pty). Windows needs UAC `runas`, which gives no stdout pipe, so the XML
  would go to a temp file. Both need a real Mac/Windows box to verify, so
  they're folded into M7.

## M12 — Profiles, re-run, import/export  *(DONE 2026-10-09)*

What shipped, and where it differs from the original plan:

- **Profiles.** Eight built-ins in `src/presets.ts` (Quick, Regular,
  Service+version, Intense `-T4 -A`, Ping sweep `-sn`, UDP top 100, Full TCP
  `-p-`, Vuln scripts `-sV --script vuln`) plus the user's own, stored in a
  SQLite `profiles` table as option text. **Behaviour change:** picking a
  profile now *replaces* the whole option set (the target stays). Before,
  presets only swapped their own flags. Saved profiles hold full builder
  states, so replacing is the only predictable rule. Profiles never store
  targets (`cmdline::options_only`). "Update" overwrites the profile you
  loaded; delete needs a second click. **Zenmap import** reads
  `scan_profile.usp` (`profiles.rs`, ConfigParser-style INI, continuation
  lines). Names that already exist are skipped, never overwritten.
- **Re-run from history.** Every saved scan has a `command`: the exact text
  the user ran (new `scans.command` column, added in place on old
  databases). For imported or older scans it is rebuilt from nmap's recorded
  args, without output and progress flags (`cmdline::command_from_args`).
  Re-run loads it into the form and runs only when the user presses Run.
  The result then shows a "changed since…" banner with a link to the diff.
- **Import nmap XML** (sidebar ↑ button): native multi-file picker. Each
  file is parsed, dated by nmap's own start time, and skipped if the
  identical XML is already in history.
- **Export** (saved-scan toolbar): nmap XML (verbatim), JSON, CSV,
  normal (`-oN`-like), grepable (`-oG`-like), and a standalone HTML report
  (inline CSS, no external resources, everything escaped). Also "Copy
  command". `export.rs` renders from the stored XML. The text formats were
  checked against real nmap output; they lack what the XML doesn't carry
  (latency, "Not shown: N closed", nmap's `?` on guessed service names).
- **File dialogs are opened by the backend** (`tauri-plugin-dialog`'s Rust
  API), so the webview never names a path to read or write, and no
  JS-side capability is granted.
- **Concurrent scans + queue:** up to 2 run at once, the rest queue (sidebar
  rows; a queued run can be removed). Running an identical command again
  shows the one already in flight. A background scan that fails reports
  through a dismissable notice. `run_nmap_scan` now returns
  `{ scanId, result }`, so history ids no longer have to be guessed.
- **Not done (follow-ups):** editing a profile's name or description in place
  (for now: save as new, then delete the old one), auto-diffing against the
  previous scan of the same target when it wasn't a re-run, and "export
  after scan" for `-oX file` typed into the command (still blocked).

## M7 — Packaging  *(moved after M8–M11)*

Unchanged scope (Homebrew, AppImage/deb, winget). It needs M8's
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
