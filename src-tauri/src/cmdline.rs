//! Understanding an nmap command line: split text into argv, classify every
//! token exactly the way nmap's own `getopt_long_only` would, and check the
//! result against Wardmap's policy before anything runs.
//!
//! Why mirror getopt instead of matching flag names: nmap accepts unique
//! abbreviations of long options (`--stats` = `--stats-every`), single-dash
//! long options (`-top 10`), clustered short flags (`-sSV`, `-nF`), attached
//! values (`-p80`, `-oXfile` = `-o Xfile` = normal output to "Xfile"), and a
//! required value is taken from the next token even if it starts with `-`
//! (`--script-args -oX` passes "-oX" as the script args). A name-matching
//! check would both miss reserved options and misread targets. The tables
//! below are transcribed from nmap.cc (`long_options[]` and the
//! `getopt_long_only` optstring, nmap 7.94/master).
//!
//! This module is the trust boundary for custom commands: the frontend may
//! display its own view, but `run_nmap_scan` re-analyzes the command here and
//! refuses to run anything with a `Block` issue.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq)]
enum Arg {
    No,
    Required,
    Optional,
}

/// nmap's short-option string, verbatim. `x:` = required value, `x::` =
/// optional value (only ever attached, e.g. `-T4`, `-PS22`).
const SHORT_OPTS: &str = "46Ab:D:d::e:Ffg:hIi:M:m:nO::o:P::p:qRrS:s::T:Vv::";

/// nmap's `long_options[]`, verbatim (the unnamed easter-egg entry decodes to
/// "yoloscan").
const LONG_OPTS: &[(&str, Arg)] = &[
    ("version", Arg::No),
    ("verbose", Arg::No),
    ("datadir", Arg::Required),
    ("servicedb", Arg::Required),
    ("versiondb", Arg::Required),
    ("debug", Arg::Optional),
    ("help", Arg::No),
    ("iflist", Arg::No),
    ("release-memory", Arg::No),
    ("nogcc", Arg::No),
    ("max-os-tries", Arg::Required),
    ("max-parallelism", Arg::Required),
    ("min-parallelism", Arg::Required),
    ("timing", Arg::Required),
    ("max-rtt-timeout", Arg::Required),
    ("min-rtt-timeout", Arg::Required),
    ("initial-rtt-timeout", Arg::Required),
    ("excludefile", Arg::Required),
    ("exclude", Arg::Required),
    ("max-hostgroup", Arg::Required),
    ("min-hostgroup", Arg::Required),
    ("open", Arg::No),
    ("scanflags", Arg::Required),
    ("defeat-rst-ratelimit", Arg::No),
    ("defeat-icmp-ratelimit", Arg::No),
    ("host-timeout", Arg::Required),
    ("scan-delay", Arg::Required),
    ("max-scan-delay", Arg::Required),
    ("max-retries", Arg::Required),
    ("oA", Arg::Required),
    ("oN", Arg::Required),
    ("oM", Arg::Required),
    ("oG", Arg::Required),
    ("oS", Arg::Required),
    ("oH", Arg::Required),
    ("oX", Arg::Required),
    ("iL", Arg::Required),
    ("iR", Arg::Required),
    ("sI", Arg::Required),
    ("source-port", Arg::Required),
    ("randomize-hosts", Arg::No),
    ("nsock-engine", Arg::Required),
    ("proxies", Arg::Required),
    ("proxy", Arg::Required),
    ("discovery-ignore-rst", Arg::No),
    ("osscan-limit", Arg::No),
    ("osscan-guess", Arg::No),
    ("fuzzy", Arg::No),
    ("packet-trace", Arg::No),
    ("version-trace", Arg::No),
    ("data", Arg::Required),
    ("data-string", Arg::Required),
    ("data-length", Arg::Required),
    ("send-eth", Arg::No),
    ("send-ip", Arg::No),
    ("stylesheet", Arg::Required),
    ("no-stylesheet", Arg::No),
    ("webxml", Arg::No),
    ("rH", Arg::No),
    ("vv", Arg::No),
    ("ff", Arg::No),
    ("privileged", Arg::No),
    ("unprivileged", Arg::No),
    ("mtu", Arg::Required),
    ("append-output", Arg::No),
    ("noninteractive", Arg::No),
    ("spoof-mac", Arg::Required),
    ("thc", Arg::No),
    ("badsum", Arg::No),
    ("ttl", Arg::Required),
    ("traceroute", Arg::No),
    ("reason", Arg::No),
    ("allports", Arg::No),
    ("version-intensity", Arg::Required),
    ("version-light", Arg::No),
    ("version-all", Arg::No),
    ("system-dns", Arg::No),
    ("resolve-all", Arg::No),
    ("unique", Arg::No),
    ("log-errors", Arg::No),
    ("deprecated-xml-osclass", Arg::No),
    ("yoloscan", Arg::No),
    ("dns-servers", Arg::Required),
    ("port-ratio", Arg::Required),
    ("exclude-ports", Arg::Required),
    ("top-ports", Arg::Required),
    ("script", Arg::Required),
    ("script-trace", Arg::No),
    ("script-updatedb", Arg::No),
    ("script-args", Arg::Required),
    ("script-args-file", Arg::Required),
    ("script-help", Arg::Required),
    ("script-timeout", Arg::Required),
    ("ip-options", Arg::Required),
    ("min-rate", Arg::Required),
    ("max-rate", Arg::Required),
    ("adler32", Arg::No),
    ("stats-every", Arg::Required),
    ("disable-arp-ping", Arg::No),
    ("route-dst", Arg::Required),
    ("resume", Arg::Required),
];

/// Letters nmap accepts after `-s` (see the `case 's'` loop in nmap.cc).
const SCAN_TYPES: &str = "PnACFLMNORSTUVWXYZ";

fn short_arg(c: char) -> Option<Arg> {
    if c == ':' {
        return None;
    }
    let i = SHORT_OPTS.find(c)?;
    let rest = &SHORT_OPTS[i + c.len_utf8()..];
    Some(if rest.starts_with("::") {
        Arg::Optional
    } else if rest.starts_with(':') {
        Arg::Required
    } else {
        Arg::No
    })
}

enum LongMatch {
    Found(&'static str, Arg),
    Ambiguous(Vec<&'static str>),
    None,
}

/// getopt's long-option lookup: an exact name wins; otherwise a unique
/// prefix. In `long_only` mode (nmap's), any two prefix matches are
/// ambiguous.
fn lookup_long(name: &str) -> LongMatch {
    if let Some(&(n, a)) = LONG_OPTS.iter().find(|(n, _)| *n == name) {
        return LongMatch::Found(n, a);
    }
    let hits: Vec<_> = LONG_OPTS
        .iter()
        .filter(|(n, _)| n.starts_with(name))
        .collect();
    match hits.as_slice() {
        [] => LongMatch::None,
        [(n, a)] => LongMatch::Found(n, *a),
        many => LongMatch::Ambiguous(many.iter().map(|(n, _)| *n).collect()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// An option nmap knows.
    Option,
    /// A target (host, range, CIDR…).
    Target,
    /// Looks like an option, but isn't in nmap 7.94's tables.
    Unknown,
}

/// One logical piece of the command. `tokens` is its canonical argv form;
/// concatenating every item's tokens gives an argv nmap reads identically
/// to the original (clusters split, abbreviations expanded, aliases mapped).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    pub kind: Kind,
    /// Canonical spelling: `-sS`, `-p`, `-T`, `-PS`, `-oX`, `--min-rate`, or
    /// the target / unknown token itself.
    pub name: String,
    pub value: Option<String>,
    pub tokens: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Wardmap won't run this command.
    Block,
    /// Runs, but the user should know something.
    Warn,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Issue {
    pub level: Level,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Analysis {
    /// The text started with `sudo` (stripped; we can't elevate yet).
    pub sudo: bool,
    pub items: Vec<Item>,
    pub issues: Vec<Issue>,
}

impl Analysis {
    pub fn blocked(&self) -> bool {
        self.issues.iter().any(|i| i.level == Level::Block)
    }

    /// The canonical argv to hand to nmap (without our own capture flags).
    pub fn argv(&self) -> Vec<String> {
        self.items.iter().flat_map(|i| i.tokens.clone()).collect()
    }

    pub fn targets(&self) -> impl Iterator<Item = &str> {
        self.items
            .iter()
            .filter(|i| i.kind == Kind::Target)
            .map(|i| i.name.as_str())
    }

    /// How the scan is labelled in history: its targets, or the list file
    /// for an `-iL` scan; empty when there are neither.
    pub fn target_label(&self) -> String {
        let targets: Vec<&str> = self.targets().collect();
        if !targets.is_empty() {
            return targets.join(" ");
        }
        self.items
            .iter()
            .find(|i| i.name == "-iL")
            .and_then(|i| i.value.as_deref())
            .map(|f| format!("-iL {f}"))
            .unwrap_or_default()
    }

    /// Human-readable reasons the command can't run, one per line.
    pub fn block_reasons(&self) -> String {
        self.issues
            .iter()
            .filter(|i| i.level == Level::Block)
            .map(|i| i.message.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn issue(&mut self, level: Level, message: impl Into<String>) {
        self.issues.push(Issue {
            level,
            message: message.into(),
        });
    }
}

/// Analyze command text as a user would type or paste it. POSIX shell
/// quoting is honoured; a leading `sudo` and/or `nmap` is stripped.
pub fn analyze_text(text: &str) -> Analysis {
    let mut argv = match shell_words::split(text) {
        Ok(v) => v,
        Err(_) => {
            let mut a = Analysis {
                sudo: false,
                items: vec![],
                issues: vec![],
            };
            a.issue(Level::Block, "Unbalanced quotes in the command.");
            return a;
        }
    };
    let sudo = argv.first().is_some_and(|t| t == "sudo");
    if sudo {
        argv.remove(0);
    }
    if argv.first().is_some_and(|t| is_nmap_binary(t)) {
        argv.remove(0);
    }
    let mut a = analyze_argv(&argv);
    if sudo {
        a.sudo = true;
        if cfg!(target_os = "linux") {
            a.issue(
                Level::Warn,
                "Runs as root: you'll be asked for your password when the scan starts.",
            );
        } else {
            a.issue(
                Level::Block,
                "Running as root from Wardmap only works on Linux so far. \
                 Remove sudo, or run this command in a terminal.",
            );
        }
    }
    a
}

/// Options Wardmap adds to every run (or that only redirect output), so a
/// recorded command line drops them before it can be run again.
const CAPTURE_OPTIONS: &[&str] = &[
    "-oA",
    "-oN",
    "-oM",
    "-oG",
    "-oS",
    "-oH",
    "-oX",
    "--stats-every",
];

/// The command to run a scan again, from the command line nmap recorded for
/// it (`<nmaprun args="…">`): the binary path becomes `nmap`, and output and
/// progress options (ours, or the CLI user's `-oX file`) are dropped. nmap
/// records args unquoted, so a value with spaces may not round-trip; the
/// result is analyzed again before it can run, like anything typed.
pub fn command_from_args(args: &str) -> String {
    let mut argv = shell_words::split(args)
        .unwrap_or_else(|_| args.split_whitespace().map(String::from).collect());
    if argv.first().is_some_and(|t| is_nmap_binary(t)) {
        argv.remove(0);
    }
    let kept: Vec<String> = analyze_argv(&argv)
        .items
        .into_iter()
        .filter(|i| !(i.kind == Kind::Option && CAPTURE_OPTIONS.contains(&i.name.as_str())))
        .flat_map(|i| i.tokens)
        .collect();
    if kept.is_empty() {
        "nmap".into()
    } else {
        format!("nmap {}", shell_words::join(kept))
    }
}

/// Just the options of a command (no `sudo`, `nmap` or targets), quoted —
/// what a scan profile stores. Targets are dropped on purpose: a profile says
/// *how* to scan, and the user enters *what* each time.
pub fn options_only(command: &str) -> String {
    let a = analyze_text(command);
    shell_words::join(
        a.items
            .into_iter()
            .filter(|i| i.kind != Kind::Target)
            .flat_map(|i| i.tokens),
    )
}

fn is_nmap_binary(t: &str) -> bool {
    let base = t.rsplit(['/', '\\']).next().unwrap_or(t);
    base == "nmap" || base.eq_ignore_ascii_case("nmap.exe")
}

/// Classify an argv (no leading `nmap`) the way nmap would, then apply policy.
pub fn analyze_argv(argv: &[String]) -> Analysis {
    let mut a = Analysis {
        sudo: false,
        items: vec![],
        issues: vec![],
    };
    let mut i = 0;
    let mut only_targets = false;

    while i < argv.len() {
        let tok = &argv[i];
        i += 1;

        if starts_with_fancy_dash(tok) {
            a.issue(
                Level::Block,
                format!(
                    "{tok:?} starts with a typographic dash (often from copy-paste); \
                     use a plain '-'."
                ),
            );
            a.items.push(unknown(tok));
            continue;
        }
        if only_targets || !tok.starts_with('-') || tok == "-" {
            a.items.push(target(tok));
            continue;
        }
        if tok == "--" {
            only_targets = true;
            continue;
        }

        let double = tok.starts_with("--");
        let body = &tok[if double { 2 } else { 1 }..];
        let first = body.chars().next().unwrap_or('-');

        // getopt_long_only tries a long match first unless the token is a
        // lone known short letter like `-p`.
        if double || body.chars().count() > 1 || short_arg(first).is_none() {
            let (name, eq_val) = match body.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (body, None),
            };
            match lookup_long(name) {
                LongMatch::Found(name, arg) => {
                    let value = match (arg, eq_val) {
                        (Arg::No, Some(_)) => {
                            a.issue(Level::Block, format!("--{name} doesn't take a value."));
                            None
                        }
                        (Arg::No, None) => None,
                        (Arg::Optional, v) => v,
                        (Arg::Required, Some(v)) => Some(v),
                        (Arg::Required, None) => take_next(argv, &mut i),
                    };
                    if arg == Arg::Required && value.is_none() {
                        a.issue(
                            Level::Block,
                            format!("{} needs a value.", long_display(name)),
                        );
                    }
                    a.items.push(long_item(name, arg, value));
                    continue;
                }
                LongMatch::Ambiguous(cands) => {
                    let list: Vec<_> = cands.iter().map(|c| long_display(c)).collect();
                    a.issue(
                        Level::Block,
                        format!("{tok} is ambiguous: it could be {}.", list.join(", ")),
                    );
                    a.items.push(unknown(tok));
                    continue;
                }
                LongMatch::None if double || short_arg(first).is_none() => {
                    a.issue(
                        Level::Warn,
                        format!("{tok} isn't an option in nmap 7.94; nmap may reject it."),
                    );
                    a.items.push(unknown(tok));
                    continue;
                }
                LongMatch::None => {} // fall through: a cluster of short options
            }
        }

        let chars: Vec<char> = body.chars().collect();
        let mut j = 0;
        while j < chars.len() {
            let c = chars[j];
            j += 1;
            let rest: String = chars[j..].iter().collect();
            match short_arg(c) {
                None => {
                    a.issue(Level::Block, format!("-{c} isn't an nmap option."));
                    a.items.push(unknown(&format!("-{c}")));
                }
                Some(Arg::No) => a.items.push(short_item(&mut a.issues, c, None)),
                Some(Arg::Optional) => {
                    j = chars.len();
                    let v = (!rest.is_empty()).then_some(rest);
                    for item in expand_short(&mut a.issues, c, v) {
                        a.items.push(item);
                    }
                }
                Some(Arg::Required) => {
                    j = chars.len();
                    let v = if rest.is_empty() {
                        take_next(argv, &mut i)
                    } else {
                        Some(rest)
                    };
                    if v.is_none() {
                        a.issue(Level::Block, format!("-{c} needs a value."));
                    }
                    a.items.push(short_item(&mut a.issues, c, v));
                }
            }
        }
    }

    apply_policy(&mut a);
    a
}

fn take_next(argv: &[String], i: &mut usize) -> Option<String> {
    let v = argv.get(*i).cloned();
    if v.is_some() {
        *i += 1;
    }
    v
}

fn starts_with_fancy_dash(tok: &str) -> bool {
    // nmap itself refuses U+2010..U+2015 (hyphen, en/em dash, …).
    tok.chars()
        .next()
        .is_some_and(|c| ('\u{2010}'..='\u{2015}').contains(&c))
}

fn target(tok: &str) -> Item {
    Item {
        kind: Kind::Target,
        name: tok.to_string(),
        value: None,
        tokens: vec![tok.to_string()],
    }
}

fn unknown(tok: &str) -> Item {
    Item {
        kind: Kind::Unknown,
        name: tok.to_string(),
        value: None,
        tokens: vec![tok.to_string()],
    }
}

/// nmap's convention: two-letter long options (-oX, -iL, -sI) take one dash.
fn long_display(name: &str) -> String {
    if name.len() <= 2 {
        format!("-{name}")
    } else {
        format!("--{name}")
    }
}

/// Long options that are just another spelling of a short one.
fn long_alias(name: &str) -> Option<char> {
    Some(match name {
        "version" => 'V',
        "verbose" => 'v',
        "debug" => 'd',
        "help" => 'h',
        "timing" => 'T',
        "max-parallelism" => 'M',
        "source-port" => 'g',
        _ => return None,
    })
}

fn long_item(name: &str, arg: Arg, value: Option<String>) -> Item {
    if let Some(c) = long_alias(name) {
        return short_item(&mut vec![], c, value);
    }
    let name = match name {
        "fuzzy" => "osscan-guess",
        n => n,
    };
    let display = long_display(name);
    let tokens = match (&value, arg) {
        (Some(v), Arg::Optional) => vec![format!("{display}={v}")],
        (Some(v), _) => vec![display.clone(), v.clone()],
        (None, _) => vec![display.clone()],
    };
    Item {
        kind: Kind::Option,
        name: display,
        value,
        tokens,
    }
}

/// Short options whose (optional) value is always written attached.
fn expand_short(issues: &mut Vec<Issue>, c: char, value: Option<String>) -> Vec<Item> {
    match c {
        's' => {
            let Some(types) = value else {
                issues.push(Issue {
                    level: Level::Block,
                    message: "-s needs a scan type, e.g. -sT, -sS, -sU, -sn.".into(),
                });
                return vec![unknown("-s")];
            };
            types
                .chars()
                .map(|t| {
                    if !SCAN_TYPES.contains(t) {
                        issues.push(Issue {
                            level: Level::Block,
                            message: format!("-s{t} isn't an nmap scan type."),
                        });
                        return unknown(&format!("-s{t}"));
                    }
                    // Deprecated spellings nmap maps itself.
                    let t = match t {
                        'P' => 'n',
                        'R' => 'V',
                        t => t,
                    };
                    let name = format!("-s{t}");
                    Item {
                        kind: Kind::Option,
                        tokens: vec![name.clone()],
                        name,
                        value: None,
                    }
                })
                .collect()
        }
        'P' => {
            // Bare -P is nmap's old spelling of -PE.
            let v = value.unwrap_or_else(|| "E".into());
            let mut chars = v.chars();
            let kind = chars.next().expect("non-empty");
            let rest: String = chars.collect();
            vec![Item {
                kind: Kind::Option,
                name: format!("-P{kind}"),
                value: (!rest.is_empty()).then_some(rest),
                tokens: vec![format!("-P{v}")],
            }]
        }
        _ => vec![short_item(issues, c, value)],
    }
}

fn short_item(issues: &mut Vec<Issue>, c: char, value: Option<String>) -> Item {
    match c {
        's' | 'P' => return expand_short(issues, c, value).remove(0),
        // Deprecated single-letter aliases: -i = -iL, -o = -oN, -m = -oG.
        'i' => return long_item("iL", Arg::Required, value),
        'o' => return long_item("oN", Arg::Required, value),
        'm' => return long_item("oG", Arg::Required, value),
        _ => {}
    }
    let name = format!("-{c}");
    let value = match (c, value) {
        ('T', Some(v)) => Some(timing_level(&v).unwrap_or(v)),
        (_, v) => v,
    };
    let tokens = match (short_arg(c), &value) {
        // Optional values only exist attached (-T4, -d2, -v3, -O2).
        (Some(Arg::Optional), Some(v)) => vec![format!("{name}{v}")],
        (_, Some(v)) if c == 'T' || v.starts_with('-') => vec![format!("{name}{v}")],
        (_, Some(v)) => vec![name.clone(), v.clone()],
        (_, None) => vec![name.clone()],
    };
    Item {
        kind: Kind::Option,
        name,
        value,
        tokens,
    }
}

/// -T also accepts template names; normalise them to the digit.
fn timing_level(v: &str) -> Option<String> {
    let names = [
        "paranoid",
        "sneaky",
        "polite",
        "normal",
        "aggressive",
        "insane",
    ];
    names
        .iter()
        .position(|n| n.eq_ignore_ascii_case(v))
        .map(|i| i.to_string())
}

/// Wardmap's own rules, on top of "does nmap understand it".
fn apply_policy(a: &mut Analysis) {
    let mut has_input_list = false;
    let mut issues = Vec::new();
    for item in &a.items {
        let mut block = |m: String| {
            issues.push(Issue {
                level: Level::Block,
                message: m,
            })
        };
        match (item.kind, item.name.as_str(), item.value.as_deref()) {
            (Kind::Option, "-oA" | "-oN" | "-oM" | "-oG" | "-oS" | "-oH" | "-oX", _) => {
                block(format!(
                    "{} writes an output file. Wardmap captures nmap's XML itself; \
                     export results after the scan instead.",
                    item.name
                ))
            }
            (Kind::Option, "--stats-every", _) => {
                block("--stats-every is set by Wardmap (it drives the progress bar).".into())
            }
            (Kind::Option, "--resume", _) => block(
                "--resume continues a scan from an nmap log file; run it in a terminal.".into(),
            ),
            (Kind::Option, "-iR", _) => block(
                "-iR scans random internet hosts. Wardmap only scans targets you \
                 enter explicitly."
                    .into(),
            ),
            (Kind::Option, "-iL", Some("-")) => {
                block("-iL - reads targets from stdin, which Wardmap doesn't provide.".into())
            }
            (Kind::Option, "-iL", _) => has_input_list = true,
            (Kind::Option, "-h" | "-V" | "--iflist" | "--script-help" | "--script-updatedb", _) => {
                block(format!(
                    "{} doesn't run a scan; run it in a terminal instead.",
                    item.name
                ))
            }
            (Kind::Option, "--noninteractive", _) => issues.push(Issue {
                level: Level::Warn,
                message: "--noninteractive stops nmap reporting progress.".into(),
            }),
            (Kind::Target, t, _) if t.starts_with('-') => block(format!(
                "Target {t:?} starts with '-', which nmap would read as an option."
            )),
            _ => {}
        }
    }
    a.issues.extend(issues);
    if !has_input_list && a.targets().next().is_none() {
        a.issue(Level::Block, "Add at least one target.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn an(text: &str) -> Analysis {
        analyze_text(text)
    }

    /// (name, value) of every option item, for compact assertions.
    fn opts(a: &Analysis) -> Vec<(String, Option<String>)> {
        a.items
            .iter()
            .filter(|i| i.kind != Kind::Target)
            .map(|i| (i.name.clone(), i.value.clone()))
            .collect()
    }

    fn o(name: &str, value: Option<&str>) -> (String, Option<String>) {
        (name.to_string(), value.map(str::to_string))
    }

    fn targets(a: &Analysis) -> Vec<&str> {
        a.targets().collect()
    }

    fn blocked_with(a: &Analysis, needle: &str) -> bool {
        a.issues
            .iter()
            .any(|i| i.level == Level::Block && i.message.contains(needle))
    }

    #[test]
    fn typical_command() {
        let a = an("nmap -sS -sV -p 22,80 -T4 scanme.nmap.org");
        assert_eq!(
            opts(&a),
            vec![
                o("-sS", None),
                o("-sV", None),
                o("-p", Some("22,80")),
                o("-T", Some("4"))
            ]
        );
        assert_eq!(targets(&a), vec!["scanme.nmap.org"]);
        assert!(!a.blocked());
        assert!(a.issues.is_empty());
    }

    #[test]
    fn clusters_and_attached_values() {
        let a = an("-sSVU -nF -Pn -PS22,80 -p80 -p- -T aggressive -v3 -d -O host");
        assert_eq!(
            opts(&a),
            vec![
                o("-sS", None),
                o("-sV", None),
                o("-sU", None),
                o("-n", None),
                o("-F", None),
                o("-Pn", None),
                o("-PS", Some("22,80")),
                o("-p", Some("80")),
                o("-p", Some("-")),
                o("-T", Some("4")),
                o("-v", Some("3")),
                o("-d", None),
                o("-O", None),
            ]
        );
        assert_eq!(targets(&a), vec!["host"]);
    }

    #[test]
    fn targets_anywhere_and_after_double_dash() {
        let a = an("10.0.0.1 -F 10.0.0.0/24 scanme.nmap.org");
        assert_eq!(
            targets(&a),
            vec!["10.0.0.1", "10.0.0.0/24", "scanme.nmap.org"]
        );
        // After `--` everything is a target, and a dash-target is refused.
        assert!(blocked_with(&an("-F -- -oX"), "starts with '-'"));
    }

    #[test]
    fn required_value_takes_next_token_even_if_it_looks_like_a_flag() {
        // Exactly what nmap does: "-oX" is the script-args value, not an option.
        let a = an("--script-args -oX host");
        assert_eq!(opts(&a), vec![o("--script-args", Some("-oX"))]);
        assert_eq!(targets(&a), vec!["host"]);
        assert!(!a.blocked());
    }

    #[test]
    fn output_options_are_blocked_in_every_spelling() {
        for cmd in [
            "-oX out.xml h",
            "-oX=out.xml h",
            "--oX out.xml h",
            "-oN out h",
            "-oG out h",
            "-oA base h",
            "-oS out h",
            "-oXfoo h", // = -o Xfoo = normal output to file "Xfoo"
            "-o out h", // deprecated alias of -oN
            "-m out h", // deprecated alias of -oG
            "-nFo out h",
        ] {
            assert!(blocked_with(&an(cmd), "output file"), "{cmd}");
        }
    }

    #[test]
    fn abbreviations_resolve_like_getopt() {
        let a = an("-top 10 --min-ra=100 host");
        assert_eq!(
            opts(&a),
            vec![o("--top-ports", Some("10")), o("--min-rate", Some("100"))]
        );
        // A reserved option can't hide behind an abbreviation.
        assert!(blocked_with(&an("--stats 5s h"), "--stats-every"));
        assert!(blocked_with(&an("-stats-e 5s h"), "--stats-every"));
        assert!(blocked_with(&an("--resu x h"), "--resume"));
        assert!(blocked_with(&an("--max-r 5 h"), "ambiguous"));
        assert!(blocked_with(&an("--res x h"), "ambiguous"));
    }

    #[test]
    fn exact_long_name_beats_longer_prefixes() {
        // "script" is also a prefix of script-args etc.; exact wins.
        let a = an("--script=default,vuln host");
        assert_eq!(opts(&a), vec![o("--script", Some("default,vuln"))]);
        assert_eq!(a.items[0].tokens, vec!["--script", "default,vuln"]);
    }

    #[test]
    fn input_options() {
        let a = an("-iL targets.txt");
        assert!(!a.blocked(), "{:?}", a.issues); // no explicit target needed
        assert!(blocked_with(&an("-iL -"), "stdin"));
        assert!(blocked_with(&an("-i -"), "stdin")); // deprecated -i = -iL
        assert!(blocked_with(&an("-iR 100"), "random"));
    }

    #[test]
    fn non_scan_modes_are_blocked() {
        for cmd in [
            "-h",
            "--help",
            "-V h",
            "--version",
            "--iflist",
            "--script-help=ssl-cert",
            "--script-updatedb h",
        ] {
            assert!(blocked_with(&an(cmd), "doesn't run a scan"), "{cmd}");
        }
    }

    #[test]
    fn malformed_input() {
        assert!(blocked_with(&an("-p"), "needs a value"));
        assert!(blocked_with(&an("--open=yes h"), "doesn't take a value"));
        assert!(blocked_with(&an("-s h"), "scan type"));
        assert!(blocked_with(&an("-sQ h"), "-sQ isn't"));
        assert!(blocked_with(&an("-nQ h"), "-Q isn't")); // unknown letter in a cluster
        assert!(!an("-Q h").blocked()); // lone unknown: long lookup, warn only
        assert!(blocked_with(&an("-sV \"unterminated"), "Unbalanced"));
        assert!(blocked_with(&an("\u{2013}sV h"), "typographic dash"));
        assert!(blocked_with(&an("-sV"), "at least one target"));
    }

    #[test]
    fn unknown_long_options_warn_but_run() {
        let a = an("--frobnicate host");
        assert!(!a.blocked());
        assert_eq!(a.items[0].kind, Kind::Unknown);
        assert_eq!(a.issues[0].level, Level::Warn);
    }

    #[test]
    fn sudo_and_binary_are_stripped() {
        let a = an("sudo /usr/bin/nmap -sS 'my host'");
        assert!(a.sudo);
        assert_eq!(targets(&a), vec!["my host"]);
        // sudo = run as root via pkexec; only implemented on Linux.
        assert_eq!(a.blocked(), !cfg!(target_os = "linux"));
        assert!(a.issues.iter().any(|i| i.message.contains("root")));
        assert_eq!(an("nmap.exe -F h").argv(), vec!["-F", "h"]);
    }

    #[test]
    fn aliases_are_canonicalised() {
        let a = an("-sP --timing 4 --source-port=53 --fuzzy -P host");
        assert_eq!(
            opts(&a),
            vec![
                o("-sn", None),
                o("-T", Some("4")),
                o("-g", Some("53")),
                o("--osscan-guess", None),
                o("-PE", None),
            ]
        );
    }

    #[test]
    fn canonical_argv_reparses_identically() {
        // The builder edits canonical tokens, so they must mean exactly what
        // the user typed.
        for cmd in [
            "-sSVU -nF -Pn -PS22,80 -p- -T aggressive -v3 h1 h2",
            "--script-args -oX h",
            "-top 10 --min-ra=100 --script=a,b -d2 -O2 h",
            "-sP --timing 4 --source-port=53 --fuzzy -P host",
            "-iL list.txt --exclude 10.0.0.1 --debug=2",
            "-p80 -e eth0 -S 1.2.3.4 -D RND:5 -b ftp.example h",
        ] {
            let first = an(cmd);
            let again = analyze_argv(&first.argv());
            assert_eq!(first.items, again.items, "{cmd}");
        }
    }

    /// The UI's option catalogue (src/nmap-options.json) builds tokens itself
    /// (`makeItem` in src/options.ts). Every entry must parse back to exactly
    /// that option, value and spelling, and none may be blocked — otherwise
    /// the builder and the backend would disagree about what will run.
    #[test]
    fn ui_catalogue_matches_the_parser() {
        let json: serde_json::Value =
            serde_json::from_str(include_str!("../../src/nmap-options.json")).unwrap();
        let mut checked = 0;
        for section in json["sections"].as_array().unwrap() {
            for def in section["options"].as_array().unwrap() {
                let name = def["name"].as_str().unwrap();
                let form = def["form"].as_str().unwrap();
                let sample = match def["arg"]["kind"].as_str() {
                    None => None,
                    Some("choice") => {
                        Some(def["arg"]["choices"][0][0].as_str().unwrap().to_string())
                    }
                    Some("ports") => Some("80".to_string()),
                    Some("int") => Some("5".to_string()),
                    Some("float") => Some("1.5".to_string()),
                    Some("time") => Some("5s".to_string()),
                    Some(_) => Some("x".to_string()),
                };
                // Mirror of makeItem() in src/options.ts.
                let tokens: Vec<String> = match (form, &sample) {
                    ("flag", _) => vec![name.into()],
                    ("attached", v) => vec![format!("{name}{}", v.as_deref().unwrap_or(""))],
                    ("value", Some(v)) if !name.starts_with("--") && v.starts_with('-') => {
                        vec![format!("{name}{v}")]
                    }
                    ("value", Some(v)) => vec![name.into(), v.clone()],
                    other => panic!("{name}: bad form/arg {other:?}"),
                };
                let mut argv = tokens.clone();
                argv.push("h".into());
                let a = analyze_argv(&argv);
                assert!(!a.blocked(), "{name}: {:?}", a.issues);
                assert_eq!(a.items.len(), 2, "{name}: {:?}", a.items);
                let item = &a.items[0];
                assert_eq!(item.kind, Kind::Option, "{name}");
                assert_eq!(item.name, name, "{name}");
                assert_eq!(item.value, sample, "{name}");
                assert_eq!(item.tokens, tokens, "{name}");
                checked += 1;
            }
        }
        assert!(checked > 100, "only {checked} catalogue options");
    }

    #[test]
    fn short_option_table_matches_nmap() {
        assert_eq!(short_arg('p'), Some(Arg::Required));
        assert_eq!(short_arg('T'), Some(Arg::Required));
        assert_eq!(short_arg('s'), Some(Arg::Optional));
        assert_eq!(short_arg('P'), Some(Arg::Optional));
        assert_eq!(short_arg('n'), Some(Arg::No));
        assert_eq!(short_arg('x'), None);
        assert_eq!(short_arg(':'), None);
    }

    #[test]
    fn command_from_recorded_args_drops_capture_options() {
        // What our runner records (under pkexec the binary is a full path).
        assert_eq!(
            command_from_args("/usr/bin/nmap --stats-every 1s -oX - -sV -p 22,80 localhost"),
            "nmap -sV -p 22,80 localhost"
        );
        // A CLI user's own output flags, in any spelling.
        assert_eq!(
            command_from_args("nmap -oA out -T4 -oXscan.xml 10.0.0.0/24"),
            "nmap -T4 10.0.0.0/24"
        );
        assert_eq!(command_from_args("nmap -oX -"), "nmap");
        // Values that need quoting come back quoted.
        assert_eq!(
            command_from_args("nmap --script \"http-* and not intrusive\" h"),
            "nmap --script 'http-* and not intrusive' h"
        );
    }

    #[test]
    fn saved_profile_reads_back_as_the_same_options() {
        // The UI saves `nmap <options>` (quoted for display) and later checks
        // the profile's re-parsed items against the current ones to show it
        // as selected — so the round trip must be lossless.
        for cmd in [
            "nmap -T4 -A -v",
            "nmap -p- -sV",
            "nmap -PS80,443 -g 53 --script 'default or (discovery and safe)'",
            "nmap --script-args 'http.useragent=Mozilla 5' -oX - -sC",
            "sudo nmap -sS -O 10.0.0.0/24",
        ] {
            let options = |c: &str| -> Vec<Vec<String>> {
                analyze_text(c)
                    .items
                    .into_iter()
                    .filter(|i| i.kind != Kind::Target)
                    .map(|i| i.tokens)
                    .collect()
            };
            let saved = options_only(cmd);
            assert_eq!(options(&format!("nmap {saved}")), options(cmd), "{cmd}");
        }
    }

    #[test]
    fn options_only_strips_sudo_binary_and_targets() {
        assert_eq!(
            options_only("sudo nmap -sS -T4 scanme.nmap.org 10.0.0.1"),
            "-sS -T4"
        );
        assert_eq!(options_only("nmap"), "");
        assert_eq!(options_only("-p- -sV"), "-p- -sV");
    }

    #[test]
    fn target_label_prefers_targets_then_list_file() {
        assert_eq!(an("nmap -F a b").target_label(), "a b");
        assert_eq!(an("nmap -iL hosts.txt").target_label(), "-iL hosts.txt");
        assert_eq!(an("nmap -F").target_label(), "");
    }
}
