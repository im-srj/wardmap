//! Long-running scans: spawn nmap, stream progress while it runs, allow
//! cancelling, and hand back the raw XML when it finishes.
//!
//! Progress comes from nmap itself: `--stats-every 1s` makes it interleave
//! `<taskprogress task=.. percent=.. remaining=..>` elements into the `-oX -`
//! stream. **nmap only checks that timer when it has a controlling terminal**
//! (verified on 7.94: piped → zero progress elements; under a pty → one per
//! second). A GUI app has no terminal, so on Unix we give nmap a pseudo-
//! terminal as its stdin/controlling tty. Its stdout stays our XML pipe, so
//! the XML is byte-for-byte what it would otherwise be (plus the progress
//! elements, which the parser ignores). If the pty can't be set up — or on
//! Windows — the scan still runs, just without percentages.

use std::collections::HashMap;
use std::io::{BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

use quick_xml::events::Event;
use serde::Serialize;

use crate::cmdline::Analysis;
use crate::scan::ScanError;

/// One progress update, from a `<taskprogress>` element.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanProgress {
    /// nmap's phase name, e.g. "Connect Scan", "Service scan", "NSE".
    pub task: String,
    pub percent: f64,
    /// nmap's estimate; absent early in a phase.
    pub remaining_secs: Option<u64>,
}

#[derive(Debug)]
pub enum RunError {
    Scan(ScanError),
    /// The user cancelled the scan (it was killed; nothing is saved).
    Cancelled,
    /// A scan with this run id is already running.
    DuplicateRun(String),
    /// The command failed Cartograph's checks (see `cmdline`); never spawned.
    Blocked(String),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::Scan(e) => e.fmt(f),
            RunError::Cancelled => write!(f, "scan cancelled"),
            RunError::DuplicateRun(id) => write!(f, "a scan with id {id:?} is already running"),
            RunError::Blocked(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for RunError {}

impl From<ScanError> for RunError {
    fn from(e: ScanError) -> Self {
        RunError::Scan(e)
    }
}

struct Running {
    child: Child,
    cancelled: bool,
}

/// Registry of in-flight nmap processes, keyed by a caller-chosen run id.
/// Tauri-managed state; also used on app exit to kill stragglers.
#[derive(Default)]
pub struct Runs(Mutex<HashMap<String, Running>>);

impl Runs {
    /// Kill a running scan. Returns false if no such run (already finished).
    pub fn cancel(&self, run_id: &str) -> bool {
        let mut runs = self.0.lock().unwrap_or_else(|e| e.into_inner());
        match runs.get_mut(run_id) {
            Some(r) => {
                r.cancelled = true;
                let _ = r.child.kill();
                true
            }
            None => false,
        }
    }

    /// Kill every running scan (app shutdown — don't leave orphaned nmaps).
    pub fn kill_all(&self) {
        let mut runs = self.0.lock().unwrap_or_else(|e| e.into_inner());
        for r in runs.values_mut() {
            let _ = r.child.kill();
        }
    }
}

/// Run nmap to completion, calling `on_progress` as it reports, and return
/// the raw `-oX` XML. Blocks the calling thread for the scan's duration.
///
/// Takes an [`Analysis`] rather than raw args so nothing can reach nmap
/// without passing `cmdline`'s checks; a blocked command is refused here.
pub fn run(
    runs: &Runs,
    run_id: &str,
    command: &Analysis,
    on_progress: impl FnMut(ScanProgress),
) -> Result<String, RunError> {
    if command.blocked() {
        return Err(RunError::Blocked(command.block_reasons()));
    }

    // Our capture flags go first; policy guarantees the user's argv contains
    // no output options or --stats-every to contradict them.
    let mut cmd = Command::new("nmap");
    cmd.args(["--stats-every", "1s", "-oX", "-"])
        .args(command.argv())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    pty::attach(&mut cmd);

    let mut child = cmd.spawn().map_err(ScanError::Spawn)?;
    let stdout = child.stdout.take().expect("stdout is piped");
    let mut stderr = child.stderr.take().expect("stderr is piped");

    {
        let mut map = runs.0.lock().unwrap_or_else(|e| e.into_inner());
        if map.contains_key(run_id) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(RunError::DuplicateRun(run_id.to_string()));
        }
        map.insert(
            run_id.to_string(),
            Running {
                child,
                cancelled: false,
            },
        );
    }

    // Drain stderr concurrently so a chatty nmap can't block on a full pipe.
    let stderr_thread = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = stderr.read_to_string(&mut s);
        s
    });

    let xml = read_with_progress(stdout, on_progress);

    let Running {
        mut child,
        cancelled,
    } = runs
        .0
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(run_id)
        .expect("registered above; only run() removes");
    let status = child.wait().map_err(ScanError::Spawn)?;
    let stderr = stderr_thread.join().unwrap_or_default();

    if cancelled {
        return Err(RunError::Cancelled);
    }
    if !status.success() {
        return Err(ScanError::NmapFailed {
            code: status.code(),
            stderr,
        }
        .into());
    }
    let xml = xml.map_err(ScanError::Spawn)?;
    String::from_utf8(xml).map_err(|e| ScanError::Utf8(e).into())
}

/// Read nmap's stdout to EOF, returning every byte, while reporting each
/// `<taskprogress>` as it streams past. Progress is best-effort: if the
/// streaming parser ever trips, we stop reporting but still capture the rest
/// of the output, so the result never depends on it.
pub fn read_with_progress<R: Read>(
    stdout: R,
    mut on_progress: impl FnMut(ScanProgress),
) -> std::io::Result<Vec<u8>> {
    let mut reader = quick_xml::Reader::from_reader(BufReader::new(Tee {
        inner: stdout,
        captured: Vec::new(),
    }));
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Ok(Event::Empty(e) | Event::Start(e)) if e.name().as_ref() == "taskprogress" => {
                let attr = |name: &str| {
                    e.try_get_attribute(name).ok().flatten().and_then(|a| {
                        a.normalized_value(quick_xml::XmlVersion::Implicit1_0)
                            .ok()
                            .map(|v| v.into_owned())
                    })
                };
                if let (Some(task), Some(percent)) =
                    (attr("task"), attr("percent").and_then(|p| p.parse().ok()))
                {
                    on_progress(ScanProgress {
                        task,
                        percent,
                        remaining_secs: attr("remaining").and_then(|r| r.parse().ok()),
                    });
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
        buf.clear();
    }
    let mut rest = reader.into_inner();
    std::io::copy(&mut rest, &mut std::io::sink())?; // drain; Tee still captures
    Ok(rest.into_inner().captured)
}

/// A reader that keeps a copy of every byte read through it.
struct Tee<R> {
    inner: R,
    captured: Vec<u8>,
}

impl<R: Read> Read for Tee<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.captured.extend_from_slice(&buf[..n]);
        Ok(n)
    }
}

#[cfg(unix)]
mod pty {
    use std::fs::File;
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    /// Make a fresh pseudo-terminal nmap's stdin and controlling terminal.
    /// On any failure, leave `cmd` untouched (scan runs without progress).
    pub fn attach(cmd: &mut Command) {
        let (mut master, mut slave) = (-1, -1);
        // SAFETY: openpty writes two fds into the out-params; null name/
        // termios/winsize are permitted.
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if rc != 0 {
            return;
        }
        // SAFETY: both fds were just returned by openpty and are owned here.
        let (master, slave) =
            unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };

        cmd.stdin(Stdio::from(slave)); // dropped (closed) in parent after spawn
                                       // SAFETY: only async-signal-safe calls (setsid, ioctl) between fork
                                       // and exec. By this point std has already dup'd the slave onto fd 0.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        // Keep the master open for nmap's lifetime (closing it would hang up
        // nmap's terminal) and drain anything nmap writes to the tty. The read
        // fails with EIO once nmap exits and the last slave fd closes.
        std::thread::spawn(move || {
            let mut master = File::from(master);
            let _ = std::io::copy(&mut master, &mut std::io::sink());
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROGRESS: &str = include_str!("../tests/fixtures/localhost-progress.xml");

    /// Hands out at most `n` bytes per read, to prove progress parsing doesn't
    /// depend on how the pipe happens to chunk nmap's output.
    struct Trickle<'a>(&'a [u8], usize);
    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.1.min(buf.len()).min(self.0.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }

    #[test]
    fn reports_each_taskprogress_and_keeps_every_byte() {
        let mut seen = Vec::new();
        let bytes = read_with_progress(PROGRESS.as_bytes(), |p| seen.push(p)).unwrap();
        assert_eq!(bytes, PROGRESS.as_bytes());

        assert_eq!(seen.len(), 9);
        assert_eq!(
            seen[0],
            ScanProgress {
                task: "Ping Scan".into(),
                percent: 0.0,
                remaining_secs: None
            }
        );
        assert_eq!(
            seen[1],
            ScanProgress {
                task: "Connect Scan".into(),
                percent: 12.15,
                remaining_secs: Some(8)
            }
        );
        assert_eq!(seen[8].percent, 98.95);
    }

    #[test]
    fn chunking_does_not_change_the_result() {
        for chunk in [1, 7, 64] {
            let mut n = 0;
            let bytes =
                read_with_progress(Trickle(PROGRESS.as_bytes(), chunk), |_| n += 1).unwrap();
            assert_eq!(bytes, PROGRESS.as_bytes(), "chunk {chunk}");
            assert_eq!(n, 9, "chunk {chunk}");
        }
    }

    #[test]
    fn malformed_stream_still_captures_everything() {
        // Progress stops at the broken tag; the bytes are still all returned
        // (the real parser then reports the error on the full document).
        let broken = "<nmaprun><taskprogress task=\"A\" percent=\"5\"/><<<garbage \
                      <taskprogress task=\"B\" percent=\"9\"/></nmaprun>";
        let mut seen = Vec::new();
        let bytes = read_with_progress(broken.as_bytes(), |p| seen.push(p.task)).unwrap();
        assert_eq!(bytes, broken.as_bytes());
        assert_eq!(seen, vec!["A"]);
    }

    #[test]
    fn cancel_unknown_run_is_false() {
        assert!(!Runs::default().cancel("nope"));
    }

    #[cfg(unix)]
    #[test]
    fn cancel_kills_the_process_and_marks_it() {
        let runs = Runs::default();
        let child = Command::new("sleep").arg("30").spawn().unwrap();
        runs.0.lock().unwrap().insert(
            "r1".into(),
            Running {
                child,
                cancelled: false,
            },
        );
        assert!(runs.cancel("r1"));
        let mut r = runs.0.lock().unwrap().remove("r1").unwrap();
        assert!(r.cancelled);
        assert!(!r.child.wait().unwrap().success()); // killed, not a 30s wait
    }

    // Live checks against a real nmap (not run in CI):
    //   cargo test --lib runner -- --ignored
    // A deliberately slowed localhost scan, so nmap's 1s stats timer fires.
    fn slow_scan() -> Analysis {
        crate::cmdline::analyze_text("-sT -p 1-1500 --scan-delay 4ms localhost")
    }

    #[test]
    #[ignore = "needs nmap installed"]
    fn live_scan_streams_progress_through_the_pty() {
        let mut seen = Vec::new();
        let xml = run(&Runs::default(), "live", &slow_scan(), |p| seen.push(p)).unwrap();
        assert!(crate::scan::parse_nmap_xml(&xml).is_ok());
        assert!(seen.len() >= 3, "expected progress, got {seen:?}");
        assert!(seen.iter().any(|p| p.remaining_secs.is_some()));
    }

    #[test]
    #[ignore = "needs nmap installed"]
    fn live_cancel_stops_nmap() {
        let runs = std::sync::Arc::new(Runs::default());
        let r2 = runs.clone();
        let started = std::time::Instant::now();
        let handle = std::thread::spawn(move || run(&r2, "c", &slow_scan(), |_| {}));
        std::thread::sleep(std::time::Duration::from_millis(1500));
        assert!(runs.cancel("c"));
        assert!(matches!(handle.join().unwrap(), Err(RunError::Cancelled)));
        assert!(started.elapsed().as_secs() < 4);
        assert!(runs.0.lock().unwrap().is_empty());
    }

    #[test]
    fn refuses_a_blocked_command_before_spawning() {
        let blocked = crate::cmdline::analyze_text("-oX /tmp/out.xml localhost");
        let err = run(&Runs::default(), "r1", &blocked, |_| {}).unwrap_err();
        assert!(matches!(err, RunError::Blocked(ref m) if m.contains("output file")));
    }
}
