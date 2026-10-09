//! NSE script catalogue: ask the installed `nmap` for every script it knows
//! (`nmap --script-help all -oX -`) and parse that XML into a searchable list.
//!
//! Asking nmap (rather than reading its `scripts/` directory ourselves) means
//! we never have to guess the install path per OS, and the list always matches
//! the scripts the user's nmap will actually run.

use serde::Serialize;
use std::process::Command;

/// One NSE script, as described by `--script-help`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NseScript {
    /// The name passed to `--script`, e.g. "ssl-cert" (filename minus `.nse`).
    pub id: String,
    /// NSE categories, sorted (e.g. ["default", "discovery", "safe"]).
    pub categories: Vec<String>,
    /// NSEDoc description, trimmed, with `<code>` markup removed.
    pub description: String,
}

/// Errors from loading the script catalogue.
#[derive(Debug)]
pub enum NseError {
    Xml(roxmltree::Error),
    /// The document root was not `<nse-scripts>`.
    MissingRoot,
    /// Failed to spawn `nmap` (e.g. not installed / not on PATH).
    Spawn(std::io::Error),
    /// nmap ran but exited non-zero.
    NmapFailed {
        code: Option<i32>,
        stderr: String,
    },
    /// nmap's stdout was not valid UTF-8.
    Utf8(std::string::FromUtf8Error),
}

impl std::fmt::Display for NseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NseError::Xml(e) => write!(f, "invalid script-help XML: {e}"),
            NseError::MissingRoot => write!(f, "expected <nse-scripts> root element"),
            NseError::Spawn(e) => write!(f, "could not run nmap: {e} (is nmap installed?)"),
            NseError::NmapFailed { code, stderr } => {
                write!(
                    f,
                    "nmap --script-help exited with {code:?}: {}",
                    stderr.trim()
                )
            }
            NseError::Utf8(e) => write!(f, "nmap output was not valid UTF-8: {e}"),
        }
    }
}

impl std::error::Error for NseError {}

impl From<roxmltree::Error> for NseError {
    fn from(e: roxmltree::Error) -> Self {
        NseError::Xml(e)
    }
}

/// Parse `nmap --script-help <spec> -oX -` output. Pure — no process spawning.
/// Scripts are returned sorted by id.
pub fn parse_script_help_xml(xml: &str) -> Result<Vec<NseScript>, NseError> {
    let doc = roxmltree::Document::parse(xml)?;
    let root = doc.root_element();
    if root.tag_name().name() != "nse-scripts" {
        return Err(NseError::MissingRoot);
    }

    let mut scripts: Vec<NseScript> = root
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == "script")
        .filter_map(|node| {
            let id = script_id(node.attribute("filename")?)?;
            let mut categories = Vec::new();
            let mut description = String::new();
            for child in node.children().filter(|n| n.is_element()) {
                match child.tag_name().name() {
                    "categories" => categories.extend(
                        child
                            .children()
                            .filter(|n| n.is_element() && n.tag_name().name() == "category")
                            .filter_map(|c| c.text())
                            .map(|t| t.trim().to_string()),
                    ),
                    "description" => description = clean_description(child.text().unwrap_or("")),
                    _ => {}
                }
            }
            categories.sort();
            categories.dedup();
            Some(NseScript {
                id,
                categories,
                description,
            })
        })
        .collect();

    scripts.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(scripts)
}

/// "/usr/share/nmap/scripts/ssl-cert.nse" (or a Windows `\` path) → "ssl-cert".
fn script_id(filename: &str) -> Option<String> {
    let base = filename.rsplit(['/', '\\']).next()?;
    let id = base.strip_suffix(".nse").unwrap_or(base);
    (!id.is_empty()).then(|| id.to_string())
}

/// NSEDoc uses literal `<code>…</code>` markup inside descriptions; it arrives
/// as text (escaped in the XML), so strip it for plain-text display.
fn clean_description(raw: &str) -> String {
    raw.replace("<code>", "")
        .replace("</code>", "")
        .trim()
        .to_string()
}

/// Ask the installed nmap for its full script catalogue.
pub fn list_scripts() -> Result<Vec<NseScript>, NseError> {
    let output = Command::new("nmap")
        .args(["--script-help", "all", "-oX", "-"])
        .output()
        .map_err(NseError::Spawn)?;

    if !output.status.success() {
        return Err(NseError::NmapFailed {
            code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }

    let xml = String::from_utf8(output.stdout).map_err(NseError::Utf8)?;
    parse_script_help_xml(&xml)
}

// ---------------------------------------------------------------------------
// Tests (do NOT require nmap to be installed)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Five real entries from nmap 7.94's `--script-help all -oX -`.
    const SCRIPT_HELP: &str = include_str!("../tests/fixtures/script-help.xml");

    #[test]
    fn parses_script_help_fixture() {
        let scripts = parse_script_help_xml(SCRIPT_HELP).expect("should parse");
        let ids: Vec<&str> = scripts.iter().map(|s| s.id.as_str()).collect();
        // Sorted by id; `<directory>` entries ignored.
        assert_eq!(
            ids,
            [
                "afp-brute",
                "http-slowloris",
                "http-title",
                "smb-vuln-ms17-010",
                "ssl-cert"
            ]
        );

        let title = &scripts[2];
        assert_eq!(title.categories, ["default", "discovery", "safe"]);
        assert!(title
            .description
            .starts_with("Shows the title of the default page"));
        assert!(!title.description.ends_with('\n'));

        let dos = &scripts[1];
        assert_eq!(dos.categories, ["dos", "intrusive"]);
        // `<code>` markup stripped, but the content inside kept.
        assert!(dos.description.contains("--max-parallelism option"));
        assert!(!dos.description.contains("<code>"));
    }

    #[test]
    fn script_id_handles_unix_and_windows_paths() {
        assert_eq!(
            script_id("/usr/bin/../share/nmap/scripts/ssl-cert.nse").as_deref(),
            Some("ssl-cert")
        );
        assert_eq!(
            script_id(r"C:\Program Files (x86)\Nmap\scripts\http-title.nse").as_deref(),
            Some("http-title")
        );
        assert_eq!(script_id("/scripts/"), None);
    }

    #[test]
    fn rejects_wrong_root_and_malformed_xml() {
        assert!(matches!(
            parse_script_help_xml("<nmaprun/>"),
            Err(NseError::MissingRoot)
        ));
        assert!(matches!(
            parse_script_help_xml("<nse-scripts><script>"),
            Err(NseError::Xml(_))
        ));
    }

    #[test]
    fn script_without_categories_or_description_still_parses() {
        let xml = r#"<nse-scripts><script filename="/x/custom.nse"></script></nse-scripts>"#;
        let scripts = parse_script_help_xml(xml).unwrap();
        assert_eq!(scripts.len(), 1);
        assert_eq!(scripts[0].id, "custom");
        assert!(scripts[0].categories.is_empty());
        assert_eq!(scripts[0].description, "");
    }
}
