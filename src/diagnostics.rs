use crate::a2ml::Manifest;
use anyhow::{anyhow, Context, Result};
use std::env;
use std::fs;
use std::path::Path;

const HYPATIA_ENV: &str = "HYPATIA_API_KEY";
const GITBOT_FLEET_ENV: &str = "GITBOT_FLEET_ENDPOINT";

pub fn run_self_diagnostics(manifest: &Manifest) -> Result<()> {
    println!("panic-attack self-diagnostics");

    let mut checks = Vec::new();
    checks.push(Diagnostic::ok(
        "version",
        format!("panic-attack {}", env!("CARGO_PKG_VERSION")),
    ));
    checks.push(Diagnostic::ok(
        "AI manifest",
        format!(
            "AI.a2ml parsed (formats: {:?}, storage: {:?})",
            manifest.report_formats(),
            manifest.storage_modes(),
        ),
    ));

    checks.push(check_directory(
        "reports directory",
        Path::new("reports"),
        Severity::Warn,
    ));
    checks.push(check_directory(
        "profiles directory",
        Path::new("profiles"),
        Severity::Warn,
    ));
    checks.push(check_verisimdb(Path::new("verisimdb-data/verisimdb")));
    checks.push(check_file(
        "ambush timeline spec",
        Path::new("docs/ambush-timeline.md"),
    ));
    checks.push(check_file(
        "panll export guide",
        Path::new("docs/panll-export.md"),
    ));

    checks.push(check_watcher("Hypatia scanner", HYPATIA_ENV));
    checks.push(check_watcher("gitbot-fleet observer", GITBOT_FLEET_ENV));

    println!();
    for entry in &checks {
        entry.print();
    }

    if checks
        .iter()
        .any(|entry| matches!(entry.level, Level::Error))
    {
        Err(anyhow!("self-diagnostics reported issues"))
    } else {
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Level {
    Ok,
    Warn,
    Error,
}

struct Diagnostic {
    label: &'static str,
    level: Level,
    detail: String,
}

impl Diagnostic {
    fn new(label: &'static str, level: Level, detail: String) -> Self {
        Self {
            label,
            level,
            detail,
        }
    }

    fn ok(label: &'static str, detail: String) -> Self {
        Self::new(label, Level::Ok, detail)
    }

    fn warning(label: &'static str, detail: String) -> Self {
        Self::new(label, Level::Warn, detail)
    }

    fn error(label: &'static str, detail: String) -> Self {
        Self::new(label, Level::Error, detail)
    }

    fn print(&self) {
        println!("  [{}] {:22} {}", self.level.tag(), self.label, self.detail,);
    }
}

impl Level {
    fn tag(&self) -> &'static str {
        match self {
            Level::Ok => "OK",
            Level::Warn => "WARN",
            Level::Error => "ERR",
        }
    }
}

fn check_directory(label: &'static str, path: &Path, missing_level: Severity) -> Diagnostic {
    if path.is_dir() {
        Diagnostic::ok(label, format!("{} exists", path.display()))
    } else if path.exists() {
        Diagnostic::warning(
            label,
            format!("{} exists but is not a directory", path.display()),
        )
    } else if missing_level == Severity::Error {
        Diagnostic::error(label, format!("{} missing", path.display()))
    } else {
        Diagnostic::warning(
            label,
            format!(
                "{} missing (create with mkdir -p {})",
                path.display(),
                path.display()
            ),
        )
    }
}

fn check_file(label: &'static str, path: &Path) -> Diagnostic {
    if path.is_file() {
        Diagnostic::ok(label, format!("{} exists", path.display()))
    } else if path.exists() {
        Diagnostic::warning(
            label,
            format!("{} exists but is not a regular file", path.display()),
        )
    } else {
        Diagnostic::error(label, format!("{} missing", path.display()))
    }
}

fn check_verisimdb(path: &Path) -> Diagnostic {
    if !path.exists() {
        return Diagnostic::warning(
            "verisimdb cache",
            "verisimdb-data/verisimdb missing (run panic-attack to populate)".to_string(),
        );
    }

    let entries = fs::read_dir(path)
        .with_context(|| format!("reading {}", path.display()))
        .map(|iter| iter.filter_map(|entry| entry.ok()).count());

    match entries {
        Ok(count) if count > 0 => {
            Diagnostic::ok("verisimdb cache", format!("{} reports stored", count))
        }
        Ok(_) => Diagnostic::warning(
            "verisimdb cache",
            "directory is empty (run panic-attack to create verisimdb reports)".to_string(),
        ),
        Err(err) => Diagnostic::warning(
            "verisimdb cache",
            format!("unable to read {}: {}", path.display(), err),
        ),
    }
}

fn check_watcher(label: &'static str, env_key: &str) -> Diagnostic {
    match env::var(env_key) {
        Ok(value) if !value.trim().is_empty() => {
            Diagnostic::ok(label, format!("configured ({})", env_key))
        }
        _ => Diagnostic::warning(label, format!("not configured (set {} to enable)", env_key)),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Severity {
    Warn,
    Error,
}
