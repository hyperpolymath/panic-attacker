// SPDX-License-Identifier: PMPL-1.0-or-later

//! Persistent storage helpers for assault reports

use crate::report::ReportOutputFormat;
use crate::types::AssaultReport;
use anyhow::{anyhow, Result};
use chrono::Utc;
use serde_json;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageMode {
    Filesystem,
    VerisimDb,
}

impl StorageMode {
    pub fn from_str(value: &str) -> Option<Self> {
        match value.to_lowercase().as_str() {
            "filesystem" | "disk" | "local" => Some(StorageMode::Filesystem),
            "verisimdb" | "verisim" | "veri" => Some(StorageMode::VerisimDb),
            _ => None,
        }
    }
}

pub fn persist_report(
    report: &AssaultReport,
    directory: Option<&Path>,
    formats: &[ReportOutputFormat],
    modes: &[StorageMode],
) -> Result<Vec<PathBuf>> {
    let mut stored = Vec::new();
    let timestamp = Utc::now().format("%Y%m%d%H%M%S").to_string();

    if modes.contains(&StorageMode::Filesystem) {
        let base_dir = directory
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("reports"));
        fs::create_dir_all(&base_dir)?;
        for format in formats {
            let file_name = format!("panic-attack-{}.{}", timestamp, format.extension());
            let path = base_dir.join(&file_name);
            let content = format.serialize(report)?;
            fs::write(&path, content)?;
            stored.push(path);
        }
    }

    if modes.contains(&StorageMode::VerisimDb) {
        let base_dir = directory
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("verisimdb-data"));
        let verisim_dir = base_dir.join("verisimdb");
        fs::create_dir_all(&verisim_dir)?;
        let path = verisim_dir.join(format!("panic-attack-{}.json", timestamp));
        let payload = serde_json::to_string_pretty(report)?;
        fs::write(&path, payload)?;
        stored.push(path);
    }

    Ok(stored)
}

pub fn latest_reports(dir: &Path, count: usize) -> Result<Vec<PathBuf>> {
    if !dir.exists() {
        return Err(anyhow!("verisimdb directory not found: {}", dir.display()));
    }

    let mut entries: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("json"))
                .unwrap_or(false)
        })
        .collect();

    entries.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
    if entries.len() < count {
        return Err(anyhow!(
            "not enough reports in {} (need {}, found {})",
            dir.display(),
            count,
            entries.len()
        ));
    }
    let start = entries.len() - count;
    Ok(entries[start..].to_vec())
}
