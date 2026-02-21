// SPDX-License-Identifier: PMPL-1.0-or-later

//! Sweep: batch scanning across multiple git repositories
//!
//! Walks a parent directory, finds subdirectories containing `.git/`,
//! runs `assail::analyze()` on each, and produces a summary report
//! sorted by weak point count (highest first).

use crate::assail;
use crate::types::AssailReport;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Configuration for a sweep run
#[allow(dead_code)]
pub struct SweepConfig {
    /// Parent directory to scan for git repos
    pub directory: PathBuf,
    /// Output path for JSON report (handled by caller)
    pub output: Option<PathBuf>,
    /// Only show repos with findings
    pub findings_only: bool,
    /// Minimum number of findings to include
    pub min_findings: usize,
    /// Emit SARIF instead of default JSON (handled by caller)
    pub sarif: bool,
}

/// Results from scanning a single repository
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoResult {
    pub repo_path: PathBuf,
    pub repo_name: String,
    pub weak_point_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub total_files: usize,
    pub total_lines: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip)]
    pub report: Option<AssailReport>,
}

/// Complete sweep report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepReport {
    pub created_at: String,
    pub directory: PathBuf,
    pub repos_scanned: usize,
    pub repos_with_findings: usize,
    pub total_weak_points: usize,
    pub total_critical: usize,
    pub results: Vec<RepoResult>,
}

/// Find all git repositories under the given directory
fn discover_repos(directory: &Path) -> Result<Vec<PathBuf>> {
    let mut repos = Vec::new();

    if !directory.is_dir() {
        anyhow::bail!("Not a directory: {}", directory.display());
    }

    let entries = fs::read_dir(directory)?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let git_dir = path.join(".git");
            if git_dir.exists() && git_dir.is_dir() {
                repos.push(path);
            }
        }
    }

    repos.sort();
    Ok(repos)
}

/// Run sweep across all repos in a directory
pub fn run(config: &SweepConfig) -> Result<SweepReport> {
    let repos = discover_repos(&config.directory)?;
    let mut results: Vec<RepoResult> = Vec::new();

    for repo_path in &repos {
        let repo_name = repo_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| repo_path.display().to_string());

        match assail::analyze(repo_path) {
            Ok(report) => {
                let critical_count = report
                    .weak_points
                    .iter()
                    .filter(|wp| matches!(wp.severity, crate::types::Severity::Critical))
                    .count();
                let high_count = report
                    .weak_points
                    .iter()
                    .filter(|wp| matches!(wp.severity, crate::types::Severity::High))
                    .count();

                let result = RepoResult {
                    repo_path: repo_path.clone(),
                    repo_name,
                    weak_point_count: report.weak_points.len(),
                    critical_count,
                    high_count,
                    total_files: report.file_statistics.len(),
                    total_lines: report.statistics.total_lines,
                    error: None,
                    report: Some(report),
                };
                results.push(result);
            }
            Err(e) => {
                results.push(RepoResult {
                    repo_path: repo_path.clone(),
                    repo_name,
                    weak_point_count: 0,
                    critical_count: 0,
                    high_count: 0,
                    total_files: 0,
                    total_lines: 0,
                    error: Some(e.to_string()),
                    report: None,
                });
            }
        }
    }

    // Sort by weak point count descending (riskiest repos first)
    results.sort_by(|a, b| b.weak_point_count.cmp(&a.weak_point_count));

    // Apply filters
    if config.findings_only {
        results.retain(|r| r.weak_point_count > 0);
    }
    if config.min_findings > 0 {
        results.retain(|r| r.weak_point_count >= config.min_findings);
    }

    let repos_with_findings = results.iter().filter(|r| r.weak_point_count > 0).count();
    let total_weak_points: usize = results.iter().map(|r| r.weak_point_count).sum();
    let total_critical: usize = results.iter().map(|r| r.critical_count).sum();

    Ok(SweepReport {
        created_at: chrono::Utc::now().to_rfc3339(),
        directory: config.directory.clone(),
        repos_scanned: repos.len(),
        repos_with_findings,
        total_weak_points,
        total_critical,
        results,
    })
}

/// Print a summary table to the terminal
pub fn print_summary(report: &SweepReport, quiet: bool) {
    if quiet {
        return;
    }

    println!("\n=== SWEEP SUMMARY ===");
    println!(
        "Directory: {}  |  Repos scanned: {}  |  With findings: {}",
        report.directory.display(),
        report.repos_scanned,
        report.repos_with_findings
    );
    println!(
        "Total weak points: {}  |  Critical: {}",
        report.total_weak_points, report.total_critical
    );
    println!();

    if report.results.is_empty() {
        println!("  No repositories with findings.");
        return;
    }

    // Header
    println!(
        "  {:<40} {:>6} {:>6} {:>6} {:>8} {:>8}",
        "Repository", "Total", "Crit", "High", "Files", "Lines"
    );
    println!("  {}", "-".repeat(78));

    // Show top 20 repos
    for result in report.results.iter().take(20) {
        if let Some(err) = &result.error {
            println!("  {:<40} ERROR: {}", result.repo_name, err);
        } else {
            println!(
                "  {:<40} {:>6} {:>6} {:>6} {:>8} {:>8}",
                result.repo_name,
                result.weak_point_count,
                result.critical_count,
                result.high_count,
                result.total_files,
                result.total_lines,
            );
        }
    }

    if report.results.len() > 20 {
        println!("  ... and {} more repos", report.results.len() - 20);
    }
    println!();
}

/// Write sweep report as JSON
pub fn write_report(report: &SweepReport, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(report)?;
    fs::write(path, json)?;
    Ok(())
}
