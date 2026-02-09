// SPDX-License-Identifier: PMPL-1.0-or-later

//! Report generation module

pub mod formatter;
pub mod generator;

use crate::types::*;
use anyhow::Result;
use std::path::Path;

pub use formatter::ReportFormatter;
pub use generator::ReportGenerator;

/// Generate a comprehensive assault report
pub fn generate_assault_report(
    assail_report: AssailReport,
    attack_results: Vec<AttackResult>,
) -> Result<AssaultReport> {
    let generator = ReportGenerator::new();
    generator.generate(assail_report, attack_results)
}

/// Save report to file
pub fn save_report<P: AsRef<Path>>(report: &AssaultReport, path: P) -> Result<()> {
    let formatter = ReportFormatter::new();
    formatter.save(report, path)
}

/// Print report to console
pub fn print_report(report: &AssaultReport) {
    let formatter = ReportFormatter::new();
    formatter.print(report);
}
