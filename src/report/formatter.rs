// SPDX-License-Identifier: PMPL-1.0-or-later

//! Report formatting and output

use crate::types::*;
use anyhow::Result;
use colored::*;
use std::fs;
use std::path::Path;

pub struct ReportFormatter;

impl ReportFormatter {
    pub fn new() -> Self {
        Self
    }

    pub fn print(&self, report: &AssaultReport) {
        println!("\n{}", "=== PANIC-ATTACKER ASSAULT REPORT ===".bold().cyan());
        println!();

        self.print_xray_summary(&report.xray_report);
        println!();

        self.print_attack_summary(&report.attack_results);
        println!();

        self.print_signatures(&report.attack_results);
        println!();

        self.print_overall_assessment(&report.overall_assessment);
        println!();
    }

    fn print_xray_summary(&self, xray: &XRayReport) {
        println!("{}", "X-RAY ANALYSIS".bold().yellow());
        println!("  Program: {}", xray.program_path.display());
        println!("  Language: {:?}", xray.language);
        println!("  Frameworks: {:?}", xray.frameworks);
        println!();

        println!("  Statistics:");
        println!("    Total lines: {}", xray.statistics.total_lines);
        println!("    Unsafe blocks: {}", xray.statistics.unsafe_blocks);
        println!("    Panic sites: {}", xray.statistics.panic_sites);
        println!("    Unwrap calls: {}", xray.statistics.unwrap_calls);
        println!("    Allocation sites: {}", xray.statistics.allocation_sites);
        println!("    I/O operations: {}", xray.statistics.io_operations);
        println!("    Threading constructs: {}", xray.statistics.threading_constructs);
        println!();

        if !xray.weak_points.is_empty() {
            println!("  Weak Points Detected: {}", xray.weak_points.len());
            for (i, wp) in xray.weak_points.iter().enumerate() {
                let severity_color = match wp.severity {
                    Severity::Critical => "red",
                    Severity::High => "yellow",
                    Severity::Medium => "blue",
                    Severity::Low => "green",
                };
                println!(
                    "    {}. [{:?}] {} - {}",
                    i + 1,
                    wp.severity.to_string().color(severity_color),
                    format!("{:?}", wp.category).bold(),
                    wp.description
                );
            }
        }
    }

    fn print_attack_summary(&self, results: &[AttackResult]) {
        println!("{}", "ATTACK RESULTS".bold().yellow());

        for result in results {
            let status = if result.success {
                "PASSED".green()
            } else {
                "FAILED".red()
            };

            println!(
                "  {:?} attack: {} (exit code: {:?}, duration: {:.2}s)",
                result.axis,
                status,
                result.exit_code,
                result.duration.as_secs_f64()
            );

            if !result.crashes.is_empty() {
                println!("    Crashes: {}", result.crashes.len().to_string().red().bold());
                for (i, crash) in result.crashes.iter().enumerate() {
                    println!("      {}. Signal: {:?}", i + 1, crash.signal);
                    if let Some(bt) = &crash.backtrace {
                        println!("         Backtrace available: {} bytes", bt.len());
                    }
                }
            }

            if result.peak_memory > 0 {
                println!(
                    "    Peak memory: {} MB",
                    result.peak_memory / (1024 * 1024)
                );
            }
        }
    }

    fn print_signatures(&self, results: &[AttackResult]) {
        let total_sigs: usize = results.iter().map(|r| r.signatures_detected.len()).sum();

        if total_sigs > 0 {
            println!("{}", "BUG SIGNATURES DETECTED".bold().red());
            println!("  Total: {}", total_sigs);
            println!();

            for result in results {
                if !result.signatures_detected.is_empty() {
                    println!("  During {:?} attack:", result.axis);
                    for sig in &result.signatures_detected {
                        println!(
                            "    - {:?} (confidence: {:.2})",
                            sig.signature_type, sig.confidence
                        );
                        for evidence in &sig.evidence {
                            println!("      Evidence: {}", evidence.dimmed());
                        }
                        if let Some(loc) = &sig.location {
                            println!("      Location: {}", loc.dimmed());
                        }
                    }
                    println!();
                }
            }
        } else {
            println!("{}", "No bug signatures detected".green());
        }
    }

    fn print_overall_assessment(&self, assessment: &OverallAssessment) {
        println!("{}", "OVERALL ASSESSMENT".bold().yellow());

        let score_color = if assessment.robustness_score >= 80.0 {
            "green"
        } else if assessment.robustness_score >= 50.0 {
            "yellow"
        } else {
            "red"
        };

        println!(
            "  Robustness Score: {}/100",
            format!("{:.1}", assessment.robustness_score)
                .color(score_color)
                .bold()
        );
        println!();

        if !assessment.critical_issues.is_empty() {
            println!("  Critical Issues:");
            for issue in &assessment.critical_issues {
                println!("    - {}", issue.red());
            }
            println!();
        }

        if !assessment.recommendations.is_empty() {
            println!("  Recommendations:");
            for rec in &assessment.recommendations {
                println!("    - {}", rec);
            }
        }
    }

    pub fn save<P: AsRef<Path>>(&self, report: &AssaultReport, path: P) -> Result<()> {
        let json = serde_json::to_string_pretty(report)?;
        fs::write(path.as_ref(), json)?;
        println!("Report saved to: {}", path.as_ref().display());
        Ok(())
    }
}

impl Default for ReportFormatter {
    fn default() -> Self {
        Self::new()
    }
}
