// SPDX-License-Identifier: PMPL-1.0-or-later

//! X-Ray static analysis module
//!
//! Pre-analyzes target programs to identify weak points and recommend attacks

pub mod analyzer;
pub mod patterns;

use crate::types::*;
use anyhow::Result;
use std::path::Path;

pub use analyzer::Analyzer;

/// Run X-Ray analysis on a target program
pub fn analyze<P: AsRef<Path>>(target: P) -> Result<XRayReport> {
    let analyzer = Analyzer::new(target.as_ref())?;
    analyzer.analyze()
}

/// Run X-Ray analysis with verbose output including per-file breakdown
pub fn analyze_verbose<P: AsRef<Path>>(target: P) -> Result<XRayReport> {
    let analyzer = Analyzer::new_verbose(target.as_ref())?;
    let report = analyzer.analyze()?;

    println!("X-Ray Analysis Complete");
    println!("  Language: {:?}", report.language);
    println!("  Frameworks: {:?}", report.frameworks);
    println!("  Weak Points: {}", report.weak_points.len());
    println!("  Recommended Attacks: {:?}", report.recommended_attacks);

    // Per-file breakdown sorted by risk score
    if !report.file_statistics.is_empty() {
        println!("\n  Per-file Breakdown (top 10 by risk):");

        let mut scored: Vec<_> = report
            .file_statistics
            .iter()
            .map(|fs| {
                let risk = fs.unsafe_blocks * 3
                    + fs.panic_sites * 2
                    + fs.unwrap_calls
                    + fs.threading_constructs * 2;
                (risk, fs)
            })
            .collect();
        scored.sort_by(|a, b| b.0.cmp(&a.0));

        for (rank, (risk, fs)) in scored.iter().take(10).enumerate() {
            println!(
                "    {}. {} (risk: {}, lines: {}, unsafe: {}, panics: {}, \
                unwraps: {}, alloc: {}, io: {}, threads: {})",
                rank + 1,
                fs.file_path,
                risk,
                fs.lines,
                fs.unsafe_blocks,
                fs.panic_sites,
                fs.unwrap_calls,
                fs.allocation_sites,
                fs.io_operations,
                fs.threading_constructs,
            );
        }

        if scored.len() > 10 {
            println!("    ... and {} more files", scored.len() - 10);
        }
    }

    Ok(report)
}
