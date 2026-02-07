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

/// Run X-Ray analysis with verbose output
pub fn analyze_verbose<P: AsRef<Path>>(target: P) -> Result<XRayReport> {
    let analyzer = Analyzer::new(target.as_ref())?;
    let report = analyzer.analyze()?;

    println!("X-Ray Analysis Complete");
    println!("  Language: {:?}", report.language);
    println!("  Frameworks: {:?}", report.frameworks);
    println!("  Weak Points: {}", report.weak_points.len());
    println!("  Recommended Attacks: {:?}", report.recommended_attacks);

    Ok(report)
}
