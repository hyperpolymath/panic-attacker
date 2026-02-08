// SPDX-License-Identifier: PMPL-1.0-or-later

//! panic-attack: Universal stress testing and logic-based bug signature detection
//!
//! A tool for stress testing programs across multiple attack axes (CPU, memory, disk, network,
//! concurrency) and detecting bug signatures using logic programming techniques inspired by
//! Mozart/Oz and Datalog.

mod attack;
mod report;
mod signatures;
mod types;
mod xray;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::Duration;
use types::*;

#[derive(Parser)]
#[command(name = "panic-attack")]
#[command(version = "1.0.1")]
#[command(about = "Universal stress testing and logic-based bug signature detection")]
#[command(long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run assail static analysis on a target program
    Assail {
        /// Target program or directory to analyze
        #[arg(value_name = "TARGET")]
        target: PathBuf,

        /// Output report to file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },

    /// Execute a single attack on a target program
    Attack {
        /// Target program to attack
        #[arg(value_name = "PROGRAM")]
        program: PathBuf,

        /// Attack axis to use
        #[arg(short, long, value_enum)]
        axis: AttackAxisArg,

        /// Attack intensity
        #[arg(short, long, default_value = "medium")]
        intensity: IntensityArg,

        /// Attack duration in seconds
        #[arg(short, long, default_value = "60")]
        duration: u64,
    },

    /// Full assault: assail + multi-axis attacks
    Assault {
        /// Target program to assault
        #[arg(value_name = "PROGRAM")]
        program: PathBuf,

        /// Attack axes (default: all)
        #[arg(short, long, value_delimiter = ',')]
        axes: Option<Vec<AttackAxisArg>>,

        /// Attack intensity
        #[arg(short, long, default_value = "medium")]
        intensity: IntensityArg,

        /// Attack duration per axis in seconds
        #[arg(short, long, default_value = "30")]
        duration: u64,

        /// Output report to file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Analyze crash reports for bug signatures
    Analyze {
        /// Crash report file (JSON)
        #[arg(value_name = "REPORT")]
        report: PathBuf,
    },
}

// CLI argument types
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum AttackAxisArg {
    Cpu,
    Memory,
    Disk,
    Network,
    Concurrency,
    Time,
}

impl From<AttackAxisArg> for AttackAxis {
    fn from(arg: AttackAxisArg) -> Self {
        match arg {
            AttackAxisArg::Cpu => AttackAxis::Cpu,
            AttackAxisArg::Memory => AttackAxis::Memory,
            AttackAxisArg::Disk => AttackAxis::Disk,
            AttackAxisArg::Network => AttackAxis::Network,
            AttackAxisArg::Concurrency => AttackAxis::Concurrency,
            AttackAxisArg::Time => AttackAxis::Time,
        }
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum IntensityArg {
    Light,
    Medium,
    Heavy,
    Extreme,
}

impl From<IntensityArg> for IntensityLevel {
    fn from(arg: IntensityArg) -> Self {
        match arg {
            IntensityArg::Light => IntensityLevel::Light,
            IntensityArg::Medium => IntensityLevel::Medium,
            IntensityArg::Heavy => IntensityLevel::Heavy,
            IntensityArg::Extreme => IntensityLevel::Extreme,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Assail {
            target,
            output,
            verbose,
        } => {
            println!("Running assail analysis on: {}", target.display());

            let report = if verbose {
                xray::analyze_verbose(&target)?
            } else {
                xray::analyze(&target)?
            };

            if let Some(output_path) = output {
                let json = serde_json::to_string_pretty(&report)?;
                std::fs::write(&output_path, json)?;
                println!("Report saved to: {}", output_path.display());
            } else {
                // Print summary
                println!("\nAssail Summary:");
                println!("  Language: {:?}", report.language);
                println!("  Weak points: {}", report.weak_points.len());
                println!("  Recommended attacks: {:?}", report.recommended_attacks);
            }
        }

        Commands::Attack {
            program,
            axis,
            intensity,
            duration,
        } => {
            println!(
                "Attacking {} with {:?} (intensity: {:?}, duration: {}s)",
                program.display(),
                axis,
                intensity,
                duration
            );

            let config = AttackConfig {
                axes: vec![axis.into()],
                duration: Duration::from_secs(duration),
                intensity: intensity.into(),
                target_programs: vec![program],
                data_corpus: None,
                parallel_attacks: false,
            };

            let results = attack::execute_attack(config)?;

            for result in &results {
                println!("\nResult:");
                println!("  Success: {}", result.success);
                println!("  Exit code: {:?}", result.exit_code);
                println!("  Duration: {:.2}s", result.duration.as_secs_f64());
                println!("  Crashes: {}", result.crashes.len());
                println!("  Signatures: {}", result.signatures_detected.len());

                if !result.signatures_detected.is_empty() {
                    println!("\n  Bug Signatures:");
                    for sig in &result.signatures_detected {
                        println!(
                            "    - {:?} (confidence: {:.2})",
                            sig.signature_type, sig.confidence
                        );
                    }
                }
            }
        }

        Commands::Assault {
            program,
            axes,
            intensity,
            duration,
            output,
        } => {
            println!("Launching full assault on: {}", program.display());

            // First, run assail analysis
            println!("\nPhase 1: Assail Analysis");
            let xray_report = xray::analyze_verbose(&program)?;

            // Then, execute attacks
            println!("\nPhase 2: Attack Execution");
            let attack_axes = if let Some(axes_arg) = axes {
                axes_arg.into_iter().map(|a| a.into()).collect()
            } else {
                AttackAxis::all()
            };

            let config = AttackConfig {
                axes: attack_axes,
                duration: Duration::from_secs(duration),
                intensity: intensity.into(),
                target_programs: vec![program],
                data_corpus: None,
                parallel_attacks: false,
            };

            let attack_results = attack::execute_attack_with_patterns(
                config,
                xray_report.language,
                &xray_report.frameworks,
            )?;

            // Generate comprehensive report
            println!("\nPhase 3: Report Generation");
            let assault_report = report::generate_assault_report(xray_report, attack_results)?;

            // Print report
            report::print_report(&assault_report);

            // Save if requested
            if let Some(output_path) = output {
                report::save_report(&assault_report, output_path)?;
            }
        }

        Commands::Analyze {
            report: report_path,
        } => {
            println!("Analyzing crash report: {}", report_path.display());

            let content = std::fs::read_to_string(&report_path)?;
            let crash: CrashReport = serde_json::from_str(&content)?;

            let signatures = signatures::detect_signatures(&crash);

            println!("\nSignatures Detected: {}", signatures.len());
            for sig in &signatures {
                println!(
                    "\n  {:?} (confidence: {:.2})",
                    sig.signature_type, sig.confidence
                );
                println!("  Evidence:");
                for evidence in &sig.evidence {
                    println!("    - {}", evidence);
                }
                if let Some(loc) = &sig.location {
                    println!("  Location: {}", loc);
                }
            }
        }
    }

    Ok(())
}
