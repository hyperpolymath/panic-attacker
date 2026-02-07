// SPDX-License-Identifier: PMPL-1.0-or-later

//! Attack execution engine

use crate::attack::strategies::*;
use crate::signatures::SignatureEngine;
use crate::types::*;
use crate::xray::patterns::PatternDetector;
use anyhow::{Context, Result};
use std::process::{Command, Stdio};
use std::time::Instant;

pub struct AttackExecutor {
    config: AttackConfig,
    patterns: Vec<AttackPattern>,
}

impl AttackExecutor {
    pub fn new(config: AttackConfig) -> Self {
        Self {
            config,
            patterns: Vec::new(),
        }
    }

    pub fn with_patterns(
        config: AttackConfig,
        language: Language,
        frameworks: &[Framework],
    ) -> Self {
        let patterns = PatternDetector::patterns_for(language, frameworks);
        Self { config, patterns }
    }

    pub fn execute(&self) -> Result<Vec<AttackResult>> {
        let mut results = Vec::new();

        for program in &self.config.target_programs {
            for axis in &self.config.axes {
                println!("Attacking {:?} on axis {:?}...", program, axis);

                let result = self.execute_single_attack(program, *axis)?;
                results.push(result);
            }
        }

        Ok(results)
    }

    fn execute_single_attack(
        &self,
        program: &std::path::PathBuf,
        axis: AttackAxis,
    ) -> Result<AttackResult> {
        let strategy = self.select_strategy(axis);
        println!("  Strategy: {}", strategy.description());

        // Log applicable patterns for this axis
        let applicable: Vec<_> = self
            .patterns
            .iter()
            .filter(|p| p.applicable_axes.contains(&axis))
            .collect();
        if !applicable.is_empty() {
            println!("  Applicable patterns:");
            for pat in &applicable {
                println!("    - {}: {}", pat.name, pat.description);
            }
        }

        let start = Instant::now();
        let mut crashes = Vec::new();
        let mut peak_memory = 0u64;

        // Execute attack based on strategy
        let (exit_code, success) = match strategy {
            AttackStrategy::CpuStress => self.attack_cpu(program, &mut crashes)?,
            AttackStrategy::MemoryExhaustion => {
                self.attack_memory(program, &mut crashes, &mut peak_memory)?
            }
            AttackStrategy::DiskThrashing => self.attack_disk(program, &mut crashes)?,
            AttackStrategy::NetworkFlood => self.attack_network(program, &mut crashes)?,
            AttackStrategy::ConcurrencyStorm => self.attack_concurrency(program, &mut crashes)?,
            AttackStrategy::TimeBomb => self.attack_time(program, &mut crashes)?,
        };

        let duration = start.elapsed();

        // Run signature detection on any crashes
        let signatures_detected = if !crashes.is_empty() {
            let engine = SignatureEngine::new();
            crashes
                .iter()
                .flat_map(|crash| engine.detect_from_crash(crash))
                .collect()
        } else {
            Vec::new()
        };

        Ok(AttackResult {
            program: program.clone(),
            axis,
            success,
            exit_code,
            duration,
            peak_memory,
            crashes,
            signatures_detected,
        })
    }

    fn select_strategy(&self, axis: AttackAxis) -> AttackStrategy {
        match axis {
            AttackAxis::Cpu => AttackStrategy::CpuStress,
            AttackAxis::Memory => AttackStrategy::MemoryExhaustion,
            AttackAxis::Disk => AttackStrategy::DiskThrashing,
            AttackAxis::Network => AttackStrategy::NetworkFlood,
            AttackAxis::Concurrency => AttackStrategy::ConcurrencyStorm,
            AttackAxis::Time => AttackStrategy::TimeBomb,
        }
    }

    fn attack_cpu(
        &self,
        program: &std::path::PathBuf,
        crashes: &mut Vec<CrashReport>,
    ) -> Result<(Option<i32>, bool)> {
        // CPU stress: run program with high computational load
        let iterations = (1000.0 * self.config.intensity.multiplier()) as u64;

        let output = Command::new(program)
            .arg("--iterations")
            .arg(iterations.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("Failed to execute program")?;

        let success = output.status.success();
        let exit_code = output.status.code();

        if !success {
            crashes.push(CrashReport {
                timestamp: chrono::Utc::now().to_rfc3339(),
                signal: Self::extract_signal(&output.stderr),
                backtrace: Self::extract_backtrace(&output.stderr),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            });
        }

        Ok((exit_code, success))
    }

    fn attack_memory(
        &self,
        program: &std::path::PathBuf,
        crashes: &mut Vec<CrashReport>,
        peak_memory: &mut u64,
    ) -> Result<(Option<i32>, bool)> {
        // Memory exhaustion: allocate large amounts of memory
        let memory_mb = (1024.0 * self.config.intensity.multiplier()) as u64;

        let output = Command::new(program)
            .arg("--allocate-mb")
            .arg(memory_mb.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("Failed to execute program")?;

        *peak_memory = memory_mb * 1024 * 1024;

        let success = output.status.success();
        let exit_code = output.status.code();

        if !success {
            crashes.push(CrashReport {
                timestamp: chrono::Utc::now().to_rfc3339(),
                signal: Self::extract_signal(&output.stderr),
                backtrace: Self::extract_backtrace(&output.stderr),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            });
        }

        Ok((exit_code, success))
    }

    fn attack_disk(
        &self,
        program: &std::path::PathBuf,
        crashes: &mut Vec<CrashReport>,
    ) -> Result<(Option<i32>, bool)> {
        // Disk I/O stress
        let file_count = (100.0 * self.config.intensity.multiplier()) as u64;

        let output = Command::new(program)
            .arg("--write-files")
            .arg(file_count.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("Failed to execute program")?;

        let success = output.status.success();
        let exit_code = output.status.code();

        if !success {
            crashes.push(CrashReport {
                timestamp: chrono::Utc::now().to_rfc3339(),
                signal: Self::extract_signal(&output.stderr),
                backtrace: Self::extract_backtrace(&output.stderr),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            });
        }

        Ok((exit_code, success))
    }

    fn attack_network(
        &self,
        program: &std::path::PathBuf,
        crashes: &mut Vec<CrashReport>,
    ) -> Result<(Option<i32>, bool)> {
        // Network flood
        let connections = (100.0 * self.config.intensity.multiplier()) as u64;

        let output = Command::new(program)
            .arg("--connections")
            .arg(connections.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("Failed to execute program")?;

        let success = output.status.success();
        let exit_code = output.status.code();

        if !success {
            crashes.push(CrashReport {
                timestamp: chrono::Utc::now().to_rfc3339(),
                signal: Self::extract_signal(&output.stderr),
                backtrace: Self::extract_backtrace(&output.stderr),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            });
        }

        Ok((exit_code, success))
    }

    fn attack_concurrency(
        &self,
        program: &std::path::PathBuf,
        crashes: &mut Vec<CrashReport>,
    ) -> Result<(Option<i32>, bool)> {
        // Concurrency storm: spawn many threads/tasks
        let threads = (50.0 * self.config.intensity.multiplier()) as u64;

        let output = Command::new(program)
            .arg("--threads")
            .arg(threads.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("Failed to execute program")?;

        let success = output.status.success();
        let exit_code = output.status.code();

        if !success {
            crashes.push(CrashReport {
                timestamp: chrono::Utc::now().to_rfc3339(),
                signal: Self::extract_signal(&output.stderr),
                backtrace: Self::extract_backtrace(&output.stderr),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            });
        }

        Ok((exit_code, success))
    }

    fn attack_time(
        &self,
        program: &std::path::PathBuf,
        crashes: &mut Vec<CrashReport>,
    ) -> Result<(Option<i32>, bool)> {
        // Time-based attacks: run for extended duration
        let duration_secs = (60.0 * self.config.intensity.multiplier()) as u64;

        let output = Command::new("timeout")
            .arg(duration_secs.to_string())
            .arg(program)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("Failed to execute program")?;

        let success = output.status.success();
        let exit_code = output.status.code();

        if !success {
            crashes.push(CrashReport {
                timestamp: chrono::Utc::now().to_rfc3339(),
                signal: Self::extract_signal(&output.stderr),
                backtrace: Self::extract_backtrace(&output.stderr),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            });
        }

        Ok((exit_code, success))
    }

    fn extract_signal(stderr: &[u8]) -> Option<String> {
        let stderr_str = String::from_utf8_lossy(stderr);
        if stderr_str.contains("SIGSEGV") {
            Some("SIGSEGV".to_string())
        } else if stderr_str.contains("SIGABRT") {
            Some("SIGABRT".to_string())
        } else if stderr_str.contains("SIGILL") {
            Some("SIGILL".to_string())
        } else {
            None
        }
    }

    fn extract_backtrace(stderr: &[u8]) -> Option<String> {
        let stderr_str = String::from_utf8_lossy(stderr);
        if stderr_str.contains("backtrace") || stderr_str.contains("stack backtrace") {
            Some(stderr_str.to_string())
        } else {
            None
        }
    }
}
