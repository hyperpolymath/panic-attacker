// SPDX-License-Identifier: PMPL-1.0-or-later

//! Core X-Ray analyzer implementation

use crate::types::*;
use anyhow::{Context, Result};
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

pub struct Analyzer {
    target: PathBuf,
    language: Language,
}

impl Analyzer {
    pub fn new(target: &Path) -> Result<Self> {
        if !target.exists() {
            anyhow::bail!("Target does not exist: {}", target.display());
        }

        let language = if target.is_file() {
            Language::detect(target.to_str().unwrap_or(""))
        } else {
            // For directories, scan for predominant language
            Self::detect_directory_language(target)?
        };

        Ok(Self {
            target: target.to_path_buf(),
            language,
        })
    }

    pub fn analyze(&self) -> Result<XRayReport> {
        let mut weak_points = Vec::new();
        let mut statistics = ProgramStatistics {
            total_lines: 0,
            unsafe_blocks: 0,
            panic_sites: 0,
            unwrap_calls: 0,
            allocation_sites: 0,
            io_operations: 0,
            threading_constructs: 0,
        };

        // Collect all source files
        let files = self.collect_source_files()?;

        for file in &files {
            let content = fs::read_to_string(file)
                .with_context(|| format!("Failed to read {}", file.display()))?;

            // Update statistics
            statistics.total_lines += content.lines().count();

            // Language-specific analysis
            match self.language {
                Language::Rust => {
                    self.analyze_rust(&content, &mut statistics, &mut weak_points)?;
                }
                Language::C | Language::Cpp => {
                    self.analyze_c_cpp(&content, &mut statistics, &mut weak_points)?;
                }
                Language::Go => {
                    self.analyze_go(&content, &mut statistics, &mut weak_points)?;
                }
                Language::Python => {
                    self.analyze_python(&content, &mut statistics, &mut weak_points)?;
                }
                _ => {
                    // Generic analysis for other languages
                    self.analyze_generic(&content, &mut statistics, &mut weak_points)?;
                }
            }
        }

        // Detect frameworks
        let frameworks = self.detect_frameworks(&files)?;

        // Generate recommendations
        let recommended_attacks = self.generate_recommendations(&weak_points, &statistics);

        Ok(XRayReport {
            program_path: self.target.clone(),
            language: self.language,
            frameworks,
            weak_points,
            statistics,
            recommended_attacks,
        })
    }

    fn collect_source_files(&self) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();

        if self.target.is_file() {
            files.push(self.target.clone());
        } else {
            self.walk_directory(&self.target, &mut files)?;
        }

        Ok(files)
    }

    fn walk_directory(&self, dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                // Skip common non-source directories
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if !["target", "build", "node_modules", ".git", "vendor"].contains(&name) {
                    self.walk_directory(&path, files)?;
                }
            } else if path.is_file() {
                let lang = Language::detect(path.to_str().unwrap_or(""));
                if lang != Language::Unknown {
                    files.push(path);
                }
            }
        }

        Ok(())
    }

    fn detect_directory_language(dir: &Path) -> Result<Language> {
        let mut counts = std::collections::HashMap::new();

        Self::count_languages_recursive(dir, &mut counts, 0)?;

        counts.remove(&Language::Unknown);

        counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(lang, _)| lang)
            .ok_or_else(|| anyhow::anyhow!("Could not detect language"))
    }

    fn count_languages_recursive(
        dir: &Path,
        counts: &mut std::collections::HashMap<Language, usize>,
        depth: usize,
    ) -> Result<()> {
        if depth > 10 {
            return Ok(());
        }
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            let name_str = name.to_str().unwrap_or("");

            if path.is_dir() {
                // Skip build artifacts and hidden dirs
                if name_str.starts_with('.')
                    || name_str == "target"
                    || name_str == "node_modules"
                    || name_str == "vendor"
                    || name_str == "build"
                {
                    continue;
                }
                Self::count_languages_recursive(&path, counts, depth + 1)?;
            } else if path.is_file() {
                let lang = Language::detect(path.to_str().unwrap_or(""));
                *counts.entry(lang).or_insert(0) += 1;
            }
        }
        Ok(())
    }

    fn analyze_rust(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
    ) -> Result<()> {
        // Count unsafe blocks
        stats.unsafe_blocks += content.matches("unsafe {").count();
        stats.unsafe_blocks += content.matches("unsafe fn").count();

        // Count panic sites
        stats.panic_sites += content.matches("panic!(").count();
        stats.panic_sites += content.matches("unreachable!(").count();

        // Count unwraps
        stats.unwrap_calls += content.matches(".unwrap()").count();
        stats.unwrap_calls += content.matches(".expect(").count();

        // Count allocations
        stats.allocation_sites += content.matches("Vec::new()").count();
        stats.allocation_sites += content.matches("Box::new(").count();
        stats.allocation_sites += content.matches("String::new()").count();

        // Count I/O operations
        stats.io_operations += content.matches("std::fs::").count();
        stats.io_operations += content.matches("std::io::").count();

        // Count threading
        stats.threading_constructs += content.matches("std::thread::").count();
        stats.threading_constructs += content.matches("std::sync::").count();

        // Detect weak points
        if stats.unsafe_blocks > 0 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: None,
                severity: Severity::High,
                description: format!("{} unsafe blocks detected", stats.unsafe_blocks),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Concurrency],
            });
        }

        if stats.unwrap_calls > 5 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::PanicPath,
                location: None,
                severity: Severity::Medium,
                description: format!("{} unwrap/expect calls detected", stats.unwrap_calls),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Disk],
            });
        }

        Ok(())
    }

    fn analyze_c_cpp(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
    ) -> Result<()> {
        // Count allocations
        stats.allocation_sites += content.matches("malloc(").count();
        stats.allocation_sites += content.matches("calloc(").count();
        stats.allocation_sites += content.matches("new ").count();

        // Count I/O
        stats.io_operations += content.matches("fopen(").count();
        stats.io_operations += content.matches("read(").count();
        stats.io_operations += content.matches("write(").count();

        // Count threading
        stats.threading_constructs += content.matches("pthread_").count();
        stats.threading_constructs += content.matches("std::thread").count();

        // Detect weak points
        let unchecked_malloc = Regex::new(r"malloc\([^)]+\)\s*;").unwrap();
        if unchecked_malloc.is_match(content) {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UncheckedAllocation,
                location: None,
                severity: Severity::Critical,
                description: "Unchecked malloc detected".to_string(),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        Ok(())
    }

    fn analyze_go(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
    ) -> Result<()> {
        stats.allocation_sites += content.matches("make(").count();
        stats.threading_constructs += content.matches("go func").count();
        stats.threading_constructs += content.matches("go ").count();

        // Detect goroutine leaks
        let go_count = content.matches("go ").count();
        if go_count > 10 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::ResourceLeak,
                location: None,
                severity: Severity::Medium,
                description: format!("{} goroutines spawned", go_count),
                recommended_attack: vec![AttackAxis::Concurrency, AttackAxis::Memory],
            });
        }

        Ok(())
    }

    fn analyze_python(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
    ) -> Result<()> {
        stats.io_operations += content.matches("open(").count();
        stats.threading_constructs += content.matches("threading.").count();

        // Detect unbounded loops
        if content.contains("while True:") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnboundedLoop,
                location: None,
                severity: Severity::High,
                description: "Unbounded while True loop detected".to_string(),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Time],
            });
        }

        Ok(())
    }

    fn analyze_generic(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        _weak_points: &mut Vec<WeakPoint>,
    ) -> Result<()> {
        // Generic heuristics
        stats.allocation_sites += content.matches("alloc").count();
        stats.io_operations += content.matches("open").count();
        stats.threading_constructs += content.matches("thread").count();

        Ok(())
    }

    fn detect_frameworks(&self, files: &[PathBuf]) -> Result<Vec<Framework>> {
        let mut frameworks = HashSet::new();

        for file in files {
            let content = fs::read_to_string(file)?;

            // Web servers
            if content.contains("actix_web")
                || content.contains("warp")
                || content.contains("axum")
                || content.contains("rocket")
                || content.contains("express")
                || content.contains("flask")
            {
                frameworks.insert(Framework::WebServer);
            }

            // Databases
            if content.contains("diesel")
                || content.contains("sqlx")
                || content.contains("mongodb")
                || content.contains("postgres")
            {
                frameworks.insert(Framework::Database);
            }

            // Message queues
            if content.contains("kafka")
                || content.contains("rabbitmq")
                || content.contains("nats")
            {
                frameworks.insert(Framework::MessageQueue);
            }

            // Caching
            if content.contains("redis") || content.contains("memcached") {
                frameworks.insert(Framework::Cache);
            }

            // Networking
            if content.contains("tokio") || content.contains("async_std") {
                frameworks.insert(Framework::Networking);
            }

            // Concurrency
            if content.contains("rayon") || content.contains("crossbeam") {
                frameworks.insert(Framework::Concurrent);
            }
        }

        Ok(frameworks.into_iter().collect())
    }

    fn generate_recommendations(
        &self,
        weak_points: &[WeakPoint],
        stats: &ProgramStatistics,
    ) -> Vec<AttackAxis> {
        let mut recommendations = HashSet::new();

        // Based on weak points
        for wp in weak_points {
            recommendations.extend(&wp.recommended_attack);
        }

        // Based on statistics
        if stats.allocation_sites > 10 {
            recommendations.insert(AttackAxis::Memory);
        }

        if stats.io_operations > 5 {
            recommendations.insert(AttackAxis::Disk);
        }

        if stats.threading_constructs > 3 {
            recommendations.insert(AttackAxis::Concurrency);
        }

        // Always include CPU stress
        recommendations.insert(AttackAxis::Cpu);

        recommendations.into_iter().collect()
    }
}
