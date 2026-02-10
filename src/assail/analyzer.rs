// SPDX-License-Identifier: PMPL-1.0-or-later

//! Core Assail analyzer implementation
//!
//! Language-specific static analysis for 40+ programming languages.
//! Detects weak points, unsafe patterns, and security anti-patterns
//! across BEAM, ML, Lisp, proof assistant, logic programming,
//! systems, functional, config, scripting, and custom DSL families.

use crate::types::*;
use anyhow::Result;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

pub struct Analyzer {
    target: PathBuf,
    language: Language,
    verbose: bool,
}

impl Analyzer {
    pub fn new(target: &Path) -> Result<Self> {
        Self::build(target, false)
    }

    pub fn new_verbose(target: &Path) -> Result<Self> {
        Self::build(target, true)
    }

    fn build(target: &Path, verbose: bool) -> Result<Self> {
        if !target.exists() {
            anyhow::bail!("Target does not exist: {}", target.display());
        }

        let language = if target.is_file() {
            Language::detect(target.to_str().unwrap_or(""))
        } else {
            Self::detect_directory_language(target)?
        };

        Ok(Self {
            target: target.to_path_buf(),
            language,
            verbose,
        })
    }

    pub fn analyze(&self) -> Result<AssailReport> {
        let mut global_stats = ProgramStatistics {
            total_lines: 0,
            unsafe_blocks: 0,
            panic_sites: 0,
            unwrap_calls: 0,
            allocation_sites: 0,
            io_operations: 0,
            threading_constructs: 0,
        };
        let mut all_weak_points = Vec::new();
        let mut file_statistics = Vec::new();

        let files = self.collect_source_files()?;

        let base = if self.target.is_dir() {
            self.target.clone()
        } else {
            self.target.parent().unwrap_or(Path::new(".")).to_path_buf()
        };

        for file in &files {
            let raw_bytes = match fs::read(file) {
                Ok(b) => b,
                Err(e) => {
                    if self.verbose {
                        eprintln!("Skipping unreadable file: {} ({})", file.display(), e);
                    }
                    continue;
                }
            };

            // Try UTF-8 first, then Latin-1 fallback
            let content = match String::from_utf8(raw_bytes.clone()) {
                Ok(s) => s,
                Err(_) => {
                    let (cow, _, had_errors) = encoding_rs::WINDOWS_1252.decode(&raw_bytes);
                    if had_errors {
                        if self.verbose {
                            eprintln!(
                                "Skipping non-text file: {} (neither UTF-8 nor Latin-1)",
                                file.display()
                            );
                        }
                        continue;
                    }
                    cow.into_owned()
                }
            };

            let rel_path = file
                .strip_prefix(&base)
                .unwrap_or(file)
                .to_string_lossy()
                .to_string();

            let mut file_stats = ProgramStatistics {
                total_lines: 0,
                unsafe_blocks: 0,
                panic_sites: 0,
                unwrap_calls: 0,
                allocation_sites: 0,
                io_operations: 0,
                threading_constructs: 0,
            };

            file_stats.total_lines = content.lines().count();

            let mut file_weak_points = Vec::new();

            // Dispatch to language-specific analyzer
            let file_lang = Language::detect(file.to_str().unwrap_or(""));
            match file_lang {
                Language::Rust => {
                    self.analyze_rust(&content, &mut file_stats, &mut file_weak_points, &rel_path)?;
                }
                Language::C | Language::Cpp => {
                    self.analyze_c_cpp(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                Language::Go => {
                    self.analyze_go(&content, &mut file_stats, &mut file_weak_points, &rel_path)?;
                }
                Language::Python => {
                    self.analyze_python(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                Language::JavaScript => {
                    self.analyze_javascript(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                Language::Ruby => {
                    self.analyze_ruby(&content, &mut file_stats, &mut file_weak_points, &rel_path)?;
                }
                // BEAM family
                Language::Elixir => {
                    self.analyze_elixir(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                Language::Erlang => {
                    self.analyze_erlang(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                Language::Gleam => {
                    self.analyze_gleam(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                // ML family
                Language::ReScript => {
                    self.analyze_rescript(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                Language::OCaml => {
                    self.analyze_ocaml(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                Language::StandardML => {
                    self.analyze_sml(&content, &mut file_stats, &mut file_weak_points, &rel_path)?;
                }
                // Lisp family
                Language::Scheme | Language::Racket => {
                    self.analyze_lisp(&content, &mut file_stats, &mut file_weak_points, &rel_path)?;
                }
                // Functional
                Language::Haskell => {
                    self.analyze_haskell(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                Language::PureScript => {
                    self.analyze_purescript(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                // Proof assistants
                Language::Idris => {
                    self.analyze_idris(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                Language::Lean => {
                    self.analyze_lean(&content, &mut file_stats, &mut file_weak_points, &rel_path)?;
                }
                Language::Agda => {
                    self.analyze_agda(&content, &mut file_stats, &mut file_weak_points, &rel_path)?;
                }
                // Logic programming
                Language::Prolog | Language::Logtalk | Language::Datalog => {
                    self.analyze_logic(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                // Systems languages
                Language::Zig => {
                    self.analyze_zig(&content, &mut file_stats, &mut file_weak_points, &rel_path)?;
                }
                Language::Ada => {
                    self.analyze_ada(&content, &mut file_stats, &mut file_weak_points, &rel_path)?;
                }
                Language::Odin => {
                    self.analyze_odin(&content, &mut file_stats, &mut file_weak_points, &rel_path)?;
                }
                Language::Nim => {
                    self.analyze_nim(&content, &mut file_stats, &mut file_weak_points, &rel_path)?;
                }
                Language::Pony => {
                    self.analyze_pony(&content, &mut file_stats, &mut file_weak_points, &rel_path)?;
                }
                Language::DLang => {
                    self.analyze_dlang(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                // Config languages
                Language::Nickel | Language::Nix => {
                    self.analyze_config(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                // Scripting
                Language::Shell => {
                    self.analyze_shell(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                Language::Julia => {
                    self.analyze_julia(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                Language::Lua => {
                    self.analyze_lua(&content, &mut file_stats, &mut file_weak_points, &rel_path)?;
                }
                // Nextgen DSLs - shared analyzer
                Language::WokeLang
                | Language::Eclexia
                | Language::MyLang
                | Language::JuliaTheViper
                | Language::Oblibeny
                | Language::Anvomidav
                | Language::AffineScript
                | Language::Ephapax
                | Language::BetLang
                | Language::ErrorLang
                | Language::VQL
                | Language::FBQL => {
                    self.analyze_nextgen_dsl(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                Language::Java => {
                    self.analyze_java(&content, &mut file_stats, &mut file_weak_points, &rel_path)?;
                }
                _ => {
                    self.analyze_generic(&content, &mut file_stats, &rel_path)?;
                }
            }

            // Cross-language security checks (run on all files)
            self.analyze_cross_language(&content, &mut file_weak_points, &rel_path)?;

            // Accumulate global stats
            global_stats.total_lines += file_stats.total_lines;
            global_stats.unsafe_blocks += file_stats.unsafe_blocks;
            global_stats.panic_sites += file_stats.panic_sites;
            global_stats.unwrap_calls += file_stats.unwrap_calls;
            global_stats.allocation_sites += file_stats.allocation_sites;
            global_stats.io_operations += file_stats.io_operations;
            global_stats.threading_constructs += file_stats.threading_constructs;

            all_weak_points.extend(file_weak_points);

            let has_findings = file_stats.unsafe_blocks > 0
                || file_stats.panic_sites > 0
                || file_stats.unwrap_calls > 0
                || file_stats.allocation_sites > 0
                || file_stats.io_operations > 0
                || file_stats.threading_constructs > 0;

            if has_findings {
                file_statistics.push(FileStatistics {
                    file_path: rel_path,
                    lines: file_stats.total_lines,
                    unsafe_blocks: file_stats.unsafe_blocks,
                    panic_sites: file_stats.panic_sites,
                    unwrap_calls: file_stats.unwrap_calls,
                    allocation_sites: file_stats.allocation_sites,
                    io_operations: file_stats.io_operations,
                    threading_constructs: file_stats.threading_constructs,
                });
            }
        }

        let frameworks = self.detect_frameworks(&files)?;
        let recommended_attacks = self.generate_recommendations(&all_weak_points, &global_stats);
        let dependency_graph = Self::build_dependency_graph(&file_statistics, &frameworks);
        let taint_matrix = Self::build_taint_matrix(&all_weak_points, &frameworks);

        Ok(AssailReport {
            program_path: self.target.clone(),
            language: self.language,
            frameworks,
            weak_points: all_weak_points,
            statistics: global_stats,
            file_statistics,
            recommended_attacks,
            dependency_graph,
            taint_matrix,
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
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                // Skip build artifacts, hidden dirs, and dependency dirs
                if ![
                    "target",
                    "build",
                    "node_modules",
                    ".git",
                    "vendor",
                    "_build",
                    "_opam",
                    ".stack-work",
                    "dist-newstyle",
                    "deps",
                    "_deps",
                    "zig-cache",
                    "zig-out",
                    ".elixir_ls",
                    ".lexical",
                    "__pycache__",
                    "ebin",
                    "_checkouts",
                    ".fetch",
                    ".hex",
                    ".nimble",
                    ".dub",
                    "obj",
                ]
                .contains(&name)
                {
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
                if name_str.starts_with('.')
                    || [
                        "target",
                        "node_modules",
                        "vendor",
                        "build",
                        "_build",
                        "_opam",
                        ".stack-work",
                        "dist-newstyle",
                        "deps",
                        "zig-cache",
                        "zig-out",
                        "ebin",
                    ]
                    .contains(&name_str)
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

    // ============================================================
    // Original language analyzers
    // ============================================================

    fn analyze_rust(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        stats.unsafe_blocks += content.matches("unsafe {").count();
        stats.unsafe_blocks += content.matches("unsafe fn").count();
        stats.panic_sites += content.matches("panic!(").count();
        stats.panic_sites += content.matches("unreachable!(").count();
        stats.unwrap_calls += content.matches(".unwrap()").count();
        stats.unwrap_calls += content.matches(".expect(").count();
        stats.allocation_sites += content.matches("Vec::new()").count();
        stats.allocation_sites += content.matches("Box::new(").count();
        stats.allocation_sites += content.matches("String::new()").count();
        stats.io_operations += content.matches("std::fs::").count();
        stats.io_operations += content.matches("std::io::").count();
        stats.threading_constructs += content.matches("std::thread::").count();
        stats.threading_constructs += content.matches("std::sync::").count();

        if stats.unsafe_blocks > 0 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("{} unsafe blocks in {}", stats.unsafe_blocks, file_path),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Concurrency],
            });
        }

        if stats.unwrap_calls > 5 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::PanicPath,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!(
                    "{} unwrap/expect calls in {}",
                    stats.unwrap_calls, file_path
                ),
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
        file_path: &str,
    ) -> Result<()> {
        stats.allocation_sites += content.matches("malloc(").count();
        stats.allocation_sites += content.matches("calloc(").count();
        stats.allocation_sites += content.matches("new ").count();
        stats.io_operations += content.matches("fopen(").count();
        stats.io_operations += content.matches("read(").count();
        stats.io_operations += content.matches("write(").count();
        stats.threading_constructs += content.matches("pthread_").count();
        stats.threading_constructs += content.matches("std::thread").count();

        let unchecked_malloc = Regex::new(r"malloc\([^)]+\)\s*;").unwrap();
        if unchecked_malloc.is_match(content) {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UncheckedAllocation,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("Unchecked malloc in {}", file_path),
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
        file_path: &str,
    ) -> Result<()> {
        stats.allocation_sites += content.matches("make(").count();
        stats.threading_constructs += content.matches("go func").count();
        stats.threading_constructs += content.matches("go ").count();

        let go_count = content.matches("go ").count();
        if go_count > 10 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::ResourceLeak,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} goroutines spawned in {}", go_count, file_path),
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
        file_path: &str,
    ) -> Result<()> {
        stats.io_operations += content.matches("open(").count();
        stats.threading_constructs += content.matches("threading.").count();

        if content.contains("while True:") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnboundedLoop,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("Unbounded while True loop in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Time],
            });
        }

        if content.contains("eval(") || content.contains("exec(") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::DynamicCodeExecution,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("Dynamic code execution (eval/exec) in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Memory],
            });
        }

        Ok(())
    }

    fn analyze_javascript(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        stats.io_operations += content.matches("fs.read").count();
        stats.io_operations += content.matches("fs.write").count();
        stats.io_operations += content.matches("fetch(").count();
        stats.threading_constructs += content.matches("Worker(").count();
        stats.threading_constructs += content.matches("new Worker").count();

        if content.contains("eval(") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::DynamicCodeExecution,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("eval() usage in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Memory],
            });
        }

        // Deno -A permission check
        if content.contains("deno run -A") || content.contains("deno run --allow-all") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::ExcessivePermissions,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("Deno -A (all permissions) in {}", file_path),
                recommended_attack: vec![AttackAxis::Network, AttackAxis::Disk],
            });
        }

        // JSON.parseExn / JSON.parse without try-catch
        let parse_exn_count = content.matches("JSON.parseExn").count();
        if parse_exn_count > 0 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeDeserialization,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("{} JSON.parseExn calls in {}", parse_exn_count, file_path),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Cpu],
            });
        }

        Ok(())
    }

    fn analyze_ruby(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        stats.io_operations += content.matches("File.open").count();
        stats.io_operations += content.matches("IO.read").count();
        stats.threading_constructs += content.matches("Thread.new").count();

        if content.contains("eval(") || content.contains("send(") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::DynamicCodeExecution,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("Dynamic code execution in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Memory],
            });
        }

        Ok(())
    }

    fn analyze_java(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        stats.allocation_sites += content.matches("new ").count();
        stats.io_operations += content.matches("FileInputStream").count();
        stats.io_operations += content.matches("FileOutputStream").count();
        stats.threading_constructs += content.matches("new Thread").count();
        stats.threading_constructs += content.matches("ExecutorService").count();

        if content.contains("Runtime.getRuntime().exec(") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("Runtime.exec() in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
            });
        }

        Ok(())
    }

    // ============================================================
    // BEAM family (Elixir, Erlang, Gleam)
    // ============================================================

    fn analyze_elixir(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // Process spawning (concurrency)
        stats.threading_constructs += content.matches("spawn(").count();
        stats.threading_constructs += content.matches("spawn_link(").count();
        stats.threading_constructs += content.matches("Task.async(").count();
        stats.threading_constructs += content.matches("Task.start(").count();
        stats.threading_constructs += content.matches("GenServer.start").count();

        // I/O operations
        stats.io_operations += content.matches("File.read").count();
        stats.io_operations += content.matches("File.write").count();
        stats.io_operations += content.matches("IO.read").count();
        stats.io_operations += content.matches("HTTPoison").count();
        stats.io_operations += content.matches("Req.").count();

        // Allocations (ETS tables, large data structures)
        stats.allocation_sites += content.matches(":ets.new").count();
        stats.allocation_sites += content.matches("Agent.start").count();

        // Dynamic code execution
        if content.contains("Code.eval_string") || content.contains("Code.eval_quoted") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::DynamicCodeExecution,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("Code.eval_string/eval_quoted in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Memory],
            });
        }

        // Atom exhaustion
        let atom_count = content.matches("String.to_atom").count();
        if atom_count > 0 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::AtomExhaustion,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!(
                    "{} String.to_atom calls in {} (use String.to_existing_atom)",
                    atom_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // Port/System.cmd - command injection risk
        if content.contains("Port.open") || content.contains("System.cmd") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("System command execution in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
            });
        }

        // Unsafe apply
        let apply_re = Regex::new(r"apply\([^,]+,\s*[^,]+,").unwrap();
        if apply_re.is_match(content) {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::DynamicCodeExecution,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("Dynamic apply/3 in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu],
            });
        }

        Ok(())
    }

    fn analyze_erlang(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        stats.threading_constructs += content.matches("spawn(").count();
        stats.threading_constructs += content.matches("spawn_link(").count();
        stats.threading_constructs += content.matches("spawn_monitor(").count();
        stats.io_operations += content.matches("file:read").count();
        stats.io_operations += content.matches("file:write").count();
        stats.io_operations += content.matches("httpc:request").count();
        stats.allocation_sites += content.matches("ets:new").count();

        // Atom exhaustion
        let atom_count =
            content.matches("list_to_atom").count() + content.matches("binary_to_atom").count();
        if atom_count > 0 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::AtomExhaustion,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!(
                    "{} unchecked atom creation in {} (use list_to_existing_atom)",
                    atom_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // os:cmd - command injection
        if content.contains("os:cmd") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("os:cmd call in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
            });
        }

        Ok(())
    }

    fn analyze_gleam(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // Gleam external functions (FFI boundary)
        let external_count = content.matches("@external(").count();
        stats.unsafe_blocks += external_count;

        stats.io_operations += content.matches("simplifile").count();
        stats.io_operations += content.matches("gleam/http").count();

        if external_count > 5 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeFFI,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} @external FFI calls in {}", external_count, file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        Ok(())
    }

    // ============================================================
    // ML family (ReScript, OCaml, Standard ML)
    // ============================================================

    fn analyze_rescript(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // External bindings (FFI boundary)
        let external_count = content.matches("@val external").count()
            + content.matches("@module external").count()
            + content.matches("@send external").count()
            + content.matches("@get external").count();
        stats.unsafe_blocks += external_count;

        // Unsafe JSON parsing
        let parse_exn = content.matches("JSON.parseExn").count();
        if parse_exn > 0 {
            stats.panic_sites += parse_exn;
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeDeserialization,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!(
                    "{} JSON.parseExn calls in {} (use JSON.parse for safe Result)",
                    parse_exn, file_path
                ),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Cpu],
            });
        }

        // Mutable refs
        stats.allocation_sites += content.matches("ref(").count();

        // Ignored results (potential mutation bug)
        let ignore_count = content.matches("ignore(").count();
        if ignore_count > 3 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UncheckedError,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!(
                    "{} ignore() calls in {} (may discard important results)",
                    ignore_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // getUnsafe / getExn
        let unsafe_gets = content.matches("getUnsafe").count()
            + content.matches("getExn").count()
            + content.matches("getOrExn").count();
        if unsafe_gets > 0 {
            stats.unwrap_calls += unsafe_gets;
            weak_points.push(WeakPoint {
                category: WeakPointCategory::PanicPath,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} unsafe get calls in {}", unsafe_gets, file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // I/O via Deno/Node APIs
        stats.io_operations += content.matches("Deno.readTextFile").count();
        stats.io_operations += content.matches("Deno.writeTextFile").count();
        stats.io_operations += content.matches("fetch(").count();

        Ok(())
    }

    fn analyze_ocaml(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // Unsafe operations
        if content.contains("Obj.magic") {
            stats.unsafe_blocks += content.matches("Obj.magic").count();
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeTypeCoercion,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("Obj.magic (unsafe type coercion) in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        if content.contains("Obj.repr") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("Obj.repr (unsafe representation access) in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // Unsafe deserialization
        if content.contains("Marshal.from_string") || content.contains("Marshal.from_channel") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeDeserialization,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("Unsafe Marshal deserialization in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Cpu],
            });
        }

        // Command execution
        if content.contains("Unix.system") || content.contains("Unix.execvp") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("Unix.system/execvp command execution in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
            });
        }

        stats.io_operations += content.matches("open_in").count();
        stats.io_operations += content.matches("open_out").count();
        stats.threading_constructs += content.matches("Thread.create").count();
        stats.threading_constructs += content.matches("Mutex.").count();

        Ok(())
    }

    fn analyze_sml(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        stats.io_operations += content.matches("TextIO.").count();
        stats.io_operations += content.matches("BinIO.").count();

        // Unsafe operations
        let unsafe_count =
            content.matches("Unsafe.").count() + content.matches("MLton.Pointer").count();
        if unsafe_count > 0 {
            stats.unsafe_blocks += unsafe_count;
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("{} unsafe operations in {}", unsafe_count, file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // Exception handling
        let raise_count = content.matches("raise ").count();
        stats.panic_sites += raise_count;

        Ok(())
    }

    // ============================================================
    // Lisp family (Scheme, Racket)
    // ============================================================

    fn analyze_lisp(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // Dynamic code execution
        if content.contains("(eval ") || content.contains("(eval\n") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::DynamicCodeExecution,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("eval usage in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Memory],
            });
        }

        // System calls
        if content.contains("(system ") || content.contains("(process ") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("System/process call in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
            });
        }

        // I/O
        stats.io_operations += content.matches("open-input-file").count();
        stats.io_operations += content.matches("open-output-file").count();
        stats.io_operations += content.matches("call-with-input-file").count();
        stats.io_operations += content.matches("call-with-output-file").count();

        // Continuations (can blow the stack)
        let callcc_count = content.matches("call-with-current-continuation").count()
            + content.matches("call/cc").count();
        if callcc_count > 3 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::ResourceLeak,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} call/cc usage in {}", callcc_count, file_path),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Cpu],
            });
        }

        Ok(())
    }

    // ============================================================
    // Functional (Haskell, PureScript)
    // ============================================================

    fn analyze_haskell(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // Unsafe operations
        let unsafe_io = content.matches("unsafePerformIO").count();
        let unsafe_coerce = content.matches("unsafeCoerce").count();
        stats.unsafe_blocks += unsafe_io + unsafe_coerce;

        if unsafe_io > 0 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("{} unsafePerformIO in {}", unsafe_io, file_path),
                recommended_attack: vec![AttackAxis::Concurrency, AttackAxis::Memory],
            });
        }

        if unsafe_coerce > 0 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeTypeCoercion,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("{} unsafeCoerce in {}", unsafe_coerce, file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // Partial functions (crash on empty input)
        let head_count = content.matches(" head ").count() + content.matches("(head ").count();
        let tail_count = content.matches(" tail ").count() + content.matches("(tail ").count();
        let from_just = content.matches("fromJust").count();
        let partials = head_count + tail_count + from_just;
        stats.unwrap_calls += partials;

        if partials > 3 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::PanicPath,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!(
                    "{} partial function calls (head/tail/fromJust) in {}",
                    partials, file_path
                ),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // error/undefined
        let error_count = content.matches("error \"").count()
            + content.matches("error \"").count()
            + content.matches("undefined").count();
        stats.panic_sites += error_count;

        if error_count > 0 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::PanicPath,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("{} error/undefined in {}", error_count, file_path),
                recommended_attack: vec![AttackAxis::Cpu],
            });
        }

        stats.io_operations += content.matches("readFile").count();
        stats.io_operations += content.matches("writeFile").count();
        stats.threading_constructs += content.matches("forkIO").count();
        stats.threading_constructs += content.matches("MVar").count();
        stats.threading_constructs += content.matches("STM").count();

        Ok(())
    }

    fn analyze_purescript(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // FFI boundary
        let ffi_count = content.matches("foreign import").count();
        stats.unsafe_blocks += ffi_count;

        if ffi_count > 5 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeFFI,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} foreign imports in {}", ffi_count, file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // unsafeCoerce / unsafePartial
        if content.contains("unsafeCoerce") || content.contains("unsafePartial") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeTypeCoercion,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("Unsafe coercion in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        Ok(())
    }

    // ============================================================
    // Proof assistants (Idris, Lean, Agda)
    // ============================================================

    fn analyze_idris(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // believe_me bypasses the type checker
        let believe_count = content.matches("believe_me").count();
        if believe_count > 0 {
            stats.unsafe_blocks += believe_count;
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!(
                    "{} believe_me (type checker bypass) in {}",
                    believe_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // unsafePerformIO
        if content.contains("unsafePerformIO") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("unsafePerformIO in {}", file_path),
                recommended_attack: vec![AttackAxis::Concurrency],
            });
        }

        // FFI
        let ffi_count = content.matches("%foreign").count();
        stats.unsafe_blocks += ffi_count;

        Ok(())
    }

    fn analyze_lean(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // sorry - admits unproven propositions
        let sorry_count = content.matches("sorry").count();
        if sorry_count > 0 {
            stats.unsafe_blocks += sorry_count;
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!(
                    "{} sorry (unproven proposition) in {}",
                    sorry_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Cpu],
            });
        }

        // native_decide - can crash at runtime
        if content.contains("native_decide") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::PanicPath,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("native_decide in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Memory],
            });
        }

        // unsafe operations
        if content.contains("unsafeCast") || content.contains("implementedBy") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeTypeCoercion,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("Unsafe cast/implementedBy in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        Ok(())
    }

    fn analyze_agda(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // trustMe bypasses proof obligations
        if content.contains("trustMe") || content.contains("primTrustMe") {
            stats.unsafe_blocks += 1;
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("trustMe/primTrustMe (proof bypass) in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu],
            });
        }

        // COMPILED pragma (FFI boundary)
        let compiled_count =
            content.matches("{-# COMPILED").count() + content.matches("{-# FOREIGN").count();
        stats.unsafe_blocks += compiled_count;

        Ok(())
    }

    // ============================================================
    // Logic programming (Prolog, Logtalk, Datalog)
    // ============================================================

    fn analyze_logic(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // Dynamic predicates (mutable state)
        let assert_count = content.matches("assert(").count()
            + content.matches("assertz(").count()
            + content.matches("asserta(").count();
        let retract_count =
            content.matches("retract(").count() + content.matches("retractall(").count();
        stats.allocation_sites += assert_count + retract_count;

        if assert_count + retract_count > 5 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::RaceCondition,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!(
                    "{} dynamic predicate modifications in {}",
                    assert_count + retract_count,
                    file_path
                ),
                recommended_attack: vec![AttackAxis::Concurrency],
            });
        }

        // System calls
        if content.contains("shell(") || content.contains("process_create(") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("Shell/process_create in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
            });
        }

        // Meta-interpretation (can be slow)
        if content.contains("call(") {
            stats.allocation_sites += content.matches("call(").count();
        }

        stats.io_operations += content.matches("open(").count();
        stats.io_operations += content.matches("read_term(").count();
        stats.io_operations += content.matches("write_term(").count();

        Ok(())
    }

    // ============================================================
    // Systems languages (Zig, Ada, Odin, Nim, Pony, D)
    // ============================================================

    fn analyze_zig(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // Unsafe pointer operations
        let ptr_ops = content.matches("@intToPtr").count()
            + content.matches("@ptrToInt").count()
            + content.matches("@ptrCast").count();
        stats.unsafe_blocks += ptr_ops;

        if ptr_ops > 0 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("{} unsafe pointer casts in {}", ptr_ops, file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // C interop
        let c_import = content.matches("@cImport").count();
        stats.unsafe_blocks += c_import;

        // unreachable (crash if reached)
        let unreachable_count = content.matches("unreachable").count();
        stats.panic_sites += unreachable_count;

        // Allocator usage
        stats.allocation_sites += content.matches("allocator.alloc").count();
        stats.allocation_sites += content.matches("allocator.create").count();

        stats.io_operations += content.matches("std.fs.").count();
        stats.io_operations += content.matches("std.net.").count();
        stats.threading_constructs += content.matches("std.Thread").count();
        stats.threading_constructs += content.matches("@import(\"std\").Thread").count();

        Ok(())
    }

    fn analyze_ada(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // Unchecked operations
        let unchecked = content.matches("Unchecked_Conversion").count()
            + content.matches("Unchecked_Deallocation").count()
            + content.matches("Unchecked_Access").count();
        stats.unsafe_blocks += unchecked;

        if unchecked > 0 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("{} Unchecked_* operations in {}", unchecked, file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // pragma Suppress (disables runtime checks)
        if content.contains("pragma Suppress") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("pragma Suppress (runtime checks disabled) in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Cpu],
            });
        }

        // Tasking (concurrency)
        stats.threading_constructs += content.matches("task type").count();
        stats.threading_constructs += content.matches("task body").count();
        stats.threading_constructs += content.matches("protected type").count();

        stats.io_operations += content.matches("Ada.Text_IO").count();
        stats.io_operations += content.matches("Ada.Streams").count();
        stats.allocation_sites += content.matches("new ").count();

        Ok(())
    }

    fn analyze_odin(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // Raw pointers
        let raw_ptr = content.matches("rawptr").count() + content.matches("^").count(); // pointer dereference
        stats.unsafe_blocks += content.matches("rawptr").count();

        if content.contains("#force_inline") || content.contains("#force_no_inline") {
            stats.unsafe_blocks += 1;
        }

        // Foreign imports
        let foreign_count = content.matches("foreign import").count();
        stats.unsafe_blocks += foreign_count;

        stats.allocation_sites += content.matches("make(").count();
        stats.allocation_sites += content.matches("new(").count();
        stats.io_operations += content.matches("os.read").count();
        stats.io_operations += content.matches("os.write").count();
        stats.threading_constructs += content.matches("thread.create").count();

        if raw_ptr > 0 {
            // Only flag if rawptr explicitly used
            let rawptr_count = content.matches("rawptr").count();
            if rawptr_count > 0 {
                weak_points.push(WeakPoint {
                    category: WeakPointCategory::UnsafeCode,
                    location: Some(file_path.to_string()),
                    severity: Severity::Medium,
                    description: format!("{} rawptr usage in {}", rawptr_count, file_path),
                    recommended_attack: vec![AttackAxis::Memory],
                });
            }
        }

        Ok(())
    }

    fn analyze_nim(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // Unsafe pragmas
        if content.contains("{.emit:") || content.contains("{.emit.}") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("emit pragma (raw code injection) in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Cpu],
            });
        }

        // cast (unsafe type coercion)
        let cast_count = content.matches("cast[").count();
        if cast_count > 0 {
            stats.unsafe_blocks += cast_count;
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeTypeCoercion,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("{} cast[] (unsafe coercion) in {}", cast_count, file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // unsafeAddr
        if content.contains("unsafeAddr") {
            stats.unsafe_blocks += 1;
        }

        stats.allocation_sites += content.matches("new(").count();
        stats.allocation_sites += content.matches("alloc(").count();
        stats.io_operations += content.matches("readFile(").count();
        stats.io_operations += content.matches("writeFile(").count();
        stats.threading_constructs += content.matches("spawn ").count();
        stats.threading_constructs += content.matches("createThread").count();

        Ok(())
    }

    fn analyze_pony(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // FFI calls (@ prefix)
        let ffi_re = Regex::new(r"@[a-zA-Z_]\w*\[").unwrap();
        let ffi_count = ffi_re.find_iter(content).count();
        stats.unsafe_blocks += ffi_count;

        if ffi_count > 3 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeFFI,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} FFI calls in {}", ffi_count, file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // recover blocks (capability manipulation)
        stats.unsafe_blocks += content.matches("recover").count();
        stats.threading_constructs += content.matches("actor ").count();

        Ok(())
    }

    fn analyze_dlang(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // @system (unsafe by default)
        let system_count = content.matches("@system").count();
        stats.unsafe_blocks += system_count;

        // @trusted (unsafe but marked as "trusted")
        let trusted_count = content.matches("@trusted").count();
        stats.unsafe_blocks += trusted_count;

        if system_count > 5 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} @system functions in {}", system_count, file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // __traits (compiler intrinsics)
        stats.unsafe_blocks += content.matches("__traits").count();

        stats.allocation_sites += content.matches("new ").count();
        stats.io_operations += content.matches("std.stdio").count();
        stats.threading_constructs += content.matches("spawn(").count();
        stats.threading_constructs += content.matches("std.concurrency").count();

        Ok(())
    }

    // ============================================================
    // Config languages (Nickel, Nix)
    // ============================================================

    fn analyze_config(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // Nix-specific
        if file_path.ends_with(".nix") {
            // builtins.exec (arbitrary command execution)
            if content.contains("builtins.exec") {
                weak_points.push(WeakPoint {
                    category: WeakPointCategory::CommandInjection,
                    location: Some(file_path.to_string()),
                    severity: Severity::Critical,
                    description: format!("builtins.exec (command execution) in {}", file_path),
                    recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
                });
            }

            // import from untrusted paths
            let import_count = content.matches("import ").count();
            stats.io_operations += import_count;

            // fetchurl / fetchGit (network)
            stats.io_operations += content.matches("fetchurl").count();
            stats.io_operations += content.matches("fetchGit").count();
            stats.io_operations += content.matches("fetchFromGitHub").count();
        }

        // Nickel-specific
        if file_path.ends_with(".ncl") {
            // import (file reading)
            stats.io_operations += content.matches("import ").count();
        }

        Ok(())
    }

    // ============================================================
    // Shell scripting
    // ============================================================

    fn analyze_shell(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        stats.io_operations += content.matches("cat ").count();
        stats.io_operations += content.matches("curl ").count();
        stats.io_operations += content.matches("wget ").count();

        // Command injection via eval
        if content.contains("eval ") || content.contains("eval\t") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("eval usage in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
            });
        }

        // Unquoted variable expansion (potential injection)
        let unquoted_var = Regex::new(r#"\$[A-Za-z_]\w*"#).unwrap();
        let dollar_vars = unquoted_var.find_iter(content).count();
        // Only flag if high number of unquoted vars
        if dollar_vars > 20 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!(
                    "{} potentially unquoted variable expansions in {}",
                    dollar_vars, file_path
                ),
                recommended_attack: vec![AttackAxis::Cpu],
            });
        }

        // World-writable permissions
        if content.contains("chmod 777") || content.contains("chmod a+w") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::ExcessivePermissions,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("World-writable permissions in {}", file_path),
                recommended_attack: vec![AttackAxis::Disk],
            });
        }

        // Deno -A in shell scripts
        if content.contains("deno run -A") || content.contains("deno run --allow-all") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::ExcessivePermissions,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("Deno -A (all permissions) in {}", file_path),
                recommended_attack: vec![AttackAxis::Network, AttackAxis::Disk],
            });
        }

        // Unsafe temp files
        if content.contains("/tmp/") && !content.contains("mktemp") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::PathTraversal,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("Hardcoded /tmp/ path without mktemp in {}", file_path),
                recommended_attack: vec![AttackAxis::Disk],
            });
        }

        Ok(())
    }

    // ============================================================
    // Julia
    // ============================================================

    fn analyze_julia(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // eval / Meta.parse (dynamic code execution)
        if content.contains("eval(") || content.contains("Meta.parse(") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::DynamicCodeExecution,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("eval/Meta.parse in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Memory],
            });
        }

        // ccall / @ccall (FFI)
        let ccall_count = content.matches("ccall(").count() + content.matches("@ccall").count();
        stats.unsafe_blocks += ccall_count;

        if ccall_count > 0 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeFFI,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} ccall/FFI calls in {}", ccall_count, file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // Unsafe pointer operations
        let ptr_ops = content.matches("pointer_from_objref").count()
            + content.matches("unsafe_load").count()
            + content.matches("unsafe_store!").count();
        stats.unsafe_blocks += ptr_ops;

        stats.io_operations += content.matches("open(").count();
        stats.io_operations += content.matches("read(").count();
        stats.io_operations += content.matches("write(").count();
        stats.io_operations += content.matches("download(").count();
        stats.threading_constructs += content.matches("@spawn").count();
        stats.threading_constructs += content.matches("Threads.@threads").count();
        stats.threading_constructs += content.matches("@distributed").count();
        stats.allocation_sites += content.matches("Array{").count();

        Ok(())
    }

    // ============================================================
    // Lua
    // ============================================================

    fn analyze_lua(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // Dynamic code execution
        if content.contains("loadstring(") || content.contains("dofile(") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::DynamicCodeExecution,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("loadstring/dofile in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Memory],
            });
        }

        // os.execute (command injection)
        if content.contains("os.execute(") || content.contains("io.popen(") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("os.execute/io.popen in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
            });
        }

        stats.io_operations += content.matches("io.open(").count();
        stats.io_operations += content.matches("io.read(").count();
        stats.threading_constructs += content.matches("coroutine.").count();

        Ok(())
    }

    // ============================================================
    // Nextgen custom DSLs (shared analyzer)
    // ============================================================

    fn analyze_nextgen_dsl(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // Generic pattern detection for custom DSLs
        // These languages are custom and type-safe by design,
        // so we mainly check for FFI boundaries and resource usage

        // FFI / external bindings
        let ffi_patterns = content.matches("foreign").count()
            + content.matches("external").count()
            + content.matches("@ffi").count()
            + content.matches("@native").count();
        stats.unsafe_blocks += ffi_patterns;

        if ffi_patterns > 3 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeFFI,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} FFI/external bindings in {}", ffi_patterns, file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // Resource budgets (Eclexia-specific)
        if file_path.ends_with(".ecl") {
            stats.allocation_sites += content.matches("budget").count();
        }

        // Unsafe/unverified blocks
        let unsafe_count = content.matches("unsafe").count() + content.matches("unchecked").count();
        stats.unsafe_blocks += unsafe_count;

        stats.io_operations += content.matches("read").count().min(10); // cap for generic matches
        stats.io_operations += content.matches("write").count().min(10);

        Ok(())
    }

    // ============================================================
    // Cross-language security checks (run on ALL files)
    // ============================================================

    fn analyze_cross_language(
        &self,
        content: &str,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // HTTP (insecure) URLs - should be HTTPS
        // Count http:// URLs that are NOT localhost/127.0.0.1 (those are fine)
        let http_re = Regex::new(r#"http://[a-zA-Z0-9]"#).unwrap();
        let http_localhost_re =
            Regex::new(r#"http://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])"#).unwrap();
        let http_total = http_re.find_iter(content).count();
        let http_local = http_localhost_re.find_iter(content).count();
        let http_count = http_total.saturating_sub(http_local);
        if http_count > 0 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::InsecureProtocol,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} HTTP (non-HTTPS) URLs in {}", http_count, file_path),
                recommended_attack: vec![AttackAxis::Network],
            });
        }

        // Hardcoded secrets patterns
        let secret_re = Regex::new(
            r#"(?i)(api[_-]?key|api[_-]?secret|password|passwd|secret[_-]?key|access[_-]?token|private[_-]?key)\s*[=:]\s*["'][^"']{8,}"#
        ).unwrap();
        if secret_re.is_match(content) {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::HardcodedSecret,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("Possible hardcoded secret in {}", file_path),
                recommended_attack: vec![AttackAxis::Network],
            });
        }

        // TODO/FIXME/HACK/XXX markers
        let todo_count = content.matches("TODO").count()
            + content.matches("FIXME").count()
            + content.matches("HACK").count()
            + content.matches("XXX").count();
        if todo_count > 10 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UncheckedError,
                location: Some(file_path.to_string()),
                severity: Severity::Low,
                description: format!("{} TODO/FIXME/HACK markers in {}", todo_count, file_path),
                recommended_attack: vec![AttackAxis::Cpu],
            });
        }

        Ok(())
    }

    // ============================================================
    // Generic fallback
    // ============================================================

    fn analyze_generic(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        _file_path: &str,
    ) -> Result<()> {
        stats.allocation_sites += content.matches("alloc").count();
        stats.io_operations += content.matches("open").count();
        stats.threading_constructs += content.matches("thread").count();

        Ok(())
    }

    // ============================================================
    // Framework detection (expanded)
    // ============================================================

    fn detect_frameworks(&self, files: &[PathBuf]) -> Result<Vec<Framework>> {
        let mut frameworks = HashSet::new();

        for file in files {
            let content = match fs::read_to_string(file) {
                Ok(c) => c,
                Err(_) => continue,
            };

            // Web servers (original)
            if content.contains("actix_web")
                || content.contains("warp")
                || content.contains("axum")
                || content.contains("rocket")
                || content.contains("express")
                || content.contains("flask")
                || content.contains("Plug.Router")
                || content.contains("Bandit")
            {
                frameworks.insert(Framework::WebServer);
            }

            // Phoenix (Elixir web framework)
            if content.contains("Phoenix.") || content.contains("use Phoenix") {
                frameworks.insert(Framework::Phoenix);
            }

            // Ecto (Elixir database)
            if content.contains("Ecto.") || content.contains("use Ecto") {
                frameworks.insert(Framework::Ecto);
            }

            // OTP (BEAM supervision trees)
            if content.contains("GenServer")
                || content.contains("Supervisor")
                || content.contains("gen_server")
                || content.contains("supervisor")
            {
                frameworks.insert(Framework::OTP);
            }

            // Cowboy (Erlang web server)
            if content.contains("cowboy") || content.contains(":cowboy") {
                frameworks.insert(Framework::Cowboy);
            }

            // Databases (original + expanded)
            if content.contains("diesel")
                || content.contains("sqlx")
                || content.contains("mongodb")
                || content.contains("postgres")
                || content.contains("Ecto.Repo")
                || content.contains("Mnesia")
            {
                frameworks.insert(Framework::Database);
            }

            // Message queues
            if content.contains("kafka")
                || content.contains("rabbitmq")
                || content.contains("nats")
                || content.contains("Broadway")
            {
                frameworks.insert(Framework::MessageQueue);
            }

            // Caching
            if content.contains("redis")
                || content.contains("memcached")
                || content.contains("Cachex")
                || content.contains("ConCache")
            {
                frameworks.insert(Framework::Cache);
            }

            // Networking
            if content.contains("tokio")
                || content.contains("async_std")
                || content.contains("Mint")
                || content.contains("Finch")
            {
                frameworks.insert(Framework::Networking);
            }

            // Concurrency
            if content.contains("rayon")
                || content.contains("crossbeam")
                || content.contains("Flow")
                || content.contains("GenStage")
            {
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

        for wp in weak_points {
            recommendations.extend(&wp.recommended_attack);
        }

        if stats.allocation_sites > 10 {
            recommendations.insert(AttackAxis::Memory);
        }

        if stats.io_operations > 5 {
            recommendations.insert(AttackAxis::Disk);
        }

        if stats.threading_constructs > 3 {
            recommendations.insert(AttackAxis::Concurrency);
        }

        recommendations.insert(AttackAxis::Cpu);

        recommendations.into_iter().collect()
    }

    fn build_dependency_graph(
        file_statistics: &[FileStatistics],
        frameworks: &[Framework],
    ) -> DependencyGraph {
        let mut edges = Vec::new();
        let mut dir_groups: HashMap<String, Vec<String>> = HashMap::new();

        for stat in file_statistics {
            let dir = Path::new(&stat.file_path)
                .parent()
                .and_then(|p| p.to_str())
                .unwrap_or(".")
                .to_string();
            dir_groups
                .entry(dir)
                .or_default()
                .push(stat.file_path.clone());
        }

        for (dir, files) in dir_groups {
            for window in files.windows(2) {
                if let [from, to] = &window {
                    edges.push(DependencyEdge {
                        from: from.clone(),
                        to: to.clone(),
                        relation: format!("shared_dir:{}", dir),
                        weight: 1.0,
                    });
                }
            }
        }

        for stat in file_statistics {
            let risk = (stat.unsafe_blocks * 3
                + stat.panic_sites * 2
                + stat.unwrap_calls
                + stat.threading_constructs * 2) as f64;
            for framework in frameworks {
                edges.push(DependencyEdge {
                    from: stat.file_path.clone(),
                    to: format!("{:?}", framework),
                    relation: "framework".to_string(),
                    weight: risk.max(1.0),
                });
            }
        }

        DependencyGraph { edges }
    }

    fn build_taint_matrix(weak_points: &[WeakPoint], frameworks: &[Framework]) -> TaintMatrix {
        let mut matrix: HashMap<(WeakPointCategory, AttackAxis), TaintMatrixRow> = HashMap::new();

        for wp in weak_points {
            for axis in &wp.recommended_attack {
                let key = (wp.category, *axis);
                let entry = matrix.entry(key).or_insert_with(|| TaintMatrixRow {
                    source_category: wp.category,
                    sink_axis: *axis,
                    severity_value: Self::severity_value(wp.severity),
                    files: Vec::new(),
                    frameworks: frameworks.to_vec(),
                    relation: format!("{:?}->{:?}", wp.category, axis),
                });
                entry
                    .files
                    .push(wp.location.clone().unwrap_or_else(|| "unknown".to_string()));
                entry.severity_value = entry.severity_value.max(Self::severity_value(wp.severity));
            }
        }

        TaintMatrix {
            rows: matrix.into_values().collect(),
        }
    }

    fn severity_value(severity: Severity) -> f64 {
        match severity {
            Severity::Low => 1.0,
            Severity::Medium => 2.5,
            Severity::High => 3.5,
            Severity::Critical => 5.0,
        }
    }
}
