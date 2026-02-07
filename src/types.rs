// SPDX-License-Identifier: PMPL-1.0-or-later

//! Core type definitions for panic-attacker

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Supported programming languages
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    Rust,
    C,
    Cpp,
    Go,
    Java,
    Python,
    JavaScript,
    Ruby,
    Unknown,
}

impl Language {
    pub fn detect(path: &str) -> Self {
        let ext = std::path::Path::new(path)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("");

        match ext {
            "rs" => Language::Rust,
            "c" | "h" => Language::C,
            "cpp" | "cc" | "cxx" | "hpp" => Language::Cpp,
            "go" => Language::Go,
            "java" => Language::Java,
            "py" => Language::Python,
            "js" | "ts" => Language::JavaScript,
            "rb" => Language::Ruby,
            _ => Language::Unknown,
        }
    }
}

/// Application frameworks detected in the codebase
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Framework {
    WebServer,
    Database,
    MessageQueue,
    Cache,
    FileSystem,
    Networking,
    Concurrent,
    Unknown,
}

/// Attack axes for stress testing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttackAxis {
    Cpu,
    Memory,
    Disk,
    Network,
    Concurrency,
    Time,
}

impl AttackAxis {
    pub fn all() -> Vec<Self> {
        vec![
            AttackAxis::Cpu,
            AttackAxis::Memory,
            AttackAxis::Disk,
            AttackAxis::Network,
            AttackAxis::Concurrency,
            AttackAxis::Time,
        ]
    }
}

/// Known weak points in program behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeakPoint {
    pub category: WeakPointCategory,
    pub location: Option<String>,
    pub severity: Severity,
    pub description: String,
    pub recommended_attack: Vec<AttackAxis>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WeakPointCategory {
    UncheckedAllocation,
    UnboundedLoop,
    BlockingIO,
    UnsafeCode,
    PanicPath,
    RaceCondition,
    DeadlockPotential,
    ResourceLeak,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Bug signatures detected via logic programming
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BugSignature {
    pub signature_type: SignatureType,
    pub confidence: f64,
    pub evidence: Vec<String>,
    pub location: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureType {
    UseAfterFree,
    DoubleFree,
    MemoryLeak,
    Deadlock,
    DataRace,
    BufferOverflow,
    IntegerOverflow,
    NullPointerDeref,
    UnhandledError,
}

/// Per-file statistics from X-Ray analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileStatistics {
    pub file_path: String,
    pub lines: usize,
    pub unsafe_blocks: usize,
    pub panic_sites: usize,
    pub unwrap_calls: usize,
    pub allocation_sites: usize,
    pub io_operations: usize,
    pub threading_constructs: usize,
}

/// X-Ray analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XRayReport {
    pub program_path: PathBuf,
    pub language: Language,
    pub frameworks: Vec<Framework>,
    pub weak_points: Vec<WeakPoint>,
    pub statistics: ProgramStatistics,
    pub file_statistics: Vec<FileStatistics>,
    pub recommended_attacks: Vec<AttackAxis>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramStatistics {
    pub total_lines: usize,
    pub unsafe_blocks: usize,
    pub panic_sites: usize,
    pub unwrap_calls: usize,
    pub allocation_sites: usize,
    pub io_operations: usize,
    pub threading_constructs: usize,
}

/// Attack configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackConfig {
    pub axes: Vec<AttackAxis>,
    pub duration: Duration,
    pub intensity: IntensityLevel,
    pub target_programs: Vec<PathBuf>,
    pub data_corpus: Option<PathBuf>,
    pub parallel_attacks: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntensityLevel {
    Light,
    Medium,
    Heavy,
    Extreme,
}

impl IntensityLevel {
    pub fn multiplier(&self) -> f64 {
        match self {
            IntensityLevel::Light => 1.0,
            IntensityLevel::Medium => 5.0,
            IntensityLevel::Heavy => 10.0,
            IntensityLevel::Extreme => 50.0,
        }
    }
}

/// Attack execution results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackResult {
    pub program: PathBuf,
    pub axis: AttackAxis,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub duration: Duration,
    pub peak_memory: u64,
    pub crashes: Vec<CrashReport>,
    pub signatures_detected: Vec<BugSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashReport {
    pub timestamp: String,
    pub signal: Option<String>,
    pub backtrace: Option<String>,
    pub stderr: String,
    pub stdout: String,
}

/// Complete assault report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssaultReport {
    pub xray_report: XRayReport,
    pub attack_results: Vec<AttackResult>,
    pub total_crashes: usize,
    pub total_signatures: usize,
    pub overall_assessment: OverallAssessment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverallAssessment {
    pub robustness_score: f64,
    pub critical_issues: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Pattern library entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPattern {
    pub name: String,
    pub description: String,
    pub applicable_axes: Vec<AttackAxis>,
    pub applicable_languages: Vec<Language>,
    pub applicable_frameworks: Vec<Framework>,
    pub command_template: String,
}

/// Datalog fact for signature detection
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Fact {
    Alloc {
        var: String,
        location: usize,
    },
    Free {
        var: String,
        location: usize,
    },
    Use {
        var: String,
        location: usize,
    },
    Lock {
        mutex: String,
        location: usize,
    },
    Unlock {
        mutex: String,
        location: usize,
    },
    ThreadSpawn {
        id: String,
        location: usize,
    },
    #[allow(dead_code)] // Reserved for v0.5 Datalog engine
    ThreadJoin {
        id: String,
        location: usize,
    },
    Write {
        var: String,
        location: usize,
    },
    Read {
        var: String,
        location: usize,
    },
    #[allow(dead_code)] // Reserved for v0.5 Datalog engine
    Ordering {
        before: usize,
        after: usize,
    },
}

/// Datalog rule for pattern detection
#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    #[allow(dead_code)] // Reserved for v0.5 Datalog engine
    pub head: Predicate,
    #[allow(dead_code)] // Reserved for v0.5 Datalog engine
    pub body: Vec<Predicate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Predicate {
    UseAfterFree {
        var: String,
        use_loc: usize,
        free_loc: usize,
    },
    DoubleFree {
        var: String,
        loc1: usize,
        loc2: usize,
    },
    Deadlock {
        m1: String,
        m2: String,
    },
    DataRace {
        var: String,
        loc1: usize,
        loc2: usize,
    },
    Fact(Fact),
}
