// SPDX-License-Identifier: PMPL-1.0-or-later

//! Pattern detection for common program types

use crate::types::*;

pub struct PatternDetector;

impl PatternDetector {
    /// Get attack patterns for a specific program type
    pub fn patterns_for(
        language: Language,
        frameworks: &[Framework],
    ) -> Vec<AttackPattern> {
        let mut patterns = Vec::new();

        // Language-specific patterns
        match language {
            Language::Rust => {
                patterns.extend(Self::rust_patterns());
            }
            Language::C | Language::Cpp => {
                patterns.extend(Self::c_cpp_patterns());
            }
            Language::Go => {
                patterns.extend(Self::go_patterns());
            }
            Language::Python => {
                patterns.extend(Self::python_patterns());
            }
            _ => {}
        }

        // Framework-specific patterns
        for framework in frameworks {
            match framework {
                Framework::WebServer => {
                    patterns.extend(Self::webserver_patterns());
                }
                Framework::Database => {
                    patterns.extend(Self::database_patterns());
                }
                Framework::Concurrent => {
                    patterns.extend(Self::concurrency_patterns());
                }
                _ => {}
            }
        }

        patterns
    }

    fn rust_patterns() -> Vec<AttackPattern> {
        vec![
            AttackPattern {
                name: "Memory Exhaustion".to_string(),
                description: "Allocate large vectors to trigger OOM".to_string(),
                applicable_axes: vec![AttackAxis::Memory],
                applicable_languages: vec![Language::Rust],
                applicable_frameworks: vec![],
                command_template: "RUST_BACKTRACE=1 timeout {duration} {program} --large-input"
                    .to_string(),
            },
            AttackPattern {
                name: "Panic Trigger".to_string(),
                description: "Send invalid inputs to trigger panics".to_string(),
                applicable_axes: vec![AttackAxis::Memory, AttackAxis::Cpu],
                applicable_languages: vec![Language::Rust],
                applicable_frameworks: vec![],
                command_template: "echo 'invalid' | {program}".to_string(),
            },
        ]
    }

    fn c_cpp_patterns() -> Vec<AttackPattern> {
        vec![
            AttackPattern {
                name: "Buffer Overflow".to_string(),
                description: "Send oversized inputs to trigger buffer overflows".to_string(),
                applicable_axes: vec![AttackAxis::Memory],
                applicable_languages: vec![Language::C, Language::Cpp],
                applicable_frameworks: vec![],
                command_template: "python -c 'print(\"A\" * 10000)' | {program}".to_string(),
            },
            AttackPattern {
                name: "Use-After-Free".to_string(),
                description: "Trigger rapid allocation/deallocation cycles".to_string(),
                applicable_axes: vec![AttackAxis::Memory, AttackAxis::Concurrency],
                applicable_languages: vec![Language::C, Language::Cpp],
                applicable_frameworks: vec![],
                command_template: "{program} --stress-memory".to_string(),
            },
        ]
    }

    fn go_patterns() -> Vec<AttackPattern> {
        vec![
            AttackPattern {
                name: "Goroutine Leak".to_string(),
                description: "Spawn many concurrent operations".to_string(),
                applicable_axes: vec![AttackAxis::Concurrency],
                applicable_languages: vec![Language::Go],
                applicable_frameworks: vec![],
                command_template: "{program} --concurrent-requests 10000".to_string(),
            },
        ]
    }

    fn python_patterns() -> Vec<AttackPattern> {
        vec![
            AttackPattern {
                name: "CPU Spin".to_string(),
                description: "Trigger compute-heavy operations".to_string(),
                applicable_axes: vec![AttackAxis::Cpu],
                applicable_languages: vec![Language::Python],
                applicable_frameworks: vec![],
                command_template: "{program} --iterations 1000000".to_string(),
            },
        ]
    }

    fn webserver_patterns() -> Vec<AttackPattern> {
        vec![
            AttackPattern {
                name: "HTTP Flood".to_string(),
                description: "Send many concurrent HTTP requests".to_string(),
                applicable_axes: vec![AttackAxis::Network, AttackAxis::Concurrency],
                applicable_languages: vec![],
                applicable_frameworks: vec![Framework::WebServer],
                command_template: "wrk -t12 -c400 -d{duration}s http://localhost:8080/"
                    .to_string(),
            },
            AttackPattern {
                name: "Large POST".to_string(),
                description: "Send very large POST bodies".to_string(),
                applicable_axes: vec![AttackAxis::Memory, AttackAxis::Network],
                applicable_languages: vec![],
                applicable_frameworks: vec![Framework::WebServer],
                command_template:
                    "curl -X POST -d @/dev/zero --max-time {duration} http://localhost:8080/"
                        .to_string(),
            },
        ]
    }

    fn database_patterns() -> Vec<AttackPattern> {
        vec![
            AttackPattern {
                name: "Query Storm".to_string(),
                description: "Execute many concurrent queries".to_string(),
                applicable_axes: vec![AttackAxis::Disk, AttackAxis::Concurrency],
                applicable_languages: vec![],
                applicable_frameworks: vec![Framework::Database],
                command_template: "{program} --query-load 1000".to_string(),
            },
        ]
    }

    fn concurrency_patterns() -> Vec<AttackPattern> {
        vec![
            AttackPattern {
                name: "Deadlock Induction".to_string(),
                description: "Trigger concurrent operations that may deadlock".to_string(),
                applicable_axes: vec![AttackAxis::Concurrency],
                applicable_languages: vec![],
                applicable_frameworks: vec![Framework::Concurrent],
                command_template: "{program} --threads 100 --contention high".to_string(),
            },
        ]
    }
}
