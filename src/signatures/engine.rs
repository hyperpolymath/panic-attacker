// SPDX-License-Identifier: PMPL-1.0-or-later

//! Signature detection engine using logic programming concepts

use crate::signatures::rules::RuleSet;
use crate::types::*;
use std::collections::{HashMap, HashSet};

pub struct SignatureEngine {
    rules: RuleSet,
}

impl SignatureEngine {
    pub fn new() -> Self {
        Self {
            rules: RuleSet::default(),
        }
    }

    /// Detect bug signatures from a crash report
    pub fn detect_from_crash(&self, crash: &CrashReport) -> Vec<BugSignature> {
        let mut signatures = Vec::new();

        // Extract facts from crash report
        let facts = self.extract_facts(crash);

        // Apply inference rules
        signatures.extend(self.infer_use_after_free(&facts, crash));
        signatures.extend(self.infer_double_free(&facts, crash));
        signatures.extend(self.infer_deadlock(&facts, crash));
        signatures.extend(self.infer_data_race(&facts, crash));
        signatures.extend(self.infer_null_deref(&facts, crash));
        signatures.extend(self.infer_buffer_overflow(&facts, crash));

        signatures
    }

    /// Extract Datalog-style facts from crash report
    fn extract_facts(&self, crash: &CrashReport) -> HashSet<Fact> {
        let mut facts = HashSet::new();

        let stderr = &crash.stderr;

        // Parse allocation patterns
        if stderr.contains("malloc") || stderr.contains("alloc") {
            facts.insert(Fact::Alloc {
                var: "heap_var".to_string(),
                location: 0,
            });
        }

        // Parse free patterns
        if stderr.contains("free") || stderr.contains("drop") {
            facts.insert(Fact::Free {
                var: "heap_var".to_string(),
                location: 1,
            });
        }

        // Parse use patterns
        if stderr.contains("use") || stderr.contains("access") {
            facts.insert(Fact::Use {
                var: "heap_var".to_string(),
                location: 2,
            });
        }

        // Parse locking patterns
        if stderr.contains("lock") || stderr.contains("mutex") {
            facts.insert(Fact::Lock {
                mutex: "mutex1".to_string(),
                location: 0,
            });
        }

        if stderr.contains("unlock") {
            facts.insert(Fact::Unlock {
                mutex: "mutex1".to_string(),
                location: 1,
            });
        }

        // Parse thread patterns
        if stderr.contains("thread") || stderr.contains("spawn") {
            facts.insert(Fact::ThreadSpawn {
                id: "thread1".to_string(),
                location: 0,
            });
        }

        facts
    }

    /// Infer use-after-free bugs
    ///
    /// Rule: UseAfterFree(var, use_loc, free_loc) :-
    ///       Free(var, free_loc),
    ///       Use(var, use_loc),
    ///       Ordering(free_loc, use_loc)
    fn infer_use_after_free(
        &self,
        facts: &HashSet<Fact>,
        crash: &CrashReport,
    ) -> Vec<BugSignature> {
        let mut signatures = Vec::new();

        // Find all free and use pairs
        for fact1 in facts {
            if let Fact::Free { var: var1, location: free_loc } = fact1 {
                for fact2 in facts {
                    if let Fact::Use { var: var2, location: use_loc } = fact2 {
                        if var1 == var2 && free_loc < use_loc {
                            // Pattern matched!
                            signatures.push(BugSignature {
                                signature_type: SignatureType::UseAfterFree,
                                confidence: 0.85,
                                evidence: vec![
                                    format!("Free at location {}", free_loc),
                                    format!("Use at location {}", use_loc),
                                    "Temporal ordering violation detected".to_string(),
                                ],
                                location: Some(format!("Location {}", use_loc)),
                            });
                        }
                    }
                }
            }
        }

        // Also check for common patterns in stderr
        if crash.stderr.contains("use after free")
            || crash.stderr.contains("use-after-free")
            || (crash.stderr.contains("freed") && crash.stderr.contains("accessed"))
        {
            signatures.push(BugSignature {
                signature_type: SignatureType::UseAfterFree,
                confidence: 0.95,
                evidence: vec!["Direct mention in error message".to_string()],
                location: None,
            });
        }

        signatures
    }

    /// Infer double-free bugs
    ///
    /// Rule: DoubleFree(var, loc1, loc2) :-
    ///       Free(var, loc1),
    ///       Free(var, loc2),
    ///       loc1 != loc2
    fn infer_double_free(
        &self,
        facts: &HashSet<Fact>,
        crash: &CrashReport,
    ) -> Vec<BugSignature> {
        let mut signatures = Vec::new();
        let mut free_locations: HashMap<String, Vec<usize>> = HashMap::new();

        // Collect all free operations per variable
        for fact in facts {
            if let Fact::Free { var, location } = fact {
                free_locations
                    .entry(var.clone())
                    .or_insert_with(Vec::new)
                    .push(*location);
            }
        }

        // Check for multiple frees of same variable
        for (var, locations) in free_locations {
            if locations.len() > 1 {
                signatures.push(BugSignature {
                    signature_type: SignatureType::DoubleFree,
                    confidence: 0.90,
                    evidence: vec![
                        format!("Variable {} freed multiple times", var),
                        format!("Locations: {:?}", locations),
                    ],
                    location: Some(format!("Locations {:?}", locations)),
                });
            }
        }

        // Pattern matching in stderr
        if crash.stderr.contains("double free")
            || crash.stderr.contains("double-free")
            || crash.stderr.contains("freed twice")
        {
            signatures.push(BugSignature {
                signature_type: SignatureType::DoubleFree,
                confidence: 0.95,
                evidence: vec!["Direct mention in error message".to_string()],
                location: None,
            });
        }

        signatures
    }

    /// Infer deadlock bugs
    ///
    /// Rule: Deadlock(m1, m2) :-
    ///       Lock(m1, loc1), Lock(m2, loc2),
    ///       Lock(m2, loc3), Lock(m1, loc4),
    ///       Ordering(loc1, loc2), Ordering(loc3, loc4)
    fn infer_deadlock(&self, facts: &HashSet<Fact>, crash: &CrashReport) -> Vec<BugSignature> {
        let mut signatures = Vec::new();

        // Check for lock ordering violations (simplified)
        let mut locks: Vec<(String, usize)> = Vec::new();
        for fact in facts {
            if let Fact::Lock { mutex, location } = fact {
                locks.push((mutex.clone(), *location));
            }
        }

        // Look for potential circular dependencies
        if locks.len() >= 2 {
            signatures.push(BugSignature {
                signature_type: SignatureType::Deadlock,
                confidence: 0.70,
                evidence: vec![
                    format!("{} locks detected", locks.len()),
                    "Potential lock ordering issue".to_string(),
                ],
                location: None,
            });
        }

        // Pattern matching
        if crash.stderr.contains("deadlock")
            || crash.stderr.contains("deadlocked")
            || (crash.stderr.contains("waiting") && crash.stderr.contains("lock"))
        {
            signatures.push(BugSignature {
                signature_type: SignatureType::Deadlock,
                confidence: 0.90,
                evidence: vec!["Deadlock pattern in error message".to_string()],
                location: None,
            });
        }

        signatures
    }

    /// Infer data race bugs
    ///
    /// Rule: DataRace(var, loc1, loc2) :-
    ///       Write(var, loc1), Read(var, loc2),
    ///       Concurrent(loc1, loc2),
    ///       ¬Synchronized(loc1, loc2)
    fn infer_data_race(&self, facts: &HashSet<Fact>, crash: &CrashReport) -> Vec<BugSignature> {
        let mut signatures = Vec::new();

        // Check for concurrent accesses
        let has_writes = facts.iter().any(|f| matches!(f, Fact::Write { .. }));
        let has_reads = facts.iter().any(|f| matches!(f, Fact::Read { .. }));
        let has_threads = facts.iter().any(|f| matches!(f, Fact::ThreadSpawn { .. }));

        if has_writes && has_reads && has_threads {
            signatures.push(BugSignature {
                signature_type: SignatureType::DataRace,
                confidence: 0.65,
                evidence: vec![
                    "Concurrent reads and writes detected".to_string(),
                    "Multiple threads present".to_string(),
                ],
                location: None,
            });
        }

        // Pattern matching
        if crash.stderr.contains("data race")
            || crash.stderr.contains("race condition")
            || crash.stderr.contains("ThreadSanitizer")
        {
            signatures.push(BugSignature {
                signature_type: SignatureType::DataRace,
                confidence: 0.95,
                evidence: vec!["Race condition detected by sanitizer".to_string()],
                location: None,
            });
        }

        signatures
    }

    /// Infer null pointer dereference
    fn infer_null_deref(&self, _facts: &HashSet<Fact>, crash: &CrashReport) -> Vec<BugSignature> {
        let mut signatures = Vec::new();

        if crash.signal == Some("SIGSEGV".to_string())
            || crash.stderr.contains("null pointer")
            || crash.stderr.contains("nullptr")
            || crash.stderr.contains("nil pointer")
            || crash.stderr.contains("address 0x0")
        {
            signatures.push(BugSignature {
                signature_type: SignatureType::NullPointerDeref,
                confidence: 0.90,
                evidence: vec!["SIGSEGV or null pointer pattern detected".to_string()],
                location: None,
            });
        }

        signatures
    }

    /// Infer buffer overflow
    fn infer_buffer_overflow(
        &self,
        _facts: &HashSet<Fact>,
        crash: &CrashReport,
    ) -> Vec<BugSignature> {
        let mut signatures = Vec::new();

        if crash.stderr.contains("buffer overflow")
            || crash.stderr.contains("stack smashing")
            || crash.stderr.contains("heap corruption")
            || crash.stderr.contains("AddressSanitizer")
        {
            signatures.push(BugSignature {
                signature_type: SignatureType::BufferOverflow,
                confidence: 0.95,
                evidence: vec!["Buffer overflow pattern detected".to_string()],
                location: None,
            });
        }

        signatures
    }
}

impl Default for SignatureEngine {
    fn default() -> Self {
        Self::new()
    }
}
