// SPDX-License-Identifier: PMPL-1.0-or-later

//! Datalog-style rule definitions for bug detection
//!
//! This module defines the logical rules used for pattern matching,
//! inspired by Datalog and Mozart/Oz constraint logic programming.

use crate::types::*;

pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    pub fn new() -> Self {
        Self {
            rules: Self::build_rules(),
        }
    }

    /// Build the complete rule set for bug detection
    fn build_rules() -> Vec<Rule> {
        vec![
            // Use-after-free detection
            Rule {
                name: "use_after_free".to_string(),
                head: Predicate::UseAfterFree {
                    var: "X".to_string(),
                    use_loc: 0,
                    free_loc: 0,
                },
                body: vec![
                    Predicate::Fact(Fact::Free {
                        var: "X".to_string(),
                        location: 0,
                    }),
                    Predicate::Fact(Fact::Use {
                        var: "X".to_string(),
                        location: 0,
                    }),
                ],
            },
            // Double-free detection
            Rule {
                name: "double_free".to_string(),
                head: Predicate::DoubleFree {
                    var: "X".to_string(),
                    loc1: 0,
                    loc2: 0,
                },
                body: vec![
                    Predicate::Fact(Fact::Free {
                        var: "X".to_string(),
                        location: 0,
                    }),
                    Predicate::Fact(Fact::Free {
                        var: "X".to_string(),
                        location: 0,
                    }),
                ],
            },
            // Deadlock detection (simplified)
            Rule {
                name: "deadlock".to_string(),
                head: Predicate::Deadlock {
                    m1: "M1".to_string(),
                    m2: "M2".to_string(),
                },
                body: vec![
                    Predicate::Fact(Fact::Lock {
                        mutex: "M1".to_string(),
                        location: 0,
                    }),
                    Predicate::Fact(Fact::Lock {
                        mutex: "M2".to_string(),
                        location: 0,
                    }),
                ],
            },
            // Data race detection
            Rule {
                name: "data_race".to_string(),
                head: Predicate::DataRace {
                    var: "X".to_string(),
                    loc1: 0,
                    loc2: 0,
                },
                body: vec![
                    Predicate::Fact(Fact::Write {
                        var: "X".to_string(),
                        location: 0,
                    }),
                    Predicate::Fact(Fact::Read {
                        var: "X".to_string(),
                        location: 0,
                    }),
                ],
            },
        ]
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
}

impl Default for RuleSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ruleset_creation() {
        let ruleset = RuleSet::new();
        assert!(!ruleset.rules().is_empty());
        assert!(ruleset.rules().len() >= 4);
    }

    #[test]
    fn test_rule_names() {
        let ruleset = RuleSet::new();
        let names: Vec<_> = ruleset.rules().iter().map(|r| &r.name).collect();

        assert!(names.contains(&&"use_after_free".to_string()));
        assert!(names.contains(&&"double_free".to_string()));
        assert!(names.contains(&&"deadlock".to_string()));
        assert!(names.contains(&&"data_race".to_string()));
    }
}
