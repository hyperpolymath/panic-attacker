// SPDX-License-Identifier: PMPL-1.0-or-later

//! Attack orchestration module

pub mod executor;
pub mod strategies;

use crate::types::*;
use anyhow::Result;

pub use executor::AttackExecutor;

/// Execute an attack against a target program
pub fn execute_attack(config: AttackConfig) -> Result<Vec<AttackResult>> {
    let executor = AttackExecutor::new(config);
    executor.execute()
}

/// Execute an attack with pattern-aware strategy selection
pub fn execute_attack_with_patterns(
    config: AttackConfig,
    language: Language,
    frameworks: &[Framework],
) -> Result<Vec<AttackResult>> {
    let executor = AttackExecutor::with_patterns(config, language, frameworks);
    executor.execute()
}
