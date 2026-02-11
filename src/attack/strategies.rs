// SPDX-License-Identifier: PMPL-1.0-or-later

//! Attack strategies for different axes

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackStrategy {
    CpuStress,
    MemoryExhaustion,
    DiskThrashing,
    NetworkFlood,
    ConcurrencyStorm,
    TimeBomb,
}

impl AttackStrategy {
    pub fn description(&self) -> &str {
        // Human-readable labels are used directly in CLI progress output.
        match self {
            AttackStrategy::CpuStress => "Stress test CPU with high computational load",
            AttackStrategy::MemoryExhaustion => "Exhaust available memory with large allocations",
            AttackStrategy::DiskThrashing => "Thrash disk I/O with many file operations",
            AttackStrategy::NetworkFlood => "Flood network connections",
            AttackStrategy::ConcurrencyStorm => "Create concurrency storm with many threads/tasks",
            AttackStrategy::TimeBomb => "Run for extended duration to find time-dependent bugs",
        }
    }
}
