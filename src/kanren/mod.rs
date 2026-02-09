// SPDX-License-Identifier: PMPL-1.0-or-later

//! miniKanren-inspired relational logic engine for panic-attack
//!
//! Provides:
//! - **Relational fact database** with unification-based queries
//! - **Taint analysis** tracking data flow from sources to sinks
//! - **Cross-language reasoning** for multi-language codebases
//! - **Search strategies** for prioritising analysis order
//!
//! Inspired by miniKanren (Byrd, Friedman) and Mozart/Oz constraint
//! programming, adapted for static analysis of source code.

pub mod core;
pub mod crosslang;
pub mod strategy;
pub mod taint;

pub use self::core::{FactDB, LogicEngine, Query, QueryResult};
pub use crosslang::CrossLangAnalyzer;
pub use strategy::SearchStrategy;
pub use taint::{TaintAnalyzer, TaintSink, TaintSource};
