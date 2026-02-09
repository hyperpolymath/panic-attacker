;; SPDX-License-Identifier: PMPL-1.0-or-later
;; Meta-level information for panic-attack (formerly panic-attacker)
;; Media Type: application/meta+scheme

(meta
  (version "1.0")
  (project "panic-attack")

  (architecture-decisions
    (adr
      (id "ADR-001")
      (date "2026-02-06")
      (status "accepted")
      (title "Use Rust for implementation")
      (context "Need memory safety, performance, strong type system")
      (decision "Implement in Rust with Cargo")
      (consequences
        "Memory safety without garbage collection"
        "Excellent CLI tooling with clap"
        "Strong ecosystem for system-level programming"
        "Portable to multiple platforms"))

    (adr
      (id "ADR-002")
      (date "2026-02-06")
      (status "superseded")
      (superseded-by "ADR-008")
      (title "Datalog-inspired signature detection")
      (context "Need expressive bug pattern matching beyond regex")
      (decision "Use Datalog-inspired rules with fact extraction")
      (consequences
        "More powerful than string matching"
        "Extensible rule system"
        "Superseded by miniKanren logic engine in v2.0.0"))

    (adr
      (id "ADR-003")
      (date "2026-02-07")
      (status "accepted")
      (title "Per-file analysis eliminates duplicates")
      (context "v0.1 produced duplicate weak points with running totals")
      (decision "Create fresh ProgramStatistics per file, accumulate into global")
      (consequences
        "Weak point counts accurate (271->15 on echidna)"
        "All locations populated (never null)"
        "FileStatistics provides per-file breakdown"
        "Risk scoring identifies hotspot files"))

    (adr
      (id "ADR-004")
      (date "2026-02-07")
      (status "accepted")
      (title "Latin-1 fallback for non-UTF-8 files")
      (context "Vendored third-party C files with ISO-8859-1 author names")
      (decision "Try UTF-8 first, fallback to encoding_rs WINDOWS_1252, then skip")
      (consequences
        "No crashes on non-UTF-8 files"
        "Verbose mode logs skipped files"
        "Handles common non-UTF-8 cases (Latin-1, ISO-8859-1)"))

    (adr
      (id "ADR-005")
      (date "2026-02-07")
      (status "accepted")
      (title "Infrastructure-first path to v1.0")
      (context "15 weeks for full-feature v1.0 vs. 3-5 days for stable foundation")
      (decision "v1.0 = RSR compliance + tests + CI/CD + polish, defer v0.4-v0.7 features")
      (consequences
        "Faster path to production-ready release"
        "Solid foundation for feature expansion"
        "Feature development continued in v2.0.0"
        "Focus on quality over quantity"))

    (adr
      (id "ADR-006")
      (date "2026-02-07")
      (status "accepted")
      (title "Pattern library wired into attack executor")
      (context "v0.1 defined AttackPattern but never used it")
      (decision "AttackExecutor::with_patterns() applies language/framework-specific patterns")
      (consequences
        "Smarter attack selection"
        "Logs applicable patterns during execution"
        "Framework detection influences strategy"
        "Extensible pattern system for new languages"))

    (adr
      (id "ADR-007")
      (date "2026-02-07")
      (status "accepted")
      (title "RuleSet wired into signature engine")
      (context "v0.1 stored rules but never dispatched on them")
      (decision "detect_from_crash() iterates rules, dispatches by name")
      (consequences
        "Rules are now read and used"
        "Eliminates dead code warnings"
        "Prepares for miniKanren integration"
        "User-definable rules possible in future"))

    (adr
      (id "ADR-008")
      (date "2026-02-08")
      (status "accepted")
      (title "miniKanren-inspired logic engine for relational reasoning")
      (context "Datalog-inspired rules (ADR-002) were too limited for cross-language and taint analysis")
      (decision "Implement miniKanren-inspired engine with substitution-based unification, forward chaining, and backward queries")
      (consequences
        "Taint analysis: source-to-sink data flow tracking across files"
        "Cross-language vulnerability chain detection (FFI/NIF/Port/subprocess boundaries)"
        "Search strategy optimisation (auto-select from 5 strategies)"
        "Forward chaining derives new vulnerability facts from rules"
        "Backward queries find files by vulnerability category"
        "More expressive than Datalog for relational reasoning"))

    (adr
      (id "ADR-009")
      (date "2026-02-08")
      (status "accepted")
      (title "Rename xray to assail throughout codebase")
      (context "xray was a medical metaphor; assail better conveys offensive security testing")
      (decision "Rename all references: xray->assail, XRayReport->AssailReport, src/xray/->src/assail/")
      (consequences
        "Consistent naming across binary, library, and documentation"
        "Binary subcommand: panic-attack assail"
        "Module path: src/assail/"
        "Report type: AssailReport"))

    (adr
      (id "ADR-010")
      (date "2026-02-08")
      (status "accepted")
      (title "47-language support with per-file language detection")
      (context "v0.2 supported 5 languages; hyperpolymath repos use 40+ languages")
      (decision "Expand to 47 languages across 10 families: BEAM, ML, Lisp, Functional, Proof, Logic, Systems, Config, Scripting, NextGen DSLs")
      (consequences
        "Covers all languages in hyperpolymath ecosystem"
        "20 weak point categories (up from ~5)"
        "Per-file language detection with family-specific patterns"
        "Cross-language analysis possible via kanren engine")))

  (development-practices
    (practice
      (name "Zero warnings policy")
      (description "cargo build --release must produce 0 warnings")
      (rationale "Warnings hide real issues, signal poor code quality")
      (enforcement "CI fails on warnings"))

    (practice
      (name "Test-driven quality")
      (description "All features must have tests")
      (rationale "Untested code is untrusted code")
      (target "80% code coverage")
      (current "30 tests: 16 unit + 11 analyzer + 3 integration"))

    (practice
      (name "RSR compliance")
      (description "Follow Reproducible Software Repositories standard")
      (rationale "Consistency across hyperpolymath ecosystem")
      (requirements
        "AI manifest (AI.a2ml)"
        "SCM checkpoint files (.machine_readable/)"
        "17 standard workflows"
        "PMPL-1.0-or-later license"))

    (practice
      (name "Semantic versioning")
      (description "MAJOR.MINOR.PATCH with clear upgrade paths")
      (rationale "Predictable releases, clear breaking changes")
      (policy
        "1.x = stable foundation, naming finalised"
        "2.x = major feature expansion (logic engine, 47 langs)"
        "3.0 = public release (crates.io)"))

    (practice
      (name "Documentation-first")
      (description "Write docs before/during implementation, not after")
      (rationale "Better API design, fewer mistakes")
      (requirements
        "rustdoc for all public APIs"
        "README examples that actually work"
        "CHANGELOG for all releases"))

    (practice
      (name "Eat your own dogfood")
      (description "Run panic-attack on panic-attack itself")
      (rationale "Find bugs, validate thresholds, prove usefulness")
      (status "active: self-scan shows 3 weak points")))

  (design-rationale
    (rationale
      (aspect "Multi-axis testing")
      (reasoning "Real failures are multi-dimensional (CPU + memory + network, not just one)")
      (future "Constraint sets enable simultaneous multi-axis attacks"))

    (rationale
      (aspect "Assail pre-analysis")
      (reasoning "Static analysis guides dynamic testing, avoiding wasted effort")
      (benefit "Recommended attacks based on detected weak points"))

    (rationale
      (aspect "miniKanren logic engine")
      (reasoning "Relational reasoning enables taint analysis, cross-language chains, and search strategy optimisation")
      (inspiration "Mozart/Oz constraint logic programming, miniKanren relational paradigm")
      (components "core.rs (unification, facts, rules), taint.rs (source-sink), crosslang.rs (FFI boundaries), strategy.rs (file prioritisation)"))

    (rationale
      (aspect "Per-file statistics")
      (reasoning "Identify hotspot files, prioritize fixes, avoid duplicates")
      (benefit "Risk scoring highlights worst offenders"))

    (rationale
      (aspect "47-language support")
      (reasoning "One tool for all languages in the hyperpolymath ecosystem")
      (current "47 languages: BEAM, ML, Lisp, Functional, Proof, Logic, Systems, Config, Scripting, NextGen DSLs")
      (benefit "Cross-language vulnerability detection via kanren engine"))

    (rationale
      (aspect "CLI + library")
      (reasoning "Useful standalone and as integration component")
      (benefit "src/lib.rs enables testing, hypatia integration, verisimdb pipeline")))

  (cross-cutting-concerns
    (concern
      (name "Error handling")
      (approach "anyhow for CLI, Result<T, E> for library")
      (policy "Never panic in library code, only in CLI after reporting"))

    (concern
      (name "Performance")
      (approach "Reasonable defaults, search strategy optimisation via kanren")
      (current "Single-threaded file analysis with risk-weighted prioritisation")
      (future "rayon for parallel assail analysis"))

    (concern
      (name "Security")
      (approach "cargo-audit in CI, SBOM generation, self-testing")
      (policy "No unsafe code in panic-attack itself except when required for FFI"))

    (concern
      (name "Portability")
      (approach "Pure Rust, minimal platform-specific code")
      (targets "Linux, macOS, Windows")
      (limitations "Some attacks require Unix tools (timeout command)"))

    (concern
      (name "Extensibility")
      (approach "Pattern library, kanren rule system, pluggable analyzers")
      (current "miniKanren rules for taint, cross-language, and strategy")
      (future "User-definable rules, plugin system")))

  (metadata
    (created "2026-02-07")
    (updated "2026-02-08")
    (maintainer "Jonathan D.A. Jewell <jonathan.jewell@open.ac.uk>")
    (license "PMPL-1.0-or-later")))
