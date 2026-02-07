;; SPDX-License-Identifier: PMPL-1.0-or-later
;; Meta-level information for panic-attacker
;; Media Type: application/meta+scheme

(meta
  (version "1.0")
  (project "panic-attacker")

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
      (status "accepted")
      (title "Datalog-inspired signature detection")
      (context "Need expressive bug pattern matching beyond regex")
      (decision "Use Datalog-inspired rules with fact extraction")
      (consequences
        "More powerful than string matching"
        "Extensible rule system"
        "Deferred to v0.5: integrate real Datalog engine (Crepe/Datafrog)"
        "Current v0.2: simplified inference with explicit functions"))

    (adr
      (id "ADR-003")
      (date "2026-02-07")
      (status "accepted")
      (title "Per-file analysis eliminates duplicates")
      (context "v0.1 produced duplicate weak points with running totals")
      (decision "Create fresh ProgramStatistics per file, accumulate into global")
      (consequences
        "Weak point counts accurate (271→15 on echidna)"
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
        "Constraint sets, real Datalog, multi-program deferred to v1.x/v2.0"
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
        "Prepares for v0.5 real Datalog engine"
        "User-definable rules possible in future")))

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
      (target "80% code coverage by v1.0")
      (current "~60% coverage"))

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
        "0.x = pre-release, breaking changes allowed"
        "1.0 = stable API, MSRV policy"
        "1.x = backwards-compatible features"
        "2.0 = breaking changes"))

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
      (description "Run panic-attacker on panic-attacker itself")
      (rationale "Find bugs, validate thresholds, prove usefulness")
      (status "planned for v1.0 hardening")))

  (design-rationale
    (rationale
      (aspect "Multi-axis testing")
      (reasoning "Real failures are multi-dimensional (CPU + memory + network, not just one)")
      (future "v0.4 constraint sets enable simultaneous multi-axis attacks"))

    (rationale
      (aspect "X-Ray pre-analysis")
      (reasoning "Static analysis guides dynamic testing, avoiding wasted effort")
      (benefit "Recommended attacks based on detected weak points"))

    (rationale
      (aspect "Logic programming for bug detection")
      (reasoning "String matching is brittle, logic rules are expressive and composable")
      (inspiration "Mozart/Oz constraint logic programming, Datalog inference")
      (future "v0.5 real Datalog engine (Crepe or Datafrog)"))

    (rationale
      (aspect "Per-file statistics")
      (reasoning "Identify hotspot files, prioritize fixes, avoid duplicates")
      (benefit "Risk scoring highlights worst offenders"))

    (rationale
      (aspect "Language-agnostic design")
      (reasoning "One tool for all languages, not per-language tools")
      (current "5 languages: Rust, C/C++, Go, Python, generic")
      (future "v0.7 deeper analysis per language"))

    (rationale
      (aspect "CLI + library")
      (reasoning "Useful standalone and as integration component")
      (benefit "src/lib.rs enables testing, hypatia integration, CI/CD plugins")))

  (cross-cutting-concerns
    (concern
      (name "Error handling")
      (approach "anyhow for CLI, Result<T, E> for library")
      (policy "Never panic in library code, only in CLI after reporting"))

    (concern
      (name "Performance")
      (approach "Reasonable defaults, parallel analysis deferred to v0.9")
      (current "Single-threaded file analysis, sufficient for most repos")
      (future "rayon for parallel X-Ray in v0.9"))

    (concern
      (name "Security")
      (approach "cargo-audit in CI, SBOM generation, self-testing")
      (policy "No unsafe code in panic-attacker itself except when required for FFI"))

    (concern
      (name "Portability")
      (approach "Pure Rust, minimal platform-specific code")
      (targets "Linux, macOS, Windows")
      (limitations "Some attacks require Unix tools (timeout command)"))

    (concern
      (name "Extensibility")
      (approach "Pattern library, rule system, pluggable analyzers")
      (future "v0.5+ user-definable rules, v0.7+ plugin system")))

  (metadata
    (created "2026-02-07")
    (updated "2026-02-07")
    (maintainer "Jonathan D.A. Jewell <jonathan.jewell@open.ac.uk>")
    (license "PMPL-1.0-or-later")))
