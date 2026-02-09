# SPDX-License-Identifier: PMPL-1.0-or-later

# panic-attacker Roadmap

## Current State: v1.0.0

**3,200+ lines of Rust.** Production-ready with RSR compliance, comprehensive tests, and CI/CD.

| Component | Status | Notes |
|---|---|---|
| Assail static analysis | Working | 5 language-specific analyzers |
| Attack executor (6 axes) | Working | CPU, memory, disk, network, concurrency, time |
| Signature detection | Working | Simplified (string matching, not real Datalog) |
| Report generation | Working | Robustness scoring, coloured terminal output, JSON |
| CLI (4 commands) | Working | assail, attack, assault, analyze |
| Pattern library | Defined but unused | Not wired into attack selection |
| Tests | 2 unit tests | Effectively untested |
| Constraint sets | Not started | — |
| Multi-program testing | Not started | — |

### Tested Against

- **eclexia** (23,295 lines Rust): 66 weak points, 0 unsafe blocks, high unwrap density
- **echidna** (60,248 lines Rust): 271 weak points, 15 unsafe blocks, 4 frameworks detected

---

## v0.2 — Fix What's Broken ✅ COMPLETE

**Theme: Make the existing output trustworthy**

- [x] Fix Assail duplicate entries (running counts → per-file delta counts)
- [x] Add file paths to weak point `location` field (currently all `null`)
- [x] Wire pattern library into attack selection (currently defined but unused)
- [x] Connect `RuleSet` to signature engine (currently stored but ignored)
- [x] Handle non-UTF-8 source files gracefully (skip with warning, not crash)
  - encoding_rs Latin-1/Windows-1252 fallback implemented
  - Verbose mode logs skipped files
- [x] Fix the 10 compiler warnings (dead code)
- [x] Add integration test using `examples/vulnerable_program.rs`
- [x] Per-file breakdown in verbose output (which files contribute most weak points)

**Completed: 2026-02-07** (1 day)

---

## v0.3 — Test Coverage ✅ COMPLETE

**Theme: Trust the tool enough to use it on real code**

- [x] Unit tests for Assail (each language analyzer: Rust, C/C++, Go, Python, generic)
- [x] Unit tests for signature engine (each inference rule)
- [x] Integration tests: Assail → Attack → Signature pipeline
- [x] Test against example vulnerable program (panic, OOM, deadlock, race)
- [x] Regression test: eclexia baseline (7 weak points, known profile)
- [x] Regression test: echidna baseline (15 weak points, known profile)
- [x] CI with GitHub Actions (rust-ci, cargo-audit, codeql, scorecard, coverage)
- [x] Code coverage reporting (codecov integration)

**Completed: 2026-02-07** (same day as v0.2)

---

## v1.0 — Production Release ✅ COMPLETE

**Theme: Battle-tested infrastructure and documentation**

- [x] RSR compliance (AI manifest, SCM files, 17 workflows)
- [x] Comprehensive documentation (SECURITY.md, CONTRIBUTING.md, LICENSE)
- [x] Enhanced README with badges and examples
- [x] Comprehensive unit tests (20+ tests covering all analyzers)
- [x] Integration tests (Assail pipeline, vulnerable programs)
- [x] Regression tests (eclexia, echidna, self-test baselines)
- [x] CI/CD with GitHub Actions (11 workflows)
- [x] Code coverage reporting with codecov
- [x] Config file support (panic-attacker.toml)
- [x] EditorConfig for consistent formatting
- [x] Stable JSON schema (versioned, documented)
- [x] MSRV policy (1.75.0)
- [x] Zero compiler warnings

**Completed: 2026-02-07** (infrastructure-first path)

**Status**: Production-ready for Assail analysis and basic stress testing.
Advanced features (constraint sets, real Datalog, multi-program) deferred to v1.x/v2.0.

---

## v0.4 — Constraint Sets (PLANNED FOR v1.1)

**Theme: Composable stress profiles**

Constraint sets are named combinations of conditions that simulate real
failure scenarios. Real failures are never one thing — they're the
intersection of multiple pressures.

```yaml
"Production Spike":
  cpu: 80% + periodic 100% spikes
  memory: 70% with 2% leak rate
  network: 50ms latency + 1% loss
  disk: 85% full
```

- [ ] YAML-based constraint set definitions
- [ ] New CLI command: `panic-attacker stress ./program --profile spike.yaml`
- [ ] Multi-axis simultaneous attacks (not just sequential)
- [ ] Built-in profiles:
  - `production-spike` — CPU + memory + network pressure
  - `memory-leak` — gradual memory growth over time
  - `disk-full` — I/O with shrinking free space
  - `network-partition` — intermittent connectivity loss
  - `thundering-herd` — sudden concurrency burst
- [ ] Custom profile authoring with slider-like intensity controls
- [ ] Profile composition (combine two profiles into a new one)

**Estimated: 1 week**

---

## v0.5 — Real Signature Engine

**Theme: Replace string matching with actual logic programming**

This is the critical path milestone. The current engine pattern-matches
on stderr strings. A real engine would parse structured crash data and
run inference over facts using Datalog rules.

- [ ] Integrate Crepe or Datafrog (Rust Datalog engines)
- [ ] Real fact extraction from crash traces (parse backtraces, not just string contains)
- [ ] Proper temporal ordering of events
- [ ] Confidence scoring based on evidence chain strength
- [ ] User-definable rules (not just hardcoded)
- [ ] Rule composition (combine rules to detect compound bugs)
- [ ] Implement remaining signatures:
  - Integer overflow detection
  - Unhandled error detection
  - Resource leak detection (file descriptors, sockets)
  - Goroutine/task leak detection
- [ ] Evidence chain visualisation in reports

**Estimated: 2–3 weeks**

---

## v0.6 — Multi-Program & Data Testing

**Theme: Test relationships, not just programs**

- [ ] Test program A under stress while program B is also stressed
- [ ] Test program + its data (corrupt inputs, malformed configs)
- [ ] Corpus-based testing (known-bad inputs per framework type)
- [ ] Dependency chain analysis (what happens when a dependency fails)
- [ ] Inter-process communication testing (what happens when IPC degrades)
- [ ] Database + server combined stress (realistic service topology)

**Estimated: 1–2 weeks**

---

## v0.7 — Language Coverage Expansion

**Theme: Support more than just Rust well**

Each language gets a dedicated analyzer with language-specific
vulnerability patterns and framework detection.

- [ ] Deeper C/C++ analysis
  - AddressSanitizer integration
  - Valgrind integration
  - malloc/free pair tracking
- [ ] Java/JVM analysis
  - Heap dump analysis
  - Thread dump parsing
  - GC pressure simulation
- [ ] JavaScript/Node analysis
  - Event loop starvation detection
  - Memory leak patterns (closures, listeners)
  - Promise rejection handling
- [ ] Erlang/BEAM analysis
  - Process mailbox overflow
  - Supervisor tree stress testing
  - ETS table pressure
- [ ] Chapel analysis
  - Locale distribution imbalance
  - Task spawning overhead
  - Data distribution skew
  - Parallel proof search scaling
- [ ] eclexia-specific analysis
  - Resource constraint behaviour under stress
  - Adaptive function degradation
  - `@solution` block fallback testing
- [ ] Julia analysis
  - Type instability detection
  - GC pressure simulation
  - ccall FFI boundary testing
- [ ] Non-UTF-8 source file support (Latin-1, Shift-JIS, etc.)
  - Detect encoding from BOM or heuristics
  - Transcode to UTF-8 before analysis

**Estimated: 2–3 weeks** (each language ~2–3 days)

---

## v0.8 — Reporting & CI/CD Integration

**Theme: Make it useful in real workflows**

- [ ] HTML report output (not just terminal + JSON)
- [ ] Trend tracking (compare runs over time, detect regressions)
- [ ] GitHub Actions integration (run panic-attacker in CI)
- [ ] Exit codes that CI can act on (fail build if robustness < threshold)
- [ ] SARIF output for GitHub Security tab integration
- [ ] Baseline support (suppress known issues, alert on new ones)
- [ ] Comparative reports (diff two Assail runs)
- [ ] Badge generation (robustness score badge for README)

**Estimated: 1–2 weeks**

---

## v0.9 — Performance & Polish

**Theme: Make it fast and reliable enough for production use**

- [ ] Parallel Assail analysis (rayon for file scanning)
- [ ] Incremental analysis (only re-scan changed files)
- [ ] Resource limits on panic-attacker itself (don't crash the host)
- [ ] Graceful cleanup (kill child processes on SIGINT/SIGTERM)
- [ ] Config file support (`panic-attacker.toml`)
- [ ] Shell completions (bash, zsh, fish, nushell)
- [ ] Man page generation
- [ ] `--quiet` mode for CI pipelines
- [ ] Memory-mapped file reading for large codebases

**Estimated: 1 week**

---

## v1.0 — Production Release

**Theme: Battle-tested and documented**

- [ ] Run against 50+ real-world programs and fix false positives
- [ ] Comprehensive user guide (not just README)
- [ ] Published to crates.io
- [ ] Reproducible builds
- [ ] SBOM generation
- [ ] Security audit of panic-attacker itself (eat your own dogfood)
- [ ] Assail panic-attacker with panic-attacker (meta-test)
- [ ] Stable JSON output schema (versioned, documented)
- [ ] Minimum supported Rust version (MSRV) policy

**Estimated: 1–2 weeks of hardening**

---

## Enhancements Identified (2026-02-08)

### Naming/Branding (HIGH PRIORITY)

- Rename tool from `panic-attacker` to `panic-attack` (cleaner, more direct)
- Rename `assail` command to `assail` (better panic-attack metaphor; "hypervigilance" as alternative)
- Consider renaming `assault` to `overwhelm` or `barrage` to avoid confusion with `assail`
- Update all CLI help text, README, and docs to reflect new names

### Output Format Expansion

- Add SARIF output format (GitHub Security integration)
- Add Markdown output format (documentation-friendly)
- Add HTML report generation (stakeholder-ready reports)
- YAML output format (referenced in config but not implemented)

### Integration

- Native verisimdb integration: output results directly to verisimdb hexad API
- Container/Flatpak awareness: option to extract and scan contents within containers
- Support scanning inside Flatpak app directories (`~/.var/app/*`)
- MCP server mode: expose panic-attack as an MCP tool for AI agent integration

### Performance

- Parallel assail scanning (currently sequential) using rayon
- Compiled regex patterns instead of `string contains()`
- Incremental analysis with result caching
- Memory-mapped file reading for large codebases

### Analysis Depth

- Real Datalog engine (Crepe or Datafrog) to replace string matching in signatures
- Backtrace analysis for crash reports (parse structured backtraces)
- Integer overflow/underflow detection patterns
- Resource descriptor leak detection (file handles, sockets)
- Dynamic dispatch bottleneck detection (Rust `dyn Trait`)
- Browser extension analysis mode (scan `.xpi`/`.crx` files)

### Testing

- Expand test suite beyond current 2 unit tests
- Add property-based testing (proptest/quickcheck)
- Fuzzing integration for the parser
- Regression test suite with real-world programs

### CI/CD

- GitHub Actions workflow for running panic-attack in CI
- Pre-built binaries for common platforms
- Baseline/suppression system for ignoring known issues

---

## Timeline Summary

| Version | Theme | Effort | Cumulative |
|---|---|---|---|
| v0.2 | Fix what's broken | 1–2 days | 2 days |
| v0.3 | Test coverage | 2–3 days | 1 week |
| v0.4 | Constraint sets | 1 week | 2 weeks |
| v0.5 | Real Datalog engine | 2–3 weeks | 5 weeks |
| v0.6 | Multi-program testing | 1–2 weeks | 7 weeks |
| v0.7 | Language expansion | 2–3 weeks | 10 weeks |
| v0.8 | Reporting & CI/CD | 1–2 weeks | 12 weeks |
| v0.9 | Performance & polish | 1 week | 13 weeks |
| v1.0 | Production release | 1–2 weeks | ~15 weeks |

**Roughly 4 months of focused work** from v0.1 to v1.0.

---

## Critical Path

**v0.5 (Real Datalog Engine)** is the make-or-break milestone. Everything
else is incremental improvement, but the signature engine is what separates
panic-attacker from "a fancy grep + stress test script." If the logic
programming works well, the tool is genuinely novel.

**v0.4 (Constraint Sets)** is the second most important — it's the feature
that makes panic-attacker *composable* rather than just a list of
individual stress tests.

---

## Post v1.0

See [VISION.md](VISION.md) for the long-range roadmap:

- **v1.5** — Generic constraint modelling (not software-specific)
- **v2.0** — Sensor/actuator integration
- **v2.5** — Physical system modelling
- **v3.0** — Digital twin stress testing

### Separate Products (Informed by panic-attacker)

- **Resource Topology Simulator** — Cisco-like GUI for resource flow design
- **Software Fuse Framework** — Rust library for building fuse components
- **eclexia Profiler** — eclexia-specific stress testing integration
- **Safety Priority Scheduler** — Production daemon for resource management

---

## Authors

- **Concept & Design:** Jonathan D.A. Jewell
- **Initial Implementation:** Claude (Anthropic) + Jonathan D.A. Jewell
- **Date:** 2026-02-07
