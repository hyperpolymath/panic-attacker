# SPDX-License-Identifier: PMPL-1.0-or-later

# panic-attacker Roadmap

## Current State: v0.1.0

**2,359 lines of Rust.** Functional proof of concept, not scaffolding.

| Component | Status | Notes |
|---|---|---|
| X-Ray static analysis | Working | 5 language-specific analyzers |
| Attack executor (6 axes) | Working | CPU, memory, disk, network, concurrency, time |
| Signature detection | Working | Simplified (string matching, not real Datalog) |
| Report generation | Working | Robustness scoring, coloured terminal output, JSON |
| CLI (4 commands) | Working | xray, attack, assault, analyze |
| Pattern library | Defined but unused | Not wired into attack selection |
| Tests | 2 unit tests | Effectively untested |
| Constraint sets | Not started | — |
| Multi-program testing | Not started | — |

### Tested Against

- **eclexia** (23,295 lines Rust): 66 weak points, 0 unsafe blocks, high unwrap density
- **echidna** (60,248 lines Rust): 271 weak points, 15 unsafe blocks, 4 frameworks detected

---

## v0.2 — Fix What's Broken

**Theme: Make the existing output trustworthy**

- [ ] Fix X-Ray duplicate entries (running counts → per-file delta counts)
- [ ] Add file paths to weak point `location` field (currently all `null`)
- [ ] Wire pattern library into attack selection (currently defined but unused)
- [ ] Connect `RuleSet` to signature engine (currently stored but ignored)
- [ ] Handle non-UTF-8 source files gracefully (skip with warning, not crash)
  - Already partially fixed: `fs::read_to_string` failures now `continue`
  - Improvement: attempt Latin-1/ISO-8859-1 fallback before skipping
  - Improvement: log skipped files in verbose mode
  - Root cause: vendored third-party C files with non-ASCII author names
    (e.g. `Jørn` encoded as ISO-8859-1 `0xf8` instead of UTF-8 `0xc3b8`)
- [ ] Fix the 10 compiler warnings (dead code)
- [ ] Add integration test using `examples/vulnerable_program.rs`
- [ ] Per-file breakdown in verbose output (which files contribute most weak points)

**Estimated: 1–2 days**

---

## v0.3 — Test Coverage

**Theme: Trust the tool enough to use it on real code**

- [ ] Unit tests for X-Ray (each language analyzer: Rust, C/C++, Go, Python, generic)
- [ ] Unit tests for signature engine (each inference rule)
- [ ] Integration tests: X-Ray → Attack → Signature pipeline
- [ ] Test against example vulnerable program (panic, OOM, deadlock, race)
- [ ] Regression test: eclexia baseline (66 weak points, known profile)
- [ ] Regression test: echidna baseline (271 weak points, known profile)
- [ ] CI with GitHub Actions
- [ ] Code coverage reporting

**Estimated: 2–3 days**

---

## v0.4 — Constraint Sets

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
- [ ] Comparative reports (diff two X-Ray runs)
- [ ] Badge generation (robustness score badge for README)

**Estimated: 1–2 weeks**

---

## v0.9 — Performance & Polish

**Theme: Make it fast and reliable enough for production use**

- [ ] Parallel X-Ray analysis (rayon for file scanning)
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
- [ ] X-Ray panic-attacker with panic-attacker (meta-test)
- [ ] Stable JSON output schema (versioned, documented)
- [ ] Minimum supported Rust version (MSRV) policy

**Estimated: 1–2 weeks of hardening**

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
