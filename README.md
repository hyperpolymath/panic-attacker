# panic-attack

[![CI](https://github.com/hyperpolymath/panic-attacker/workflows/Rust%20CI/badge.svg)](https://github.com/hyperpolymath/panic-attacker/actions/workflows/rust-ci.yml)
[![Security Audit](https://github.com/hyperpolymath/panic-attacker/workflows/Security%20Audit/badge.svg)](https://github.com/hyperpolymath/panic-attacker/actions/workflows/cargo-audit.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/hyperpolymath/panic-attacker/badge)](https://securityscorecards.dev/viewer/?uri=github.com/hyperpolymath/panic-attacker)
[![codecov](https://codecov.io/gh/hyperpolymath/panic-attacker/branch/main/graph/badge.svg)](https://codecov.io/gh/hyperpolymath/panic-attacker)
[![License: PMPL](https://img.shields.io/badge/License-PMPL--1.0--or--later-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.85.0-blue)](Cargo.toml)

Universal stress testing and logic-based bug signature detection tool.

## Overview

`panic-attack` is a comprehensive program testing tool that combines:

1. **Assail Static Analysis**: Pre-analyzes programs to identify weak points across 5 languages
2. **Multi-Axis Stress Testing**: Attacks programs across 6 different dimensions
3. **Logic-Based Bug Detection**: Uses Datalog-inspired rules to detect bug signatures

## Features

### ✨ What's New in v0.2

- **Zero duplicate weak points**: Per-file analysis eliminates running totals (271→15 on echidna)
- **All locations populated**: Every weak point includes file path (never `null`)
- **Per-file breakdown**: Verbose mode shows top 10 files by risk score
- **Latin-1 fallback**: Handles non-UTF-8 source files gracefully
- **Pattern library wired**: Language/framework-specific attack selection
- **Zero compiler warnings**: Clean builds, quality code

### Assail Analysis

Static analysis that detects:
- ✅ Language and framework identification (Rust, C/C++, Go, Python, generic)
- ✅ Unsafe code patterns
- ✅ Panic sites and unwrap calls
- ✅ Memory allocation patterns
- ✅ I/O operations
- ✅ Concurrency constructs
- ✅ Weak points with severity levels (Critical, High, Medium, Low)
- ✅ Per-file statistics and risk scoring

### Attack Axes

Six different stress testing dimensions:

1. **CPU**: High computational load
2. **Memory**: Large allocations, memory exhaustion
3. **Disk**: Heavy I/O operations
4. **Network**: Connection flooding
5. **Concurrency**: Thread/task storms
6. **Time**: Extended duration testing

### Bug Signature Detection

Logic programming-based detection (inspired by Mozart/Oz and Datalog) for:

- Use-after-free
- Double-free
- Memory leaks
- Deadlocks
- Data races
- Buffer overflows
- Integer overflows
- Null pointer dereferences
- Unhandled errors

## Installation

### From Source

```bash
git clone https://github.com/hyperpolymath/panic-attacker.git
cd panic-attack
cargo build --release
cargo install --path .
```

### Requirements

- Rust 1.85.0 or later
- Cargo

## Quick Start

```bash
# Analyze a program
panic-attack assail ./target/release/my-program --verbose

# Full assault (assail + multi-axis attacks)
panic-attack assault ./target/release/my-program

# Single attack
panic-attack attack ./target/release/my-program --axis memory --intensity heavy
```

## Usage

### Assail Analysis

Analyze a program to identify weak points:

```bash
# Basic analysis
panic-attack assail ./target/release/my-program

# Verbose with per-file breakdown
panic-attack assail /path/to/project --verbose

# Save report to JSON
panic-attack assail ./my-program --output assail-report.json
```

**Example output:**

```
Assail Analysis Complete
  Language: Rust
  Frameworks: [WebServer, Database]
  Weak Points: 15
  Recommended Attacks: [Memory, Disk, Concurrency, Cpu]

  Per-file Breakdown (top 10 by risk):
    1. src/server.rs (risk: 38, unsafe: 3, panics: 11, unwraps: 16)
    2. src/database.rs (risk: 33, unsafe: 0, panics: 10, unwraps: 13)
    3. src/ffi.rs (risk: 27, unsafe: 7, panics: 0, unwraps: 4)
```

### Single Attack

Execute a single attack on a specific axis:

```bash
# CPU stress test
panic-attack attack ./my-program --axis cpu --intensity medium --duration 60

# Memory exhaustion
panic-attack attack ./my-program --axis memory --intensity heavy --duration 30

# Concurrency storm
panic-attack attack ./my-program --axis concurrency --intensity extreme --duration 120
```

### Full Assault

Run assail analysis followed by multi-axis attacks:

```bash
# Full assault with all axes
panic-attack assault ./my-program

# Custom axes only
panic-attack assault ./my-program --axes cpu,memory,concurrency

# With output report
panic-attack assault ./my-program --output assault-report.json --intensity heavy
```

### Analyze Crash Reports

Detect bug signatures from existing crash reports:

```bash
panic-attack analyze crash-report.json
```

## Example Output

```
=== PANIC-ATTACK ASSAULT REPORT ===

ASSAIL ANALYSIS
  Program: ./target/release/my-server
  Language: Rust
  Frameworks: [WebServer, Database]

  Statistics:
    Total lines: 15234
    Unsafe blocks: 3
    Panic sites: 12
    Unwrap calls: 47

  Weak Points Detected: 2
    1. [High] UnsafeCode - 3 unsafe blocks in src/ffi.rs
    2. [Medium] PanicPath - 47 unwrap/expect calls in src/server.rs

ATTACK RESULTS
  Cpu attack: PASSED (exit code: 0, duration: 60.23s)
  Memory attack: FAILED (exit code: 137, duration: 15.45s)
    Crashes: 1
      1. Signal: SIGKILL
  Concurrency attack: FAILED (exit code: 134, duration: 30.12s)
    Crashes: 2

BUG SIGNATURES DETECTED
  Total: 3
  - Deadlock (confidence: 0.91)
  - DataRace (confidence: 0.75)
  - MemoryLeak (confidence: 0.82)

OVERALL ASSESSMENT
  Robustness Score: 43.5/100

  Critical Issues:
    - Program crashed under Memory attack
    - High-confidence Deadlock detected

  Recommendations:
    - Add comprehensive error handling
    - Replace unwrap() calls with proper error handling
    - Review lock ordering to prevent deadlocks
```

## Architecture

### Core Components

```
panic-attack/
├── src/
│   ├── main.rs           # CLI interface
│   ├── lib.rs            # Library interface
│   ├── types.rs          # Core type definitions
│   ├── xray/             # Static analysis
│   │   ├── analyzer.rs   # Language-specific analyzers
│   │   └── patterns.rs   # Attack pattern library
│   ├── attack/           # Attack orchestration
│   │   ├── executor.rs   # Attack execution
│   │   └── strategies.rs # Attack strategies
│   ├── signatures/       # Logic-based detection
│   │   ├── engine.rs     # Signature detection engine
│   │   └── rules.rs      # Datalog-style rules
│   └── report/           # Report generation
│       ├── generator.rs  # Report logic
│       └── formatter.rs  # Output formatting
├── tests/                # Integration tests
├── examples/             # Example programs
└── .machine_readable/    # RSR checkpoint files
```

### Logic Programming Approach

The signature detection engine uses a Datalog-inspired approach:

**Facts** (extracted from crash reports):
```
Alloc(var, location)
Free(var, location)
Use(var, location)
Lock(mutex, location)
```

**Rules** (inference patterns):
```prolog
UseAfterFree(var, use_loc, free_loc) :-
    Free(var, free_loc),
    Use(var, use_loc),
    Ordering(free_loc, use_loc)

DoubleFree(var, loc1, loc2) :-
    Free(var, loc1),
    Free(var, loc2),
    loc1 != loc2
```

## Supported Languages

Currently supports analysis for:

- **Rust** (full support)
- **C/C++** (full support)
- **Go** (full support)
- **Python** (full support)
- **Generic** (basic heuristics for other languages)

## Roadmap

See [ROADMAP.md](ROADMAP.md) for detailed development plans.

**Current focus (v1.0):**
- ✅ RSR compliance (AI manifests, workflows, SCM files)
- ✅ Comprehensive test coverage
- 🚧 CI/CD integration
- 🚧 Documentation polish
- 🚧 Production hardening

**Future milestones:**
- v1.x: Constraint sets (YAML stress profiles)
- v2.0: Real Datalog engine (Crepe/Datafrog)
- v2.x: Multi-program testing
- v3.0: Language expansion and performance optimization

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

Key points:
- Follow RSR standards
- Zero warnings policy
- 80% test coverage target
- Comprehensive documentation

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

Licensed under the [Palimpsest Meta-Public License v1.0 or later](LICENSE).

SPDX-License-Identifier: PMPL-1.0-or-later

## Author

**Jonathan D.A. Jewell** <jonathan.jewell@open.ac.uk>

## Related Projects

- [hypatia](https://github.com/hyperpolymath/hypatia) - Neurosymbolic CI/CD intelligence
- [git-seo](https://github.com/hyperpolymath/git-seo) - Git repository analysis
- [gitbot-fleet](https://github.com/hyperpolymath/gitbot-fleet) - Repository automation bots
- [echidna](https://github.com/hyperpolymath/echidna) - Automated theorem proving
- [eclexia](https://github.com/hyperpolymath/eclexia) - Resource-aware adaptive programming

## Citation

If you use panic-attack in your research, please cite:

```bibtex
@software{panic_attack,
  author = {Jewell, Jonathan D.A.},
  title = {panic-attack: Universal Stress Testing and Logic-Based Bug Detection},
  year = {2026},
  url = {https://github.com/hyperpolymath/panic-attacker},
  version = {0.2.0}
}
```

---

**Status**: Active development | **Version**: 0.2.0 | **MSRV**: 1.85.0
