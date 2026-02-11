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

1. **Assail Static Analysis**: Pre-analyzes programs to identify weak points across 5 languages. This is done via the `assail` subcommand.
2. **Multi-Axis Stress Testing**: Attacks programs across 6 different dimensions. This is done via the `attack` subcommand. The `assault` subcommand combines both **Assail Static Analysis** and **Multi-Axis Stress Testing** into a single, comprehensive test.
3. **Logic-Based Bug Detection**: Uses Datalog-inspired rules to detect bug signatures.

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
# Analyze a program (static analysis of source code)
panic-attack assail ./target/release/my-program --verbose

# Full assault (combines static analysis with multi-axis stress testing on a binary)
panic-attack assault ./target/release/my-program

# Ambush: run program under ambient stressors
# Note: The `ambush` subcommand may not be available in all installed versions of panic-attack.
panic-attack ambush ./target/release/my-program

# Amuck: mutate a file with dangerous combinations and save a report
panic-attack amuck ./src/main.rs --preset dangerous

# Abduct: isolate and lock a target with controlled time skew
panic-attack abduct ./src/main.rs --scope direct --mtime-offset-days 21

# Adjudicate: compile multiple reports into a campaign verdict
panic-attack adjudicate reports/run-a.json reports/run-b.json

# Audience: observe reactions from tool execution and report artifacts
panic-attack audience ./src/main.rs --report reports/amuck-run.json

# Single attack (dynamic stress test on a binary)
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

# Analyze source separately from the target binary
panic-attack assault --source /path/to/source ./target/release/my-program
```

### Ambush (Ambient Stressors)

Run the target program while the system is stressed on selected axes. This works even when the
target does not accept attack flags (use profiles/args to pass normal program flags if needed).

```bash
# Ambush with all axes (default)
panic-attack ambush ./my-program

# Limit axes
panic-attack ambush ./my-program --axes cpu,memory,concurrency

# Pass args to the target program
panic-attack ambush ./my-program --arg --config --arg cfg.toml

# Include assail source separate from binary
panic-attack ambush --source /path/to/source ./target/release/my-program

# DAW-style timeline (JSON/YAML)
panic-attack ambush ./my-program --timeline timeline.yaml
```

Timeline format draft: `docs/ambush-timeline.md`.

### Amuck (Mutation Combinations)

Run mutation combinations against a target file. `amuck` never edits the original file in place; it writes variants under `runtime/amuck/` by default and emits a JSON report.

```bash
# Built-in dangerous presets
panic-attack amuck ./src/main.rs --preset dangerous

# Restrict number of combinations and custom output directory
panic-attack amuck ./src/main.rs --max-combinations 6 --output-dir ./tmp/amuck

# Execute a checker command for each mutation (inject mutated file at {file})
panic-attack amuck ./src/main.rs \
  --exec-program rustc \
  --exec-arg {file}

# User-defined combinations
panic-attack amuck ./src/main.rs --spec ./profiles/amuck-spec.json
```

Spec file format (`json` or `yaml`) example:

```json
{
  "combos": [
    {
      "name": "flip-check",
      "operations": [
        { "op": "replace_first", "from": "==", "to": "!=" },
        { "op": "append_text", "text": "\n/* amuck */\n" }
      ]
    }
  ]
}
```

### Abduct (Isolation + Time Skew)

`abduct` creates an isolated workspace copy of a target file, optionally includes related files,
applies readonly lock-down, and can shift file modification times to simulate delayed-trigger
conditions. This is defensive analysis support and does not attempt sandbox anti-detection.

```bash
# Copy target + direct dependency neighborhood, lock files, and age mtimes by 3 weeks
panic-attack abduct ./src/main.rs --scope direct --mtime-offset-days 21

# Same-directory isolation without locking
panic-attack abduct ./src/main.rs --scope directory --no-lock

# Run a checker command inside abduct workflow
panic-attack abduct ./src/main.rs \
  --exec-program rustc \
  --exec-arg {file} \
  --exec-timeout 30

# Time metadata for downstream harnesses
panic-attack abduct ./src/main.rs --time-mode slow --time-scale 0.05
```

### Adjudicate (Campaign Verdict)

Aggregate multiple run artifacts (`assault`, `amuck`, `abduct`) into a campaign-level verdict using miniKanren-style rule inference.

```bash
# Build an expert-style campaign verdict from mixed report types
panic-attack adjudicate reports/assault-a.json reports/amuck-a.json reports/abduct-a.json

# Save adjudication to a specific path
panic-attack adjudicate reports/*.json --output reports/campaign-adjudication.json
```

### Audience (Reaction Observer)

Observe how a target responds when another tool/program runs against it, and/or listen to existing report artifacts for reaction signals.

```bash
# Observe one tool command repeatedly
panic-attack audience ./src/main.rs \
  --exec-program panic-attack \
  --exec-arg amuck \
  --exec-arg {target} \
  --repeat 3

# Observe report artifacts without executing a command
panic-attack audience ./src/main.rs \
  --report reports/amuck-a.json \
  --report reports/abduct-a.json

# Focus on excerpts and pattern search
panic-attack audience ./src/main.rs \
  --report reports/amuck-a.json \
  --head 30 --tail 30 \
  --grep "panic" \
  --agrep "segmntation" --agrep-distance 2

# Enable aspell and localized markdown output
panic-attack audience ./src/main.rs \
  --report reports/amuck-a.json \
  --aspell --aspell-lang en \
  --lang fr \
  --markdown-output reports/audience-fr.md

# Optional pandoc conversion from markdown
panic-attack audience ./src/main.rs \
  --report reports/amuck-a.json \
  --pandoc-to html \
  --pandoc-output reports/audience.html
```

### Attack Profiles & Probe Mode

Assaults can pass custom arguments to targets via a profile file (JSON/YAML) or CLI flags:

```bash
# Use a profile file
panic-attack assault ./my-program --profile profiles/attack-profile.example.json

# Pass common args to every axis
panic-attack assault ./my-program --arg --config --arg cfg.toml

# Axis-specific args (format: AXIS=ARG)
panic-attack assault ./my-program --axis-arg cpu=--iterations --axis-arg cpu=5000

# Probe modes: auto (default), always, never
panic-attack assault ./my-program --probe always
```

Sample profiles live in `profiles/` and are documented in `docs/attack-profiles.md`.

### Analyze Crash Reports

Detect bug signatures from existing crash reports:

```bash
panic-attack analyze crash-report.json
```

### Report Views, Storage, and TUI

Control the experience of generated assault reports with a set of flags:
- `--report-view` chooses between `summary`, `accordion`, `dashboard`, or the `matrix` pivot display.
- Add `--expand-sections` to open accordions automatically or `--pivot` to append the taint matrix to any printout.
- Use `--store <dir>` to persist JSON/YAML/Nickel exports to disk plus the `verisimdb-data/` cache when configured via the manifest.
- Drop `--quiet` to suppress chatter, `--parallel` to run attack phases concurrently, and `--output <file>` with `--output-format` (json|yaml|nickel) to save a single report.
- Browse saved reports with `panic-attack report path/to/report.json`, launch the terminal UI with `panic-attack tui path/to/report.json`, or start the GUI with `panic-attack gui path/to/report.json`.

### VerisimDB Diff Viewer

Compare two reports (JSON/YAML) or use the latest two stored in `verisimdb-data/verisimdb`:

```bash
# Use explicit paths
panic-attack diff base-report.json compare-report.json

# Use latest two stored reports
panic-attack diff
```

### AI Manifest & Nickel

The repository’s `AI.a2ml` manifest now exposes a `(reports ...)` block that dictates the default `formats` (`json`, `nickel`, `yaml`) and `storage-targets` (`filesystem`, `verisimdb`). Run `panic-attack manifest` (or `panic-attack manifest --output manifest.ncl`) to render that manifest as Nickel for downstream configuration and tooling.

### A2ML Report Bundle Import/Export

Convert report artifacts to/from a schema-versioned A2ML report document:

```bash
# Export assail, attack, or ambush reports into A2ML
panic-attack a2ml-export --kind assail reports/assail.json --output reports/assail.a2ml
panic-attack a2ml-export --kind attack reports/attack-results.json --output reports/attack.a2ml
panic-attack a2ml-export --kind ambush reports/ambush.json --output reports/ambush.a2ml

# Export other report families too
panic-attack a2ml-export --kind amuck reports/amuck.json --output reports/amuck.a2ml
panic-attack a2ml-export --kind abduct reports/abduct.json --output reports/abduct.a2ml
panic-attack a2ml-export --kind adjudicate reports/adjudicate.json --output reports/adjudicate.a2ml
panic-attack a2ml-export --kind audience reports/audience.json --output reports/audience.a2ml

# Import back to JSON (optional kind assertion)
panic-attack a2ml-import reports/ambush.a2ml --output reports/ambush.roundtrip.json --kind ambush
```

### PanLL Export

Export an assault report to a PanLL event-chain model:

```bash
panic-attack panll reports/assault-report.json --output panll-event-chain.json
```

See `docs/panll-export.md` for the current export shape.

## Help & Diagnostics

Use `panic-attack help` to print the classic man-style overview that mirrors `man/panic-attack.1` (the bundled man page is installed under `/usr/local/share/man/man1/` inside the verified container) or specify a subcommand to get focused guidance (e.g., `panic-attack help ambush`).  

```bash
# Focused help for mutation and isolation workflows
panic-attack help amuck
panic-attack help abduct
panic-attack help adjudicate
panic-attack help audience
```

Run `panic-attack diagnostics` before publishing a bundle so Hypatia and gitbot-fleet can see whether the AI manifest, reports directories, timeline docs, and watcher endpoints are in place. The command sets `HYPATIA_API_KEY` and `GITBOT_FLEET_ENDPOINT` as environmental hooks and exits non-zero if any check fails, making it safe to gate container builds on its success.

Both commands are wired into the PanLL security menu (help for command hints, diagnostics to confirm Hypatia/gitbot coverage) so the UX layer can surface readiness signals in one place.

## Code Annotation Map

For architecture-level annotations across the codebase, see `docs/codebase-annotations.md`.
For release validation/staging guidance in a dirty worktree, see `docs/release-prep.md`.

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
│   ├── assail/           # Static analysis
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
