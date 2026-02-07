# panic-attacker

Universal stress testing and logic-based bug signature detection tool.

## Overview

`panic-attacker` is a comprehensive program testing tool that combines:

1. **X-Ray Static Analysis**: Pre-analyzes programs to identify weak points
2. **Multi-Axis Stress Testing**: Attacks programs across 6 different axes
3. **Logic-Based Bug Detection**: Uses Datalog-inspired rules to detect bug signatures

## Features

### X-Ray Analysis

Static analysis that detects:
- Language and framework identification
- Unsafe code patterns
- Panic sites and unwrap calls
- Memory allocation patterns
- I/O operations
- Concurrency constructs
- Weak points with severity levels

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

```bash
cargo install --path .
```

## Usage

### X-Ray Analysis

Analyze a program to identify weak points:

```bash
panic-attacker xray ./target/release/my-program

# With detailed output
panic-attacker xray ./target/release/my-program --verbose

# Save report to JSON
panic-attacker xray ./target/release/my-program --output xray-report.json
```

### Single Attack

Execute a single attack on a specific axis:

```bash
# CPU stress test
panic-attacker attack ./target/release/my-program --axis cpu --intensity medium --duration 60

# Memory exhaustion
panic-attacker attack ./target/release/my-program --axis memory --intensity heavy --duration 30

# Concurrency storm
panic-attacker attack ./target/release/my-program --axis concurrency --intensity extreme --duration 120
```

### Full Assault

Run X-Ray analysis followed by multi-axis attacks:

```bash
# Full assault with all axes
panic-attacker assault ./target/release/my-program

# Custom axes
panic-attacker assault ./target/release/my-program --axes cpu,memory,concurrency

# With output report
panic-attacker assault ./target/release/my-program --output assault-report.json --intensity heavy
```

### Analyze Crash Reports

Detect bug signatures from existing crash reports:

```bash
panic-attacker analyze crash-report.json
```

## Architecture

### Core Components

```
panic-attacker/
├── src/
│   ├── main.rs           # CLI interface
│   ├── types.rs          # Core type definitions
│   ├── xray/             # Static analysis
│   │   ├── analyzer.rs
│   │   └── patterns.rs
│   ├── attack/           # Attack orchestration
│   │   ├── executor.rs
│   │   └── strategies.rs
│   ├── signatures/       # Logic-based detection
│   │   ├── engine.rs
│   │   └── rules.rs
│   └── report/           # Report generation
│       ├── generator.rs
│       └── formatter.rs
```

### Logic Programming Approach

The signature detection engine uses a Datalog-inspired approach:

**Facts** (extracted from crash reports):
```
Alloc(var, location)
Free(var, location)
Use(var, location)
Lock(mutex, location)
Write(var, location)
Read(var, location)
```

**Rules** (inference patterns):
```
UseAfterFree(var, use_loc, free_loc) :-
    Free(var, free_loc),
    Use(var, use_loc),
    Ordering(free_loc, use_loc)

DoubleFree(var, loc1, loc2) :-
    Free(var, loc1),
    Free(var, loc2),
    loc1 != loc2

Deadlock(m1, m2) :-
    Lock(m1, loc1), Lock(m2, loc2),
    Lock(m2, loc3), Lock(m1, loc4),
    Ordering(loc1, loc2), Ordering(loc3, loc4)

DataRace(var, loc1, loc2) :-
    Write(var, loc1), Read(var, loc2),
    Concurrent(loc1, loc2),
    ¬Synchronized(loc1, loc2)
```

## Design Philosophy

### Mozart/Oz Inspiration

The tool is inspired by Mozart/Oz's logic programming model:

1. **Declarative Rules**: Bug patterns defined as logical rules
2. **Constraint Solving**: Facts extracted and matched against constraints
3. **Inference Engine**: Forward-chaining to detect complex patterns
4. **Temporal Logic**: Ordering constraints for sequence-dependent bugs

### Multi-Program Testing

The architecture supports testing multiple programs simultaneously:

- Parallel attack execution
- Cross-program correlation
- Comparative robustness analysis

### Program-Data Corpus

Supports testing with real-world data:

- Custom input corpus
- Mutation-based fuzzing
- Coverage-guided exploration

## Example Output

```
=== PANIC-ATTACKER ASSAULT REPORT ===

X-RAY ANALYSIS
  Program: ./target/release/my-server
  Language: Rust
  Frameworks: [WebServer, Database]

  Statistics:
    Total lines: 15234
    Unsafe blocks: 3
    Panic sites: 12
    Unwrap calls: 47

  Weak Points Detected: 2
    1. [High] UnsafeCode - 3 unsafe blocks detected
    2. [Medium] PanicPath - 47 unwrap/expect calls detected

ATTACK RESULTS
  Cpu attack: PASSED (exit code: Some(0), duration: 60.23s)
  Memory attack: FAILED (exit code: Some(137), duration: 15.45s)
    Crashes: 1
      1. Signal: Some("SIGKILL")
  Concurrency attack: FAILED (exit code: Some(134), duration: 30.12s)
    Crashes: 2
      1. Signal: Some("SIGABRT")
      2. Signal: Some("SIGABRT")

BUG SIGNATURES DETECTED
  Total: 3

  During Memory attack:
    - MemoryLeak (confidence: 0.82)
      Evidence: Unbounded allocation detected
      Evidence: No cleanup on error paths

  During Concurrency attack:
    - Deadlock (confidence: 0.91)
      Evidence: Deadlock pattern in error message
    - DataRace (confidence: 0.75)
      Evidence: Concurrent reads and writes detected

OVERALL ASSESSMENT
  Robustness Score: 43.5/100

  Critical Issues:
    - Program crashed under Memory attack (1 crashes)
    - Program crashed under Concurrency attack (2 crashes)
    - High-confidence Deadlock detected (confidence: 0.91)

  Recommendations:
    - Add comprehensive error handling for edge cases
    - Replace unwrap() calls with proper error handling
    - Audit unsafe blocks for memory safety violations
    - Review lock ordering to prevent deadlocks
```

## Supported Languages

Currently supports analysis for:

- Rust
- C/C++
- Go
- Python
- JavaScript/TypeScript
- Ruby
- Java

## Extensibility

### Adding New Attack Patterns

Create pattern definitions in `src/xray/patterns.rs`:

```rust
AttackPattern {
    name: "Custom Attack".to_string(),
    description: "Description of attack".to_string(),
    applicable_axes: vec![AttackAxis::Memory],
    applicable_languages: vec![Language::Rust],
    applicable_frameworks: vec![Framework::WebServer],
    command_template: "{program} --custom-flag".to_string(),
}
```

### Adding New Signature Rules

Define rules in `src/signatures/rules.rs`:

```rust
Rule {
    name: "custom_bug".to_string(),
    head: Predicate::CustomBug { ... },
    body: vec![
        Predicate::Fact(Fact::CustomFact { ... }),
        // ... more predicates
    ],
}
```

## Contributing

This is a hyperpolymath project following RSR (Reproducible Software Repositories) standards.

## License

SPDX-License-Identifier: PMPL-1.0-or-later

Palimpsest Meta-Public License v1.0 or later.

## Author

Jonathan D.A. Jewell <jonathan.jewell@open.ac.uk>

## Related Projects

- `git-seo`: Git repository analysis and optimization
- `hypatia`: Neurosymbolic CI/CD intelligence
- `gitbot-fleet`: Repository automation bots
