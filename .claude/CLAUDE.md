# Panic Attack - Project Instructions

## Overview

Static analysis and bug signature detection tool. Scans source code for weak points (unwrap/expect, unsafe blocks, panic sites, error handling gaps) across multiple languages.

**IMPORTANT: This tool was renamed on 2026-02-08:**
- Binary: `panic-attacker` → `panic-attack`
- Subcommand: `xray` → `assail`
- Report header: `X-RAY` → `ASSAIL`

## Architecture

```
src/
├── main.rs              # CLI entry point (clap)
├── lib.rs               # Library API
├── types.rs             # Core types (ScanResult, WeakPoint, etc.)
├── xray/mod.rs          # Assail analyzer (renamed from xray internally)
├── attacks/             # 6-axis stress testing
├── signatures/          # Logic-based bug signatures (Datalog-inspired)
├── patterns/            # Language-specific pattern matching
└── report/
    └── formatter.rs     # Output formatting (text + JSON)
```

## Build & Test

```bash
cargo build --release
cargo test

# Run scan:
panic-attack assail /path/to/repo
panic-attack assail /path/to/repo --format json --output report.json
panic-attack assail self-test  # Self-scan for validation
```

## Key Design Decisions

- **5 language analyzers**: Rust, C/C++, Go, Python, generic fallback
- **Weak point categories**: unwrap/expect, unsafe blocks, panic sites, todo/fixme, error suppression
- **Per-file statistics**: Each file gets individual risk scoring
- **Latin-1 fallback**: Non-UTF-8 files handled gracefully
- **JSON output**: Machine-readable for pipeline integration

## Planned Features (Next Priorities)

1. **`sweep` subcommand**: Scan entire directory of git repos in one go
2. **verisimdb integration**: Push results as hexads to verisimdb API
3. **hypatia pipeline**: Feed results through rule engine for pattern detection
4. **SARIF output**: GitHub Security tab integration
5. **RSR compliance**: Standard workflows, docs, shell completions

## Integration Points

- **verisimdb**: Store scan results as hexads (document + semantic modalities)
- **hypatia**: Neurosymbolic rule engine processes findings
- **echidnabot**: Proof verification of scan claims
- **sustainabot**: Ecological/economic code health metrics
- **hardware-crash-team**: Sibling tool (hardware diagnostics vs software analysis)

## Code Style

- SPDX headers on all files: `PMPL-1.0-or-later`
- Author: Jonathan D.A. Jewell <jonathan.jewell@open.ac.uk>
- Use anyhow::Result for error handling
- Zero compiler warnings policy
- Serde derive on public types for JSON serialization
