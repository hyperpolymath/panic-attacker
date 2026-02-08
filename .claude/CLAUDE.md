# Panic Attack - Project Instructions

## Overview

Static analysis and bug signature detection tool. Scans source code for weak points (unwrap/expect, unsafe blocks, panic sites, error handling gaps) across multiple languages.

**Position in AmbientOps ecosystem**: Part of the hospital model, loosely affiliated. Sits alongside the Operating Room as a diagnostic tool for software health (while hardware-crash-team handles hardware health). Independent top-level repo, but feeds findings to the hospital's Records system via verisimdb.

**Relationship to AmbientOps**: See [ambientops/.claude/CLAUDE.md](https://github.com/hyperpolymath/ambientops/blob/main/.claude/CLAUDE.md) for the hospital model overview.

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

## Sweep Subcommand (Priority - Sonnet Task)

Add a `sweep` subcommand that scans an entire directory of git repos in one pass.

### Design

```
panic-attack sweep /path/to/repos/ [options]
  --format json|text|sarif       Output format (default: text)
  --output report.json           Save aggregate report
  --push-to-verisimdb URL        Push each result to verisimdb API
  --push-to-data-repo PATH       Write each result to verisimdb-data repo
  --min-risk medium              Only report repos at or above this risk level
  --parallel N                   Number of concurrent scans (default: 4)
```

### Implementation Steps

1. Add `Sweep` variant to the `Commands` enum in main.rs
2. Walk the directory looking for `.git/` subdirectories (use walkdir, already a dependency)
3. For each repo found, call the existing `assail` scan logic
4. Aggregate results into a summary report
5. Optionally push each result to verisimdb-data repo as JSON files
6. Print aggregate summary (total repos, total weak points, top offenders)

### verisimdb-data Integration

When `--push-to-data-repo` is specified:
- Write each scan result to `{data-repo}/scans/{repo-name}.json`
- Update `{data-repo}/index.json` with summary entry
- Git add + commit with message "scan: update {repo-name} results"

### GitHub Actions Reusable Workflow

Create `.github/workflows/scan-and-report.yml` as a reusable workflow:
```yaml
# Other repos call this:
# uses: hyperpolymath/panic-attacker/.github/workflows/scan-and-report.yml@main
# This runs panic-attack assail on the calling repo
# and dispatches results to verisimdb-data
```

## Scan Results from 2026-02-08 Session

21 repos scanned, 118 total weak points, zero critical, 17 high:
- protocol-squisher: 39 weak points (highest)
- echidna: 15 weak points
- verisimdb: 12 weak points
- Most high-severity findings are expected unsafe blocks in FFI/GC code

Results loaded into verisimdb as hexads (verified working with text search).

## Code Style

- SPDX headers on all files: `PMPL-1.0-or-later`
- Author: Jonathan D.A. Jewell <jonathan.jewell@open.ac.uk>
- Use anyhow::Result for error handling
- Zero compiler warnings policy
- Serde derive on public types for JSON serialization
