# Changelog

## [1.0.1] - 2026-02-07

### Fixed
- **CI/CD workflows**: All GitHub Actions now passing
  - Updated MSRV from 1.75.0 → 1.85.0 (required for Cargo.lock v4 format)
  - Fixed invalid codeql-action SHA pins (using version tags for Scorecard compatibility)
  - Fixed TruffleHog configuration (BASE/HEAD commit conflict)
  - Fixed EditorConfig indentation violations
- **Code quality**:
  - Resolved clippy warnings (manual_clamp, unwrap_or_default)
  - Added `#[allow]` attributes for intentional vulnerabilities in examples
  - Removed unused imports
  - Applied rustfmt to all source files

### Changed
- **MSRV**: Updated from 1.75.0 to 1.85.0
- **Workflows**: codeql-action now uses version tags instead of SHA pins

## [1.0.0] - 2026-02-07

### Added
- **Production-ready infrastructure**:
  - Complete RSR compliance (AI.a2ml manifest, 3 SCM files)
  - 11 GitHub Actions workflows (CI, security, coverage, quality)
  - Comprehensive documentation (SECURITY.md, CONTRIBUTING.md, LICENSE)
  - Stable JSON schema (v1.0, documented, versioned)
- **Testing**:
  - 21 unit tests covering all analyzers
  - 3 integration tests (X-Ray pipeline, vulnerable programs)
  - 3 regression tests (echidna, eclexia, self-test baselines)
  - Code coverage reporting with codecov
- **Configuration**:
  - Config file support (panic-attacker.toml)
  - EditorConfig for consistent formatting
  - MSRV policy (1.75.0, later updated to 1.85.0)

## [0.2.0] - 2026-02-07

### Fixed
- **Weak points now per-file, not running totals**: v0.1 produced duplicate weak points with cumulative counts across all files. v0.2 analyzes each file independently, eliminating duplicates.
  - Example: echidna went from 271 weak points (v0.1) → 15 weak points (v0.2)
- **File locations always populated**: Weak points now include `location: Some("path/to/file.rs")` instead of `location: None`
- **Descriptions include filenames**: e.g., "12 unwrap/expect calls in src/server.rs" instead of "219 unwrap/expect calls detected"

### Added
- **FileStatistics**: Per-file breakdown of all metrics (unsafe blocks, panics, unwraps, allocations, I/O, threading)
- **Latin-1 fallback**: Non-UTF-8 source files are decoded with Windows-1252 before skipping
- **Verbose mode**: `--verbose` flag prints per-file breakdown sorted by risk score (top 10)
- **Pattern library wired**: AttackExecutor now uses PatternDetector to select language/framework-specific attacks
- **RuleSet wired**: SignatureEngine dispatches on rule names from RuleSet
- **Library interface**: `src/lib.rs` re-exports all modules for integration tests and external consumers
- **Integration tests**: 3 new tests verify locations, no-duplicates, and per-file stats
- **encoding_rs dependency**: For robust Latin-1 decoding

### Changed
- **Analyzer refactored**: Fresh `ProgramStatistics` per file, accumulated into global stats
- **Attack executor**: Added `with_patterns()` constructor, logs strategy descriptions and applicable patterns
- **Assault command**: Uses pattern-aware attack execution (`execute_attack_with_patterns`)
- **Report formatter**: Prints per-file breakdown in assault reports

### Removed
- **Dead code warnings**: Suppressed with `#[allow(dead_code)]` on 4 items reserved for v0.5 Datalog engine
- **Unused Context import**: Removed from `xray/analyzer.rs`
- **Stale chrono import**: Removed duplicate from `attack/executor.rs` (already in Cargo.toml)

### Verification
- Zero compiler warnings
- 7/7 tests pass (2 unit + 2 unit-via-main + 3 integration)
- echidna: 271 → 15 weak points, all with file locations
- eclexia: 7 weak points, all with file locations, 49 files analyzed

## [0.1.0] - 2026-02-06

Initial proof-of-concept release with X-Ray static analysis, multi-axis stress testing, and logic-based bug signature detection.
