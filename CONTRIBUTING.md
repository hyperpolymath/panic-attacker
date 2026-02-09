# Contributing to panic-attacker

Thank you for your interest in contributing to panic-attacker! This document provides guidelines and information for contributors.

## Code of Conduct

This project follows the Contributor Covenant Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to jonathan.jewell@open.ac.uk.

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates. When creating a bug report, include:

- **Clear title** describing the issue
- **Detailed description** of the problem
- **Steps to reproduce** the behavior
- **Expected behavior** vs actual behavior
- **Environment** (OS, Rust version, panic-attacker version)
- **Logs or error messages** if applicable

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- **Use a clear and descriptive title**
- **Provide a detailed description** of the proposed feature
- **Explain why this enhancement would be useful** to most users
- **List any alternatives** you've considered

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Follow the coding standards** described below
3. **Add tests** for any new functionality
4. **Update documentation** including README, rustdoc, and examples
5. **Ensure all tests pass** (`cargo test`)
6. **Ensure zero warnings** (`cargo build --release`)
7. **Run clippy** (`cargo clippy -- -D warnings`)
8. **Format code** (`cargo fmt`)
9. **Write a clear commit message** following the project's commit style

## Development Setup

### Prerequisites

- Rust 1.75.0 or later
- Cargo
- Git

### Building

```bash
git clone https://github.com/hyperpolymath/panic-attacker.git
cd panic-attacker
cargo build
```

### Running Tests

```bash
# Run all tests
cargo test

# Run with verbose output
cargo test -- --nocapture

# Run specific test
cargo test test_name
```

### Running Locally

```bash
cargo run -- assail ./examples/vulnerable_program.rs --verbose
```

## Coding Standards

### Rust Style

- Follow the [Rust Style Guide](https://doc.rust-lang.org/1.0.0/style/)
- Use `cargo fmt` for consistent formatting
- Use `cargo clippy` to catch common mistakes
- Maximum line length: 100 characters (flexible for readability)

### Documentation

- All public APIs must have rustdoc comments
- Include examples in rustdoc where appropriate
- Keep comments up-to-date with code changes
- Use `//!` for module-level documentation
- Use `///` for item-level documentation

### Testing

- Write unit tests for all non-trivial functions
- Write integration tests for user-facing features
- Aim for 80% code coverage
- Test edge cases and error conditions
- Use descriptive test names: `test_<what>_<condition>_<expected_result>`

### Commit Messages

Follow the Conventional Commits specification:

```
<type>: <description>

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Adding or updating tests
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `chore`: Maintenance tasks

Example:
```
feat: add Latin-1 fallback for non-UTF-8 files

Implements encoding_rs fallback when UTF-8 decoding fails.
Verbose mode logs skipped files. Fixes handling of vendored
C files with non-ASCII author names.

Closes #42
```

## Project Structure

```
panic-attacker/
├── src/
│   ├── main.rs          # CLI entry point
│   ├── lib.rs           # Library interface
│   ├── types.rs         # Core type definitions
│   ├── assail/            # Static analysis
│   │   ├── analyzer.rs  # Language-specific analyzers
│   │   └── patterns.rs  # Attack pattern library
│   ├── attack/          # Attack execution
│   │   ├── executor.rs  # Attack orchestration
│   │   └── strategies.rs # Attack strategies
│   ├── signatures/      # Bug detection
│   │   ├── engine.rs    # Signature detection engine
│   │   └── rules.rs     # Datalog-style rules
│   └── report/          # Report generation
│       ├── generator.rs # Report logic
│       └── formatter.rs # Output formatting
├── tests/               # Integration tests
├── examples/            # Example programs
├── .machine_readable/   # SCM checkpoint files
└── .github/workflows/   # CI/CD workflows
```

## RSR Compliance

This project follows RSR (Reproducible Software Repositories) standards:

### Critical Invariants

1. **SCM files in .machine_readable/ only** - Never put STATE.scm, ECOSYSTEM.scm, or META.scm in the repository root
2. **AI manifest required** - AI.a2ml must be present and up-to-date
3. **License consistency** - All files must use PMPL-1.0-or-later (SPDX header)
4. **Author attribution** - Jonathan D.A. Jewell <jonathan.jewell@open.ac.uk>

### Updating Checkpoint Files

When making significant changes, update:
- `.machine_readable/STATE.scm` - Current state, completion %, next actions
- `.machine_readable/ECOSYSTEM.scm` - If adding new dependencies or integrations
- `.machine_readable/META.scm` - If making architectural decisions (ADRs)

## Release Process

1. Update version in `Cargo.toml` and `src/main.rs`
2. Update `CHANGELOG.md` with changes since last release
3. Update `.machine_readable/STATE.scm` with new version
4. Run full test suite
5. Create git tag: `git tag -a v0.x.0 -m "Release v0.x.0"`
6. Push tag: `git push origin v0.x.0`
7. GitHub Actions will create the release

## Getting Help

- **Documentation**: See README.md and DESIGN.md
- **Issues**: Check existing issues or create a new one
- **Email**: jonathan.jewell@open.ac.uk
- **Roadmap**: See ROADMAP.md for future plans

## License

By contributing to panic-attacker, you agree that your contributions will be licensed under the PMPL-1.0-or-later license. See the LICENSE file for details.

## Recognition

Contributors will be acknowledged in:
- CHANGELOG.md for their specific contributions
- GitHub contributors page
- Release notes

Thank you for contributing to panic-attacker!
