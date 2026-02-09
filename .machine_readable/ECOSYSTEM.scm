;; SPDX-License-Identifier: PMPL-1.0-or-later
;; Ecosystem position for panic-attack (formerly panic-attacker)
;; Media Type: application/vnd.ecosystem+scm

(ecosystem
  (version "1.0")
  (name "panic-attack")
  (type "tool")
  (purpose "Universal static analysis and logic-based bug signature detection for 47 languages")

  (position-in-ecosystem
    (layer "development-tools")
    (category "testing-quality")
    (subcategory "static-analysis-stress-testing")
    (maturity "stable")
    (adoption "internal"))

  (related-projects
    (project
      (name "verisimdb")
      (relationship "data-store")
      (integration "panic-attack scan results stored as hexads in verisimdb")
      (url "https://github.com/hyperpolymath/verisimdb")
      (description "Verification-similarity database for code quality metrics"))

    (project
      (name "verisimdb-data")
      (relationship "data-pipeline")
      (integration "scan JSON ingested via ingest-scan.sh into verisimdb-data repo")
      (url "https://github.com/hyperpolymath/verisimdb-data")
      (description "Git-based data store for verisimdb scan results"))

    (project
      (name "hypatia")
      (relationship "consumer")
      (integration "uses panic-attack for repository health assessment, VeriSimDB connector")
      (url "https://github.com/hyperpolymath/hypatia")
      (description "Neurosymbolic CI/CD intelligence"))

    (project
      (name "gitbot-fleet")
      (relationship "consumer")
      (integration "bots can trigger panic-attack scans via repository_dispatch")
      (url "https://github.com/hyperpolymath/gitbot-fleet")
      (description "Repository automation bots (rhodibot, echidnabot, etc.)"))

    (project
      (name "ambientops")
      (relationship "sibling-tool")
      (integration "hospital model: panic-attack is diagnostic tool, ambientops is operating room")
      (url "https://github.com/hyperpolymath/ambientops")
      (description "AmbientOps hospital model for software health"))

    (project
      (name "hardware-crash-team")
      (relationship "sibling-tool")
      (integration "panic-attack handles software diagnostics, hardware-crash-team handles hardware")
      (url "https://github.com/hyperpolymath/hardware-crash-team")
      (description "Hardware health diagnostics"))

    (project
      (name "echidna")
      (relationship "test-subject")
      (integration "used as benchmark for panic-attack testing (15 weak points)")
      (url "https://github.com/hyperpolymath/echidna")
      (description "Automated theorem proving orchestrator"))

    (project
      (name "eclexia")
      (relationship "test-subject")
      (integration "used as benchmark for panic-attack testing")
      (url "https://github.com/hyperpolymath/eclexia")
      (description "Resource-aware adaptive programming language"))

    (project
      (name "rsr-template-repo")
      (relationship "template-provider")
      (integration "panic-attack follows RSR standards")
      (url "https://github.com/hyperpolymath/rsr-template-repo")
      (description "RSR-compliant repository template"))

    (project
      (name "0-ai-gatekeeper-protocol")
      (relationship "standard-provider")
      (integration "panic-attack implements AI manifest protocol")
      (url "https://github.com/hyperpolymath/0-ai-gatekeeper-protocol")
      (description "Universal AI manifest system"))

    (project
      (name "robot-repo-automaton")
      (relationship "potential-consumer")
      (integration "could use panic-attack for automated quality checks")
      (url "https://github.com/hyperpolymath/robot-repo-automaton")
      (description "Automated repository fixes with confidence thresholds")))

  (dependencies
    (runtime
      (dependency
        (name "encoding_rs")
        (version "0.8")
        (purpose "Latin-1 fallback for non-UTF-8 files"))
      (dependency
        (name "clap")
        (version "4.5")
        (purpose "CLI argument parsing"))
      (dependency
        (name "colored")
        (version "2.1")
        (purpose "Terminal output formatting"))
      (dependency
        (name "regex")
        (version "1.10")
        (purpose "Pattern matching in source code"))
      (dependency
        (name "serde")
        (version "1.0")
        (purpose "JSON serialization"))
      (dependency
        (name "anyhow")
        (version "1.0")
        (purpose "Error handling"))
      (dependency
        (name "chrono")
        (version "0.4")
        (purpose "Timestamp generation")))

    (development
      (dependency
        (name "tempfile")
        (version "3.8")
        (purpose "Temporary files in tests"))))

  (future-integrations
    (integration
      (name "sweep subcommand")
      (status "planned-v2.1")
      (description "Bulk scanning of directory-of-repos with aggregated results"))

    (integration
      (name "verisimdb API push")
      (status "planned-v2.1")
      (description "Push scan results as hexads directly to verisimdb API"))

    (integration
      (name "hypatia pipeline")
      (status "planned-v2.1")
      (description "Feed kanren facts as Logtalk predicates to hypatia rule engine"))

    (integration
      (name "SARIF output")
      (status "planned-v2.2")
      (description "SARIF output for GitHub Security tab and CodeQL integration"))

    (integration
      (name "crates.io")
      (status "planned-v3.0")
      (description "Publish as cargo-installable tool")))

  (ecosystem-contributions
    (contribution
      (type "tool")
      (value "Universal static analysis combining assail scan + miniKanren logic engine + multi-axis stress testing"))

    (contribution
      (type "pattern")
      (value "miniKanren-inspired relational reasoning for taint analysis and cross-language vulnerability detection in Rust"))

    (contribution
      (type "benchmark")
      (value "Provides quality metrics for hyperpolymath projects across 47 languages"))

    (contribution
      (type "standard")
      (value "Follows and validates RSR compliance patterns")))

  (metadata
    (created "2026-02-07")
    (updated "2026-02-08")
    (maintainer "Jonathan D.A. Jewell <jonathan.jewell@open.ac.uk>")
    (license "PMPL-1.0-or-later")
    (repository "https://github.com/hyperpolymath/panic-attacker")))
