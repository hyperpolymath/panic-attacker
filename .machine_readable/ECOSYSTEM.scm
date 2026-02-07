;; SPDX-License-Identifier: PMPL-1.0-or-later
;; Ecosystem position for panic-attacker
;; Media Type: application/vnd.ecosystem+scm

(ecosystem
  (version "1.0")
  (name "panic-attacker")
  (type "tool")
  (purpose "Universal stress testing and logic-based bug signature detection")

  (position-in-ecosystem
    (layer "development-tools")
    (category "testing-quality")
    (subcategory "stress-testing-analysis")
    (maturity "beta")
    (adoption "internal"))

  (related-projects
    (project
      (name "hypatia")
      (relationship "consumer")
      (integration "uses panic-attacker for repository health assessment")
      (url "https://github.com/hyperpolymath/hypatia")
      (description "Neurosymbolic CI/CD intelligence"))

    (project
      (name "gitbot-fleet")
      (relationship "consumer")
      (integration "bots can trigger panic-attacker scans")
      (url "https://github.com/hyperpolymath/gitbot-fleet")
      (description "Repository automation bots (rhodibot, echidnabot, etc.)"))

    (project
      (name "git-seo")
      (relationship "sibling-tool")
      (integration "complementary repository analysis")
      (url "https://github.com/hyperpolymath/git-seo")
      (description "Git repository analysis and optimization"))

    (project
      (name "echidna")
      (relationship "test-subject")
      (integration "used as benchmark for panic-attacker testing")
      (url "https://github.com/hyperpolymath/echidna")
      (description "Automated theorem proving orchestrator"))

    (project
      (name "eclexia")
      (relationship "test-subject")
      (integration "used as benchmark for panic-attacker testing")
      (url "https://github.com/hyperpolymath/eclexia")
      (description "Resource-aware adaptive programming language"))

    (project
      (name "rsr-template-repo")
      (relationship "template-provider")
      (integration "panic-attacker follows RSR standards")
      (url "https://github.com/hyperpolymath/rsr-template-repo")
      (description "RSR-compliant repository template"))

    (project
      (name "0-ai-gatekeeper-protocol")
      (relationship "standard-provider")
      (integration "panic-attacker implements AI manifest protocol")
      (url "https://github.com/hyperpolymath/0-ai-gatekeeper-protocol")
      (description "Universal AI manifest system"))

    (project
      (name "robot-repo-automaton")
      (relationship "potential-consumer")
      (integration "could use panic-attacker for automated quality checks")
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
      (name "Datalog engine")
      (status "planned-v0.5")
      (description "Real logic programming engine (Crepe/Datafrog)"))

    (integration
      (name "Constraint sets")
      (status "planned-v0.4")
      (description "YAML-based stress profiles"))

    (integration
      (name "CI/CD platforms")
      (status "planned-v1.0")
      (description "GitHub Actions, GitLab CI, Jenkins integration"))

    (integration
      (name "crates.io")
      (status "planned-v1.0")
      (description "Publish as cargo-installable tool")))

  (ecosystem-contributions
    (contribution
      (type "tool")
      (value "Novel stress testing approach combining X-Ray + multi-axis + logic-based detection"))

    (contribution
      (type "pattern")
      (value "Demonstrates Datalog-inspired bug detection in Rust"))

    (contribution
      (type "benchmark")
      (value "Provides quality metrics for hyperpolymath projects"))

    (contribution
      (type "standard")
      (value "Follows and validates RSR compliance patterns")))

  (metadata
    (created "2026-02-07")
    (updated "2026-02-07")
    (maintainer "Jonathan D.A. Jewell <jonathan.jewell@open.ac.uk>")
    (license "PMPL-1.0-or-later")
    (repository "https://github.com/hyperpolymath/panic-attacker")))
