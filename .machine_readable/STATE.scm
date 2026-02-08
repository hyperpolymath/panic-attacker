;; SPDX-License-Identifier: PMPL-1.0-or-later
;; State checkpoint for panic-attack (formerly panic-attacker)
;; Media Type: application/vnd.state+scm
;; Last Updated: 2026-02-08

(state
  (metadata
    (version "1.0")
    (project "panic-attack")
    (last-updated "2026-02-08T14:00:00Z")
    (session-count 4))

  (project-context
    (name "panic-attack")
    (tagline "Universal static analysis and logic-based bug signature detection")
    (language "Rust")
    (type "CLI tool + library")
    (purpose "Multi-axis stress testing with Datalog-inspired bug signature detection")
    (current-version "1.0.1")
    (next-milestone "v1.1.0")
    (lines-of-code 3200))

  (naming
    (note "Renamed from panic-attacker on 2026-02-08")
    (binary "panic-attack")
    (crate "panic-attack")
    (subcommand "assail (formerly xray)")
    (report-header "ASSAIL (formerly X-RAY)"))

  (current-position
    (phase "post-rename-stabilisation")
    (milestone "v1.1.0")
    (completion-percentage 50)
    (status "active")
    (health "green")

    (completed-milestones
      (milestone
        (id "v0.1.0")
        (date "2026-02-06")
        (description "Proof-of-concept: X-Ray + 6-axis attacks + signature detection"))
      (milestone
        (id "v0.2.0")
        (date "2026-02-07")
        (description "Quality fixes: per-file stats, locations, zero warnings"))
      (milestone
        (id "v1.0.0")
        (date "2026-02-08")
        (description "Rename: xray→assail, panic-attacker→panic-attack"))
      (milestone
        (id "v1.0.1")
        (date "2026-02-08")
        (description "Bugfix: JSON output confirmed working, installed to PATH")))

    (current-capabilities
      "Assail static analysis (5 languages: Rust, C/C++, Go, Python, generic)"
      "6-axis stress testing (CPU, memory, disk, network, concurrency, time)"
      "Logic-based bug detection (use-after-free, double-free, deadlock, data-race, null-deref, buffer-overflow)"
      "Pattern library (language/framework-specific attacks)"
      "Per-file statistics and risk scoring"
      "Verbose mode with per-file breakdown"
      "Latin-1 fallback for non-UTF-8 files"
      "JSON and terminal output"
      "Self-test mode (assail self-test)"))

  (route-to-mvp
    (target "v1.1.0: Bulk scanning + verisimdb integration")
    (strategy "Add sweep subcommand for directory-of-repos scanning, push results to verisimdb")

    (milestones
      (milestone
        (id "sweep-subcommand")
        (status "planned")
        (priority "critical")
        (tasks
          "Add `sweep` subcommand for scanning directory of git repos"
          "Auto-detect repos by .git presence"
          "Aggregate results across repos"
          "Push results to verisimdb API as hexads"))

      (milestone
        (id "hypatia-integration")
        (status "planned")
        (priority "high")
        (tasks
          "Feed scan results to hypatia rule engine"
          "Support echidnabot proof verification"
          "Support sustainabot ecological scoring"))

      (milestone
        (id "rsr-compliance")
        (status "in-progress")
        (priority "high")
        (tasks
          "17 standard workflows"
          "Rust-specific workflows (ci, audit, clippy, fmt)"
          "SARIF output for GitHub Security tab"))

      (milestone
        (id "documentation")
        (status "planned")
        (priority "medium")
        (tasks
          "SECURITY.md with vulnerability reporting"
          "CONTRIBUTING.md with development guide"
          "API documentation (rustdoc)"
          "Shell completions (bash, zsh, fish)"))))

  (blockers-and-issues
    (issue
      (id "rename-commit")
      (severity "medium")
      (description "Rename changes uncommitted - needs commit")))

  (critical-next-actions
    (action
      (priority "1")
      (description "Commit rename changes (xray→assail, panic-attacker→panic-attack)")
      (estimated-effort "5 minutes"))
    (action
      (priority "2")
      (description "Add sweep subcommand for bulk directory scanning")
      (estimated-effort "2-3 hours"))
    (action
      (priority "3")
      (description "Add verisimdb integration for results storage")
      (estimated-effort "1-2 hours"))
    (action
      (priority "4")
      (description "Complete RSR compliance (workflows, docs)")
      (estimated-effort "2-3 hours")))

  (session-history
    (session
      (id "4")
      (date "2026-02-08")
      (duration "1h")
      (focus "Rename + bulk scanning + system crash diagnosis")
      (outcomes
        "Renamed xray→assail, panic-attacker→panic-attack across all files"
        "Built v1.0.1, installed to PATH"
        "Confirmed JSON output working (self-test)"
        "Scanned 21 Eclipse repos, loaded results into verisimdb"
        "Top findings: protocol-squisher (39 wp), echidna (15 wp), verisimdb (12 wp)"
        "118 total weak points across 21 repos, zero critical, 17 high"))

    (session
      (id "3")
      (date "2026-02-07")
      (duration "2h")
      (focus "v0.2.0 implementation + v1.0 planning")
      (outcomes
        "Implemented v0.2.0 (per-file stats, locations, Latin-1 fallback, patterns)"
        "Zero compiler warnings achieved"
        "7/7 tests passing (3 new integration tests)"
        "Created AI manifest and SCM files"
        "Defined v1.0 infrastructure-first roadmap"))))
