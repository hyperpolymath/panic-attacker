;; SPDX-License-Identifier: PMPL-1.0-or-later
;; State checkpoint for panic-attack (formerly panic-attacker)
;; Media Type: application/vnd.state+scm
;; Last Updated: 2026-02-09

(state
  (metadata
    (version "1.0")
    (project "panic-attack")
    (last-updated "2026-02-09T20:15:00Z")
    (session-count 6))

  (project-context
    (name "panic-attack")
    (tagline "Universal static analysis and logic-based bug signature detection")
    (language "Rust")
    (type "CLI tool + library")
    (purpose "Multi-language static analysis with miniKanren-inspired logic engine for taint analysis, cross-language reasoning, and search strategies")
    (current-version "2.0.0")
    (next-milestone "v2.1.0")
    (lines-of-code 7500))

  (naming
    (note "Renamed from panic-attacker on 2026-02-08")
    (binary "panic-attack")
    (crate "panic-attack")
    (subcommand "assail")
    (report-type "AssailReport")
    (module-dir "src/assail/"))

  (current-position
    (phase "active-development")
    (milestone "v2.0.0")
    (completion-percentage 100)
    (status "released")
    (health "green")

    (completed-milestones
      (milestone
        (id "v0.1.0")
        (date "2026-02-06")
        (description "Proof-of-concept: assail + 6-axis attacks + signature detection"))
      (milestone
        (id "v0.2.0")
        (date "2026-02-07")
        (description "Quality fixes: per-file stats, locations, zero warnings"))
      (milestone
        (id "v1.0.0")
        (date "2026-02-08")
        (description "Rename: xray->assail, panic-attacker->panic-attack"))
      (milestone
        (id "v1.0.1")
        (date "2026-02-08")
        (description "Bugfix: JSON output confirmed working, installed to PATH"))
      (milestone
        (id "v2.0.0")
        (date "2026-02-08")
        (description "47-language support + miniKanren logic engine + taint analysis + cross-language reasoning + search strategies")))

    (current-capabilities
      "Assail static analysis (47 languages: BEAM, ML, Lisp, functional, proof, logic, systems, config, scripting, nextgen DSLs)"
      "20 weak point categories (UnsafeCode, CommandInjection, UnsafeDeserialization, AtomExhaustion, UnsafeFFI, PathTraversal, HardcodedSecret, etc.)"
      "miniKanren-inspired logic engine with substitution-based unification"
      "Taint analysis: source-to-sink data flow tracking"
      "Cross-language vulnerability chain detection (FFI, NIF, Port, subprocess boundaries)"
      "Search strategy optimisation (RiskWeighted, BoundaryFirst, LanguageFamily, BreadthFirst, DepthFirst)"
      "Forward chaining: derives vulnerability facts from rules"
      "Backward queries: find files by vulnerability category"
      "6-axis stress testing (CPU, memory, disk, network, concurrency, time)"
      "Logic-based bug detection (use-after-free, double-free, deadlock, data-race)"
      "Per-file language detection and risk scoring"
      "JSON, YAML, and Nickel output formats"
      "Report views (summary, accordion, dashboard, matrix) + TUI viewer"
      "PanLL event-chain export for external timeline visualisation"
      "Ambush timeline scheduling (plan-only) for stressor sequencing"
      "Optional verisimdb storage integration"))

  (route-to-mvp
    (target "v2.1.0: Bulk scanning + verisimdb integration")
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
          "Export kanren facts as Logtalk predicates"
          "Support echidnabot proof verification"))

      (milestone
        (id "sarif-output")
        (status "planned")
        (priority "medium")
        (tasks
          "SARIF output for GitHub Security tab"
          "Integration with CodeQL workflow"))))

  (blockers-and-issues)

  (critical-next-actions
    (action
      (priority "1")
      (description "Add sweep subcommand for bulk directory scanning")
      (estimated-effort "2-3 hours"))
    (action
      (priority "2")
      (description "Add verisimdb integration for results storage")
      (estimated-effort "1-2 hours"))
    (action
      (priority "3")
      (description "Export kanren facts as Logtalk for hypatia integration")
      (estimated-effort "1-2 hours")))

  (session-history
    (session
      (id "6")
      (date "2026-02-09")
      (duration "2h")
      (focus "PanLL integration + report UX expansion")
      (outcomes
        "Added PanLL event-chain export format and docs"
        "Added ambush timeline planning + parser"
        "Added report views (accordion, dashboard, matrix) and TUI viewer"
        "Added Nickel output and report metadata wiring"))
    (session
      (id "5")
      (date "2026-02-08")
      (duration "3h")
      (focus "v2.0.0: 47-language support + miniKanren logic engine")
      (outcomes
        "Expanded from 8 to 47 languages"
        "Added 20 weak point categories"
        "Implemented miniKanren-inspired logic engine (kanren module)"
        "Added taint analysis: source->sink tracking"
        "Added cross-language vulnerability chain detection"
        "Added search strategy optimisation (auto-select)"
        "Renamed xray module to assail throughout"
        "Renamed XRayReport type to AssailReport"
        "All 30 tests passing"
        "Updated all documentation"))

    (session
      (id "4")
      (date "2026-02-08")
      (duration "1h")
      (focus "Rename + bulk scanning + system crash diagnosis")
      (outcomes
        "Renamed xray->assail, panic-attacker->panic-attack across all files"
        "Built v1.0.1, installed to PATH"
        "Scanned 21 Eclipse repos, loaded results into verisimdb"))

    (session
      (id "3")
      (date "2026-02-07")
      (duration "2h")
      (focus "v0.2.0 implementation + v1.0 planning")
      (outcomes
        "Implemented v0.2.0 (per-file stats, locations, Latin-1 fallback, patterns)"
        "Zero compiler warnings achieved"
        "Created AI manifest and SCM files"))))
