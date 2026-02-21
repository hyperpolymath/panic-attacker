<!-- SPDX-License-Identifier: PMPL-1.0-or-later -->
<!-- TOPOLOGY.md — Project architecture map and completion dashboard -->
<!-- Last updated: 2026-02-19 -->

# panic-attack — Project Topology

## System Architecture

```
                        ┌─────────────────────────────────────────┐
                        │              SECURITY TESTER            │
                        │        (CLI, TUI, GUI, CI Hook)         │
                        └───────────────────┬─────────────────────┘
                                            │ Command / Spec
                                            ▼
                        ┌─────────────────────────────────────────┐
                        │           PANIC-ATTACK CORE             │
                        │    (Orchestration, Reports, Wiring)     │
                        └──────────┬───────────────────┬──────────┘
                                   │                   │
                                   ▼                   ▼
                        ┌───────────────────────┐  ┌────────────────────────────────┐
                        │ ANALYSIIS LAYER       │  │ ATTACK LAYER                   │
                        │ - Assail (Static)     │  │ - Multi-Axis Stress (CPU, Mem) │
                        │ - Language Patterns   │  │ - Ambush (Ambient Stressors)   │
                        │ - Weak Point Scoring  │  │ - Amuck (Mutations)            │
                        └──────────┬────────────┘  └──────────┬─────────────────────┘
                                   │                          │
                                   └────────────┬─────────────┘
                                                ▼
                        ┌─────────────────────────────────────────┐
                        │           SIGNATURE ENGINE              │
                        │    (Datalog-inspired bug detection)     │
                        └───────────────────┬─────────────────────┘
                                            │
                                            ▼
                        ┌─────────────────────────────────────────┐
                        │           TARGET PROGRAM                │
                        │      (Rust, C/C++, Go, Python, etc.)    │
                        └─────────────────────────────────────────┘

                        ┌─────────────────────────────────────────┐
                        │          REPO INFRASTRUCTURE            │
                        │  Justfile / Cargo   .machine_readable/  │
                        │  VerisimDB Data     PanLL Integration   │
                        └─────────────────────────────────────────┘
```

## Completion Dashboard

```
COMPONENT                          STATUS              NOTES
─────────────────────────────────  ──────────────────  ─────────────────────────────────
CORE CAPABILITIES
  Assail Static Analysis            ██████████ 100%    5 languages supported
  Multi-Axis Stress Testing         ██████████ 100%    6 axes (CPU, Mem, Disk, etc)
  Ambush / Amuck / Abduct           ██████████ 100%    Advanced workflows stable
  Signature Detection Engine        ████████░░  80%    Datalog rules expanding

REPORTING & UI
  JSON/YAML/Nickel Reports          ██████████ 100%    Audit-grade exports stable
  TUI / GUI Dashboard               ████████░░  80%    Report browsing verified
  VerisimDB Diff Viewer             ██████████ 100%    Latest report comparison active
  A2ML Bundle Import/Export         ██████████ 100%    Schema-versioned verified

REPO INFRASTRUCTURE
  Justfile Automation               ██████████ 100%    Standard build/lint/test
  .machine_readable/                ██████████ 100%    STATE tracking active
  Test Suite (Unit/Integ)           ██████████ 100%    High coverage (306+ tests)

─────────────────────────────────────────────────────────────────────────────
OVERALL:                            █████████░  ~95%   v0.2.0 Stable Development
```

## Key Dependencies

```
Assail (Static) ───► Attack Strategy ───► Target Binary ───► Crash Report
     │                   │                   │                 │
     ▼                   ▼                   ▼                 ▼
Pattern Lib ──────► Multi-Axis ────────► Signature Engine ──► Verdict
```

## Update Protocol

This file is maintained by both humans and AI agents. When updating:

1. **After completing a component**: Change its bar and percentage
2. **After adding a component**: Add a new row in the appropriate section
3. **After architectural changes**: Update the ASCII diagram
4. **Date**: Update the `Last updated` comment at the top of this file

Progress bars use: `█` (filled) and `░` (empty), 10 characters wide.
Percentages: 0%, 10%, 20%, ... 100% (in 10% increments).
