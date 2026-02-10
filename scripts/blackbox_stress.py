#!/usr/bin/env python3
# SPDX-License-Identifier: PMPL-1.0-or-later

"""
Black-box stress runner for panic-attack.

Runs repeated assail/assault cycles with randomized axes/intensity/probe mode and logs results.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
import time
from pathlib import Path


AXES = ["cpu", "memory", "disk", "network", "concurrency", "time"]
INTENSITIES = ["light", "medium", "heavy"]
PROBES = ["auto", "always", "never"]


def run(cmd: list[str], log_dir: Path, label: str) -> int:
    log_dir.mkdir(parents=True, exist_ok=True)
    started = time.strftime("%Y-%m-%dT%H%M%S")
    result = subprocess.run(cmd, capture_output=True, text=True)
    header = f"# {started}\n# cmd: {' '.join(cmd)}\n# exit: {result.returncode}\n\n"
    (log_dir / f"{label}.out").write_text(header + result.stdout)
    (log_dir / f"{label}.err").write_text(header + result.stderr)
    return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--source", type=Path, default=None)
    parser.add_argument("--target", type=Path, default=None)
    parser.add_argument("--outdir", type=Path, default=Path("blackbox-logs"))
    parser.add_argument("--use-profile", action="store_true")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    root = Path(__file__).resolve().parents[1]
    source = args.source or root
    target = args.target or (root / "target" / "debug" / "examples" / "attack_harness")

    if args.build:
        if run(["cargo", "build"], args.outdir, "build-main") != 0:
            return 1
        if run(["cargo", "build", "--example", "attack_harness"], args.outdir, "build-harness") != 0:
            return 1

    binary = root / "target" / "debug" / "panic-attack"
    if not binary.exists():
        print(f"panic-attack binary not found at {binary}", file=sys.stderr)
        return 1

    failures = []
    reports = []
    profile = root / "profiles" / "attack-profile.example.json"

    for idx in range(1, args.runs + 1):
        axes = random.sample(AXES, k=random.randint(1, len(AXES)))
        intensity = random.choice(INTENSITIES)
        duration = random.choice([1, 3, 5])
        probe = random.choice(PROBES)
        report = root / "reports" / f"blackbox-{int(time.time())}-{idx}.json"
        cmd = [
            str(binary),
            "assault",
            "--source",
            str(source),
            str(target),
            "--axes",
            ",".join(axes),
            "--intensity",
            intensity,
            "--duration",
            str(duration),
            "--output",
            str(report),
            "--output-format",
            "json",
            "--probe",
            probe,
        ]
        if args.use_profile and profile.exists():
            cmd.extend(["--profile", str(profile)])
        label = f"assault-{idx}"
        code = run(cmd, args.outdir, label)
        if code != 0:
            failures.append({"run": idx, "exit_code": code})
        else:
            reports.append(str(report))

    summary = {
        "runs": args.runs,
        "failures": failures,
        "reports": reports,
    }
    (args.outdir / "summary.json").write_text(json.dumps(summary, indent=2))

    if failures:
        print(f"{len(failures)} runs failed. See {args.outdir}/summary.json")
        return 1
    print(f"All {args.runs} runs completed successfully. Logs: {args.outdir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
