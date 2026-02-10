<!-- SPDX-License-Identifier: PMPL-1.0-or-later -->

# PanLL Export (Event-Chain Bridge)

`panic-attack` can export an assault report into a lightweight PanLL-compatible
event-chain model. This gives PanLL a stable input describing stress events,
timing, and outcomes without forcing a heavy schema dependency.

## Command

```bash
panic-attack panll path/to/assault-report.json --output panll-event-chain.json
```

## Format (v0)

```json
{
  "format": "panll.event-chain.v0",
  "generated_at": "2026-02-09T19:12:00Z",
  "source": {
    "tool": "panic-attack",
    "report_path": "reports/assault-report.json"
  },
  "summary": {
    "program": "/path/to/target",
    "weak_points": 7,
    "critical_weak_points": 1,
    "total_crashes": 2,
    "robustness_score": 63.5
  },
  "timeline": {
    "duration_ms": 120000,
    "events": 5
  },
  "event_chain": [
    {
      "id": "cpu-1",
      "axis": "cpu",
      "start_ms": 0,
      "duration_ms": 30000,
      "intensity": "Heavy",
      "status": "ran",
      "peak_memory": null,
      "notes": null
    }
  ],
  "constraints": []
}
```

Notes:
- If the report includes ambush timeline metadata, the `event_chain` is derived
  from timeline events.
- Otherwise, each attack result becomes a single event entry with `start_ms`
  unset and `intensity = "unknown"`.

## Next Steps

Future versions can enrich this export with constraints, event dependencies,
and a full PanLL graph import/export pipeline.
