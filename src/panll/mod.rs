// SPDX-License-Identifier: PMPL-1.0-or-later

//! PanLL export helpers.

use crate::types::{AssaultReport, AttackAxis, Severity};
use anyhow::{Context, Result};
use serde::Serialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize)]
struct PanllExport {
    format: String,
    generated_at: String,
    source: PanllSource,
    summary: PanllSummary,
    timeline: Option<PanllTimeline>,
    event_chain: Vec<PanllEvent>,
    constraints: Vec<PanllConstraint>,
}

#[derive(Debug, Serialize)]
struct PanllSource {
    tool: String,
    report_path: Option<String>,
}

#[derive(Debug, Serialize)]
struct PanllSummary {
    program: String,
    weak_points: usize,
    critical_weak_points: usize,
    total_crashes: usize,
    robustness_score: f64,
}

#[derive(Debug, Serialize)]
struct PanllTimeline {
    duration_ms: u64,
    events: usize,
}

#[derive(Debug, Serialize)]
struct PanllEvent {
    id: String,
    axis: String,
    start_ms: Option<u64>,
    duration_ms: u64,
    intensity: String,
    status: String,
    peak_memory: Option<u64>,
    notes: Option<String>,
}

#[derive(Debug, Serialize)]
struct PanllConstraint {
    id: String,
    description: String,
}

pub fn export_report(report: &AssaultReport, report_path: Option<&Path>) -> PanllExport {
    let timeline = report.timeline.as_ref().map(|timeline| PanllTimeline {
        duration_ms: timeline.duration.as_millis() as u64,
        events: timeline.events.len(),
    });

    let mut event_chain = Vec::new();
    if let Some(timeline) = &report.timeline {
        for event in &timeline.events {
            let status = if event.ran { "ran" } else { "skipped" };
            event_chain.push(PanllEvent {
                id: event.id.clone(),
                axis: axis_label(event.axis),
                start_ms: Some(event.start_offset.as_millis() as u64),
                duration_ms: event.duration.as_millis() as u64,
                intensity: format!("{:?}", event.intensity),
                status: status.to_string(),
                peak_memory: event.peak_memory,
                notes: None,
            });
        }
    } else {
        for (index, result) in report.attack_results.iter().enumerate() {
            let status = if result.skipped {
                "skipped"
            } else if result.success {
                "passed"
            } else {
                "failed"
            };
            event_chain.push(PanllEvent {
                id: format!("attack-{}-{}", axis_label(result.axis), index + 1),
                axis: axis_label(result.axis),
                start_ms: None,
                duration_ms: result.duration.as_millis() as u64,
                intensity: "unknown".to_string(),
                status: status.to_string(),
                peak_memory: Some(result.peak_memory),
                notes: result.skip_reason.clone(),
            });
        }
    }

    let critical_weak_points = report
        .assail_report
        .weak_points
        .iter()
        .filter(|wp| wp.severity == Severity::Critical)
        .count();

    PanllExport {
        format: "panll.event-chain.v0".to_string(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        source: PanllSource {
            tool: "panic-attack".to_string(),
            report_path: report_path.map(|path| path.display().to_string()),
        },
        summary: PanllSummary {
            program: report.assail_report.program_path.display().to_string(),
            weak_points: report.assail_report.weak_points.len(),
            critical_weak_points,
            total_crashes: report.total_crashes,
            robustness_score: report.overall_assessment.robustness_score,
        },
        timeline,
        event_chain,
        constraints: Vec::new(),
    }
}

pub fn write_export(report: &AssaultReport, report_path: Option<&Path>, output: &Path) -> Result<()> {
    let export = export_report(report, report_path);
    let json = serde_json::to_string_pretty(&export)?;
    fs::write(output, json).with_context(|| format!("writing panll export {}", output.display()))?;
    Ok(())
}

fn axis_label(axis: AttackAxis) -> String {
    match axis {
        AttackAxis::Cpu => "cpu",
        AttackAxis::Memory => "memory",
        AttackAxis::Disk => "disk",
        AttackAxis::Network => "network",
        AttackAxis::Concurrency => "concurrency",
        AttackAxis::Time => "time",
    }
    .to_string()
}
