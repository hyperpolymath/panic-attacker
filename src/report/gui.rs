// SPDX-License-Identifier: PMPL-1.0-or-later

//! Minimal GUI for reviewing assault reports.

use crate::report::formatter::ReportFormatter;
use crate::types::{AssaultReport, FileStatistics};
use anyhow::{anyhow, Result};
use eframe::{egui, App, Frame, NativeOptions};

pub struct ReportGui {
    report: AssaultReport,
    tab: ReportTab,
    file_filter: String,
    weak_filter: String,
    attack_filter: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReportTab {
    Summary,
    Assail,
    Matrix,
    Attacks,
    Assessment,
}

impl ReportGui {
    pub fn run(report: AssaultReport) -> Result<()> {
        let options = NativeOptions::default();
        let app = Self {
            report,
            tab: ReportTab::Summary,
            file_filter: String::new(),
            weak_filter: String::new(),
            attack_filter: String::new(),
        };
        eframe::run_native(
            "panic-attack report",
            options,
            Box::new(|_cc| Box::new(app)),
        )
        .map_err(|err| anyhow!("failed to launch report GUI: {err}"))?;
        Ok(())
    }
}

impl App for ReportGui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.heading("panic-attack report");
        });

        egui::SidePanel::left("nav").show(ctx, |ui| {
            ui.selectable_value(&mut self.tab, ReportTab::Summary, "Summary");
            ui.selectable_value(&mut self.tab, ReportTab::Assail, "Assail");
            ui.selectable_value(&mut self.tab, ReportTab::Matrix, "Matrix");
            ui.selectable_value(&mut self.tab, ReportTab::Attacks, "Attacks");
            ui.selectable_value(&mut self.tab, ReportTab::Assessment, "Assessment");
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            ReportTab::Summary => self.render_summary(ui),
            ReportTab::Assail => self.render_assail(ui),
            ReportTab::Matrix => self.render_matrix(ui),
            ReportTab::Attacks => self.render_attacks(ui),
            ReportTab::Assessment => self.render_assessment(ui),
        });
    }
}

impl ReportGui {
    fn render_summary(&self, ui: &mut egui::Ui) {
        let assail = &self.report.assail_report;
        ui.heading("Summary");
        ui.label(format!("Program: {}", assail.program_path.display()));
        ui.label(format!("Language: {:?}", assail.language));
        ui.label(format!("Frameworks: {:?}", assail.frameworks));
        ui.label(format!("Weak points: {}", assail.weak_points.len()));
        ui.label(format!("Total crashes: {}", self.report.total_crashes));
        ui.label(format!(
            "Total signatures: {}",
            self.report.total_signatures
        ));
        let (passed, failed, skipped) = count_attack_status(&self.report.attack_results);
        ui.label(format!(
            "Attack outcomes: passed={} failed={} skipped={}",
            passed, failed, skipped
        ));
    }

    fn render_assail(&mut self, ui: &mut egui::Ui) {
        let assail = &self.report.assail_report;
        ui.heading("Assail details");
        ui.label(format!(
            "Stats: lines={} unsafe={} panics={} unwraps={}",
            assail.statistics.total_lines,
            assail.statistics.unsafe_blocks,
            assail.statistics.panic_sites,
            assail.statistics.unwrap_calls
        ));
        ui.separator();

        ui.heading("File risk");
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.text_edit_singleline(&mut self.file_filter);
        });
        let mut files: Vec<&FileStatistics> = assail.file_statistics.iter().collect();
        files.sort_by_key(|fs| file_risk(fs));
        files.reverse();
        egui::Grid::new("file-risk").striped(true).show(ui, |ui| {
            ui.label("File");
            ui.label("Risk");
            ui.label("Unsafe");
            ui.label("Panics");
            ui.label("Unwraps");
            ui.end_row();
            for fs in files.iter().take(50) {
                if !self.file_filter.trim().is_empty()
                    && !fs
                        .file_path
                        .to_lowercase()
                        .contains(&self.file_filter.to_lowercase())
                {
                    continue;
                }
                let risk = file_risk(fs);
                ui.label(&fs.file_path);
                ui.label(risk.to_string());
                ui.label(fs.unsafe_blocks.to_string());
                ui.label(fs.panic_sites.to_string());
                ui.label(fs.unwrap_calls.to_string());
                ui.end_row();
            }
        });

        ui.separator();
        ui.heading("Weak points");
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.text_edit_singleline(&mut self.weak_filter);
        });
        egui::ScrollArea::vertical().show(ui, |ui| {
            for wp in &assail.weak_points {
                let desc = wp.description.trim();
                let match_filter = self.weak_filter.trim().is_empty()
                    || desc
                        .to_lowercase()
                        .contains(&self.weak_filter.to_lowercase())
                    || format!("{:?}", wp.category)
                        .to_lowercase()
                        .contains(&self.weak_filter.to_lowercase());
                if match_filter {
                    ui.label(format!("[{:?}] {}", wp.category, desc));
                }
            }
        });

        ui.separator();
        ui.collapsing("Dependencies", |ui| {
            for edge in assail.dependency_graph.edges.iter().take(40) {
                ui.label(format!(
                    "{} -> {} ({}, weight {:.1})",
                    edge.from, edge.to, edge.relation, edge.weight
                ));
            }
        });
    }

    fn render_matrix(&self, ui: &mut egui::Ui) {
        let assail = &self.report.assail_report;
        ui.heading("Matrix view");
        let formatter = ReportFormatter::new();
        let pivots = formatter.pivot_rows(assail);
        ui.label(format!("Pivot rows: {}", pivots.len()));
        egui::ScrollArea::vertical().show(ui, |ui| {
            for (source, axis, severity) in pivots.iter().take(40) {
                ui.label(format!(
                    "{:?} -> {:?} (severity {:.1})",
                    source, axis, severity
                ));
            }
        });
        ui.separator();
        ui.heading("Taint matrix rows");
        egui::ScrollArea::vertical().show(ui, |ui| {
            for row in assail.taint_matrix.rows.iter().take(60) {
                ui.label(format!(
                    "{:?} -> {:?} (severity {:.1}, files {})",
                    row.source_category,
                    row.sink_axis,
                    row.severity_value,
                    row.files.len()
                ));
            }
        });
    }

    fn render_attacks(&mut self, ui: &mut egui::Ui) {
        ui.heading("Attack results");
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.text_edit_singleline(&mut self.attack_filter);
        });
        egui::ScrollArea::vertical().show(ui, |ui| {
            for result in &self.report.attack_results {
                let status = if result.skipped {
                    "skipped"
                } else if result.success {
                    "passed"
                } else {
                    "failed"
                };
                let label = format!(
                    "{:?}: {} (exit {:?}, crashes {})",
                    result.axis,
                    status,
                    result.exit_code,
                    result.crashes.len()
                );
                if !self.attack_filter.trim().is_empty()
                    && !label
                        .to_lowercase()
                        .contains(&self.attack_filter.to_lowercase())
                {
                    continue;
                }
                ui.label(label);
                if let Some(reason) = &result.skip_reason {
                    ui.label(format!("  reason: {}", reason));
                }
            }
        });
    }

    fn render_assessment(&self, ui: &mut egui::Ui) {
        let assessment = &self.report.overall_assessment;
        ui.heading("Overall assessment");
        ui.label(format!(
            "Robustness score: {:.1}/100",
            assessment.robustness_score
        ));
        if !assessment.critical_issues.is_empty() {
            ui.separator();
            ui.label("Critical issues:");
            for issue in &assessment.critical_issues {
                ui.label(format!("- {}", issue));
            }
        }
        if !assessment.recommendations.is_empty() {
            ui.separator();
            ui.label("Recommendations:");
            for rec in &assessment.recommendations {
                ui.label(format!("- {}", rec));
            }
        }
    }
}

fn file_risk(fs: &FileStatistics) -> usize {
    fs.unsafe_blocks * 3 + fs.panic_sites * 2 + fs.unwrap_calls + fs.threading_constructs * 2
}

fn count_attack_status(results: &[crate::types::AttackResult]) -> (usize, usize, usize) {
    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;
    for result in results {
        if result.skipped {
            skipped += 1;
        } else if result.success {
            passed += 1;
        } else {
            failed += 1;
        }
    }
    (passed, failed, skipped)
}
