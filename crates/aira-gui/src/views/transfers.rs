//! File transfers view — active transfers with progress bars and completed files.

use egui::{RichText, ScrollArea, Ui};

use crate::state::GuiState;
use crate::theme;

/// Render the file transfers view.
pub fn transfers_view(ui: &mut Ui, state: &mut GuiState) {
    ui.vertical(|ui| {
        ui.add_space(4.0);
        ui.label(
            RichText::new("File Transfers")
                .size(theme::FONT_HEADING)
                .color(theme::TEXT_PRIMARY)
                .strong(),
        );
        ui.add_space(6.0);

        ScrollArea::vertical().show(ui, |ui| {
            // Active transfers
            if state.transfers.is_empty() && state.completed_files.is_empty() {
                ui.add_space(ui.available_height() / 3.0);
                ui.vertical_centered(|ui| {
                    ui.label(
                        RichText::new("No file transfers")
                            .size(theme::FONT_HEADING)
                            .color(theme::TEXT_MUTED),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("Send a file in a chat to start")
                            .size(theme::FONT_BODY)
                            .color(theme::TEXT_MUTED),
                    );
                });
                return;
            }

            if !state.transfers.is_empty() {
                ui.add_space(theme::PANEL_PADDING);
                ui.label(
                    RichText::new("Active")
                        .size(theme::FONT_BODY)
                        .color(theme::ACCENT)
                        .strong(),
                );
                ui.add_space(theme::ITEM_GAP);

                for (id, progress) in &state.transfers {
                    egui::Frame::none()
                        .fill(theme::BG_CARD)
                        .rounding(6.0)
                        .inner_margin(egui::Margin::same(theme::CARD_PADDING))
                        .show(ui, |ui| {
                            let id_hex = hex::encode(&id[..4]);
                            let pct = if progress.total > 0 {
                                progress.bytes_sent as f32 / progress.total as f32
                            } else {
                                0.0
                            };
                            ui.label(
                                RichText::new(format!("Transfer {id_hex}"))
                                    .size(theme::FONT_BODY)
                                    .color(theme::TEXT_PRIMARY),
                            );
                            ui.add(egui::ProgressBar::new(pct).show_percentage());
                            ui.label(
                                RichText::new(format!(
                                    "{} / {} bytes",
                                    progress.bytes_sent, progress.total
                                ))
                                .size(theme::FONT_SMALL)
                                .color(theme::TEXT_SECONDARY),
                            );
                        });
                    ui.add_space(theme::ITEM_GAP);
                }
            }

            // Completed files
            if !state.completed_files.is_empty() {
                ui.add_space(theme::PANEL_PADDING);
                ui.label(
                    RichText::new("Completed")
                        .size(theme::FONT_BODY)
                        .color(theme::ACCENT)
                        .strong(),
                );
                ui.add_space(theme::ITEM_GAP);

                for path in &state.completed_files {
                    let path_clone = path.clone();
                    egui::Frame::none()
                        .fill(theme::BG_CARD)
                        .rounding(6.0)
                        .inner_margin(egui::Margin::same(theme::CARD_PADDING))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                let name = path_clone.file_name().map_or_else(
                                    || path_clone.display().to_string(),
                                    |n| n.to_string_lossy().to_string(),
                                );
                                ui.label(
                                    RichText::new(name)
                                        .size(theme::FONT_BODY)
                                        .color(theme::TEXT_PRIMARY),
                                );
                                if ui.small_button("Open").clicked() {
                                    let _ = open::that(&path_clone);
                                }
                            });
                        });
                    ui.add_space(theme::ITEM_GAP);
                }
            }
        });
    });
}
