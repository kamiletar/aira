//! Identity view — own address, backup export/import.

use egui::{RichText, Ui};

use crate::ipc::GuiCommand;
use crate::state::GuiState;
use crate::theme;

/// Render the identity/export view.
///
/// Returns a `GuiCommand` if the user triggers a backup operation.
pub fn identity_view(ui: &mut Ui, state: &mut GuiState) -> Option<GuiCommand> {
    let mut command = None;

    ui.vertical(|ui| {
        ui.horizontal(|ui| {
            if ui.button("<").on_hover_text("Back").clicked() {
                state.go_back();
            }
            ui.add_space(8.0);
            ui.label(
                RichText::new("Identity")
                    .size(theme::FONT_HEADING)
                    .color(theme::TEXT_PRIMARY)
                    .strong(),
            );
        });
        ui.separator();
        ui.add_space(theme::PANEL_PADDING);

        // My Address
        ui.label(
            RichText::new("Your Public Key")
                .size(theme::FONT_BODY)
                .color(theme::ACCENT)
                .strong(),
        );
        ui.add_space(theme::ITEM_GAP);

        let addr_hex = if state.my_address.is_empty() {
            "Loading...".to_string()
        } else {
            hex::encode(&state.my_address)
        };

        egui::Frame::none()
            .fill(theme::BG_CARD)
            .rounding(6.0)
            .inner_margin(egui::Margin::same(theme::CARD_PADDING))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(&addr_hex)
                            .size(theme::FONT_SMALL)
                            .color(theme::TEXT_PRIMARY)
                            .monospace(),
                    );
                });
                ui.add_space(4.0);
                if ui.button("Copy to clipboard").clicked() {
                    ui.output_mut(|o| o.copied_text.clone_from(&addr_hex));
                    state.status_message = Some("Copied!".into());
                }
            });

        ui.add_space(theme::PANEL_PADDING);
        ui.separator();

        // Backup Export
        ui.add_space(theme::PANEL_PADDING);
        ui.label(
            RichText::new("Backup")
                .size(theme::FONT_BODY)
                .color(theme::ACCENT)
                .strong(),
        );
        ui.add_space(theme::ITEM_GAP);

        ui.horizontal(|ui| {
            if ui.button("Export Backup").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .set_file_name("aira-backup.bin")
                    .save_file()
                {
                    command = Some(GuiCommand::ExportBackup {
                        path,
                        include_messages: true,
                    });
                }
            }
            if ui.button("Import Backup").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    command = Some(GuiCommand::ImportBackup { path });
                }
            }
        });

        ui.add_space(theme::ITEM_GAP);
        ui.label(
            RichText::new("Backups are encrypted with your seed phrase")
                .size(theme::FONT_SMALL)
                .color(theme::TEXT_SECONDARY),
        );
    });

    command
}
