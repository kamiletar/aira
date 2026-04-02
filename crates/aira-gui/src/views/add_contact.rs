//! Add contact dialog — input for hex pubkey and alias.

use egui::{RichText, Ui};

use crate::ipc::GuiCommand;
use crate::state::GuiState;
use crate::theme;

/// Render the add-contact view.
///
/// Returns a `GuiCommand::AddContact` if the user submits valid input.
pub fn add_contact_view(ui: &mut Ui, state: &mut GuiState) -> Option<GuiCommand> {
    let mut command = None;

    ui.vertical(|ui| {
        ui.horizontal(|ui| {
            if ui.button("<").on_hover_text("Back").clicked() {
                state.go_back();
            }
            ui.add_space(8.0);
            ui.label(
                RichText::new("Add Contact")
                    .size(theme::FONT_HEADING)
                    .color(theme::TEXT_PRIMARY)
                    .strong(),
            );
        });
        ui.separator();
        ui.add_space(theme::PANEL_PADDING);

        // Public key input
        ui.label(
            RichText::new("Public Key (hex)")
                .size(theme::FONT_BODY)
                .color(theme::TEXT_SECONDARY),
        );
        ui.add(
            egui::TextEdit::singleline(&mut state.add_contact_pubkey)
                .hint_text("Enter ML-DSA public key in hex...")
                .desired_width(ui.available_width()),
        );
        ui.add_space(theme::ITEM_GAP);

        // Alias input
        ui.label(
            RichText::new("Display Name")
                .size(theme::FONT_BODY)
                .color(theme::TEXT_SECONDARY),
        );
        ui.add(
            egui::TextEdit::singleline(&mut state.add_contact_alias)
                .hint_text("Enter a display name...")
                .desired_width(ui.available_width()),
        );
        ui.add_space(theme::PANEL_PADDING);

        // Validation
        let pubkey_bytes = hex::decode(&state.add_contact_pubkey).ok();
        let valid = pubkey_bytes.is_some() && !state.add_contact_alias.is_empty();

        if ui
            .add_enabled(valid, egui::Button::new("Add Contact"))
            .clicked()
        {
            if let Some(pk) = pubkey_bytes {
                command = Some(GuiCommand::AddContact {
                    pubkey: pk,
                    alias: state.add_contact_alias.clone(),
                });
            }
        }

        if !state.add_contact_pubkey.is_empty() && hex::decode(&state.add_contact_pubkey).is_err() {
            ui.add_space(4.0);
            ui.label(
                RichText::new("Invalid hex string")
                    .size(theme::FONT_SMALL)
                    .color(theme::DANGER),
            );
        }
    });

    command
}
