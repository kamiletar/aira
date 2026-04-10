//! Unlock screen — shown when the keychain holds a password-protected
//! vault instead of a plain seed phrase.
//!
//! The user enters their password; submitting it emits
//! `GuiCommand::SubmitPassword { password }` which the IPC bridge
//! forwards to `password_vault::unlock`.

use egui::{RichText, Ui};
use zeroize::Zeroizing;

use crate::ipc::GuiCommand;
use crate::state::{ConnectionStatus, GuiState};
use crate::theme;

/// Render the unlock screen. Returns a `GuiCommand::SubmitPassword` when
/// the user clicks Unlock (or presses Enter).
pub fn unlock_view(ui: &mut Ui, state: &mut GuiState) -> Option<GuiCommand> {
    let mut command = None;

    ui.vertical_centered(|ui| {
        ui.add_space(80.0);
        ui.label(
            RichText::new("Unlock Aira")
                .size(26.0)
                .color(theme::TEXT_PRIMARY)
                .strong(),
        );
        ui.add_space(6.0);
        ui.label(
            RichText::new("Enter your password to decrypt your identity.")
                .size(theme::FONT_SMALL)
                .color(theme::TEXT_SECONDARY),
        );
        ui.add_space(theme::PANEL_PADDING * 2.0);

        egui::Frame::none()
            .fill(theme::BG_INPUT)
            .rounding(6.0)
            .inner_margin(egui::Margin::same(theme::CARD_PADDING))
            .show(ui, |ui| {
                let response = ui.add_sized(
                    [280.0, 24.0],
                    egui::TextEdit::singleline(&mut state.unlock_input)
                        .password(true)
                        .hint_text("Password"),
                );

                // Submit on Enter.
                if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    command = take_password(state);
                }
            });

        if let ConnectionStatus::Locked {
            last_error: Some(err),
        } = &state.conn_status
        {
            ui.add_space(theme::ITEM_GAP * 2.0);
            ui.label(
                RichText::new(err)
                    .size(theme::FONT_SMALL)
                    .color(theme::DANGER),
            );
        }

        ui.add_space(theme::PANEL_PADDING);

        let submit_enabled = !state.unlock_input.is_empty();
        let button = egui::Button::new(
            RichText::new("Unlock")
                .size(theme::FONT_BODY)
                .color(theme::TEXT_PRIMARY)
                .strong(),
        )
        .fill(if submit_enabled {
            theme::ACCENT
        } else {
            theme::BG_CARD
        });
        if ui.add_enabled(submit_enabled, button).clicked() {
            command = take_password(state);
        }

        ui.add_space(theme::PANEL_PADDING * 2.0);
        ui.separator();
        ui.add_space(theme::ITEM_GAP * 2.0);

        ui.label(
            RichText::new("Forgot your password?")
                .size(theme::FONT_SMALL)
                .color(theme::TEXT_MUTED),
        );
        if ui.small_button("Reset identity").clicked() {
            // Wipes the vault and returns to the welcome flow. The user
            // will need their written-down BIP-39 phrase to import the
            // identity; without it, the keychain data is unrecoverable.
            command = Some(GuiCommand::ResetIdentity);
        }
    });

    command
}

/// Drain the password input into a Zeroizing wrapper, overwriting the
/// UI buffer before clearing so the bytes don't linger in the String's
/// capacity.
fn take_password(state: &mut GuiState) -> Option<GuiCommand> {
    if state.unlock_input.is_empty() {
        return None;
    }
    let password = Zeroizing::new(state.unlock_input.clone());
    // SAFETY: overwriting valid UTF-8 with zero bytes before clear().
    for b in unsafe { state.unlock_input.as_bytes_mut() } {
        *b = 0;
    }
    state.unlock_input.clear();
    Some(GuiCommand::SubmitPassword { password })
}
