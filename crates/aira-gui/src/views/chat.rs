//! Chat view — message history with input field.

use egui::{Key, RichText, ScrollArea, Ui};

use crate::ipc::GuiCommand;
use crate::state::GuiState;
use crate::theme;
use crate::widgets::message_bubble::message_bubble;

/// Render the chat view for the currently selected contact.
///
/// Returns a `GuiCommand` if the user sends a message.
pub fn chat_view(ui: &mut Ui, state: &mut GuiState) -> Option<GuiCommand> {
    let mut command = None;

    let Some(contact_pk) = state.selected_contact.clone() else {
        ui.label("No contact selected");
        return None;
    };

    let alias = state.contact_alias(&contact_pk);
    let is_online = state.online.contains(&contact_pk);

    ui.vertical(|ui| {
        // Chat header
        ui.horizontal(|ui| {
            if ui.button("<").on_hover_text("Back").clicked() {
                state.go_back();
            }
            ui.add_space(8.0);
            crate::widgets::status_badge::status_badge(ui, is_online);
            ui.add_space(4.0);
            ui.label(
                RichText::new(&alias)
                    .size(theme::FONT_HEADING)
                    .color(theme::TEXT_PRIMARY)
                    .strong(),
            );

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Send file").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        command = Some(GuiCommand::SendFile {
                            to: contact_pk.clone(),
                            path,
                        });
                    }
                }
            });
        });
        ui.separator();

        // Messages area
        let messages = state.messages.get(&contact_pk).cloned().unwrap_or_default();
        ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
            ui.add_space(theme::ITEM_GAP);
            for msg in &messages {
                message_bubble(ui, msg);
                ui.add_space(theme::ITEM_GAP);
            }
        });

        // Input area
        ui.separator();
        ui.horizontal(|ui| {
            let input = ui.add(
                egui::TextEdit::singleline(&mut state.chat_input)
                    .hint_text("Type a message...")
                    .desired_width(ui.available_width() - 70.0),
            );

            let send_clicked = ui
                .add_enabled(!state.chat_input.is_empty(), egui::Button::new("Send"))
                .clicked();

            let enter_pressed = input.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));

            if (send_clicked || enter_pressed) && !state.chat_input.is_empty() {
                let text = state.chat_input.clone();
                state.chat_input.clear();

                // Add message to local display immediately
                let msg = crate::state::DisplayMessage {
                    id: [0; 16],
                    is_self: true,
                    text: text.clone(),
                    timestamp_micros: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_micros() as u64,
                    sender_alias: None,
                };
                state
                    .messages
                    .entry(contact_pk.clone())
                    .or_default()
                    .push(msg);

                command = Some(GuiCommand::SendMessage {
                    to: contact_pk.clone(),
                    text,
                });
            }

            // Refocus input after sending
            if send_clicked || enter_pressed {
                input.request_focus();
            }
        });
    });

    command
}
