//! Contact list view — sidebar showing all contacts with online status and unread counts.

use egui::{RichText, ScrollArea, Ui};

use crate::ipc::GuiCommand;
use crate::state::GuiState;
use crate::theme;
use crate::widgets::status_badge::status_badge;

/// Render the contact list panel.
///
/// Returns a `GuiCommand` if the user triggers an action (e.g., requesting history).
pub fn contacts_view(ui: &mut Ui, state: &mut GuiState) -> Option<GuiCommand> {
    let mut command = None;

    ui.vertical(|ui| {
        // Header
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("Contacts")
                    .size(theme::FONT_HEADING)
                    .color(theme::TEXT_PRIMARY)
                    .strong(),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("+").on_hover_text("Add contact").clicked() {
                    state.navigate(crate::state::View::AddContact);
                }
            });
        });
        ui.add_space(theme::ITEM_GAP);
        ui.separator();
        ui.add_space(theme::ITEM_GAP);

        // Contact list
        ScrollArea::vertical().show(ui, |ui| {
            let contacts = state.contacts.clone();
            for contact in &contacts {
                let is_online = state.online.contains(&contact.pubkey);
                let unread = state.unread.get(&contact.pubkey).copied().unwrap_or(0);
                let is_selected = state.selected_contact.as_deref() == Some(&contact.pubkey);

                let frame = if is_selected {
                    egui::Frame::none()
                        .fill(theme::ACCENT.linear_multiply(0.15))
                        .rounding(6.0)
                        .inner_margin(egui::Margin::same(theme::CARD_PADDING))
                } else {
                    egui::Frame::none()
                        .fill(egui::Color32::TRANSPARENT)
                        .rounding(6.0)
                        .inner_margin(egui::Margin::same(theme::CARD_PADDING))
                };

                let resp = frame
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            status_badge(ui, is_online);
                            ui.add_space(4.0);

                            ui.vertical(|ui| {
                                ui.label(
                                    RichText::new(&contact.alias)
                                        .size(theme::FONT_BODY)
                                        .color(theme::TEXT_PRIMARY),
                                );
                                // Show last message preview if available
                                if let Some(msgs) = state.messages.get(&contact.pubkey) {
                                    if let Some(last) = msgs.last() {
                                        let preview = if last.text.len() > 30 {
                                            format!("{}...", &last.text[..30])
                                        } else {
                                            last.text.clone()
                                        };
                                        ui.label(
                                            RichText::new(preview)
                                                .size(theme::FONT_SMALL)
                                                .color(theme::TEXT_SECONDARY),
                                        );
                                    }
                                }
                            });

                            // Unread badge
                            if unread > 0 {
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        let badge_text = if unread > 99 {
                                            "99+".to_string()
                                        } else {
                                            unread.to_string()
                                        };
                                        egui::Frame::none()
                                            .fill(theme::BADGE_BG)
                                            .rounding(10.0)
                                            .inner_margin(egui::Margin::symmetric(6.0, 2.0))
                                            .show(ui, |ui| {
                                                ui.label(
                                                    RichText::new(badge_text)
                                                        .size(theme::FONT_SMALL)
                                                        .color(egui::Color32::WHITE)
                                                        .strong(),
                                                );
                                            });
                                    },
                                );
                            }
                        });
                    })
                    .response;

                if resp.interact(egui::Sense::click()).clicked() {
                    let pk = contact.pubkey.clone();
                    state.open_chat(pk.clone());
                    command = Some(GuiCommand::GetHistory {
                        contact: pk,
                        limit: 100,
                    });
                }

                ui.add_space(theme::ITEM_GAP);
            }
        });
    });

    command
}
