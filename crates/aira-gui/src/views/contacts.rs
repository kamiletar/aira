//! Contact list view — sidebar showing all contacts with online status and unread counts.

use egui::{RichText, ScrollArea, Ui};

use crate::ipc::GuiCommand;
use crate::state::GuiState;
use crate::theme;

/// Render the contact list panel.
///
/// Returns a `GuiCommand` if the user triggers an action (e.g., requesting history).
pub fn contacts_view(ui: &mut Ui, state: &mut GuiState) -> Option<GuiCommand> {
    let mut command = None;

    ui.vertical(|ui| {
        // Header
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("Contacts")
                    .size(theme::FONT_HEADING)
                    .color(theme::TEXT_PRIMARY)
                    .strong(),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let btn = ui.add(
                    egui::Button::new(
                        RichText::new("+")
                            .size(theme::FONT_HEADING)
                            .color(theme::ACCENT),
                    )
                    .fill(theme::BG_CARD)
                    .rounding(theme::ROUNDING)
                    .min_size(egui::vec2(32.0, 32.0)),
                );
                if btn.on_hover_text("Add contact").clicked() {
                    state.navigate(crate::state::View::AddContact);
                }
            });
        });
        ui.add_space(6.0);

        if state.contacts.is_empty() {
            // Empty state
            ui.add_space(ui.available_height() / 3.0);
            ui.vertical_centered(|ui| {
                ui.label(
                    RichText::new("No contacts yet")
                        .size(theme::FONT_HEADING)
                        .color(theme::TEXT_MUTED),
                );
                ui.add_space(8.0);
                ui.label(
                    RichText::new("Tap + to add your first contact")
                        .size(theme::FONT_BODY)
                        .color(theme::TEXT_MUTED),
                );
            });
        } else {
            // Contact list
            ScrollArea::vertical().show(ui, |ui| {
                let contacts = state.contacts.clone();
                for contact in &contacts {
                    let is_online = state.online.contains(&contact.pubkey);
                    let unread = state.unread.get(&contact.pubkey).copied().unwrap_or(0);
                    let is_selected = state.selected_contact.as_deref() == Some(&contact.pubkey);

                    let fill = if is_selected {
                        theme::ACCENT.linear_multiply(0.12)
                    } else {
                        egui::Color32::TRANSPARENT
                    };

                    let frame = egui::Frame::none()
                        .fill(fill)
                        .rounding(theme::ROUNDING)
                        .inner_margin(egui::Margin::same(theme::CARD_PADDING));

                    let resp = frame
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                // Avatar circle with initials
                                let avatar_color = theme::avatar_color(&contact.alias);
                                let initials = theme::avatar_initials(&contact.alias);
                                let avatar_size = theme::AVATAR_SIZE;
                                let (rect, _) = ui.allocate_exact_size(
                                    egui::vec2(avatar_size, avatar_size),
                                    egui::Sense::hover(),
                                );
                                ui.painter().circle_filled(
                                    rect.center(),
                                    avatar_size / 2.0,
                                    avatar_color,
                                );
                                ui.painter().text(
                                    rect.center(),
                                    egui::Align2::CENTER_CENTER,
                                    &initials,
                                    egui::FontId::proportional(avatar_size * 0.4),
                                    egui::Color32::WHITE,
                                );

                                // Online status dot (overlaid on avatar bottom-right)
                                if is_online {
                                    let dot_pos = egui::pos2(rect.max.x - 4.0, rect.max.y - 4.0);
                                    // Dark ring for contrast
                                    ui.painter().circle_filled(dot_pos, 6.0, theme::BG_PRIMARY);
                                    ui.painter()
                                        .circle_filled(dot_pos, 4.5, theme::STATUS_ONLINE);
                                }

                                ui.add_space(8.0);

                                // Name + last message preview
                                ui.vertical(|ui| {
                                    ui.label(
                                        RichText::new(&contact.alias)
                                            .size(theme::FONT_BODY)
                                            .color(theme::TEXT_PRIMARY)
                                            .strong(),
                                    );
                                    if let Some(msgs) = state.messages.get(&contact.pubkey) {
                                        if let Some(last) = msgs.last() {
                                            let preview = if last.text.len() > 32 {
                                                format!("{}...", &last.text[..32])
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

                                // Right side: time + unread badge
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::TOP),
                                    |ui| {
                                        if unread > 0 {
                                            let badge_text = if unread > 99 {
                                                "99+".to_string()
                                            } else {
                                                unread.to_string()
                                            };
                                            egui::Frame::none()
                                                .fill(theme::BADGE_BG)
                                                .rounding(theme::BADGE_ROUNDING)
                                                .inner_margin(egui::Margin::symmetric(6.0, 2.0))
                                                .show(ui, |ui| {
                                                    ui.label(
                                                        RichText::new(badge_text)
                                                            .size(theme::FONT_SMALL)
                                                            .color(egui::Color32::WHITE)
                                                            .strong(),
                                                    );
                                                });
                                        }

                                        // Relative time of last message
                                        if let Some(msgs) = state.messages.get(&contact.pubkey) {
                                            if let Some(last) = msgs.last() {
                                                ui.label(
                                                    RichText::new(theme::relative_time(
                                                        last.timestamp_micros,
                                                    ))
                                                    .size(theme::FONT_SMALL)
                                                    .color(theme::TEXT_MUTED),
                                                );
                                            }
                                        }
                                    },
                                );
                            });
                        })
                        .response;

                    // Hover highlight
                    if resp.hovered() && !is_selected {
                        ui.painter().rect_filled(
                            resp.rect,
                            theme::ROUNDING,
                            egui::Color32::from_white_alpha(5),
                        );
                    }

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
        }
    });

    command
}
