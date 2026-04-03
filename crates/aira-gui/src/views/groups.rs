//! Groups view — group list, create group, and group chat.

use egui::{Key, RichText, ScrollArea, Ui};

use crate::ipc::GuiCommand;
use crate::state::{GuiState, View};
use crate::theme;
use crate::widgets::message_bubble::message_bubble;

/// Render the groups list view.
///
/// Returns commands for group actions.
pub fn groups_view(ui: &mut Ui, state: &mut GuiState) -> Vec<GuiCommand> {
    let mut commands = Vec::new();

    ui.vertical(|ui| {
        ui.add_space(4.0);
        ui.label(
            RichText::new("Groups")
                .size(theme::FONT_HEADING)
                .color(theme::TEXT_PRIMARY)
                .strong(),
        );
        ui.add_space(6.0);

        ScrollArea::vertical().show(ui, |ui| {
            // Group list
            let groups = state.groups.clone();
            for group in &groups {
                let unread = state.group_unread.get(&group.id).copied().unwrap_or(0);

                let resp = egui::Frame::none()
                    .fill(theme::BG_CARD)
                    .rounding(6.0)
                    .inner_margin(egui::Margin::same(theme::CARD_PADDING))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(&group.name)
                                    .size(theme::FONT_BODY)
                                    .color(theme::TEXT_PRIMARY),
                            );
                            ui.label(
                                RichText::new(format!("{} members", group.members.len()))
                                    .size(theme::FONT_SMALL)
                                    .color(theme::TEXT_SECONDARY),
                            );
                            if unread > 0 {
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        egui::Frame::none()
                                            .fill(theme::BADGE_BG)
                                            .rounding(10.0)
                                            .inner_margin(egui::Margin::symmetric(6.0, 2.0))
                                            .show(ui, |ui| {
                                                ui.label(
                                                    RichText::new(unread.to_string())
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
                    let gid = group.id;
                    state.open_group_chat(gid);
                    commands.push(GuiCommand::GetGroupHistory {
                        group_id: gid,
                        limit: 100,
                    });
                }
                ui.add_space(theme::ITEM_GAP);
            }

            if groups.is_empty() {
                ui.add_space(40.0);
                ui.vertical_centered(|ui| {
                    ui.label(
                        RichText::new("No groups yet")
                            .size(theme::FONT_HEADING)
                            .color(theme::TEXT_MUTED),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("Create one below to start chatting")
                            .size(theme::FONT_BODY)
                            .color(theme::TEXT_MUTED),
                    );
                });
            }

            // Create group section
            ui.add_space(theme::PANEL_PADDING);
            ui.separator();
            ui.add_space(theme::ITEM_GAP);
            ui.label(
                RichText::new("Create Group")
                    .size(theme::FONT_BODY)
                    .color(theme::ACCENT)
                    .strong(),
            );
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut state.create_group_name)
                        .hint_text("Group name...")
                        .desired_width(200.0),
                );
                if ui
                    .add_enabled(
                        !state.create_group_name.is_empty(),
                        egui::Button::new("Create"),
                    )
                    .clicked()
                {
                    commands.push(GuiCommand::CreateGroup {
                        name: state.create_group_name.clone(),
                        members: Vec::new(),
                    });
                }
            });
        });
    });

    commands
}

/// Render the group chat view.
pub fn group_chat_view(ui: &mut Ui, state: &mut GuiState) -> Option<GuiCommand> {
    let mut command = None;

    let Some(group_id) = state.selected_group else {
        ui.label("No group selected");
        return None;
    };

    let group_name = state
        .groups
        .iter()
        .find(|g| g.id == group_id)
        .map_or_else(|| "Unknown".into(), |g| g.name.clone());

    ui.vertical(|ui| {
        // Header
        ui.horizontal(|ui| {
            if ui.button("<").on_hover_text("Back").clicked() {
                state.navigate(View::Groups);
            }
            ui.add_space(8.0);
            ui.label(
                RichText::new(&group_name)
                    .size(theme::FONT_HEADING)
                    .color(theme::TEXT_PRIMARY)
                    .strong(),
            );
        });
        ui.separator();

        // Messages
        let messages = state
            .group_messages
            .get(&group_id)
            .cloned()
            .unwrap_or_default();
        ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
            ui.add_space(theme::ITEM_GAP);
            for msg in &messages {
                message_bubble(ui, msg);
                ui.add_space(theme::ITEM_GAP);
            }
        });

        // Input
        ui.separator();
        ui.horizontal(|ui| {
            let input = ui.add(
                egui::TextEdit::singleline(&mut state.group_input)
                    .hint_text("Type a message...")
                    .desired_width(ui.available_width() - 70.0),
            );

            let send_clicked = ui
                .add_enabled(!state.group_input.is_empty(), egui::Button::new("Send"))
                .clicked();
            let enter_pressed = input.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));

            if (send_clicked || enter_pressed) && !state.group_input.is_empty() {
                let text = state.group_input.clone();
                state.group_input.clear();

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
                state.group_messages.entry(group_id).or_default().push(msg);

                command = Some(GuiCommand::SendGroupMessage { group_id, text });
            }

            if send_clicked || enter_pressed {
                input.request_focus();
            }
        });
    });

    command
}
