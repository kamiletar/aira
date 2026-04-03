//! Settings view — transport mode, TTL, device management, keychain.

use egui::{RichText, ScrollArea, Ui};

use crate::ipc::GuiCommand;
use crate::state::GuiState;
use crate::theme;

/// Available transport modes for the combo box.
const TRANSPORT_MODES: &[&str] = &["direct", "obfs4", "mimicry:dns", "mimicry:quic", "cdn"];

/// Render the settings view.
///
/// Returns `GuiCommand`s for transport changes, device operations, etc.
pub fn settings_view(ui: &mut Ui, state: &mut GuiState) -> Vec<GuiCommand> {
    let mut commands = Vec::new();

    ui.vertical(|ui| {
        ui.add_space(4.0);
        ui.label(
            RichText::new("Settings")
                .size(theme::FONT_HEADING)
                .color(theme::TEXT_PRIMARY)
                .strong(),
        );
        ui.separator();

        ScrollArea::vertical().show(ui, |ui| {
            // ─── Transport Mode ─────────────────────────────────────────
            ui.add_space(theme::PANEL_PADDING);
            ui.label(
                RichText::new("Transport Mode")
                    .size(theme::FONT_BODY)
                    .color(theme::ACCENT)
                    .strong(),
            );
            ui.add_space(theme::ITEM_GAP);

            let mut current_mode = state.transport_mode.clone();
            egui::ComboBox::from_label("")
                .selected_text(&current_mode)
                .show_ui(ui, |ui| {
                    for mode in TRANSPORT_MODES {
                        ui.selectable_value(&mut current_mode, (*mode).to_string(), *mode);
                    }
                });
            if current_mode != state.transport_mode {
                state.transport_mode.clone_from(&current_mode);
                commands.push(GuiCommand::SetTransportMode { mode: current_mode });
            }

            ui.add_space(theme::PANEL_PADDING);
            ui.separator();

            // ─── Linked Devices ─────────────────────────────────────────
            ui.add_space(theme::PANEL_PADDING);
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Linked Devices")
                        .size(theme::FONT_BODY)
                        .color(theme::ACCENT)
                        .strong(),
                );
                if ui.button("Refresh").clicked() {
                    commands.push(GuiCommand::GetDevices);
                }
            });
            ui.add_space(theme::ITEM_GAP);

            for dev in &state.devices {
                egui::Frame::none()
                    .fill(theme::BG_CARD)
                    .rounding(6.0)
                    .inner_margin(egui::Margin::same(theme::CARD_PADDING))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            let label = if dev.is_primary {
                                format!("{} (primary)", dev.name)
                            } else {
                                dev.name.clone()
                            };
                            ui.label(
                                RichText::new(label)
                                    .size(theme::FONT_BODY)
                                    .color(theme::TEXT_PRIMARY),
                            );
                            if !dev.is_primary {
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if ui.small_button("Unlink").clicked() {
                                            commands.push(GuiCommand::UnlinkDevice {
                                                device_id: dev.device_id,
                                            });
                                        }
                                    },
                                );
                            }
                        });
                    });
                ui.add_space(theme::ITEM_GAP);
            }

            // Link new device
            ui.add_space(theme::ITEM_GAP);
            ui.label(
                RichText::new("Link New Device")
                    .size(theme::FONT_BODY)
                    .color(theme::TEXT_SECONDARY),
            );

            if let Some(code) = &state.link_code {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!("Code: {code}"))
                            .size(theme::FONT_HEADING)
                            .color(theme::SUCCESS)
                            .strong(),
                    );
                    if ui.button("Copy").clicked() {
                        ui.output_mut(|o| o.copied_text.clone_from(code));
                    }
                });
                ui.label(
                    RichText::new("Enter this code on the new device within 5 minutes")
                        .size(theme::FONT_SMALL)
                        .color(theme::TEXT_SECONDARY),
                );
            } else if ui.button("Generate Link Code").clicked() {
                commands.push(GuiCommand::GenerateLinkCode);
            }

            // Or enter a code from another device
            ui.add_space(theme::ITEM_GAP);
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut state.link_code_input)
                        .hint_text("Enter code from primary device...")
                        .desired_width(120.0),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut state.link_device_name)
                        .hint_text("Device name")
                        .desired_width(120.0),
                );
                let valid =
                    !state.link_code_input.is_empty() && !state.link_device_name.is_empty();
                if ui.add_enabled(valid, egui::Button::new("Link")).clicked() {
                    commands.push(GuiCommand::LinkDevice {
                        code: state.link_code_input.clone(),
                        device_name: state.link_device_name.clone(),
                    });
                    state.link_code_input.clear();
                    state.link_device_name.clear();
                }
            });

            ui.add_space(theme::PANEL_PADDING);
            ui.separator();

            // ─── Keychain ───────────────────────────────────────────────
            ui.add_space(theme::PANEL_PADDING);
            ui.label(
                RichText::new("Keychain")
                    .size(theme::FONT_BODY)
                    .color(theme::ACCENT)
                    .strong(),
            );
            ui.label(
                RichText::new("Passphrase is stored in OS keychain (Secret Service / Keychain / Credential Manager)")
                    .size(theme::FONT_SMALL)
                    .color(theme::TEXT_SECONDARY),
            );

            ui.add_space(theme::PANEL_PADDING);
            ui.separator();

            // ─── About ──────────────────────────────────────────────────
            ui.add_space(theme::PANEL_PADDING);
            ui.label(
                RichText::new("About")
                    .size(theme::FONT_BODY)
                    .color(theme::ACCENT)
                    .strong(),
            );
            ui.label(
                RichText::new("Aira — Post-quantum P2P Messenger")
                    .size(theme::FONT_BODY)
                    .color(theme::TEXT_PRIMARY),
            );
            ui.label(
                RichText::new(format!("Version {}", env!("CARGO_PKG_VERSION")))
                    .size(theme::FONT_SMALL)
                    .color(theme::TEXT_SECONDARY),
            );
        });
    });

    commands
}
