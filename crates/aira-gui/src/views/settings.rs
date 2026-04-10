//! Settings view — transport mode, TTL, device management, keychain.

use egui::{RichText, ScrollArea, Ui};
use zeroize::Zeroizing;

use crate::ipc::GuiCommand;
use crate::state::{GuiState, SecurityModal};
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
                RichText::new("Identity is stored in OS keychain (Secret Service / Keychain / Credential Manager)")
                    .size(theme::FONT_SMALL)
                    .color(theme::TEXT_SECONDARY),
            );

            ui.add_space(theme::PANEL_PADDING);
            ui.separator();

            // ─── Security ───────────────────────────────────────────────
            security_section(ui, state, &mut commands);

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

/// Render the Security section (password protection toggle + modals).
fn security_section(ui: &mut Ui, state: &mut GuiState, commands: &mut Vec<GuiCommand>) {
    ui.add_space(theme::PANEL_PADDING);
    ui.label(
        RichText::new("Security")
            .size(theme::FONT_BODY)
            .color(theme::ACCENT)
            .strong(),
    );
    ui.add_space(theme::ITEM_GAP);

    let protected = state.identity_password_protected;
    ui.label(
        RichText::new(if protected {
            "Identity is encrypted with a password. You will be asked to unlock on every launch."
        } else {
            "Identity is stored without a password. OS keychain ACLs protect it while you're logged in."
        })
        .size(theme::FONT_SMALL)
        .color(theme::TEXT_SECONDARY),
    );

    ui.add_space(theme::ITEM_GAP * 2.0);

    ui.horizontal(|ui| {
        if protected {
            if ui.button("Change password").clicked() {
                state.settings_security.reset();
                state.settings_security.modal = SecurityModal::ChangePassword;
            }
            if ui.button("Disable password protection").clicked() {
                state.settings_security.reset();
                state.settings_security.modal = SecurityModal::DisablePassword;
            }
        } else if ui.button("Protect identity with password").clicked() {
            state.settings_security.reset();
            state.settings_security.modal = SecurityModal::SetPassword;
        }
    });

    // Open modal (rendered inline below the section — egui Windows
    // don't nest well inside scrollable panels).
    match state.settings_security.modal {
        SecurityModal::None => {}
        SecurityModal::SetPassword => {
            render_set_password_modal(ui, state, commands);
        }
        SecurityModal::ChangePassword => {
            render_change_password_modal(ui, state, commands);
        }
        SecurityModal::DisablePassword => {
            render_disable_password_modal(ui, state, commands);
        }
    }
}

fn render_set_password_modal(ui: &mut Ui, state: &mut GuiState, commands: &mut Vec<GuiCommand>) {
    ui.add_space(theme::PANEL_PADDING);
    egui::Frame::none()
        .fill(theme::BG_CARD)
        .rounding(6.0)
        .inner_margin(egui::Margin::same(theme::CARD_PADDING))
        .show(ui, |ui| {
            ui.label(
                RichText::new("Set password")
                    .size(theme::FONT_BODY)
                    .color(theme::TEXT_PRIMARY)
                    .strong(),
            );
            ui.add_space(theme::ITEM_GAP * 2.0);

            ui.add(
                egui::TextEdit::singleline(&mut state.settings_security.password_input)
                    .password(true)
                    .hint_text("New password")
                    .desired_width(240.0),
            );
            ui.add_space(theme::ITEM_GAP);
            ui.add(
                egui::TextEdit::singleline(&mut state.settings_security.confirm_input)
                    .password(true)
                    .hint_text("Confirm password")
                    .desired_width(240.0),
            );

            if let Some(err) = &state.settings_security.error {
                ui.add_space(theme::ITEM_GAP);
                ui.label(
                    RichText::new(err)
                        .size(theme::FONT_SMALL)
                        .color(theme::DANGER),
                );
            }

            ui.add_space(theme::ITEM_GAP * 2.0);
            ui.horizontal(|ui| {
                if ui.button("Cancel").clicked() {
                    state.settings_security.reset();
                }
                let matches =
                    state.settings_security.password_input == state.settings_security.confirm_input
                        && !state.settings_security.password_input.is_empty();
                if ui.add_enabled(matches, egui::Button::new("Enable")).clicked() {
                    let password = Zeroizing::new(state.settings_security.password_input.clone());
                    commands.push(GuiCommand::EnablePasswordProtection { password });
                    // The bridge will emit PasswordProtectionChanged (→ reset).
                    // Zero the local buffers immediately too.
                    scrub(&mut state.settings_security.password_input);
                    scrub(&mut state.settings_security.confirm_input);
                } else if !matches && !state.settings_security.password_input.is_empty() {
                    state.settings_security.error =
                        Some("Passwords do not match".to_string());
                }
            });
        });
}

fn render_change_password_modal(
    ui: &mut Ui,
    state: &mut GuiState,
    commands: &mut Vec<GuiCommand>,
) {
    ui.add_space(theme::PANEL_PADDING);
    egui::Frame::none()
        .fill(theme::BG_CARD)
        .rounding(6.0)
        .inner_margin(egui::Margin::same(theme::CARD_PADDING))
        .show(ui, |ui| {
            ui.label(
                RichText::new("Change password")
                    .size(theme::FONT_BODY)
                    .color(theme::TEXT_PRIMARY)
                    .strong(),
            );
            ui.add_space(theme::ITEM_GAP * 2.0);

            ui.add(
                egui::TextEdit::singleline(&mut state.settings_security.old_password_input)
                    .password(true)
                    .hint_text("Current password")
                    .desired_width(240.0),
            );
            ui.add_space(theme::ITEM_GAP);
            ui.add(
                egui::TextEdit::singleline(&mut state.settings_security.password_input)
                    .password(true)
                    .hint_text("New password")
                    .desired_width(240.0),
            );
            ui.add_space(theme::ITEM_GAP);
            ui.add(
                egui::TextEdit::singleline(&mut state.settings_security.confirm_input)
                    .password(true)
                    .hint_text("Confirm new password")
                    .desired_width(240.0),
            );

            if let Some(err) = &state.settings_security.error {
                ui.add_space(theme::ITEM_GAP);
                ui.label(
                    RichText::new(err)
                        .size(theme::FONT_SMALL)
                        .color(theme::DANGER),
                );
            }

            ui.add_space(theme::ITEM_GAP * 2.0);
            ui.horizontal(|ui| {
                if ui.button("Cancel").clicked() {
                    state.settings_security.reset();
                }
                let matches = state.settings_security.password_input
                    == state.settings_security.confirm_input
                    && !state.settings_security.password_input.is_empty()
                    && !state.settings_security.old_password_input.is_empty();
                if ui.add_enabled(matches, egui::Button::new("Change")).clicked() {
                    let old = Zeroizing::new(state.settings_security.old_password_input.clone());
                    let new = Zeroizing::new(state.settings_security.password_input.clone());
                    commands.push(GuiCommand::ChangePassword { old, new });
                    scrub(&mut state.settings_security.old_password_input);
                    scrub(&mut state.settings_security.password_input);
                    scrub(&mut state.settings_security.confirm_input);
                }
            });
        });
}

fn render_disable_password_modal(
    ui: &mut Ui,
    state: &mut GuiState,
    commands: &mut Vec<GuiCommand>,
) {
    ui.add_space(theme::PANEL_PADDING);
    egui::Frame::none()
        .fill(theme::BG_CARD)
        .rounding(6.0)
        .inner_margin(egui::Margin::same(theme::CARD_PADDING))
        .show(ui, |ui| {
            ui.label(
                RichText::new("Disable password protection")
                    .size(theme::FONT_BODY)
                    .color(theme::TEXT_PRIMARY)
                    .strong(),
            );
            ui.add_space(theme::ITEM_GAP);
            ui.label(
                RichText::new(
                    "Your identity will be stored without a password. Enter your current \
                     password to confirm.",
                )
                .size(theme::FONT_SMALL)
                .color(theme::TEXT_SECONDARY),
            );
            ui.add_space(theme::ITEM_GAP * 2.0);

            ui.add(
                egui::TextEdit::singleline(&mut state.settings_security.password_input)
                    .password(true)
                    .hint_text("Current password")
                    .desired_width(240.0),
            );

            if let Some(err) = &state.settings_security.error {
                ui.add_space(theme::ITEM_GAP);
                ui.label(
                    RichText::new(err)
                        .size(theme::FONT_SMALL)
                        .color(theme::DANGER),
                );
            }

            ui.add_space(theme::ITEM_GAP * 2.0);
            ui.horizontal(|ui| {
                if ui.button("Cancel").clicked() {
                    state.settings_security.reset();
                }
                let enabled = !state.settings_security.password_input.is_empty();
                if ui.add_enabled(enabled, egui::Button::new("Disable")).clicked() {
                    let password = Zeroizing::new(state.settings_security.password_input.clone());
                    commands.push(GuiCommand::DisablePasswordProtection { password });
                    scrub(&mut state.settings_security.password_input);
                }
            });
        });
}

/// Overwrite a String with zero bytes and clear it. Best-effort memory
/// hygiene for password buffers held inside `GuiState` — the
/// allocation itself may still linger in the heap until reused.
fn scrub(s: &mut String) {
    // SAFETY: overwriting valid UTF-8 with 0x00 produces valid ASCII.
    for b in unsafe { s.as_bytes_mut() } {
        *b = 0;
    }
    s.clear();
}
