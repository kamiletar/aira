//! Main application struct implementing `eframe::App`.
//!
//! `AiraApp` holds the GUI state and IPC channels. Its `update()` method:
//! 1. Drains `GuiUpdate` messages from the IPC bridge.
//! 2. Polls system tray events.
//! 3. Renders the active view.
//! 4. Sends `GuiCommand`s triggered by user interaction.

use tokio::sync::mpsc;

use crate::ipc::{GuiCommand, GuiUpdate};
use crate::state::{GuiState, View};
use crate::theme;
use crate::tray::{self, TrayAction, TrayMenuIds};

/// The Aira desktop application.
pub struct AiraApp {
    /// All application state.
    pub state: GuiState,
    /// Channel to send commands to the IPC bridge.
    cmd_tx: mpsc::Sender<GuiCommand>,
    /// Channel to receive updates from the IPC bridge.
    update_rx: mpsc::Receiver<GuiUpdate>,
    /// Tray menu item IDs for event matching.
    tray_ids: Option<TrayMenuIds>,
    /// Whether initial data has been fetched.
    init_fetched: bool,
    /// Whether fonts have been set up.
    fonts_loaded: bool,
}

impl AiraApp {
    /// Create a new `AiraApp` with IPC channels and optional tray IDs.
    pub fn new(
        cmd_tx: mpsc::Sender<GuiCommand>,
        update_rx: mpsc::Receiver<GuiUpdate>,
        tray_ids: Option<TrayMenuIds>,
    ) -> Self {
        Self {
            state: GuiState::new(),
            cmd_tx,
            update_rx,
            tray_ids,
            init_fetched: false,
            fonts_loaded: false,
        }
    }

    /// Send a command to the IPC bridge (non-blocking from the UI thread).
    fn send_command(&self, cmd: GuiCommand) {
        let _ = self.cmd_tx.blocking_send(cmd);
    }

    /// Send multiple commands.
    fn send_commands(&self, cmds: Vec<GuiCommand>) {
        for cmd in cmds {
            self.send_command(cmd);
        }
    }

    /// Fetch initial data from the daemon (contacts, address, groups, devices).
    fn fetch_initial_data(&self) {
        self.send_command(GuiCommand::GetContacts);
        self.send_command(GuiCommand::GetMyAddress);
        self.send_command(GuiCommand::GetGroups);
        self.send_command(GuiCommand::GetDevices);
        self.send_command(GuiCommand::GetTransportMode);
    }
}

impl eframe::App for AiraApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 1. Drain updates from IPC bridge
        while let Ok(update) = self.update_rx.try_recv() {
            let should_notify = self.state.handle_update(update);
            if should_notify {
                // Show desktop notification for messages received while not focused
                // (notification details are handled in handle_update)
            }
        }

        // 2. Fetch initial data on first connected frame
        if self.state.connected && !self.init_fetched {
            self.init_fetched = true;
            self.fetch_initial_data();
        }

        // 3. Poll tray events
        if let Some(ids) = &self.tray_ids {
            if let Some(action) = tray::poll_tray_event(ids) {
                match action {
                    TrayAction::Open => {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                    }
                    TrayAction::Quit => {
                        self.send_command(GuiCommand::Shutdown);
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                }
            }
        }

        // 4. Apply custom theme + fonts (once)
        if !self.fonts_loaded {
            theme::setup_fonts(ctx);
            self.fonts_loaded = true;
        }
        theme::apply_theme(ctx);

        // 5. Render UI — top navigation bar
        egui::TopBottomPanel::top("top_bar")
            .frame(
                egui::Frame::none()
                    .fill(theme::BG_SECONDARY)
                    .inner_margin(egui::Margin::symmetric(theme::PANEL_PADDING, 10.0))
                    .stroke(egui::Stroke::new(1.0, theme::SEPARATOR)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;
                    ui.spacing_mut().button_padding = egui::vec2(10.0, 6.0);

                    let tabs = [
                        (View::Contacts, "Contacts"),
                        (View::Groups, "Groups"),
                        (View::Transfers, "Transfers"),
                        (View::Identity, "Identity"),
                        (View::Settings, "Settings"),
                    ];

                    for (view, label) in tabs {
                        let is_active = self.state.active_view == view;
                        let text =
                            egui::RichText::new(label)
                                .size(theme::FONT_BODY)
                                .color(if is_active {
                                    theme::ACCENT
                                } else {
                                    theme::TEXT_SECONDARY
                                });

                        let btn = ui.add(
                            egui::Button::new(text)
                                .frame(false)
                                .min_size(egui::vec2(0.0, 28.0))
                                .rounding(egui::Rounding::same(6.0)),
                        );

                        // Hover highlight
                        if btn.hovered() && !is_active {
                            ui.painter().rect_filled(
                                btn.rect.expand(1.0),
                                6.0,
                                egui::Color32::from_white_alpha(8),
                            );
                        }

                        // Underline indicator for active tab
                        if is_active {
                            let rect = btn.rect;
                            ui.painter().rect_filled(
                                egui::Rect::from_min_size(
                                    egui::pos2(rect.min.x + 2.0, rect.max.y + 4.0),
                                    egui::vec2(rect.width() - 4.0, 2.0),
                                ),
                                1.0,
                                theme::ACCENT,
                            );
                        }

                        if btn.clicked() {
                            self.state.active_view = view;
                        }
                    }

                    // Connection status — compact dot + label
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let (color, status_label) = if self.state.connected {
                            (theme::SUCCESS, "Online")
                        } else {
                            (theme::DANGER, "Offline")
                        };
                        ui.label(
                            egui::RichText::new(status_label)
                                .size(theme::FONT_SMALL)
                                .color(color),
                        );
                        let dot_size = 7.0;
                        let (rect, _) = ui.allocate_exact_size(
                            egui::vec2(dot_size, dot_size),
                            egui::Sense::hover(),
                        );
                        ui.painter()
                            .circle_filled(rect.center(), dot_size / 2.0, color);
                    });
                });
            });

        // Status bar at the bottom
        if self.state.status_message.is_some() {
            egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if let Some(msg) = &self.state.status_message {
                        ui.label(
                            egui::RichText::new(msg.as_str())
                                .size(theme::FONT_SMALL)
                                .color(theme::TEXT_SECONDARY),
                        );
                    }
                    if ui.small_button("x").clicked() {
                        self.state.status_message = None;
                    }
                });
            });
        }

        // Main content
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.state.active_view {
                View::Contacts => {
                    if let Some(cmd) = crate::views::contacts::contacts_view(ui, &mut self.state) {
                        self.send_command(cmd);
                    }
                }
                View::Chat => {
                    if let Some(cmd) = crate::views::chat::chat_view(ui, &mut self.state) {
                        self.send_command(cmd);
                    }
                }
                View::AddContact => {
                    if let Some(cmd) =
                        crate::views::add_contact::add_contact_view(ui, &mut self.state)
                    {
                        self.send_command(cmd);
                        // Refresh contacts after adding
                        self.send_command(GuiCommand::GetContacts);
                    }
                }
                View::Settings => {
                    let cmds = crate::views::settings::settings_view(ui, &mut self.state);
                    self.send_commands(cmds);
                }
                View::Groups => {
                    let cmds = crate::views::groups::groups_view(ui, &mut self.state);
                    self.send_commands(cmds);
                }
                View::GroupChat => {
                    if let Some(cmd) = crate::views::groups::group_chat_view(ui, &mut self.state) {
                        self.send_command(cmd);
                    }
                }
                View::Transfers => {
                    crate::views::transfers::transfers_view(ui, &mut self.state);
                }
                View::Identity => {
                    if let Some(cmd) = crate::views::identity::identity_view(ui, &mut self.state) {
                        self.send_command(cmd);
                    }
                }
            }
        });
    }
}
