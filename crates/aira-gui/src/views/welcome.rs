//! Welcome / onboarding view.
//!
//! Rendered when the IPC bridge reports that no seed phrase is stored in
//! the OS keychain (first-run or post-reset). The user either generates a
//! new 24-word BIP-39 phrase or imports an existing one. On Continue, the
//! view emits `GuiCommand::CompleteOnboarding { phrase }`, which the bridge
//! forwards to `keychain::store_seed_phrase` and then the daemon spawn.

use egui::{Align, Layout, RichText, Ui};

use crate::ipc::GuiCommand;
use crate::onboarding::{OnboardingMode, OnboardingState};
use crate::theme;

/// Render the welcome flow. Returns a `GuiCommand` when the user submits a
/// phrase (either generated or imported).
pub fn welcome_view(ui: &mut Ui, state: &mut OnboardingState) -> Option<GuiCommand> {
    match state.mode {
        OnboardingMode::Welcome => render_welcome(ui, state),
        OnboardingMode::NewIdentity => render_new_identity(ui, state),
        OnboardingMode::Import => render_import(ui, state),
    }
}

fn render_welcome(ui: &mut Ui, state: &mut OnboardingState) -> Option<GuiCommand> {
    ui.vertical_centered(|ui| {
        ui.add_space(60.0);
        ui.label(
            RichText::new("Welcome to Aira")
                .size(28.0)
                .color(theme::TEXT_PRIMARY)
                .strong(),
        );
        ui.add_space(8.0);
        ui.label(
            RichText::new("Post-quantum P2P messenger")
                .size(theme::FONT_BODY)
                .color(theme::TEXT_SECONDARY),
        );
        ui.add_space(theme::PANEL_PADDING * 3.0);

        let button_width = 260.0;
        let button_height = 52.0;

        if ui
            .add_sized(
                [button_width, button_height],
                egui::Button::new(
                    RichText::new("Create new identity")
                        .size(theme::FONT_BODY)
                        .color(theme::TEXT_PRIMARY)
                        .strong(),
                )
                .fill(theme::ACCENT),
            )
            .clicked()
        {
            state.generate();
        }

        ui.add_space(theme::ITEM_GAP * 4.0);

        if ui
            .add_sized(
                [button_width, button_height],
                egui::Button::new(
                    RichText::new("Import existing phrase")
                        .size(theme::FONT_BODY)
                        .color(theme::TEXT_PRIMARY),
                )
                .fill(theme::BG_CARD),
            )
            .clicked()
        {
            state.switch_to_import();
        }

        ui.add_space(theme::PANEL_PADDING * 2.0);
        ui.label(
            RichText::new("Your identity is a 24-word phrase. It's stored in your OS keychain.")
                .size(theme::FONT_SMALL)
                .color(theme::TEXT_MUTED),
        );
    });

    None
}

fn render_new_identity(ui: &mut Ui, state: &mut OnboardingState) -> Option<GuiCommand> {
    let mut command = None;

    ui.vertical_centered(|ui| {
        ui.add_space(24.0);
        ui.label(
            RichText::new("Your seed phrase")
                .size(22.0)
                .color(theme::TEXT_PRIMARY)
                .strong(),
        );
        ui.add_space(6.0);
        ui.label(
            RichText::new("Write these 24 words down and keep them safe.")
                .size(theme::FONT_SMALL)
                .color(theme::TEXT_SECONDARY),
        );
        ui.label(
            RichText::new("Anyone with this phrase can access your account.")
                .size(theme::FONT_SMALL)
                .color(theme::DANGER),
        );
        ui.add_space(theme::PANEL_PADDING);
    });

    let phrase_text = state
        .generated_phrase
        .as_ref()
        .map(|z| z.as_str().to_string())
        .unwrap_or_default();

    egui::Frame::none()
        .fill(theme::BG_CARD)
        .rounding(8.0)
        .inner_margin(egui::Margin::same(theme::CARD_PADDING * 1.5))
        .show(ui, |ui| {
            // Lay the 24 words out in a 4-column grid for readability.
            let words: Vec<&str> = phrase_text.split_whitespace().collect();
            egui::Grid::new("seed_phrase_grid")
                .num_columns(4)
                .spacing([18.0, 10.0])
                .show(ui, |ui| {
                    for (i, word) in words.iter().enumerate() {
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(format!("{:>2}.", i + 1))
                                    .size(theme::FONT_SMALL)
                                    .color(theme::TEXT_MUTED)
                                    .monospace(),
                            );
                            ui.label(
                                RichText::new(*word)
                                    .size(theme::FONT_BODY)
                                    .color(theme::TEXT_PRIMARY)
                                    .monospace(),
                            );
                        });
                        if (i + 1) % 4 == 0 {
                            ui.end_row();
                        }
                    }
                });
        });

    ui.add_space(theme::ITEM_GAP * 4.0);

    ui.horizontal(|ui| {
        if ui.button("Copy to clipboard").clicked() {
            ui.output_mut(|o| o.copied_text.clone_from(&phrase_text));
        }
        if ui.button("Regenerate").clicked() {
            state.generate();
        }
    });

    ui.add_space(theme::PANEL_PADDING);

    ui.checkbox(
        &mut state.written_down_confirmed,
        "I have written this phrase down and stored it safely",
    );

    ui.add_space(theme::PANEL_PADDING);

    ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
        if ui.button("◂ Back").clicked() {
            state.back_to_welcome();
        }
        ui.add_space(theme::PANEL_PADDING);

        let enabled = state.can_continue_new();
        let button = egui::Button::new(
            RichText::new("Continue")
                .size(theme::FONT_BODY)
                .color(theme::TEXT_PRIMARY)
                .strong(),
        )
        .fill(if enabled {
            theme::ACCENT
        } else {
            theme::BG_CARD
        });
        if ui.add_enabled(enabled, button).clicked() {
            if let Some(phrase) = state.take_generated() {
                command = Some(GuiCommand::CompleteOnboarding { phrase });
                // Reset state — the bridge will advance us past onboarding.
                state.back_to_welcome();
            }
        }
    });

    command
}

fn render_import(ui: &mut Ui, state: &mut OnboardingState) -> Option<GuiCommand> {
    let mut command = None;

    ui.vertical_centered(|ui| {
        ui.add_space(24.0);
        ui.label(
            RichText::new("Import existing phrase")
                .size(22.0)
                .color(theme::TEXT_PRIMARY)
                .strong(),
        );
        ui.add_space(6.0);
        ui.label(
            RichText::new("Paste your 24-word BIP-39 phrase below.")
                .size(theme::FONT_SMALL)
                .color(theme::TEXT_SECONDARY),
        );
        ui.add_space(theme::PANEL_PADDING);
    });

    egui::Frame::none()
        .fill(theme::BG_INPUT)
        .rounding(6.0)
        .inner_margin(egui::Margin::same(theme::CARD_PADDING))
        .show(ui, |ui| {
            ui.add_sized(
                [ui.available_width(), 100.0],
                egui::TextEdit::multiline(&mut state.import_input)
                    .hint_text("word1 word2 word3 ...")
                    .font(egui::TextStyle::Monospace),
            );
        });

    if let Some(err) = state.validation_error.as_ref() {
        ui.add_space(theme::ITEM_GAP * 2.0);
        ui.label(
            RichText::new(err)
                .size(theme::FONT_SMALL)
                .color(theme::DANGER),
        );
    }

    ui.add_space(theme::PANEL_PADDING);

    ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
        if ui.button("◂ Back").clicked() {
            state.back_to_welcome();
        }
        ui.add_space(theme::PANEL_PADDING);

        let button = egui::Button::new(
            RichText::new("Validate & Continue")
                .size(theme::FONT_BODY)
                .color(theme::TEXT_PRIMARY)
                .strong(),
        )
        .fill(theme::ACCENT);
        if ui.add(button).clicked() {
            if let Some(phrase) = state.validate_import() {
                command = Some(GuiCommand::CompleteOnboarding { phrase });
                state.back_to_welcome();
            }
        }
    });

    ui.add_space(theme::PANEL_PADDING);
    ui.label(
        RichText::new("Note: the daemon will derive your keys from this phrase (~1-3s).")
            .size(theme::FONT_SMALL)
            .color(theme::TEXT_MUTED),
    );

    command
}
