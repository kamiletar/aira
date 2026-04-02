//! Message bubble widget — a styled card for sent/received messages.

use egui::{Align, Layout, RichText, Ui};

use crate::state::DisplayMessage;
use crate::theme;

/// Render a message bubble.
///
/// Sent messages are right-aligned with `BUBBLE_SENT` background.
/// Received messages are left-aligned with `BUBBLE_RECV` background.
pub fn message_bubble(ui: &mut Ui, msg: &DisplayMessage) {
    let bg = if msg.is_self {
        theme::BUBBLE_SENT
    } else {
        theme::BUBBLE_RECV
    };

    let align = if msg.is_self { Align::Max } else { Align::Min };

    ui.with_layout(Layout::top_down(align), |ui| {
        // Sender alias for received messages (group context)
        if !msg.is_self {
            if let Some(alias) = &msg.sender_alias {
                ui.label(
                    RichText::new(alias)
                        .size(theme::FONT_SMALL)
                        .color(theme::ACCENT),
                );
            }
        }

        egui::Frame::none()
            .fill(bg)
            .rounding(8.0)
            .inner_margin(egui::Margin::same(theme::CARD_PADDING))
            .show(ui, |ui| {
                ui.set_max_width(300.0);
                ui.label(
                    RichText::new(&msg.text)
                        .size(theme::FONT_BODY)
                        .color(theme::TEXT_PRIMARY),
                );

                // Timestamp
                let time = format_timestamp(msg.timestamp_micros);
                ui.label(
                    RichText::new(time)
                        .size(theme::FONT_SMALL)
                        .color(theme::TEXT_SECONDARY),
                );
            });
    });
}

/// Format a microsecond timestamp into HH:MM.
fn format_timestamp(micros: u64) -> String {
    let secs = micros / 1_000_000;
    let hours = (secs / 3600) % 24;
    let minutes = (secs / 60) % 60;
    format!("{hours:02}:{minutes:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_timestamp_midnight() {
        assert_eq!(format_timestamp(0), "00:00");
    }

    #[test]
    fn format_timestamp_afternoon() {
        // 14:30 = 14*3600 + 30*60 = 52200 seconds
        let micros = 52200 * 1_000_000;
        assert_eq!(format_timestamp(micros), "14:30");
    }
}
