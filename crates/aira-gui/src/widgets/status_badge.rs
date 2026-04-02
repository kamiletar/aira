//! Online/offline status indicator — a small colored circle.

use egui::{Ui, Vec2};

use crate::theme;

/// Draw a status badge (colored circle) indicating online/offline.
pub fn status_badge(ui: &mut Ui, online: bool) {
    let color = if online {
        theme::STATUS_ONLINE
    } else {
        theme::STATUS_OFFLINE
    };
    let (rect, _response) = ui.allocate_exact_size(Vec2::splat(8.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), 4.0, color);
}
