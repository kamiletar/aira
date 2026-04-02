//! System tray integration via `tray-icon`.
//!
//! The tray icon is created on the main thread before eframe launches.
//! Menu events are polled in the `update()` loop.

use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{TrayIcon, TrayIconBuilder};

/// Tray menu item IDs.
pub struct TrayMenuIds {
    pub open_id: tray_icon::menu::MenuId,
    pub quit_id: tray_icon::menu::MenuId,
}

/// Actions from the tray menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    /// User clicked "Open" — show the main window.
    Open,
    /// User clicked "Quit" — exit the application.
    Quit,
}

/// Build the system tray icon with a context menu.
///
/// Returns the `TrayIcon` (must be kept alive) and the menu item IDs
/// for event matching.
///
/// # Errors
///
/// Returns an error string if the tray icon cannot be created.
pub fn build_tray() -> Result<(TrayIcon, TrayMenuIds), String> {
    let open_item = MenuItem::new("Open Aira", true, None);
    let quit_item = MenuItem::new("Quit", true, None);

    let open_id = open_item.id().clone();
    let quit_id = quit_item.id().clone();

    let menu = Menu::new();
    menu.append(&open_item).map_err(|e| e.to_string())?;
    menu.append(&quit_item).map_err(|e| e.to_string())?;

    // Create a simple 16x16 blue icon
    let icon = create_default_icon();

    let tray = TrayIconBuilder::new()
        .with_tooltip("Aira — Post-quantum Messenger")
        .with_menu(Box::new(menu))
        .with_icon(icon)
        .build()
        .map_err(|e| e.to_string())?;

    let ids = TrayMenuIds { open_id, quit_id };

    Ok((tray, ids))
}

/// Poll for tray menu events (non-blocking).
///
/// Should be called from the `update()` loop.
pub fn poll_tray_event(ids: &TrayMenuIds) -> Option<TrayAction> {
    if let Ok(event) = MenuEvent::receiver().try_recv() {
        if event.id == ids.open_id {
            return Some(TrayAction::Open);
        }
        if event.id == ids.quit_id {
            return Some(TrayAction::Quit);
        }
    }
    None
}

/// Create a simple 16x16 RGBA icon (solid accent blue).
fn create_default_icon() -> tray_icon::Icon {
    let size = 16;
    let mut rgba = Vec::with_capacity(size * size * 4);
    for _ in 0..size * size {
        // Accent blue: rgb(88, 166, 255)
        rgba.extend_from_slice(&[88, 166, 255, 255]);
    }
    tray_icon::Icon::from_rgba(rgba, size as u32, size as u32).expect("valid 16x16 icon")
}
