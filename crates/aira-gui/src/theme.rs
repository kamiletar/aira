//! Visual theme constants for the Aira desktop GUI.
//!
//! Provides a consistent color palette, spacing, and font sizing
//! for all views and widgets.

use egui::Color32;

// ─── Colors ─────────────────────────────────────────────────────────────────

/// Dark background for the main window.
pub const BG_PRIMARY: Color32 = Color32::from_rgb(24, 24, 32);
/// Slightly lighter background for panels (contacts sidebar).
pub const BG_SECONDARY: Color32 = Color32::from_rgb(32, 32, 44);
/// Card/item background (contact row, message bubble).
pub const BG_CARD: Color32 = Color32::from_rgb(40, 40, 56);
/// Accent color (buttons, selected items, links).
pub const ACCENT: Color32 = Color32::from_rgb(88, 166, 255);
/// Accent hover.
pub const ACCENT_HOVER: Color32 = Color32::from_rgb(110, 180, 255);
/// Sent message bubble.
pub const BUBBLE_SENT: Color32 = Color32::from_rgb(50, 80, 130);
/// Received message bubble.
pub const BUBBLE_RECV: Color32 = Color32::from_rgb(48, 48, 64);
/// Primary text color.
pub const TEXT_PRIMARY: Color32 = Color32::from_rgb(230, 230, 240);
/// Secondary text (timestamps, metadata).
pub const TEXT_SECONDARY: Color32 = Color32::from_rgb(140, 140, 160);
/// Muted text (placeholders).
pub const TEXT_MUTED: Color32 = Color32::from_rgb(90, 90, 110);
/// Online indicator.
pub const STATUS_ONLINE: Color32 = Color32::from_rgb(80, 200, 120);
/// Offline indicator.
pub const STATUS_OFFLINE: Color32 = Color32::from_rgb(100, 100, 120);
/// Error / destructive action.
pub const DANGER: Color32 = Color32::from_rgb(220, 60, 60);
/// Success / confirmation.
pub const SUCCESS: Color32 = Color32::from_rgb(80, 200, 120);
/// Unread badge background.
pub const BADGE_BG: Color32 = Color32::from_rgb(88, 166, 255);

// ─── Spacing ────────────────────────────────────────────────────────────────

/// Padding inside panels.
pub const PANEL_PADDING: f32 = 12.0;
/// Gap between items in a list.
pub const ITEM_GAP: f32 = 4.0;
/// Standard inner margin for cards.
pub const CARD_PADDING: f32 = 8.0;
/// Contact sidebar width.
pub const SIDEBAR_WIDTH: f32 = 260.0;
/// Message input area height.
pub const INPUT_HEIGHT: f32 = 48.0;

// ─── Font sizes ─────────────────────────────────────────────────────────────

/// Heading / contact name.
pub const FONT_HEADING: f32 = 16.0;
/// Normal body text.
pub const FONT_BODY: f32 = 14.0;
/// Small text (timestamps, metadata).
pub const FONT_SMALL: f32 = 11.0;
