//! Visual theme for the Aira desktop GUI.
//!
//! Provides a polished dark theme with custom `egui::Visuals`,
//! consistent color palette, spacing, font sizing, and helper utilities
//! for avatars and relative timestamps.

use egui::{
    epaint::Shadow, style::WidgetVisuals, Color32, FontData, FontDefinitions, FontFamily, Rounding,
    Stroke, Visuals,
};

// ─── Colors ─────────────────────────────────────────────────────────────────

// Backgrounds — subtle blue undertone for depth
/// Main window background.
pub const BG_PRIMARY: Color32 = Color32::from_rgb(18, 18, 26);
/// Panel / sidebar background.
pub const BG_SECONDARY: Color32 = Color32::from_rgb(24, 24, 36);
/// Card / item background.
pub const BG_CARD: Color32 = Color32::from_rgb(32, 32, 48);
/// Card hover state.
pub const BG_CARD_HOVER: Color32 = Color32::from_rgb(38, 38, 56);
/// Input field background.
pub const BG_INPUT: Color32 = Color32::from_rgb(26, 26, 40);

// Accent — soft blue
/// Primary accent (buttons, links, selected).
pub const ACCENT: Color32 = Color32::from_rgb(88, 145, 255);
/// Accent hover state.
pub const ACCENT_HOVER: Color32 = Color32::from_rgb(110, 165, 255);
/// Accent pressed/active state.
pub const ACCENT_ACTIVE: Color32 = Color32::from_rgb(70, 125, 230);
/// Subtle accent for backgrounds (selection highlight).
pub const ACCENT_SUBTLE: Color32 = Color32::from_rgb(88, 145, 255);

// Text — off-white to reduce eye strain (not pure white)
/// Primary text.
pub const TEXT_PRIMARY: Color32 = Color32::from_rgb(224, 224, 236);
/// Secondary text (timestamps, metadata).
pub const TEXT_SECONDARY: Color32 = Color32::from_rgb(140, 140, 165);
/// Muted text (placeholders, empty states).
pub const TEXT_MUTED: Color32 = Color32::from_rgb(85, 85, 110);

// Message bubbles
/// Sent message bubble.
pub const BUBBLE_SENT: Color32 = Color32::from_rgb(40, 70, 130);
/// Received message bubble.
pub const BUBBLE_RECV: Color32 = Color32::from_rgb(36, 36, 52);

// Status
/// Online indicator (soft green).
pub const STATUS_ONLINE: Color32 = Color32::from_rgb(72, 199, 115);
/// Offline indicator (dim).
pub const STATUS_OFFLINE: Color32 = Color32::from_rgb(80, 80, 100);
/// Error / destructive.
pub const DANGER: Color32 = Color32::from_rgb(235, 70, 70);
/// Success / confirmation.
pub const SUCCESS: Color32 = Color32::from_rgb(72, 199, 115);
/// Unread badge background.
pub const BADGE_BG: Color32 = Color32::from_rgb(88, 145, 255);

// Borders & separators
/// Subtle separator line.
pub const SEPARATOR: Color32 = Color32::from_rgb(44, 44, 60);
/// Widget border (inactive).
pub const BORDER: Color32 = Color32::from_rgb(50, 50, 68);
/// Widget border (focused).
pub const BORDER_FOCUS: Color32 = Color32::from_rgb(88, 145, 255);

// ─── Spacing ────────────────────────────────────────────────────────────────

/// Padding inside panels.
pub const PANEL_PADDING: f32 = 14.0;
/// Gap between items in a list.
pub const ITEM_GAP: f32 = 2.0;
/// Standard inner margin for cards.
pub const CARD_PADDING: f32 = 10.0;
/// Contact sidebar width.
pub const SIDEBAR_WIDTH: f32 = 280.0;
/// Message input area height.
pub const INPUT_HEIGHT: f32 = 44.0;
/// Avatar circle diameter.
pub const AVATAR_SIZE: f32 = 36.0;

// ─── Font sizes ─────────────────────────────────────────────────────────────

/// Page heading / large title.
pub const FONT_HEADING: f32 = 18.0;
/// Normal body text.
pub const FONT_BODY: f32 = 14.0;
/// Small text (timestamps, metadata, badges).
pub const FONT_SMALL: f32 = 12.0;
/// Monospace text (hex keys, fingerprints).
pub const FONT_MONO: f32 = 13.0;

// ─── Rounding ───────────────────────────────────────────────────────────────

/// Standard widget/card rounding.
pub const ROUNDING: f32 = 8.0;
/// Message bubble rounding.
pub const BUBBLE_ROUNDING: f32 = 14.0;
/// Small bubble rounding (consecutive messages).
pub const BUBBLE_ROUNDING_SMALL: f32 = 6.0;
/// Badge pill rounding.
pub const BADGE_ROUNDING: f32 = 10.0;
/// Input field rounding.
pub const INPUT_ROUNDING: f32 = 10.0;

// ─── Avatar colors ──────────────────────────────────────────────────────────

/// Palette of 8 avatar background colors, assigned by name hash.
const AVATAR_COLORS: [Color32; 8] = [
    Color32::from_rgb(88, 145, 255),  // blue
    Color32::from_rgb(255, 120, 100), // coral
    Color32::from_rgb(72, 199, 150),  // teal
    Color32::from_rgb(255, 175, 70),  // amber
    Color32::from_rgb(180, 120, 255), // purple
    Color32::from_rgb(255, 100, 160), // pink
    Color32::from_rgb(100, 200, 220), // cyan
    Color32::from_rgb(160, 210, 80),  // lime
];

/// Get a deterministic avatar color for a name.
#[must_use]
pub fn avatar_color(name: &str) -> Color32 {
    let hash = name.bytes().fold(0u32, |acc, b| {
        acc.wrapping_mul(31).wrapping_add(u32::from(b))
    });
    AVATAR_COLORS[(hash as usize) % AVATAR_COLORS.len()]
}

/// Get the initials (1-2 chars) from a name for the avatar.
#[must_use]
pub fn avatar_initials(name: &str) -> String {
    let mut chars = name.chars().filter(|c| c.is_alphanumeric());
    match (chars.next(), chars.next()) {
        (Some(a), Some(b)) => {
            let mut s = String::with_capacity(2);
            s.push(a.to_ascii_uppercase());
            s.push(b.to_ascii_lowercase());
            s
        }
        (Some(a), None) => a.to_ascii_uppercase().to_string(),
        _ => "?".to_string(),
    }
}

// ─── Relative time ──────────────────────────────────────────────────────────

/// Format a timestamp (micros since epoch) as a relative time string.
#[must_use]
pub fn relative_time(timestamp_micros: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64;

    let diff_secs = now.saturating_sub(timestamp_micros) / 1_000_000;

    if diff_secs < 60 {
        "now".to_string()
    } else if diff_secs < 3600 {
        format!("{}m", diff_secs / 60)
    } else if diff_secs < 86400 {
        format!("{}h", diff_secs / 3600)
    } else if diff_secs < 604_800 {
        format!("{}d", diff_secs / 86400)
    } else {
        format!("{}w", diff_secs / 604_800)
    }
}

// ─── Theme application ──────────────────────────────────────────────────────

/// Apply the full Aira visual theme to an egui context.
///
/// Call once per frame (or on init). Sets colors, rounding, spacing,
/// shadows, and widget styles for a polished dark appearance.
pub fn apply_theme(ctx: &egui::Context) {
    let mut visuals = Visuals::dark();

    // Window & panel backgrounds
    visuals.panel_fill = BG_PRIMARY;
    visuals.window_fill = BG_SECONDARY;
    visuals.window_rounding = Rounding::same(ROUNDING);
    visuals.window_shadow = Shadow {
        offset: [0.0, 4.0].into(),
        blur: 12.0,
        spread: 0.0,
        color: Color32::from_black_alpha(80),
    };
    visuals.window_stroke = Stroke::new(1.0, BORDER);

    // Faint background for frames/groups
    visuals.faint_bg_color = BG_SECONDARY;
    visuals.extreme_bg_color = BG_INPUT;

    // Selection
    visuals.selection.bg_fill = Color32::from_rgba_premultiplied(88, 145, 255, 50);
    visuals.selection.stroke = Stroke::new(1.0, ACCENT);

    // Hyperlink
    visuals.hyperlink_color = ACCENT;

    // Separator
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(0.5, SEPARATOR);

    // Text colors
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT_PRIMARY);

    // Widget styles — inactive
    visuals.widgets.inactive = WidgetVisuals {
        bg_fill: BG_CARD,
        weak_bg_fill: BG_CARD,
        bg_stroke: Stroke::new(0.5, BORDER),
        fg_stroke: Stroke::new(1.0, TEXT_PRIMARY),
        rounding: Rounding::same(ROUNDING),
        expansion: 0.0,
    };

    // Widget styles — hovered
    visuals.widgets.hovered = WidgetVisuals {
        bg_fill: BG_CARD_HOVER,
        weak_bg_fill: BG_CARD_HOVER,
        bg_stroke: Stroke::new(1.0, ACCENT),
        fg_stroke: Stroke::new(1.0, TEXT_PRIMARY),
        rounding: Rounding::same(ROUNDING),
        expansion: 1.0,
    };

    // Widget styles — active (pressed)
    visuals.widgets.active = WidgetVisuals {
        bg_fill: ACCENT_ACTIVE,
        weak_bg_fill: ACCENT_ACTIVE,
        bg_stroke: Stroke::new(1.0, ACCENT),
        fg_stroke: Stroke::new(1.0, Color32::WHITE),
        rounding: Rounding::same(ROUNDING),
        expansion: 0.0,
    };

    // Widget styles — open (combo box, etc.)
    visuals.widgets.open = WidgetVisuals {
        bg_fill: BG_CARD,
        weak_bg_fill: BG_CARD,
        bg_stroke: Stroke::new(1.0, ACCENT),
        fg_stroke: Stroke::new(1.0, TEXT_PRIMARY),
        rounding: Rounding::same(ROUNDING),
        expansion: 0.0,
    };

    // Scrollbar
    visuals.interact_cursor = None;
    visuals.resize_corner_size = 8.0;

    // Striped rows
    visuals.striped = false;

    ctx.set_visuals(visuals);

    // Spacing tweaks
    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(12.0, 6.0);
    style.spacing.window_margin = egui::Margin::same(PANEL_PADDING);
    style.spacing.scroll.bar_width = 6.0;
    style.spacing.scroll.floating = true;
    ctx.set_style(style);
}

/// Set up custom fonts for the application.
///
/// Call once at startup. Adds Inter as proportional and
/// JetBrains Mono as monospace font.
pub fn setup_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();

    // Embed Inter Regular (proportional)
    fonts.font_data.insert(
        "inter".to_owned(),
        FontData::from_static(include_bytes!("../assets/Inter-Regular.ttf")),
    );
    // Embed Inter SemiBold (for headings)
    fonts.font_data.insert(
        "inter-semibold".to_owned(),
        FontData::from_static(include_bytes!("../assets/Inter-SemiBold.ttf")),
    );
    // Embed JetBrains Mono (monospace for hex keys)
    fonts.font_data.insert(
        "jetbrains-mono".to_owned(),
        FontData::from_static(include_bytes!("../assets/JetBrainsMono-Regular.ttf")),
    );

    // Set Inter as primary proportional font (fallback to default)
    fonts
        .families
        .entry(FontFamily::Proportional)
        .or_default()
        .insert(0, "inter".to_owned());

    // Set JetBrains Mono as monospace
    fonts
        .families
        .entry(FontFamily::Monospace)
        .or_default()
        .insert(0, "jetbrains-mono".to_owned());

    ctx.set_fonts(fonts);
}
