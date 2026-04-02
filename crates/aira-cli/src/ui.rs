//! ratatui TUI: contacts list + chat window + input bar.
//!
//! Two-pane layout: contacts (25% left) + chat (75% right).
//! See SPEC.md §9 for the layout specification.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame,
};

use crate::app::{App, DisplayMessage, Focus, InputMode};

/// Render the full TUI frame.
pub fn draw(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(25), Constraint::Percentage(75)])
        .split(frame.area());

    draw_contacts(frame, app, chunks[0]);
    draw_chat(frame, app, chunks[1]);
}

/// Render the contacts panel (left side): contacts + groups.
fn draw_contacts(frame: &mut Frame, app: &App, area: Rect) {
    let is_focused = app.focus == Focus::Contacts;

    let mut items: Vec<ListItem> = Vec::new();

    // Individual contacts
    for (i, contact) in app.contacts.iter().enumerate() {
        let online = if app.is_online(&contact.pubkey) {
            " \u{25cf}" // ● filled circle
        } else {
            ""
        };

        let unread = app
            .unread
            .get(&contact.pubkey)
            .map_or(String::new(), |n| format!(" ({n})"));

        let style = if app.active_group.is_none() && i == app.selected_contact {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };

        items.push(ListItem::new(Line::from(vec![
            Span::styled(&contact.alias, style),
            Span::styled(online, Style::default().fg(Color::Green)),
            Span::styled(unread, Style::default().fg(Color::Red)),
        ])));
    }

    // Groups section
    if !app.groups.is_empty() {
        items.push(ListItem::new(Line::from(Span::styled(
            "\u{2500}\u{2500} Groups \u{2500}\u{2500}",
            Style::default().fg(Color::DarkGray),
        ))));

        for group in &app.groups {
            let unread = app
                .group_unread
                .get(&group.id)
                .map_or(String::new(), |n| format!(" ({n})"));

            let style = if app.active_group == Some(group.id) {
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Magenta)
            };

            items.push(ListItem::new(Line::from(vec![
                Span::styled(format!("# {}", group.name), style),
                Span::styled(unread, Style::default().fg(Color::Red)),
            ])));
        }
    }

    let border_style = if is_focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let contacts = List::new(items).block(
        Block::default()
            .title(" Contacts ")
            .borders(Borders::ALL)
            .border_style(border_style),
    );

    frame.render_widget(contacts, area);
}

/// Render the chat panel (right side): messages + input bar.
fn draw_chat(frame: &mut Frame, app: &App, area: Rect) {
    let is_focused = app.focus == Focus::Chat;

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),    // messages
            Constraint::Length(3), // input bar
            Constraint::Length(1), // status bar
        ])
        .split(area);

    draw_messages(frame, app, chunks[0], is_focused);
    draw_input(frame, app, chunks[1], is_focused);
    draw_status_bar(frame, app, chunks[2]);
}

/// Render the message history.
fn draw_messages(frame: &mut Frame, app: &App, area: Rect, is_focused: bool) {
    let title = if let Some(gid) = app.active_group {
        app.groups
            .iter()
            .find(|g| g.id == gid)
            .map_or(" Group Chat ".to_string(), |g| {
                format!(" # {} ({} members) ", g.name, g.members.len())
            })
    } else {
        app.current_contact().map_or(" Chat ".to_string(), |c| {
            let status = if app.is_online(&c.pubkey) {
                " [online]"
            } else {
                ""
            };
            format!(" {} {status} ", c.alias)
        })
    };

    let messages = if let Some(gid) = app.active_group {
        app.group_messages
            .get(&gid)
            .map_or(&[] as &[DisplayMessage], |v| v.as_slice())
    } else {
        app.current_messages()
    };

    let lines: Vec<Line> = if messages.is_empty() {
        vec![Line::from(Span::styled(
            "No messages yet.",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        messages.iter().map(format_message).collect()
    };

    // Show file transfer progress if any
    let mut all_lines = lines;
    for progress in app.file_transfers.values() {
        let pct = if progress.total > 0 {
            (progress.bytes_sent * 100) / progress.total
        } else {
            0
        };
        all_lines.push(Line::from(Span::styled(
            format!("[transfer: {pct}%]"),
            Style::default().fg(Color::Cyan),
        )));
    }

    let border_style = if is_focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let paragraph = Paragraph::new(all_lines)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(border_style),
        )
        .wrap(Wrap { trim: false })
        .scroll((app.scroll_offset, 0));

    frame.render_widget(paragraph, area);
}

/// Render the input bar.
fn draw_input(frame: &mut Frame, app: &App, area: Rect, is_focused: bool) {
    let title = match &app.mode {
        InputMode::Normal => " Message ",
        InputMode::Editing(_) => " Editing (Esc to cancel) ",
    };

    let border_style = if is_focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let input = Paragraph::new(app.input.as_str())
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(border_style),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(input, area);

    // Show cursor in the input field
    if is_focused {
        #[allow(clippy::cast_possible_truncation)]
        let cursor_x = area.x + 1 + app.input_cursor as u16;
        frame.set_cursor_position((cursor_x, area.y + 1));
    }
}

/// Render the status bar.
fn draw_status_bar(frame: &mut Frame, app: &App, area: Rect) {
    let status = app
        .status_message
        .as_deref()
        .unwrap_or("Ctrl+W: switch | Tab: complete | Enter: send | /help");

    let bar = Paragraph::new(Line::from(Span::styled(
        status,
        Style::default().fg(Color::DarkGray),
    )));

    frame.render_widget(bar, area);
}

/// Format a single `DisplayMessage` as a `Line`.
fn format_message(msg: &DisplayMessage) -> Line<'static> {
    let time = format_timestamp(msg.timestamp_micros);

    let sender = if msg.is_self { "You" } else { ">" };

    let status = if msg.is_self && !msg.status.is_empty() {
        format!(" {}", msg.status)
    } else {
        String::new()
    };

    let style = if msg.is_self {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::White)
    };

    Line::from(vec![
        Span::styled(format!("[{time}] "), Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{sender}: "), style.add_modifier(Modifier::BOLD)),
        Span::styled(msg.text.clone(), style),
        Span::styled(status, Style::default().fg(Color::Green)),
    ])
}

/// Format a microsecond timestamp to HH:MM.
fn format_timestamp(micros: u64) -> String {
    let secs = micros / 1_000_000;
    let hours = (secs / 3600) % 24;
    let minutes = (secs % 3600) / 60;
    format!("{hours:02}:{minutes:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_timestamp_basic() {
        // 10:42:00 UTC = 10*3600 + 42*60 = 38520 seconds
        let micros = 38_520_000_000u64;
        assert_eq!(format_timestamp(micros), "10:42");
    }

    #[test]
    fn format_timestamp_midnight() {
        assert_eq!(format_timestamp(0), "00:00");
    }

    #[test]
    fn format_message_self() {
        let msg = DisplayMessage {
            id: [0; 16],
            is_self: true,
            text: "hello".into(),
            timestamp_micros: 38_520_000_000,
            status: "[ok]",
            ttl_secs: None,
            reply_to: None,
        };
        let line = format_message(&msg);
        let text: String = line.spans.iter().map(|s| s.content.to_string()).collect();
        assert!(text.contains("You"));
        assert!(text.contains("hello"));
        assert!(text.contains("[ok]"));
    }
}
