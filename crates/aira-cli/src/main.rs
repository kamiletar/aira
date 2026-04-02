//! aira — CLI client (ratatui TUI).
//!
//! Thin client that communicates with aira-daemon via IPC.
//! All cryptography and networking happens in the daemon.
//!
//! See SPEC.md §9 for the CLI specification and command list.

#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use std::io;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use aira_daemon::types::{DaemonRequest, DaemonResponse};

mod app;
mod commands;
mod ipc;
mod notifications;
mod ui;

use app::{App, Focus, InputMode};
use commands::CliCommand;
use ipc::DaemonClient;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("AIRA_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("aira=info")),
        )
        .with_writer(std::io::stderr)
        .init();

    // Connect to daemon
    let (client, mut event_rx) = match DaemonClient::connect().await {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!("Is the aira-daemon running?");
            std::process::exit(1);
        }
    };

    // Initialize app state
    let mut app = App::new();

    // Fetch initial data from daemon
    if let Ok(DaemonResponse::Contacts(contacts)) =
        client.request(&DaemonRequest::GetContacts).await
    {
        app.contacts = contacts;
    }
    if let Ok(DaemonResponse::MyAddress(addr)) = client.request(&DaemonRequest::GetMyAddress).await
    {
        app.my_address = addr;
    }

    // Load history for first contact
    if let Some(contact) = app.contacts.first() {
        let pk = contact.pubkey.clone();
        if let Ok(DaemonResponse::History(history)) = client
            .request(&DaemonRequest::GetHistory {
                contact: pk.clone(),
                limit: 100,
            })
            .await
        {
            app.set_history(pk, &history);
        }
        app.focus = Focus::Chat;
    }

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Install panic hook to restore terminal
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic| {
        let _ = disable_raw_mode();
        let _ = io::stdout().execute(LeaveAlternateScreen);
        original_hook(panic);
    }));

    // Main event loop
    let tick_rate = Duration::from_millis(250);

    while app.running {
        terminal.draw(|f| ui::draw(f, &app))?;

        tokio::select! {
            _ = tokio::task::spawn_blocking({
                let tick = tick_rate;
                move || event::poll(tick)
            }) => {
                while event::poll(Duration::ZERO)? {
                    if let Event::Key(key) = event::read()? {
                        handle_key_event(&mut app, &client, key).await?;
                    }
                }
            }
            Some(daemon_event) = event_rx.recv() => {
                if let aira_daemon::types::DaemonEvent::MessageReceived { ref from, ref payload } = daemon_event {
                    let contact_name = app.contact_alias(from);
                    let preview = String::from_utf8_lossy(
                        &payload[..payload.len().min(100)]
                    ).to_string();
                    let is_current = app.current_contact_pubkey() == Some(from.as_slice());
                    if !is_current {
                        notifications::notify_message(&contact_name, &preview, false);
                    }
                }
                app.handle_event(daemon_event);
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;

    Ok(())
}

/// Handle a keyboard event.
async fn handle_key_event(app: &mut App, client: &DaemonClient, key: KeyEvent) -> Result<()> {
    match (key.modifiers, key.code) {
        (KeyModifiers::CONTROL, KeyCode::Char('c' | 'q')) => {
            app.running = false;
            return Ok(());
        }
        (KeyModifiers::CONTROL, KeyCode::Char('w')) => {
            app.toggle_focus();
            return Ok(());
        }
        _ => {}
    }

    match app.focus {
        Focus::Contacts => handle_contacts_key(app, client, key).await,
        Focus::Chat => handle_chat_key(app, client, key).await,
    }
}

/// Handle key events in the contacts panel.
async fn handle_contacts_key(app: &mut App, client: &DaemonClient, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            app.prev_contact();
            load_history_for_current(app, client).await;
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.next_contact();
            load_history_for_current(app, client).await;
        }
        KeyCode::Enter | KeyCode::Right => {
            app.focus = Focus::Chat;
        }
        KeyCode::Char('q') => {
            app.running = false;
        }
        _ => {}
    }
    Ok(())
}

/// Handle key events in the chat panel.
async fn handle_chat_key(app: &mut App, client: &DaemonClient, key: KeyEvent) -> Result<()> {
    match (key.modifiers, key.code) {
        (_, KeyCode::Esc) => {
            if app.mode == InputMode::Normal {
                app.focus = Focus::Contacts;
            } else {
                app.mode = InputMode::Normal;
                app.input.clear();
                app.input_cursor = 0;
            }
        }
        (KeyModifiers::ALT, KeyCode::Enter) => {
            app.input.insert(app.input_cursor, '\n');
            app.input_cursor += 1;
        }
        (_, KeyCode::Enter) => {
            let input = app.input.trim().to_string();
            if !input.is_empty() {
                match commands::parse(&input) {
                    Ok(CliCommand::Message(text)) => {
                        if let Some(req) = app.build_send_request() {
                            if let Ok(DaemonResponse::Ok) = client.request(&req).await {
                                app.add_sent_message(&text);
                            }
                        }
                    }
                    Ok(cmd) => {
                        execute_command(app, client, cmd).await?;
                    }
                    Err(e) => {
                        app.set_status(e);
                    }
                }
                app.input.clear();
                app.input_cursor = 0;
            }
        }
        (_, KeyCode::Tab) => {
            let candidates = commands::completions(&app.input);
            if candidates.len() == 1 {
                app.input = format!("{} ", candidates[0]);
                app.input_cursor = app.input.len();
            }
        }
        (_, KeyCode::Up) => {
            if app.input.is_empty() {
                if let Some(pk) = app.current_contact_pubkey().map(<[u8]>::to_vec) {
                    if let Some(msgs) = app.messages.get(&pk) {
                        if let Some(last_self) = msgs.iter().rev().find(|m| m.is_self) {
                            app.mode = InputMode::Editing(last_self.id);
                            app.input.clone_from(&last_self.text);
                            app.input_cursor = app.input.len();
                        }
                    }
                }
            } else {
                app.scroll_offset = app.scroll_offset.saturating_add(1);
            }
        }
        (_, KeyCode::Down) => {
            app.scroll_offset = app.scroll_offset.saturating_sub(1);
        }
        (_, KeyCode::Backspace) => {
            if app.input_cursor > 0 {
                app.input_cursor -= 1;
                app.input.remove(app.input_cursor);
            }
        }
        (_, KeyCode::Delete) => {
            if app.input_cursor < app.input.len() {
                app.input.remove(app.input_cursor);
            }
        }
        (_, KeyCode::Left) => {
            app.input_cursor = app.input_cursor.saturating_sub(1);
        }
        (_, KeyCode::Right) => {
            if app.input_cursor < app.input.len() {
                app.input_cursor += 1;
            }
        }
        (_, KeyCode::Home) => {
            app.input_cursor = 0;
        }
        (_, KeyCode::End) => {
            app.input_cursor = app.input.len();
        }
        (KeyModifiers::NONE | KeyModifiers::SHIFT, KeyCode::Char(c)) => {
            app.input.insert(app.input_cursor, c);
            app.input_cursor += 1;
        }
        _ => {}
    }
    Ok(())
}

/// Execute a parsed CLI command.
#[allow(clippy::too_many_lines)]
async fn execute_command(app: &mut App, client: &DaemonClient, cmd: CliCommand) -> Result<()> {
    match cmd {
        CliCommand::Add { pubkey, alias } => {
            let pk_bytes = hex::decode(&pubkey).unwrap_or_else(|_| pubkey.as_bytes().to_vec());
            let alias_str = alias.unwrap_or_else(|| pubkey[..8.min(pubkey.len())].to_string());
            match client
                .request(&DaemonRequest::AddContact {
                    pubkey: pk_bytes,
                    alias: alias_str,
                })
                .await
            {
                Ok(DaemonResponse::Ok) => {
                    if let Ok(DaemonResponse::Contacts(contacts)) =
                        client.request(&DaemonRequest::GetContacts).await
                    {
                        app.contacts = contacts;
                    }
                    app.set_status("Contact added.");
                }
                Ok(DaemonResponse::Error(e)) => app.set_status(format!("Error: {e}")),
                _ => {}
            }
        }
        CliCommand::File { path } => {
            if let Some(pk) = app.current_contact_pubkey().map(<[u8]>::to_vec) {
                match client
                    .request(&DaemonRequest::SendFile { to: pk, path })
                    .await
                {
                    Ok(DaemonResponse::Ok) => app.set_status("File transfer started."),
                    Ok(DaemonResponse::Error(e)) => app.set_status(format!("Error: {e}")),
                    _ => {}
                }
            } else {
                app.set_status("No contact selected.");
            }
        }
        CliCommand::MyKey => {
            let hex_key: String = app.my_address.iter().fold(String::new(), |mut acc, b| {
                use std::fmt::Write;
                let _ = write!(acc, "{b:02x}");
                acc
            });
            app.set_status(format!("Your key: {hex_key}"));
        }
        CliCommand::Info => {
            app.set_status(format!(
                "Aira v{} | Contacts: {} | Online: {}",
                env!("CARGO_PKG_VERSION"),
                app.contacts.len(),
                app.online.len(),
            ));
        }
        CliCommand::Disappear { time } => {
            if let Some(pk) = app.current_contact_pubkey().map(<[u8]>::to_vec) {
                let ttl_secs = parse_ttl(&time);
                match client
                    .request(&DaemonRequest::SetTtl {
                        contact: pk,
                        ttl_secs,
                    })
                    .await
                {
                    Ok(DaemonResponse::Ok) => {
                        if ttl_secs.is_some() {
                            app.set_status(format!("Disappearing messages: {time}"));
                        } else {
                            app.set_status("Disappearing messages disabled.");
                        }
                    }
                    Ok(DaemonResponse::Error(e)) => app.set_status(format!("Error: {e}")),
                    _ => {}
                }
            }
        }
        CliCommand::Export { path } => {
            let export_path = path.unwrap_or_else(|| {
                let home = dirs::home_dir().unwrap_or_default();
                home.join("aira-backup.aira")
            });
            match client
                .request(&DaemonRequest::ExportBackup {
                    path: export_path.clone(),
                    include_messages: true,
                })
                .await
            {
                Ok(DaemonResponse::Ok) => {
                    app.set_status(format!("Backup exported: {}", export_path.display()));
                }
                Ok(DaemonResponse::Error(e)) => app.set_status(format!("Error: {e}")),
                _ => {}
            }
        }
        CliCommand::Import { path } => {
            match client.request(&DaemonRequest::ImportBackup { path }).await {
                Ok(DaemonResponse::Ok) => app.set_status("Backup imported successfully."),
                Ok(DaemonResponse::Error(e)) => app.set_status(format!("Error: {e}")),
                _ => {}
            }
        }
        CliCommand::Block { contact } => {
            if let Some(pk) = find_contact_pk(app, &contact) {
                match client
                    .request(&DaemonRequest::RemoveContact { pubkey: pk })
                    .await
                {
                    Ok(DaemonResponse::Ok) => app.set_status(format!("{contact} blocked.")),
                    Ok(DaemonResponse::Error(e)) => app.set_status(format!("Error: {e}")),
                    _ => {}
                }
            } else {
                app.set_status(format!("Contact not found: {contact}"));
            }
        }
        CliCommand::Unblock { contact } => {
            app.set_status(format!("{contact} unblocked."));
        }
        CliCommand::DeleteAccount => {
            app.set_status("Type YES to confirm account deletion:");
        }
        CliCommand::Me { action } => {
            if let Some(pk) = app.current_contact_pubkey().map(<[u8]>::to_vec) {
                let text = format!("/me {action}");
                if let Ok(DaemonResponse::Ok) = client
                    .request(&DaemonRequest::SendMessage {
                        to: pk,
                        text: text.clone(),
                    })
                    .await
                {
                    app.add_sent_message(&format!("* {action}"));
                }
            }
        }
        CliCommand::Transport { mode } => {
            app.set_status(format!("Transport mode: {mode} (M7+)"));
        }
        CliCommand::Verify { .. } => {
            app.set_status("Safety Number verification (coming in M6)");
        }
        CliCommand::Mute { contact, duration } => {
            let dur = duration.as_deref().unwrap_or("indefinitely");
            app.set_status(format!("{contact} muted {dur}."));
        }
        CliCommand::Profile { field } => {
            let f = field.as_deref().unwrap_or("(no field)");
            app.set_status(format!("Profile: {f}"));
        }
        CliCommand::Lang { code } => {
            app.set_status(format!("Language set to: {code}"));
        }
        CliCommand::Search { query } => {
            app.set_status(format!("Search: {query} (local search coming soon)"));
        }
        CliCommand::Message(_) => {}
    }
    Ok(())
}

/// Load message history for the currently selected contact.
async fn load_history_for_current(app: &mut App, client: &DaemonClient) {
    if let Some(contact) = app.current_contact() {
        let pk = contact.pubkey.clone();
        if let Ok(DaemonResponse::History(history)) = client
            .request(&DaemonRequest::GetHistory {
                contact: pk.clone(),
                limit: 100,
            })
            .await
        {
            app.set_history(pk, &history);
        }
    }
}

/// Find a contact's pubkey by alias.
fn find_contact_pk(app: &App, alias: &str) -> Option<Vec<u8>> {
    app.contacts
        .iter()
        .find(|c| c.alias.eq_ignore_ascii_case(alias))
        .map(|c| c.pubkey.clone())
}

/// Parse a TTL string like "30s", "5m", "1h", "1d", "7d", "off" into seconds.
fn parse_ttl(time: &str) -> Option<u64> {
    match time.to_lowercase().as_str() {
        "off" | "0" | "none" => None,
        s => {
            let (num, mult) = if let Some(n) = s.strip_suffix('s') {
                (n, 1u64)
            } else if let Some(n) = s.strip_suffix('m') {
                (n, 60)
            } else if let Some(n) = s.strip_suffix('h') {
                (n, 3600)
            } else if let Some(n) = s.strip_suffix('d') {
                (n, 86400)
            } else {
                (s, 1)
            };
            num.parse::<u64>().ok().map(|n| n * mult)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ttl_variants() {
        assert_eq!(parse_ttl("30s"), Some(30));
        assert_eq!(parse_ttl("5m"), Some(300));
        assert_eq!(parse_ttl("1h"), Some(3600));
        assert_eq!(parse_ttl("1d"), Some(86400));
        assert_eq!(parse_ttl("7d"), Some(604_800));
        assert_eq!(parse_ttl("off"), None);
        assert_eq!(parse_ttl("none"), None);
    }
}
