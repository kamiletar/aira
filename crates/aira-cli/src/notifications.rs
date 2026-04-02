//! Desktop notifications via `notify-rust`.
//!
//! Shows OS-native notifications for incoming messages.
//! Supports privacy mode (hides message content).
//! See SPEC.md §9.

/// Maximum length for notification body text.
const MAX_PREVIEW_LEN: usize = 100;

/// Show a desktop notification for an incoming message.
///
/// In privacy mode, the message body is hidden and only
/// "New message" is shown.
pub fn notify_message(contact_name: &str, text: &str, privacy_mode: bool) {
    let body = if privacy_mode {
        "New message".to_string()
    } else {
        truncate(text, MAX_PREVIEW_LEN)
    };

    let summary = format!("Aira — {contact_name}");

    if let Err(e) = notify_rust::Notification::new()
        .appname("Aira")
        .summary(&summary)
        .body(&body)
        .show()
    {
        tracing::warn!("Desktop notification failed: {e}");
    }
}

/// Truncate a string to `max_len` characters, appending "..." if needed.
fn truncate(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max_len.saturating_sub(3)).collect();
        format!("{truncated}...")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_short_string() {
        assert_eq!(truncate("hello", 100), "hello");
    }

    #[test]
    fn truncate_long_string() {
        let long = "a".repeat(200);
        let result = truncate(&long, 100);
        assert!(result.len() <= 100);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn truncate_exact_length() {
        let exact = "a".repeat(100);
        assert_eq!(truncate(&exact, 100), exact);
    }
}
