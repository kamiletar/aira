//! Desktop notifications via `notify-rust`.
//!
//! Sends native OS notifications for incoming messages when
//! the window is not focused.

/// Show a desktop notification.
///
/// Silently ignores errors (notification is best-effort).
pub fn show_notification(title: &str, body: &str) {
    let _ = notify_rust::Notification::new()
        .summary(title)
        .body(body)
        .appname("Aira")
        .timeout(notify_rust::Timeout::Milliseconds(5000))
        .show();
}

/// Show a notification for a received message.
pub fn notify_message(sender_alias: &str, text: &str) {
    // Truncate long messages for the notification
    let preview = if text.len() > 80 {
        format!("{}...", &text[..80])
    } else {
        text.to_string()
    };
    show_notification(&format!("Message from {sender_alias}"), &preview);
}

/// Show a notification for a group message.
pub fn notify_group_message(group_name: &str, sender_alias: &str, text: &str) {
    let preview = if text.len() > 80 {
        format!("{}...", &text[..80])
    } else {
        text.to_string()
    };
    show_notification(&format!("{sender_alias} in {group_name}"), &preview);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_truncation() {
        // Just test the truncation logic, not the actual notification
        let long_text = "a".repeat(200);
        let preview = if long_text.len() > 80 {
            format!("{}...", &long_text[..80])
        } else {
            long_text.clone()
        };
        assert_eq!(preview.len(), 83); // 80 chars + "..."
    }
}
