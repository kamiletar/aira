//! Mozilla Fluent i18n — all user-facing strings.
//!
//! Supports pluralization, gender, numeric formats out of the box.
//! FTL files are embedded in the binary via rust-embed.
//! See SPEC.md §9.1.
//!
//! Languages v0.1: en, ru
//! Languages v0.2: + es, zh, ar, de, fr, ja, pt, hi
//!
//! TODO(M5): full implementation when CLI is being built

/// Get a localized string by message ID.
///
/// Falls back to English if the locale doesn't have the message.
#[must_use]
pub fn t(_locale: &str, _id: &str) -> String {
    // TODO(M5): implement via FluentBundle
    todo!("M5: implement i18n")
}
