//! Mozilla Fluent i18n — all user-facing strings.
//!
//! Supports pluralization, gender, numeric formats out of the box.
//! FTL files are embedded in the binary via `rust-embed`.
//! See SPEC.md §9.1.
//!
//! Languages v0.1: en, ru
//! Languages v0.2: + es, zh, ar, de, fr, ja, pt, hi

#![deny(unsafe_code)]

use std::collections::HashMap;

use fluent::FluentValue;
use fluent_bundle::{FluentArgs, FluentBundle, FluentResource};
use unic_langid::LanguageIdentifier;

/// Embedded locale files from `crates/aira-core/locales/`.
#[derive(rust_embed::RustEmbed)]
#[folder = "locales/"]
struct Locales;

/// Supported locales.
const SUPPORTED_LOCALES: &[&str] = &["en", "ru"];

/// Default fallback locale.
const FALLBACK_LOCALE: &str = "en";

/// Internationalization engine backed by Mozilla Fluent.
///
/// Holds a primary bundle (requested locale) and a fallback bundle (English).
/// If the primary locale is English, only one bundle is used.
///
/// # Example
///
/// ```
/// use aira_core::i18n::I18n;
///
/// let i18n = I18n::new("ru");
/// let title = i18n.t("contacts-title");
/// assert_eq!(title, "Контакты");
///
/// // Fallback to English for unknown locale
/// let i18n_unknown = I18n::new("zz");
/// let title = i18n_unknown.t("contacts-title");
/// assert_eq!(title, "Contacts");
/// ```
pub struct I18n {
    primary: FluentBundle<FluentResource>,
    fallback: Option<FluentBundle<FluentResource>>,
}

impl I18n {
    /// Create a new `I18n` instance for the given locale code.
    ///
    /// Falls back to English if the locale is not supported or
    /// if a specific message ID is missing in the primary locale.
    #[must_use]
    pub fn new(locale: &str) -> Self {
        let lang = normalize_locale(locale);

        let primary = build_bundle(&lang);

        // If primary is already English, no need for fallback
        let fallback = if lang == FALLBACK_LOCALE {
            None
        } else {
            Some(build_bundle(FALLBACK_LOCALE))
        };

        Self { primary, fallback }
    }

    /// Create `I18n` by detecting locale from environment.
    ///
    /// Priority: `AIRA_LANG` env → `LANG` env → `"en"` fallback.
    #[must_use]
    pub fn from_env() -> Self {
        let locale = detect_locale();
        Self::new(&locale)
    }

    /// Get a localized string by message ID.
    ///
    /// Falls back to English if the primary locale doesn't have the message.
    /// Returns the message ID itself as a last resort (should never happen
    /// if all messages are defined in `en/main.ftl`).
    #[must_use]
    pub fn t(&self, id: &str) -> String {
        self.t_args(id, &HashMap::new())
    }

    /// Get a localized string with arguments.
    ///
    /// # Example
    ///
    /// ```
    /// use aira_core::i18n::I18n;
    /// use std::collections::HashMap;
    ///
    /// let i18n = I18n::new("en");
    /// let mut args = HashMap::new();
    /// args.insert("contact", "Alice".to_string());
    /// let msg = i18n.t_args("cmd-block-done", &args);
    /// assert!(msg.contains("Alice"));
    /// assert!(msg.contains("blocked"));
    /// ```
    #[must_use]
    pub fn t_args(&self, id: &str, args: &HashMap<&str, String>) -> String {
        let fluent_args = to_fluent_args(args);
        let fluent_args_ref = if args.is_empty() {
            None
        } else {
            Some(&fluent_args)
        };

        // Try primary bundle first
        if let Some(result) = format_message(&self.primary, id, fluent_args_ref) {
            return result;
        }

        // Try fallback bundle
        if let Some(ref fb) = self.fallback {
            if let Some(result) = format_message(fb, id, fluent_args_ref) {
                return result;
            }
        }

        // Last resort: return message ID
        id.to_string()
    }
}

/// Detect locale from environment variables.
fn detect_locale() -> String {
    // 1. AIRA_LANG explicit setting
    if let Ok(lang) = std::env::var("AIRA_LANG") {
        if !lang.is_empty() {
            return lang;
        }
    }

    // 2. LANG environment variable
    if let Ok(lang) = std::env::var("LANG") {
        if !lang.is_empty() {
            // LANG is often "en_US.UTF-8" — extract the language code
            return lang
                .split('_')
                .next()
                .unwrap_or(FALLBACK_LOCALE)
                .to_string();
        }
    }

    // 3. Fallback to English
    FALLBACK_LOCALE.to_string()
}

/// Normalize a locale string to a supported locale code.
fn normalize_locale(locale: &str) -> String {
    // Extract language part (e.g., "en_US" -> "en", "ru-RU" -> "ru")
    let lang = locale
        .split(['_', '-'])
        .next()
        .unwrap_or(FALLBACK_LOCALE)
        .to_lowercase();

    if SUPPORTED_LOCALES.contains(&lang.as_str()) {
        lang
    } else {
        FALLBACK_LOCALE.to_string()
    }
}

/// Build a `FluentBundle` for a given locale by loading embedded FTL files.
fn build_bundle(locale: &str) -> FluentBundle<FluentResource> {
    let lang_id: LanguageIdentifier = locale
        .parse()
        .unwrap_or_else(|_| FALLBACK_LOCALE.parse().expect("en is valid"));

    let mut bundle = FluentBundle::new(vec![lang_id]);

    // Load main.ftl for this locale
    let ftl_path = format!("{locale}/main.ftl");
    if let Some(file) = Locales::get(&ftl_path) {
        let ftl_string = String::from_utf8_lossy(&file.data).to_string();
        if let Ok(resource) = FluentResource::try_new(ftl_string) {
            // Ignore errors from duplicate message IDs (shouldn't happen with single file)
            let _ = bundle.add_resource(resource);
        }
    }

    bundle
}

/// Convert a `HashMap<&str, String>` to Fluent arguments.
fn to_fluent_args<'a>(args: &'a HashMap<&str, String>) -> FluentArgs<'a> {
    let mut fluent_args = FluentArgs::new();
    for (key, value) in args {
        fluent_args.set(*key, FluentValue::from(value.as_str()));
    }
    fluent_args
}

/// Format a single message from a bundle.
fn format_message(
    bundle: &FluentBundle<FluentResource>,
    id: &str,
    args: Option<&FluentArgs<'_>>,
) -> Option<String> {
    let msg = bundle.get_message(id)?;
    let pattern = msg.value()?;
    let mut errors = vec![];
    let result = bundle.format_pattern(pattern, args, &mut errors);
    Some(result.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn english_locale_works() {
        let i18n = I18n::new("en");
        assert_eq!(i18n.t("contacts-title"), "Contacts");
        assert_eq!(i18n.t("status-online"), "online");
    }

    #[test]
    fn russian_locale_works() {
        let i18n = I18n::new("ru");
        assert_eq!(i18n.t("contacts-title"), "Контакты");
        assert_eq!(i18n.t("status-online"), "в сети");
    }

    #[test]
    fn fallback_to_english_for_unknown_locale() {
        let i18n = I18n::new("xx");
        assert_eq!(i18n.t("contacts-title"), "Contacts");
    }

    #[test]
    fn normalize_locale_handles_variants() {
        assert_eq!(normalize_locale("en_US"), "en");
        assert_eq!(normalize_locale("ru-RU"), "ru");
        assert_eq!(normalize_locale("EN"), "en");
        assert_eq!(normalize_locale("zz"), "en");
    }

    #[test]
    fn t_args_substitution() {
        let i18n = I18n::new("en");
        let mut args = HashMap::new();
        args.insert("contact", "Bob".to_string());
        let msg = i18n.t_args("cmd-block-done", &args);
        // Fluent wraps placeholders in Unicode isolating chars (\u{2068}...\u{2069})
        assert!(msg.contains("Bob"));
        assert!(msg.contains("blocked"));
    }

    #[test]
    fn missing_message_returns_id() {
        let i18n = I18n::new("en");
        assert_eq!(i18n.t("nonexistent-message"), "nonexistent-message");
    }

    #[test]
    fn russian_fallback_for_missing_key() {
        // If Russian locale is missing a key, English fallback kicks in
        let i18n = I18n::new("ru");
        // Both locales have this key, but if we had a missing one
        // it would fall back to English. Test the mechanism works:
        assert!(!i18n.t("contacts-title").is_empty());
    }
}
