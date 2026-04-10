//! First-run onboarding state machine for the GUI.
//!
//! This module holds pure state and validation for the welcome flow:
//! generate a new 24-word BIP-39 phrase or import an existing one. It has
//! no egui dependency; rendering lives in `views/welcome.rs`.
//!
//! The flow:
//! 1. `OnboardingMode::Welcome` — two big buttons: "Create new" / "Import".
//! 2. `OnboardingMode::NewIdentity` — generated phrase is displayed, user
//!    must check "I have written this down" before Continue becomes active.
//! 3. `OnboardingMode::Import` — text area, BIP-39 validation on submit.
//!
//! On submit, the IPC bridge receives `GuiCommand::CompleteOnboarding` with
//! the phrase wrapped in [`Zeroizing<String>`] so it's wiped when the enum
//! variant is dropped.

use aira_core::seed::MasterSeed;
use zeroize::Zeroizing;

/// Which screen of the onboarding flow we're on.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum OnboardingMode {
    /// Initial welcome screen with Create / Import choice.
    #[default]
    Welcome,
    /// Generated phrase is shown for the user to back up.
    NewIdentity,
    /// User is pasting/typing an existing phrase.
    Import,
}

/// Full onboarding UI state.
///
/// Manual `Debug` impl below redacts the phrase fields so a stray
/// `tracing::debug!(?state)` cannot leak secrets.
#[derive(Default)]
pub struct OnboardingState {
    pub mode: OnboardingMode,
    /// The generated phrase when `mode == NewIdentity`. `None` on the Welcome
    /// / Import screens. Dropped (and zeroized) when the user clicks Back or
    /// completes onboarding.
    pub generated_phrase: Option<Zeroizing<String>>,
    /// Checkbox "I have written this phrase down".
    pub written_down_confirmed: bool,
    /// Text buffer for the Import screen. Cleared + zeroized on leave.
    pub import_input: String,
    /// Last validation error to show inline on Import / `NewIdentity`.
    pub validation_error: Option<String>,
}

impl std::fmt::Debug for OnboardingState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnboardingState")
            .field("mode", &self.mode)
            .field(
                "generated_phrase",
                &self.generated_phrase.as_ref().map(|_| "[REDACTED]"),
            )
            .field("written_down_confirmed", &self.written_down_confirmed)
            .field(
                "import_input",
                &if self.import_input.is_empty() {
                    "[empty]"
                } else {
                    "[REDACTED]"
                },
            )
            .field("validation_error", &self.validation_error)
            .finish()
    }
}

impl OnboardingState {
    /// Generate a new 24-word BIP-39 phrase and transition to `NewIdentity`.
    ///
    /// This is fast (microseconds) — it only generates entropy + encodes the
    /// phrase; the expensive Argon2id derivation is deferred to the daemon
    /// when it receives `AIRA_SEED`. Safe to call on the UI thread.
    pub fn generate(&mut self) {
        let phrase = MasterSeed::generate_phrase_only();
        self.generated_phrase = Some(Zeroizing::new(phrase));
        self.written_down_confirmed = false;
        self.validation_error = None;
        self.mode = OnboardingMode::NewIdentity;
    }

    /// Switch to the Import screen, clearing any previously generated phrase.
    pub fn switch_to_import(&mut self) {
        self.generated_phrase = None;
        self.written_down_confirmed = false;
        self.import_input.clear();
        self.validation_error = None;
        self.mode = OnboardingMode::Import;
    }

    /// Go back to the Welcome screen, wiping any phrase in state.
    pub fn back_to_welcome(&mut self) {
        self.generated_phrase = None;
        self.written_down_confirmed = false;
        // Overwrite the buffer before clearing to help the zeroize story.
        // (String::clear sets len=0 but keeps the allocation, which may still
        // contain the bytes until reuse.)
        for b in unsafe { self.import_input.as_bytes_mut() } {
            *b = 0;
        }
        self.import_input.clear();
        self.validation_error = None;
        self.mode = OnboardingMode::Welcome;
    }

    /// Whether the "Continue" button on the `NewIdentity` screen is clickable.
    #[must_use]
    pub fn can_continue_new(&self) -> bool {
        self.generated_phrase.is_some() && self.written_down_confirmed
    }

    /// Consume the generated phrase (when `can_continue_new()` is true),
    /// returning it wrapped in `Zeroizing`. Returns `None` otherwise.
    pub fn take_generated(&mut self) -> Option<Zeroizing<String>> {
        if self.can_continue_new() {
            self.generated_phrase.take()
        } else {
            None
        }
    }

    /// Validate the Import buffer against BIP-39 and return a zeroized
    /// phrase on success. Also updates `validation_error` on failure.
    ///
    /// This performs a *full* `MasterSeed::from_phrase` derivation, which is
    /// slow (~1-3s Argon2id). Consider running it on a background thread if
    /// blocking the UI is unacceptable — currently we accept the blip since
    /// it only happens once at onboarding.
    pub fn validate_import(&mut self) -> Option<Zeroizing<String>> {
        let trimmed = self.import_input.trim();
        if trimmed.is_empty() {
            self.validation_error = Some("Phrase is empty".to_string());
            return None;
        }
        match MasterSeed::from_phrase(trimmed) {
            Ok(_seed) => {
                // Derivation succeeded — phrase is valid BIP-39.
                self.validation_error = None;
                Some(Zeroizing::new(trimmed.to_string()))
            }
            Err(e) => {
                self.validation_error = Some(format!("Invalid phrase: {e}"));
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_phrase() {
        let mut state = OnboardingState::default();
        state.generate();
        let printed = format!("{state:?}");
        // The redaction marker must be present for the phrase field.
        assert!(printed.contains("[REDACTED]"));
        // The full phrase must not appear verbatim.
        let phrase = state
            .generated_phrase
            .as_ref()
            .unwrap()
            .as_str()
            .to_string();
        assert!(!printed.contains(&phrase));
        // Any 3-word consecutive slice must not leak either (catches partial
        // serialization bugs). 3 words is long enough to avoid false
        // positives with BIP-39 vocabulary words appearing in debug field
        // names like `written_down_confirmed`.
        let words: Vec<&str> = phrase.split_whitespace().collect();
        for window in words.windows(3) {
            let slice = window.join(" ");
            assert!(
                !printed.contains(&slice),
                "Debug output leaked phrase slice: {slice}"
            );
        }
    }

    #[test]
    fn debug_import_redacted_when_nonempty() {
        let mut state = OnboardingState::default();
        state.switch_to_import();
        assert!(format!("{state:?}").contains("[empty]"));
        state.import_input.push_str("some secret words");
        assert!(format!("{state:?}").contains("[REDACTED]"));
        assert!(!format!("{state:?}").contains("secret"));
    }

    #[test]
    fn generate_transitions_and_blocks_continue() {
        let mut state = OnboardingState::default();
        assert_eq!(state.mode, OnboardingMode::Welcome);
        assert!(state.take_generated().is_none());

        state.generate();
        assert_eq!(state.mode, OnboardingMode::NewIdentity);
        assert!(state.generated_phrase.is_some());
        assert!(!state.can_continue_new());
        assert!(state.take_generated().is_none());

        state.written_down_confirmed = true;
        assert!(state.can_continue_new());
        let taken = state.take_generated();
        assert!(taken.is_some());
        // After take, the slot is empty.
        assert!(state.generated_phrase.is_none());
    }

    #[test]
    fn back_to_welcome_wipes_state() {
        let mut state = OnboardingState::default();
        state.switch_to_import();
        state.import_input.push_str("dummy");
        state.validation_error = Some("nope".into());
        state.back_to_welcome();
        assert_eq!(state.mode, OnboardingMode::Welcome);
        assert!(state.import_input.is_empty());
        assert!(state.validation_error.is_none());
    }

    #[test]
    fn validate_import_rejects_empty() {
        let mut state = OnboardingState::default();
        state.switch_to_import();
        assert!(state.validate_import().is_none());
        assert_eq!(state.validation_error.as_deref(), Some("Phrase is empty"));
    }

    #[test]
    fn validate_import_rejects_garbage() {
        let mut state = OnboardingState::default();
        state.switch_to_import();
        state.import_input.push_str("not a real phrase");
        assert!(state.validate_import().is_none());
        assert!(state
            .validation_error
            .as_deref()
            .unwrap_or("")
            .starts_with("Invalid phrase"));
    }

    // Note: testing validate_import() with a real 24-word phrase would
    // trigger the full Argon2id derivation (~1-3s) which is too slow for
    // a unit test. The `generate()` + `from_phrase` roundtrip is already
    // covered by aira-core's own test suite.
}
