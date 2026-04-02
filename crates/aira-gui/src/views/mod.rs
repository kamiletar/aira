//! View modules — each renders a distinct screen of the application.
//!
//! Routing is handled in `app.rs` based on `GuiState::active_view`.

pub mod add_contact;
pub mod chat;
pub mod contacts;
pub mod groups;
pub mod identity;
pub mod settings;
pub mod transfers;
