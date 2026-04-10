//! Aira Desktop GUI — eframe/egui application.
//!
//! Entry point: creates the system tray, spawns the IPC bridge on a
//! background thread with its own tokio runtime, then launches eframe.
//!
//! Architecture:
//! ```text
//! ┌──────────┐  mpsc channels  ┌────────────┐  IPC socket  ┌────────┐
//! │ egui UI  │ ◄────────────► │ IPC bridge │ ◄──────────► │ daemon │
//! │ (main)   │                │ (tokio rt) │              │        │
//! └──────────┘                └────────────┘              └────────┘
//! ```

#![warn(clippy::all, clippy::pedantic)]
// Allow common egui patterns and pedantic lints that conflict with GUI code
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::unnecessary_wraps)]

mod app;
mod daemon_manager;
mod ipc;
mod keychain;
#[allow(dead_code)]
mod notifications;
mod onboarding;
mod password_vault;
mod state;
#[allow(dead_code)]
mod theme;
mod tray;
mod views;
mod widgets;

use tokio::sync::mpsc;

/// Load the app icon from the embedded PNG asset.
fn load_app_icon() -> Option<egui::IconData> {
    let png_bytes = include_bytes!("../assets/icon.png");
    let img = image::load_from_memory(png_bytes).ok()?.into_rgba8();
    let (w, h) = img.dimensions();
    Some(egui::IconData {
        rgba: img.into_raw(),
        width: w,
        height: h,
    })
}

fn main() -> eframe::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("aira_gui=info".parse().expect("valid directive")),
        )
        .init();

    // Build system tray (must be on the main thread before eframe)
    let tray_result = tray::build_tray();
    let (tray_icon, tray_ids) = match tray_result {
        Ok((icon, ids)) => (Some(icon), Some(ids)),
        Err(e) => {
            tracing::warn!("System tray unavailable: {e}");
            (None, None)
        }
    };

    // Create channels for IPC bridge communication
    let (cmd_tx, cmd_rx) = mpsc::channel::<ipc::GuiCommand>(64);
    let (update_tx, update_rx) = mpsc::channel::<ipc::GuiUpdate>(256);

    // Load app icon from embedded PNG
    let icon = load_app_icon();

    // eframe options
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([440.0, 660.0])
        .with_min_inner_size([340.0, 500.0])
        .with_title("Aira");
    if let Some(icon_data) = icon {
        viewport = viewport.with_icon(icon_data);
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    // Launch eframe — the IPC bridge is spawned inside the creator closure
    // so we can pass the egui::Context for `request_repaint()`.
    eframe::run_native(
        "Aira",
        options,
        Box::new(move |cc| {
            // Spawn the IPC bridge on a background thread with its own tokio runtime
            let ctx = cc.egui_ctx.clone();
            std::thread::Builder::new()
                .name("ipc-bridge".into())
                .spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("tokio runtime");
                    rt.block_on(ipc::run_ipc_bridge(ctx, cmd_rx, update_tx));
                })
                .expect("spawn IPC bridge thread");

            Ok(Box::new(app::AiraApp::new(cmd_tx, update_rx, tray_ids)))
        }),
    )?;

    // Keep tray icon alive until the app exits
    drop(tray_icon);

    Ok(())
}
