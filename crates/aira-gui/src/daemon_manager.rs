//! Spawns and supervises the `aira-daemon` child process.
//!
//! The GUI launches the daemon as a subprocess with the BIP-39 seed phrase
//! passed via the `AIRA_SEED` environment variable (never via the command
//! line, where it would be visible to `ps`/Task Manager). On Windows we also
//! pass `CREATE_NO_WINDOW` so no console window appears.
//!
//! The [`DaemonHandle`] returned by [`spawn`] owns the child process: when
//! dropped, and if the GUI "owns" the daemon (i.e. we spawned it rather than
//! connecting to a pre-existing instance), the handle attempts a graceful
//! kill. A graceful shutdown via IPC (`DaemonRequest::Shutdown`) should be
//! tried before dropping the handle — see `ipc::Bridge::shutdown`.
//!
//! ## Memory hygiene
//!
//! The seed phrase is kept in a [`Zeroizing<String>`] throughout. However
//! `std::process::Command::env` copies the value into libstd's internal env
//! map, which we cannot zeroize. The copy lives only until `Command::spawn`
//! returns (the `Command` is dropped immediately after), so the exposure
//! window is short. A complete fix would require `posix_spawn` / `CreateProcess`
//! bindings — out of scope for this milestone.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use zeroize::Zeroizing;

/// Maximum number of bytes of stderr to capture from a failed daemon spawn,
/// to show in an error dialog without leaking potentially sensitive data.
const STDERR_CAPTURE_LIMIT: usize = 4096;

/// A spawned (or adopted) daemon process.
///
/// `owned == true` means the GUI started this daemon and should kill it on
/// shutdown. `owned == false` means the GUI connected to a pre-existing
/// daemon (e.g. started manually or by another GUI instance); we must not
/// kill it.
pub struct DaemonHandle {
    pub child: Option<Child>,
    pub owned: bool,
}

impl DaemonHandle {
    /// Create an empty handle representing "no owned daemon" — used when the
    /// GUI connects to a pre-existing daemon.
    pub fn external() -> Self {
        Self {
            child: None,
            owned: false,
        }
    }
}

impl Drop for DaemonHandle {
    fn drop(&mut self) {
        if !self.owned {
            return;
        }
        if let Some(mut child) = self.child.take() {
            // If the child is already gone we do nothing; otherwise kill and reap.
            match child.try_wait() {
                Ok(Some(_status)) => {
                    // Already exited.
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                Err(e) => {
                    tracing::warn!("daemon_manager: try_wait failed on drop: {e}");
                    let _ = child.kill();
                }
            }
        }
    }
}

/// Error returned by [`spawn`].
pub struct SpawnError {
    pub reason: String,
    pub stderr: Option<String>,
}

// Manual Debug so stderr is never logged unintentionally.
impl std::fmt::Debug for SpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpawnError")
            .field("reason", &self.reason)
            .field("stderr", &self.stderr.as_ref().map(|_| "[captured]"))
            .finish()
    }
}

/// Locate the `aira-daemon` binary.
///
/// Looks in the directory of the current executable first (`current_exe()`'s
/// parent), then falls back to searching `PATH`. Returns the resolved path
/// on success, or the expected sibling path (for error messages) on failure.
///
/// # Errors
///
/// Returns `Err(expected_path)` where `expected_path` is the location we
/// looked in first — useful for a "Daemon not found at X" error dialog.
pub fn locate_daemon_binary() -> Result<PathBuf, PathBuf> {
    let exe_name = if cfg!(windows) {
        "aira-daemon.exe"
    } else {
        "aira-daemon"
    };

    // Try sibling of the current executable first.
    let sibling = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(exe_name)));
    if let Some(path) = sibling.as_ref() {
        if path.exists() {
            return Ok(path.clone());
        }
    }

    // Fallback: search PATH.
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join(exe_name);
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    // Nothing found — return the sibling path (or a placeholder) for the error.
    Err(sibling.unwrap_or_else(|| PathBuf::from(exe_name)))
}

/// Spawn the `aira-daemon` subprocess.
///
/// The seed phrase is passed via the `AIRA_SEED` environment variable; see
/// the module-level "Memory hygiene" note for caveats.
///
/// On Windows, `CREATE_NO_WINDOW` is set so the daemon has no console
/// window. On Unix, stdin/stdout are redirected to `/dev/null`; stderr is
/// piped so we can capture the first [`STDERR_CAPTURE_LIMIT`] bytes if the
/// daemon exits early.
///
/// # Errors
///
/// Returns [`SpawnError`] if the daemon binary cannot be found or the
/// process cannot be created.
pub fn spawn(seed: &Zeroizing<String>) -> Result<DaemonHandle, SpawnError> {
    let exe = locate_daemon_binary().map_err(|p| SpawnError {
        reason: format!("aira-daemon binary not found (expected at {})", p.display()),
        stderr: None,
    })?;

    let mut cmd = Command::new(&exe);
    cmd.env("AIRA_SEED", seed.as_str())
        .env("AIRA_LOG", "aira=info")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW — daemon is a background service, no console needed.
        cmd.creation_flags(0x0800_0000);
    }

    let child = cmd.spawn().map_err(|e| SpawnError {
        reason: format!("failed to spawn {}: {e}", exe.display()),
        stderr: None,
    })?;

    // `cmd` (and its internal env map copy of AIRA_SEED) is dropped here.
    tracing::info!("daemon_manager: spawned aira-daemon (pid={})", child.id());

    Ok(DaemonHandle {
        child: Some(child),
        owned: true,
    })
}

/// Check if the owned daemon has already exited. Returns `Some(SpawnError)`
/// with captured stderr if the child has exited with non-zero status, or
/// `None` if it is still running (or has exited successfully, which we treat
/// as unexpected-but-not-an-error).
///
/// Call this during the post-spawn polling loop (Chunk A5) to detect an
/// immediate crash (bad seed, port conflict, corrupted DB, etc.) rather than
/// waiting for the full connect-timeout.
pub fn check_early_exit(handle: &mut DaemonHandle) -> Option<SpawnError> {
    let child = handle.child.as_mut()?;
    match child.try_wait() {
        Ok(Some(status)) if !status.success() => {
            let mut buf = Vec::with_capacity(STDERR_CAPTURE_LIMIT);
            if let Some(mut stderr) = child.stderr.take() {
                // Read up to the limit; any error silently truncates.
                let mut chunk = [0u8; 512];
                while buf.len() < STDERR_CAPTURE_LIMIT {
                    match stderr.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let take = n.min(STDERR_CAPTURE_LIMIT - buf.len());
                            buf.extend_from_slice(&chunk[..take]);
                        }
                    }
                }
            }
            let stderr_text = if buf.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(&buf).into_owned())
            };
            Some(SpawnError {
                reason: format!("aira-daemon exited early: {status}"),
                stderr: stderr_text,
            })
        }
        Ok(Some(_)) => {
            // Exited with status 0 — unusual but not an error we want to
            // surface; the connect loop will time out instead.
            None
        }
        Ok(None) => None,
        Err(e) => Some(SpawnError {
            reason: format!("try_wait failed: {e}"),
            stderr: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locate_returns_err_when_missing() {
        // In a CI sandbox the daemon binary is usually not next to the test
        // runner; we just verify the function returns *something* (either Ok
        // if a system-installed aira-daemon happens to exist, or Err with a
        // sensible path).
        match locate_daemon_binary() {
            Ok(path) => {
                assert!(
                    path.ends_with("aira-daemon") || path.ends_with("aira-daemon.exe"),
                    "unexpected path: {}",
                    path.display()
                );
            }
            Err(expected) => {
                let name = expected
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or_default();
                assert!(
                    name == "aira-daemon" || name == "aira-daemon.exe",
                    "unexpected expected path: {}",
                    expected.display()
                );
            }
        }
    }

    #[test]
    fn spawn_error_debug_redacts_stderr() {
        let err = SpawnError {
            reason: "boom".into(),
            stderr: Some("some stderr output".into()),
        };
        let printed = format!("{err:?}");
        assert!(printed.contains("boom"));
        assert!(printed.contains("[captured]"));
        assert!(!printed.contains("some stderr output"));
    }
}
