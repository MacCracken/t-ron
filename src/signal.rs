//! SIGHUP-based policy hot-reload (Unix only).
//!
//! Spawns a background task that watches for SIGHUP and triggers
//! `TRon::reload_policy()`. Requires the `signal` feature.
//!
//! # Example
//!
//! ```ignore
//! let tron = Arc::new(TRon::new(TRonConfig::default()));
//! tron.load_policy_file("/etc/agnos/t-ron.toml").unwrap();
//! let handle = t_ron::signal::spawn_sighup_handler(tron.clone());
//! ```

use crate::TRon;
use std::sync::Arc;

/// Spawn a background task that reloads policy on SIGHUP.
///
/// Returns a `JoinHandle` for the spawned task. The task runs until
/// the runtime shuts down or the handle is aborted.
#[cfg(unix)]
pub fn spawn_sighup_handler(tron: Arc<TRon>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut sig = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "failed to register SIGHUP handler");
                return;
            }
        };

        loop {
            sig.recv().await;
            tracing::info!("SIGHUP received, reloading policy");
            match tron.reload_policy() {
                Ok(()) => tracing::info!("policy reloaded successfully via SIGHUP"),
                Err(e) => tracing::error!(error = %e, "policy reload failed on SIGHUP"),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TRonConfig;

    #[tokio::test]
    async fn sighup_handler_starts() {
        let tron = Arc::new(TRon::new(TRonConfig::default()));
        let handle = spawn_sighup_handler(tron);
        // Just verify it spawns without panic — abort immediately
        handle.abort();
        // The abort causes a JoinError (cancelled), which is expected
        let _ = handle.await;
    }
}
