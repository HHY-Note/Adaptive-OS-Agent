// SPDX-License-Identifier: Apache-2.0

//! Scheduler child lifecycle and sched_ext attachment supervision.

use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::scheduler_client::SchedulerClient;

const SCHED_EXT_STATE: &str = "/sys/kernel/sched_ext/state";
const RESTART_WINDOW: Duration = Duration::from_secs(60);
const MAX_RESTARTS: usize = 3;

#[derive(Clone)]
struct SpawnSpec {
    binary: PathBuf,
    socket: String,
    debug: bool,
}

/// Sole owner of the scheduler child process started by Agent.
pub struct SchedulerSupervisor {
    child: Child,
    spec: SpawnSpec,
    restarts: VecDeque<Instant>,
    next_attachment_check: Instant,
}

impl SchedulerSupervisor {
    /// Starts the scheduler owned by this Agent process.
    pub fn spawn(binary: &Path, socket: &str, debug: bool) -> Result<Self> {
        let spec = SpawnSpec {
            binary: binary.to_path_buf(),
            socket: socket.to_string(),
            debug,
        };
        let child = spawn_child(&spec)?;
        Ok(Self {
            child,
            spec,
            restarts: VecDeque::new(),
            next_attachment_check: Instant::now(),
        })
    }

    /// Returns the stable child PID excluded from ordinary process classification.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Waits for protocol Hello while also detecting early child failure.
    pub fn wait_ready(&mut self, client: &SchedulerClient, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        let mut last_error = None;
        while Instant::now() < deadline {
            self.ensure_child_running()?;
            match client.wait_for_connection(Duration::from_millis(250)) {
                Ok(_) => {
                    self.verify_attachment()?;
                    return Ok(());
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("scheduler startup timed out")))
    }

    /// Checks liveness and restarts a failed child within a bounded retry window.
    pub fn check(&mut self) -> Result<Option<u32>> {
        if self
            .child
            .try_wait()
            .context("check scheduler child")?
            .is_some()
        {
            self.restart()?;
            return Ok(Some(self.child.id()));
        }
        if Instant::now() >= self.next_attachment_check {
            self.verify_attachment()?;
            self.next_attachment_check = Instant::now() + Duration::from_secs(1);
        }
        Ok(None)
    }

    /// Requests graceful detach, then uses SIGKILL only after a bounded timeout.
    pub fn stop(&mut self) {
        match self.child.try_wait() {
            Ok(Some(_)) => return,
            Err(_) => return,
            Ok(None) => {}
        }
        unsafe {
            libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn ensure_child_running(&mut self) -> Result<()> {
        if let Some(status) = self.child.try_wait().context("check scheduler child")? {
            anyhow::bail!("scx_adaptive exited unexpectedly with {status}");
        }
        Ok(())
    }

    fn restart(&mut self) -> Result<()> {
        let now = Instant::now();
        while self
            .restarts
            .front()
            .is_some_and(|started| now.duration_since(*started) >= RESTART_WINDOW)
        {
            self.restarts.pop_front();
        }
        if self.restarts.len() >= MAX_RESTARTS {
            anyhow::bail!("scx_adaptive exceeded {MAX_RESTARTS} restarts in 60 seconds");
        }
        self.child = spawn_child(&self.spec)?;
        self.restarts.push_back(now);
        self.next_attachment_check = now + Duration::from_secs(1);
        Ok(())
    }

    fn verify_attachment(&self) -> Result<()> {
        let state = match fs::read_to_string(SCHED_EXT_STATE) {
            Ok(state) => state,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error).context("read sched_ext state"),
        };
        if state.trim() != "enabled" {
            anyhow::bail!(
                "scheduler child is alive but sched_ext state is {}",
                state.trim()
            );
        }
        Ok(())
    }
}

fn spawn_child(spec: &SpawnSpec) -> Result<Child> {
    let mut command = Command::new(&spec.binary);
    command
        .arg("--agent-pid")
        .arg(std::process::id().to_string())
        .arg("--control-socket")
        .arg(&spec.socket);
    if spec.debug {
        command.arg("--debug");
    }
    command
        .spawn()
        .with_context(|| format!("start scx_adaptive from {}", spec.binary.display()))
}

impl Drop for SchedulerSupervisor {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::SCHED_EXT_STATE;

    #[test]
    fn attachment_path_is_absolute() {
        assert!(SCHED_EXT_STATE.starts_with('/'));
    }
}
