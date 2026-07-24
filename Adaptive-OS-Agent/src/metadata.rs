// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// PF_KTHREAD bit from Linux task flags; kernel threads are outside classification.
const PF_KTHREAD: u64 = 0x0020_0000;

/// `/proc` identity used before BPF supplies a process cookie.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ProcessInstanceKey {
    /// Numeric process/thread-group ID.
    pub tgid: u32,
    /// Field 22 of `/proc/<pid>/stat`, separating reused numeric IDs.
    pub start_time_ticks: u64,
}

/// Bounded process metadata sent to DeepSeek and retained for thread context.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProcessMetadata {
    /// Pre-cookie process instance identity.
    pub instance: ProcessInstanceKey,
    /// Short executable comm from `/proc/<tgid>/comm`.
    pub comm: String,
    /// Bounded argv values from `/proc/<tgid>/cmdline`.
    pub command: Vec<String>,
    /// Resolved executable path when permission allows.
    pub executable: Option<String>,
    /// Cgroup paths without controller-specific secrets.
    pub cgroups: Vec<String>,
    /// Real UID from `/proc/<tgid>/status`.
    pub uid: Option<u32>,
}

impl ProcessMetadata {
    /// Returns true only for ordinary userspace tasks sched_ext may classify.
    pub fn is_ordinary(&self) -> bool {
        !self.command.is_empty() || self.executable.is_some()
    }
}

/// Returns a bounded argv projection with common credential forms removed.
pub fn redact_command(command: &[String]) -> Vec<String> {
    let mut redact_next = false;
    command
        .iter()
        .map(|argument| {
            if redact_next {
                redact_next = false;
                return "<redacted>".to_string();
            }

            if let Some((name, _)) = argument.split_once('=') {
                if is_sensitive_name(name) {
                    return format!("{name}=<redacted>");
                }
            }
            if is_sensitive_name(argument) {
                redact_next = true;
                return argument.clone();
            }

            let lower = argument.to_ascii_lowercase();
            if lower == "bearer" {
                redact_next = true;
                return argument.clone();
            }
            if lower.contains("authorization:") || looks_like_secret(argument) {
                return "<redacted>".to_string();
            }
            if contains_url_credentials(argument) {
                return "<redacted-url-credentials>".to_string();
            }
            argument.clone()
        })
        .collect()
}

/// Matches exact credential option/environment names after normalizing flags.
fn is_sensitive_name(value: &str) -> bool {
    let normalized = value
        .trim_start_matches('-')
        .to_ascii_lowercase()
        .replace('_', "-");
    matches!(
        normalized.as_str(),
        "api-key"
            | "apikey"
            | "access-key"
            | "access-token"
            | "auth-token"
            | "authorization"
            | "credential"
            | "credentials"
            | "password"
            | "passwd"
            | "private-key"
            | "secret"
            | "token"
    )
}

/// Detects provider-token shapes that should never be useful classification input.
fn looks_like_secret(value: &str) -> bool {
    (value.starts_with("sk-") && value.len() >= 16)
        || (value.starts_with("ghp_") && value.len() >= 20)
        || (value.starts_with("github_pat_") && value.len() >= 20)
        || (value.starts_with("AKIA") && value.len() >= 16)
}

/// Detects `scheme://user:password@host` without parsing or retaining credentials.
fn contains_url_credentials(value: &str) -> bool {
    let Some((_, remainder)) = value.split_once("://") else {
        return false;
    };
    let authority = remainder.split('/').next().unwrap_or(remainder);
    authority
        .split_once('@')
        .is_some_and(|(userinfo, _)| userinfo.contains(':'))
}

/// Thread metadata used in one long-lived TGID semantic batch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ThreadMetadata {
    /// Numeric thread ID; final identity still requires scheduler task_cookie.
    pub tid: u32,
    /// Bounded `/proc/<tgid>/task/<tid>/comm` semantic feature.
    pub comm: String,
}

/// Parsed task flags and start time from `/proc/<pid>/stat`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StatIdentity {
    /// Kernel task flags including PF_KTHREAD.
    flags: u64,
    /// Numeric-ID lifetime discriminator.
    start_time_ticks: u64,
}

/// Reads one ordinary process, returning None for kernel threads or races with exit.
pub fn read_process(tgid: u32) -> io::Result<Option<ProcessMetadata>> {
    let root = PathBuf::from(format!("/proc/{tgid}"));
    let stat = match read_stat_identity(&root.join("stat")) {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if stat.flags & PF_KTHREAD != 0 {
        return Ok(None);
    }

    let comm = read_bounded_text(root.join("comm"), 256).unwrap_or_default();
    let command = read_cmdline(root.join("cmdline")).unwrap_or_default();
    let executable = fs::read_link(root.join("exe"))
        .ok()
        .map(|path| bounded_string(path.to_string_lossy().as_ref(), 1024));
    let cgroups = read_cgroups(root.join("cgroup")).unwrap_or_default();
    let uid = read_real_uid(root.join("status")).ok().flatten();
    let metadata = ProcessMetadata {
        instance: ProcessInstanceKey {
            tgid,
            start_time_ticks: stat.start_time_ticks,
        },
        comm,
        command,
        executable,
        cgroups,
        uid,
    };
    Ok(metadata.is_ordinary().then_some(metadata))
}

/// Reads all currently visible threads in a process in stable TID order.
pub fn read_threads(tgid: u32) -> io::Result<Vec<ThreadMetadata>> {
    let path = PathBuf::from(format!("/proc/{tgid}/task"));
    let mut threads = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let Some(tid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let comm = read_bounded_text(entry.path().join("comm"), 256).unwrap_or_default();
        threads.push(ThreadMetadata { tid, comm });
    }
    threads.sort_unstable_by_key(|thread| thread.tid);
    Ok(threads)
}

/// Reads the kernel start-time discriminator for one visible thread lifetime.
pub fn read_task_start_time(tgid: u32, tid: u32) -> io::Result<u64> {
    read_stat_identity(&PathBuf::from(format!("/proc/{tgid}/task/{tid}/stat")))
        .map(|identity| identity.start_time_ticks)
}

/// Parses flags and start_time while handling spaces and parentheses in comm.
fn read_stat_identity(path: &Path) -> io::Result<StatIdentity> {
    let text = fs::read_to_string(path)?;
    let comm_end = text.rfind(')').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "stat comm has no closing parenthesis",
        )
    })?;
    let fields: Vec<_> = text[comm_end + 1..].split_whitespace().collect();
    if fields.len() <= 19 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stat record ends before start_time",
        ));
    }
    let flags = fields[6].parse::<u64>().map_err(invalid_number)?;
    let start_time_ticks = fields[19].parse::<u64>().map_err(invalid_number)?;
    Ok(StatIdentity {
        flags,
        start_time_ticks,
    })
}

/// Reads and bounds a text proc file, trimming its newline.
fn read_bounded_text(path: impl AsRef<Path>, max_bytes: usize) -> io::Result<String> {
    let text = fs::read_to_string(path)?;
    Ok(bounded_string(text.trim(), max_bytes))
}

/// Reads NUL-separated argv with per-field and total limits.
fn read_cmdline(path: impl AsRef<Path>) -> io::Result<Vec<String>> {
    let mut bytes = fs::read(path)?;
    bytes.truncate(8192);
    Ok(bytes
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty())
        .take(64)
        .map(|field| bounded_string(&String::from_utf8_lossy(field), 512))
        .collect())
}

/// Reads only cgroup path components and caps the number of hierarchy rows.
fn read_cgroups(path: impl AsRef<Path>) -> io::Result<Vec<String>> {
    let text = fs::read_to_string(path)?;
    Ok(text
        .lines()
        .filter_map(|line| line.rsplit_once(':').map(|(_, path)| path))
        .take(16)
        .map(|path| bounded_string(path, 512))
        .collect())
}

/// Reads the first real UID field from proc status.
fn read_real_uid(path: impl AsRef<Path>) -> io::Result<Option<u32>> {
    let text = fs::read_to_string(path)?;
    Ok(text.lines().find_map(|line| {
        line.strip_prefix("Uid:")
            .and_then(|value| value.split_whitespace().next())
            .and_then(|uid| uid.parse().ok())
    }))
}

/// Bounds UTF-8 by characters without slicing inside a code point.
fn bounded_string(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

/// Maps integer parse errors to consistent proc InvalidData errors.
fn invalid_number(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("invalid proc number: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use super::{bounded_string, read_task_start_time, redact_command};

    #[test]
    fn reads_current_thread_start_time() {
        let pid = std::process::id();
        assert!(read_task_start_time(pid, pid).unwrap() > 0);
    }

    /// Metadata bounds never split a multi-byte UTF-8 character.
    #[test]
    fn bounds_utf8_at_character_boundary() {
        assert_eq!(bounded_string("ab中", 3), "ab");
    }

    /// Credentials are removed while ordinary semantic argv remains intact.
    #[test]
    fn redacts_common_command_credentials() {
        let input = vec![
            "curl".into(),
            "--token".into(),
            "top-secret".into(),
            "--password=hunter2".into(),
            "https://user:pass@example.test/api".into(),
            "compile".into(),
        ];
        assert_eq!(
            redact_command(&input),
            vec![
                "curl",
                "--token",
                "<redacted>",
                "--password=<redacted>",
                "<redacted-url-credentials>",
                "compile",
            ]
        );
    }
}
