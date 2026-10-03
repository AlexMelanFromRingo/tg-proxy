//! Log plumbing: hide private domain names, optionally mirror to a rotating file.
//!
//! Anything that is not a `*.telegram.org` name (Cloudflare Workers, your own
//! domains, upstream proxy hosts) is masked in the output, so a pasted log does
//! not leak the address of your private relay.

use std::fs::{File, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::EnvFilter;

// ── Domain censoring ──────────────────────────────────────────────────────────

fn is_label(l: &str) -> bool {
    !l.is_empty()
        && l.len() <= 63
        && !l.starts_with('-')
        && !l.ends_with('-')
        && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn is_domain(s: &str) -> bool {
    if s.contains('_') {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() < 2 || !labels.iter().all(|l| is_label(l)) {
        return false;
    }
    let tld = labels[labels.len() - 1];
    tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic())
}

fn censor_domain(d: &str) -> String {
    let lower = d.to_ascii_lowercase();
    if lower == "telegram.org" || lower.ends_with(".telegram.org") || lower.ends_with(".log") {
        return d.to_string();
    }
    let parts: Vec<&str> = d.split('.').collect();
    let last = parts.len() - 1;
    parts
        .iter()
        .enumerate()
        .map(|(i, p)| {
            if i == last {
                p.to_string()
            } else {
                let keep = p.len() / 2;
                format!("{}{}", &p[..keep], "*".repeat(p.len() - keep))
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn flush_token(token: &mut String, out: &mut String) {
    if token.is_empty() {
        return;
    }
    let core = token.trim_matches('.');
    if is_domain(core) {
        let start = token.len() - token.trim_start_matches('.').len();
        let end = token.trim_end_matches('.').len();
        out.push_str(&token[..start]);
        out.push_str(&censor_domain(core));
        out.push_str(&token[end..]);
    } else {
        out.push_str(token);
    }
    token.clear();
}

/// Mask every domain name in `text` except Telegram's own.
pub fn censor_line(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut token = String::new();
    for c in text.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
            token.push(c);
        } else {
            flush_token(&mut token, &mut out);
            out.push(c);
        }
    }
    flush_token(&mut token, &mut out);
    out
}

/// Remove ANSI colour sequences (`ESC [ ... m`) for the file copy.
pub fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            for n in chars.by_ref() {
                if n.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

// ── Rotating file ─────────────────────────────────────────────────────────────

pub struct RotatingFile {
    path: PathBuf,
    max_bytes: u64,
    backups: usize,
    file: File,
    size: u64,
}

impl RotatingFile {
    pub fn open(path: PathBuf, max_bytes: u64, backups: usize) -> io::Result<Self> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self { path, max_bytes, backups: backups.max(1), file, size })
    }

    fn backup_path(&self, n: usize) -> PathBuf {
        let mut s = self.path.clone().into_os_string();
        s.push(format!(".{n}"));
        PathBuf::from(s)
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.file.flush()?;
        let oldest = self.backup_path(self.backups);
        let _ = std::fs::remove_file(&oldest);
        for n in (1..self.backups).rev() {
            let from = self.backup_path(n);
            if from.exists() {
                let _ = std::fs::rename(&from, self.backup_path(n + 1));
            }
        }
        let _ = std::fs::rename(&self.path, self.backup_path(1));
        self.file = OpenOptions::new().create(true).write(true).truncate(true).open(&self.path)?;
        self.size = 0;
        Ok(())
    }
}

impl Write for RotatingFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.size > 0 && self.size + buf.len() as u64 > self.max_bytes {
            let _ = self.rotate(); // on failure keep appending rather than lose the line
        }
        self.file.write_all(buf)?;
        self.size += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

// ── tracing writer ────────────────────────────────────────────────────────────

#[derive(Clone)]
struct Tee {
    file: Option<Arc<Mutex<RotatingFile>>>,
}

struct TeeWriter {
    file: Option<Arc<Mutex<RotatingFile>>>,
}

impl Write for TeeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let censored = censor_line(&String::from_utf8_lossy(buf));
        let _ = io::stderr().write_all(censored.as_bytes());
        if let Some(f) = &self.file {
            if let Ok(mut f) = f.lock() {
                let _ = f.write_all(strip_ansi(&censored).as_bytes());
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Tee {
    type Writer = TeeWriter;
    fn make_writer(&'a self) -> TeeWriter {
        TeeWriter { file: self.file.clone() }
    }
}

pub struct LogFile {
    pub path: PathBuf,
    pub max_mb: f64,
    pub backups: usize,
}

/// Whether coloured output is appropriate on stderr.
pub fn colors_enabled() -> bool {
    if std::env::var_os("NO_COLOR").is_some() || !io::stderr().is_terminal() {
        return false;
    }
    // Legacy Windows consoles do not interpret ANSI escapes; Windows Terminal does.
    !cfg!(windows) || std::env::var_os("WT_SESSION").is_some()
}

pub fn init(verbose: bool, file: Option<LogFile>) -> anyhow::Result<()> {
    let level = if verbose { "debug" } else { "info" };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let file = match file {
        Some(f) => {
            let max = (f.max_mb.max(0.01) * 1024.0 * 1024.0) as u64;
            let rf = RotatingFile::open(f.path.clone(), max, f.backups)
                .map_err(|e| anyhow::anyhow!("cannot open log file {}: {e}", f.path.display()))?;
            Some(Arc::new(Mutex::new(rf)))
        }
        None => None,
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_ansi(colors_enabled())
        .with_writer(Tee { file })
        .init();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telegram_domains_are_kept() {
        let s = "wss://kws2.web.telegram.org/apiws via 149.154.167.220";
        assert_eq!(censor_line(s), s);
        assert_eq!(censor_line("telegram.org and t.telegram.org"), "telegram.org and t.telegram.org");
    }

    #[test]
    fn other_domains_are_masked() {
        assert_eq!(
            censor_line("trying CF worker my-relay.example.workers.dev for 1.2.3.4"),
            "trying CF worker my-r****.exa****.wor****.dev for 1.2.3.4"
        );
        assert_eq!(censor_line("kws2.pclead.co.uk failed"), "kw**.pcl***.c*.uk failed");
    }

    #[test]
    fn non_domains_pass_through() {
        for s in [
            "149.154.167.220:443",
            "2026-10-02T23:08:03.123456Z  INFO stats: total=1",
            "v0.2.0 started",
            "127.0.0.1:1443",
            "[127.0.0.1:50000] DC2m -> pool hit",
            "ratio 3/4 up=1.5KB",
            "under_score.example stays",
            "trailing dot. next",
            "",
        ] {
            assert_eq!(censor_line(s), s, "{s:?}");
        }
    }

    #[test]
    fn dots_around_a_domain_are_preserved() {
        assert_eq!(censor_line("(see example.org.)"), "(see exa****.org.)");
        assert_eq!(censor_line("host=example.org, port"), "host=exa****.org, port");
    }

    #[test]
    fn ansi_is_stripped() {
        assert_eq!(strip_ansi("\x1b[32m INFO\x1b[0m hello"), " INFO hello");
        assert_eq!(strip_ansi("plain"), "plain");
    }

    #[test]
    fn rotation_keeps_bounded_backups() {
        let dir = std::env::temp_dir().join(format!("tgproxy-log-{}", std::process::id()));
        let path = dir.join("proxy.log");
        let mut f = RotatingFile::open(path.clone(), 100, 2).unwrap();
        for i in 0..10 {
            f.write_all(format!("line {i:02} {}\n", "x".repeat(30)).as_bytes()).unwrap();
        }
        f.flush().unwrap();
        assert!(path.exists());
        assert!(dir.join("proxy.log.1").exists());
        assert!(dir.join("proxy.log.2").exists());
        assert!(!dir.join("proxy.log.3").exists(), "only two backups are kept");
        let total: u64 = ["proxy.log", "proxy.log.1", "proxy.log.2"]
            .iter()
            .map(|n| std::fs::metadata(dir.join(n)).unwrap().len())
            .sum();
        assert!(total <= 3 * (100 + 40), "every file stays near the limit");
        let newest = std::fs::read_to_string(&path).unwrap();
        assert!(newest.contains("line 09"), "latest line is in the live file");
        let _ = std::fs::remove_dir_all(dir);
    }
}
