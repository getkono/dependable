//! Handing a URL to the system browser.
//!
//! OSC 8 makes a link clickable in terminals that support it, but plenty do
//! not, and a link nobody can follow is decoration. The `o` key is the fallback
//! that always works.

use std::process::{Command, Stdio};

/// Ask the desktop to open `url`.
///
/// The child is spawned and never waited on: the browser outlives this process,
/// and blocking the event loop on it would freeze the UI. Its streams go to
/// `/dev/null`, because anything a launcher prints would land on the alternate
/// screen and corrupt the display.
///
/// # Errors
/// Returns the spawn error when no launcher could be started, so the caller can
/// tell the user rather than appearing to do nothing.
pub fn browser(url: &str) -> std::io::Result<()> {
    // Refuse anything that is not plainly a web URL. The value reaches us from
    // a registry response, and handing an arbitrary string to a shell-adjacent
    // launcher is how a `file://` or a command substitution gets run.
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "only http and https links can be opened",
        ));
    }

    let (program, args): (&str, &[&str]) = if cfg!(target_os = "macos") {
        ("open", &[])
    } else if cfg!(target_os = "windows") {
        // `start` is a shell builtin, so it needs the shell, and the empty
        // string is the window title `start` would otherwise take the URL as.
        ("cmd", &["/C", "start", ""])
    } else {
        ("xdg-open", &[])
    };

    Command::new(program)
        .args(args)
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_web_urls_are_opened() {
        // A registry controls this string; a launcher must not be handed a
        // local path or anything else it might interpret.
        for url in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "; rm -rf /",
            "ftp://example.com",
            "",
        ] {
            assert!(browser(url).is_err(), "{url} must be refused");
        }
    }
}
