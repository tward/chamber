use color_eyre::{Result, eyre::eyre};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// The clipboard operations the TUI needs. `Clipboard` is the production implementation; tests supply a double.
pub(crate) trait ClipboardBackend {
    /// Replaces the clipboard content with `text`.
    ///
    /// # Errors
    /// Returns an error if the clipboard cannot be accessed or written.
    fn set_text(&mut self, text: &str) -> Result<()>;

    /// Reads the current clipboard text. `Ok(None)` means the clipboard holds no text.
    ///
    /// # Errors
    /// Returns an error for any failure other than the clipboard holding no text.
    fn read_text(&mut self) -> Result<Option<String>>;

    /// Empties the clipboard.
    ///
    /// # Errors
    /// Returns an error if the clipboard cannot be accessed or cleared.
    fn clear(&mut self) -> Result<()>;

    /// Gives up the retained clipboard handle, if any.
    fn release(&mut self);
}

/// Lazily creates the desktop clipboard handle on first use, so a missing clipboard does not prevent startup.
/// Keeps the handle until the session locks, at which point `ClipboardBackend::release` clears it.
/// The next copy operation recreates the handle.
#[derive(Default)]
pub(crate) struct Clipboard {
    inner: Option<arboard::Clipboard>,
}

impl Clipboard {
    /// The retained handle, created on first use.
    fn handle(&mut self) -> Result<&mut arboard::Clipboard> {
        match &mut self.inner {
            Some(clipboard) => Ok(clipboard),
            slot @ None => {
                Ok(slot.insert(arboard::Clipboard::new().map_err(|e| eyre!("Failed to access clipboard: {e}"))?))
            }
        }
    }
}

impl ClipboardBackend for Clipboard {
    fn set_text(&mut self, text: &str) -> Result<()> {
        self.handle()?
            .set_text(text)
            .map_err(|e| eyre!("Failed to copy to clipboard: {e}"))
    }

    fn read_text(&mut self) -> Result<Option<String>> {
        match self.handle()?.get_text() {
            Ok(text) => Ok(Some(text)),
            Err(arboard::Error::ContentNotAvailable) => Ok(None),
            Err(e) => Err(eyre!("Failed to read clipboard: {e}")),
        }
    }

    fn clear(&mut self) -> Result<()> {
        self.handle()?
            .clear()
            .map_err(|e| eyre!("Failed to clear clipboard: {e}"))
    }

    fn release(&mut self) {
        self.inner = None;
    }
}

/// The clipboard the App retains for one TUI session.
///
/// Remembers the SHA-256 digest of the text it last copied, never the text itself, so the lock can tell
/// whether the clipboard still holds a value Chamber put there.
pub(crate) struct SessionClipboard {
    backend: Box<dyn ClipboardBackend>,
    digest: Option<[u8; 32]>,
}

impl SessionClipboard {
    pub(crate) fn new(backend: Box<dyn ClipboardBackend>) -> Self {
        Self { backend, digest: None }
    }

    /// Copies `text` to the clipboard and, on success, remembers its digest in place of any earlier one.
    ///
    /// # Errors
    /// Returns the backend's error if the copy fails. Any earlier digest is then kept.
    pub(crate) fn copy(&mut self, text: &str) -> Result<()> {
        self.backend.set_text(text)?;
        self.forget_digest();
        self.digest = Some(sha256(text.as_bytes()));
        Ok(())
    }

    /// Clears the clipboard at lock if it still holds the text this session last copied, then forgets the
    /// digest and releases the backend's handle.
    ///
    /// Does not read, clear, or initialize the clipboard when nothing was copied. Leaves the clipboard alone
    /// when it holds different text or no text, and clears it when it cannot be read. No error escapes.
    ///
    /// Returns `true` only when a clear was attempted and failed.
    pub(crate) fn clear_at_lock(&mut self) -> bool {
        let clear_failed = match &self.digest {
            None => false,
            Some(digest) => {
                let should_clear = match self.backend.read_text() {
                    Ok(Some(mut text)) => {
                        let mut read_digest = sha256(text.as_bytes());
                        text.zeroize();
                        let matches = read_digest == *digest;
                        read_digest.zeroize();
                        matches
                    }
                    Ok(None) => false,
                    // If reading back Chamber's own selection fails (possible on Wayland), clearing is intended.
                    Err(_) => true,
                };
                should_clear && self.backend.clear().is_err()
            }
        };
        self.forget_digest();
        self.backend.release();
        clear_failed
    }

    /// Whether a digest is stored.
    #[cfg(test)]
    pub(crate) const fn has_digest(&self) -> bool {
        self.digest.is_some()
    }

    /// Zeroizes and removes the stored digest.
    fn forget_digest(&mut self) {
        if let Some(digest) = self.digest.as_mut() {
            digest.zeroize();
        }
        self.digest = None;
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::{Clipboard, ClipboardBackend};

    #[test]
    #[ignore = "requires an isolated desktop clipboard, e.g. xvfb-run"]
    fn copied_text_survives_return_and_can_be_replaced() {
        let mut owner = Clipboard::default();
        owner.set_text("chamber clipboard test 🗝\nsecond line").unwrap();

        // Open the reader only after set_text returns: a short-lived writer
        // would already have relinquished ownership on X11 at this point.
        let mut reader = arboard::Clipboard::new().unwrap();
        assert_eq!(reader.get_text().unwrap(), "chamber clipboard test 🗝\nsecond line");

        owner.set_text("replacement test value").unwrap();
        assert_eq!(reader.get_text().unwrap(), "replacement test value");
        reader.clear().unwrap();
    }
}
