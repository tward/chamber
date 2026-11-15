use color_eyre::{Result, eyre::eyre};

/// Keeps ownership of copied text for the lifetime of the TUI on Linux.
/// Initialize lazily so a missing desktop clipboard does not prevent startup.
#[derive(Default)]
pub(crate) struct Clipboard {
    inner: Option<arboard::Clipboard>,
}

impl Clipboard {
    pub(crate) fn set_text(&mut self, text: &str) -> Result<()> {
        let clipboard = match &mut self.inner {
            Some(clipboard) => clipboard,
            slot @ None => {
                slot.insert(arboard::Clipboard::new().map_err(|e| eyre!("Failed to access clipboard: {e}"))?)
            }
        };
        clipboard
            .set_text(text)
            .map_err(|e| eyre!("Failed to copy to clipboard: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::Clipboard;

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
