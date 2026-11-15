# Chamber UI

Terminal user interface (TUI) for the Chamber secrets manager. Provides an interactive,
keyboard-driven interface for managing secrets with a modern terminal-based user
experience.

This crate is part of the [Chamber](https://github.com/mikeleppane/chamber) secrets manager ecosystem.

## Clipboard

Press `c` in the item list or detail view to copy a value without revealing it.
The TUI retains its desktop clipboard connection so copied values remain available
while it is running. On Linux, availability after quitting depends on the desktop
clipboard manager. Copy errors are displayed in the status bar.

Native Wayland clipboard support is enabled for compositors implementing the
data-control protocol. Other desktops fall back to X11/XWayland.

This uses the desktop clipboard on the machine running Chamber; copying over SSH
to the local terminal's clipboard is not supported yet.

The clipboard regression test requires an isolated X server and writes only test
values. With Xvfb installed, run:

```sh
xvfb-run -a cargo test -p chamber-ui copied_text_survives_return_and_can_be_replaced -- --ignored
```

## Locking

### What a lock does

The TUI locks after five minutes without a key press while a vault is unlocked. The
timeout is fixed; there is no setting to change it. Only key presses count as
activity: mouse, resize, and key-release events do not. A key press that arrives
after the timeout has passed locks the session and is discarded. There is no timer
or countdown while the TUI is locked, including at startup and on the setup form.

When it locks, the TUI:

- drops the vault key from memory, and closes any other vaults it holds open;
- clears the decrypted items it holds, the viewed or edited item, password fields,
  add and edit drafts, the search text, the import/export path, the vault selector
  input, and any generated password;
- replaces the add-item editor with a fresh one, discarding its undo history and
  yank buffer;
- resets search mode, revealed values, selection, and focus, and hides the vault
  selector;
- clears the clipboard as described below;
- shows the unlock screen with the status message "Locked due to inactivity".

Unsaved edits are discarded without saving or prompting, and an open dialog does
not prevent the lock. The master key is needed to unlock again.

### Suspend and clock changes

Time the machine spends suspended counts toward the timeout, so a machine suspended
for longer than five minutes shows the unlock screen on resume. The timer follows
both a monotonic clock and the wall clock and uses whichever reports more elapsed
time. Setting the system clock forward can therefore lock early, and setting it
backward cannot extend a session.

### Clipboard at lock

When a value is copied, the TUI remembers a SHA-256 digest of it, not the value
itself. At lock:

- If the clipboard still holds the copied value, it is cleared.
- If the clipboard was replaced with different text, or holds no text, it is left
  alone.
- If the clipboard cannot be read, it is cleared anyway.
- If nothing was copied during the session, the clipboard is not read or touched.

The digest is then removed and the retained clipboard connection is released. The
connection described under "Clipboard" is therefore kept only until the TUI locks,
not for as long as it runs. If clearing fails, the lock still completes and the
status bar shows:
"Locked due to inactivity. Clipboard could not be cleared."

Clearing happens only at lock: there is no timer-based clearing and no clearing
after a paste. Entries a clipboard manager has already saved to its history, and
values already pasted into other applications, are outside the TUI's reach.

### Memory limits

After a lock, no live application state can show or restore values from the ended
session, and secret buffers the TUI owns directly are overwritten before they are
released. This does not mean every copy is gone: earlier copies made by the memory
allocator, operating system pages, the terminal's own buffers, and private
allocations inside dependencies may still exist. Replacing the add-item editor drops
its private undo history and yank storage, but those allocations are released, not
proven to be overwritten.
