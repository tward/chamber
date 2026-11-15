# Chamber UI

Terminal user interface (TUI) for the Chamber secrets' manager. Provides an interactive, keyboard-driven interface for managing secrets with a modern terminal-based user experience.

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
