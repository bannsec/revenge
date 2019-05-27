# Overview
This is meant to be a similar functionality to `frida-trace`, but to allow for easier `Stalk` functionality.

# Examples

## Windows Messages
```bash
# Automatically discover Windows message handling locations and show event messages as they are handled.
frida-stalk -I notepad.exe windows_messages notepad.exe

# Only show information about windows message WM_CHAR and WM_KEYDOWN from notepad.exe
frida-stalk -I notepad.exe -rw windows_messages notepad.exe -wm WM_CHAR WM_KEYDOWN
```
