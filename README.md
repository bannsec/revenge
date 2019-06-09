[![Build Status](https://travis-ci.org/bannsec/frida-util.svg?branch=master)](https://travis-ci.org/bannsec/frida-util)
[![PyPI Statistics](https://img.shields.io/pypi/dm/frida-util.svg)](https://pypistats.org/packages/frida-util)
[![Coverage Status](https://coveralls.io/repos/github/bannsec/frida-util/badge.svg?branch=master)](https://coveralls.io/github/bannsec/frida-util?branch=master)

# Overview
This is meant to be a similar functionality to `frida-trace`, but to allow for easier `Stalk` functionality.

# Install
```
pip3 install https://github.com/bannsec/frida-util/archive/master.zip

# Or
pip3 install frida-util
```

# Examples

## Windows Messages
Specifically watching Windows Messages handling

```bash
# Automatically discover Windows message handling locations and show event messages as they are handled.
frida-util -I notepad.exe windows_messages notepad.exe

# Only show information about windows message WM_CHAR and WM_KEYDOWN from notepad.exe
frida-util -I notepad.exe -rw windows_messages notepad.exe -wm WM_CHAR WM_KEYDOWN
```

## Stalking
Use Frida stalk to trace through things

```
# Only look at traces from notepad's Windows Message handler function
frida-util stalk notepad.exe --include-function notepad.exe:0x3a50 -I notepad.exe
```

## Find
Find things in memory.

```
# Find where your string 'hello world' is in notepad (will check for char and wchar versions)
frida-util find notepad.exe --string "Hello world"
```

## General Options
Replacing functions dynamically during execution
```
# Replace function located at offset 0x64a in a.out binary, returning value 0x123
frida-util stalk a.out -f ./a.out --resume -rf "a.out:0x64a?0x123"

# Disable alarm and ptrace functions
frida-util stalk test2 -f ./test2 --resume -rf ":alarm?1" ":ptrace?1"
```

## Python Class Interaction
```python
import frida_util

# Any flag you pass command-line can be passed into the constructor
# Start up /bin/ls
util = frida_util.Util(action="find", target="ls", file="/bin/ls", resume=False, verbose=False)
```

### Memory
```python
# Read string from memory at ls + 0x12345
util.memory['ls:0x12345'].string_utf8

# Set re-write breakpoint (not int3, not hardware) at strmp
util.memory[':strcmp'].breakpoint = True

# "Continue" execution from strcmp break
util.memory[':strcmp'].breakpoint = False

# Write a 16-bit signed int somewhere known in memory
util.memory[0x12345].int16 = -55

# Extract a range of bytes
util.memory[0x12345:0x12345+32].bytes
```

### Threads
```python
# List threads
>>> print(util.threads)
"""
+-------+---------+----------------+--------------+
|   id  |  state  |       pc       |    module    |
+-------+---------+----------------+--------------+
| 29638 | waiting | 0x7feeb83439d0 | libc-2.27.so |
+-------+---------+----------------+--------------+
"""

>>> list(util.threads)
[<Thread 0x73c6 @ 0x7feeb83439d0 waiting (libc-2.27.so)>]

# Look at individual thread
t = util.threads[29638]

>>> t
<Thread 0x73c6 @ 0x7feeb83439d0 waiting (libc-2.27.so)>

>>> print(t)
"""
+--------+--------------------+
| TID    | 29638              |
| State  | waiting            |
| Module | libc-2.27.so       |
| pc     | 0x7feeb83439d0     |
| sp     | 0x7ffcd66cf4a0     |
| rax    | 0xfffffffffffffdfc |
| rcx    | 0x7feeb83439d0     |
| rdx    | 0x0                |
| rbx    | 0x7ffcd66cf4d0     |
| rsp    | 0x7ffcd66cf4a0     |
| rbp    | 0x7ffcd66cf4e0     |
| rsi    | 0x7ffcd66cf4e0     |
| rdi    | 0x7ffcd66cf4d0     |
| r8     | 0x0                |
| r9     | 0x0                |
| r10    | 0x7feeb8946750     |
| r11    | 0x293              |
| r12    | 0x2                |
| r13    | 0x7feeb899e8a0     |
| r14    | 0x3                |
| r15    | 0x7feeb43ed040     |
| rip    | 0x7feeb83439d0     |
+--------+--------------------+
"""
```
