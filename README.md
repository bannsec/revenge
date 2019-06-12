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

# Platforms
The goal is for this to be mostly platform independent. Since the backend is python and Frida, it should support Windows, Mac, Linux and Android. YMMV.

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

## IPython
Drop into an interactive shell from the command line
```
$ frida-util ipython ls -f /bin/ls
Spawning file                   ... [ DONE ]
Attaching to the session        ... [ DONE ]
Enumerating modules             ... [ DONE ]
Python 3.6.7 (default, Oct 22 2018, 11:32:17)
Type 'copyright', 'credits' or 'license' for more information
IPython 7.5.0 -- An enhanced Interactive Python. Type '?' for help.

In [1]: process
Out[1]: <frida_util.util.Util at 0x7fa036bc14e0>
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
process = frida_util.Util(action="find", target="ls", file="/bin/ls", resume=False, verbose=False)
```

### Memory
```python
# Read string from memory at ls + 0x12345
>>> process.memory['ls:0x12345'].string_utf8

# Set re-write breakpoint (not int3, not hardware) at strcmp
>>> process.memory[':strcmp'].breakpoint = True

# "Continue" execution from strcmp break
>>> process.memory[':strcmp'].breakpoint = False

# Write a 16-bit signed int somewhere known in memory
>>> process.memory[0x12345].int16 = -55

# Extract a range of bytes
>>> process.memory[0x12345:0x12345+32].bytes

# Write bytes into memory
>>> process.memory[0x12345:0x12345+32].bytes = b'AB\x13\x37'

# Print memory map
>>> print(process.memory)
"""
 564031418000-56403141d000          r-x  /bin/ls
 56403141d000-56403141e000          rwx  /bin/ls
 56403141e000-564031437000          r-x  /bin/ls
 564031636000-564031638000          r--  /bin/ls
 564031638000-564031639000          rw-  /bin/ls
 564031639000-56403163a000          rw-
 5640326bd000-5640326de000          rw-
 7f07f0000000-7f07f0021000          rw-
 7f07f8000000-7f07f8021000          rw-
 7f07fc272000-7f07fca72000          rw-
 7f07fca73000-7f07fd273000          rw-
 7f07fd274000-7f07fda74000          rw-
 7f07fda75000-7f07fe275000          rw-
 7f07fe275000-7f07fe412000          r-x  /lib/x86_64-linux-gnu/libm-2.27.so
 7f07fe611000-7f07fe612000          r--  /lib/x86_64-linux-gnu/libm-2.27.so
 7f07fe612000-7f07fe613000          rw-  /lib/x86_64-linux-gnu/libm-2.27.so
 7f07fe613000-7f07fe61a000          r-x  /lib/x86_64-linux-gnu/librt-2.27.so
 7f07fe819000-7f07fe81a000          r--  /lib/x86_64-linux-gnu/librt-2.27.so
 7f07fe81a000-7f07fe81b000          rw-  /lib/x86_64-linux-gnu/librt-2.27.so
 7f07fffd5000-7f0800000000          rw-
 7f0800000000-7f0800021000          rw-
 7f0804013000-7f080402a000          r-x  /lib/x86_64-linux-gnu/libresolv-2.27.so
 7f080422a000-7f080422b000          r--  /lib/x86_64-linux-gnu/libresolv-2.27.so
 7f080422b000-7f080422c000          rw-  /lib/x86_64-linux-gnu/libresolv-2.27.so
 7f080422c000-7f080422e000          rw-
 7f080422f000-7f0804a2f000          rw-
 7f0804a2f000-7f0804a49000          r-x  /lib/x86_64-linux-gnu/libpthread-2.27.so
 7f0804c48000-7f0804c49000          r--  /lib/x86_64-linux-gnu/libpthread-2.27.so
 7f0804c49000-7f0804c4a000          rw-  /lib/x86_64-linux-gnu/libpthread-2.27.so
 7f0804c4a000-7f0804c4e000          rw-
 7f0804c4e000-7f0804c51000          r-x  /lib/x86_64-linux-gnu/libdl-2.27.so
 <clipped>
"""

# Iterate through the memory map
>>> [map for map in process.memory.maps]

# Allocate some space
>>> mem = process.memory.alloc(128)

# Free it up when done
>>> mem.free()

# Allocate a string in memory
>>> mem = process.memory.alloc_string("Hello!")

# Look for something in memory
>>> f = process.memory.find(types.StringUTF8('/bin/sh'))
<MemoryFind found 1 completed>
>>> [hex(x) for x in f]
['0x7f9c1f3ede9a']
```

### Threads
```python
# List threads
>>> print(process.threads)
"""
+-------+---------+----------------+--------------+
|   id  |  state  |       pc       |    module    |
+-------+---------+----------------+--------------+
| 29638 | waiting | 0x7feeb83439d0 | libc-2.27.so |
+-------+---------+----------------+--------------+
"""

>>> list(process.threads)
[<Thread 0x73c6 @ 0x7feeb83439d0 waiting (libc-2.27.so)>]

# Look at individual thread
t = process.threads[29638]

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

### Functions
```python
# Call strlen on a string
>>> strlen = process.memory[':strlen']
>>> strlen('hello world')
11

# You can specify the arg types if you need to=
>>> abs = process.memory[':abs']
>>> abs(types.Int(-12))
12

# Sometimes you need to define what you're expecting to get in return
>>> atof = process.memory[':atof']
>>> atof.return_type = types.Double # Way to be confusing libc...
>>> atof('12.123')
12.123
```

### Tracing
```python
# Trace calls and rets
>>> t = process.tracer.instructions(call=True, ret=True)
>>> list(map(print, list(t)[0]))
call      libc-2.27.so:0x7f4b704f89de   -> libc-2.27.so:0x7f4b70544740
ret       libc-2.27.so:0x7f4b7054476f   -> libc-2.27.so:0x7f4b704f89e3
ret       libc-2.27.so:0x7f4b704f89ed   -> frida-agent-64.so:0x7f4b6df41216
ret       ld-2.27.so:0x7f4b70c420a5     -> ls:0x5613ad9b2030
call      ls:0x5613ad997874             -> libc-2.27.so:0x7f4b70435ab0
call      libc-2.27.so:0x7f4b70435af7   -> libc-2.27.so:0x7f4b70457430
call      libc-2.27.so:0x7f4b70457484   -> libc-2.27.so:0x7f4b70457220
ret       libc-2.27.so:0x7f4b704572e7   -> libc-2.27.so:0x7f4b70457489
<clipped>


# Trace all instructions executed
>>> t = process.tracer.instructions(exec=True)
```
