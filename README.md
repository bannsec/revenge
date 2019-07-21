[![Build Status](https://travis-ci.org/bannsec/frida-util.svg?branch=master)](https://travis-ci.org/bannsec/frida-util)
[![PyPI Statistics](https://img.shields.io/pypi/dm/frida-util.svg)](https://pypistats.org/packages/frida-util)
[![Latest Release](https://img.shields.io/pypi/v/frida-util.svg)](https://pypi.python.org/pypi/frida-util/)
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

## Windows Messages (Temporarily broken)
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
{'0x55d78c422250': 'StringUTF8', '0x55d78c453820': 'StringUTF8'}
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
Out[1]: <frida_util.process.Process at 0x7fa036bc14e0>
```

## General Options
Replacing functions dynamically during execution
```
# Replace function located at offset 0x64a in a.out binary, returning value 0x123
frida-util stalk ./a.out --resume -rf "a.out:0x64a?0x123"

# Disable alarm and ptrace functions
frida-util stalk test2 -f ./test2 --resume -rf ":alarm?1" ":ptrace?1"
```

## Python Class Interaction
```python
import frida_util

# Any flag you pass command-line can be passed into the constructor
# Start up /bin/ls
process = frida_util.Process("/bin/ls", resume=False, verbose=False)
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

# Grab map entry by ip
>>> m = process.memory.maps[564031418123]

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

# Change permissions on a map
>>> mem = process.memory.maps[0x12345]
>>> mem.protection = 'rwx'

# Disassemble from memory
>>> print(process.memory['a.out:main'].instruction_block)
0x804843a: lea        ecx, [esp + 4]
0x804843e: and        esp, 0xfffffff0
0x8048441: push       dword ptr [ecx - 4]
0x8048444: push       ebp
0x8048445: mov        ebp, esp
0x8048447: push       ebx
0x8048448: push       ecx
0x8048449: sub        esp, 0x10
0x804844c: call       0x8048360

# Or just analyze one instruction at a time
>>> process.memory['a.out:main'].instruction
<AssemblyInstruction 0x804843a lea ecx, [esp + 4]>
```

### Threads
```python
# List threads
>>> print(process.threads)
"""
+-------+---------+----------------+--------------+-------+
|   id  |  state  |       pc       |    module    | Trace |
+-------+---------+----------------+--------------+-------+
| 81921 | waiting | 0x7f2d9b2759d0 | libc-2.27.so |   No  |
+-------+---------+----------------+--------------+-------+
"""

>>> list(process.threads)
[<Thread 0x73c6 @ 0x7feeb83439d0 waiting (libc-2.27.so)>]

# Look at individual thread
t = process.threads[29638]

>>> t
<Thread 0x73c6 @ 0x7feeb83439d0 waiting (libc-2.27.so) tracing>

>>> print(t)
"""
+----------+--------------------+
| TID      | 81921              |
| State    | waiting            |
| Module   | libc-2.27.so       |
| Tracing? | Yes                |
| pc       | 0x7f2d9b2759d0     |
| sp       | 0x7ffc0e1eef40     |
| rax      | 0xfffffffffffffdfc |
| rcx      | 0x7f2d9b2759d0     |
| rdx      | 0x0                |
| rbx      | 0x7ffc0e1eef70     |
| rsp      | 0x7ffc0e1eef40     |
| rbp      | 0x7ffc0e1eef80     |
| rsi      | 0x7ffc0e1eef80     |
| rdi      | 0x7ffc0e1eef70     |
| r8       | 0x0                |
| r9       | 0x0                |
| r10      | 0x7f2d9b83c1a0     |
| r11      | 0x293              |
| r12      | 0x2                |
| r13      | 0x7f2d98327200     |
| r14      | 0x3                |
| r15      | 0x7f2d9b891a10     |
| rip      | 0x7f2d9b2759d0     |
+----------+--------------------+
"""
```

### Functions
```python
# Call strlen on a string
>>> strlen = process.memory[':strlen']
>>> strlen('hello world')
11

# You can specify the arg types if you need to
>>> abs = process.memory[':abs']
>>> abs(types.Int(-12))
12

# Sometimes you need to define what you're expecting to get in return
>>> atof = process.memory[':atof']
>>> atof.return_type = types.Double # Way to be confusing libc...
>>> atof('12.123')
12.123

# Replace function 'alarm' to do nothing and simply return 1
>>> alarm = process.memory[':alarm']
>>> alarm.replace = 1

# Un-replace alarm, reverting it to normal functionality
>>> alarm.replace = None
```

### Tracing
```python
# Trace calls and rets
>>> t = process.tracer.instructions(call=True, ret=True)
>>> print(list(t)[0])
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

# Trace all instructions executed only in 'ls'
>>> t = process.tracer.instructions(exec=True, from_module='ls')
```

### Modules
```python
# List current modules
>>> print(process.modules)
"""
+--------------------+----------------+-----------+---------------------------------------------------------------+
|        name        |      base      |    size   | path                                                          |
+--------------------+----------------+-----------+---------------------------------------------------------------+
|       test2        | 0x557781b84000 |  0x202000 | /home/user/tmp/test2                                          |
|  linux-vdso.so.1   | 0x7ffd3b5ee000 |   0x2000  | linux-vdso.so.1                                               |
|    libc-2.27.so    | 0x7fc6a8499000 |  0x3ed000 | /lib/x86_64-linux-gnu/libc-2.27.so                            |
|     ld-2.27.so     | 0x7fc6a888a000 |  0x229000 | /lib/x86_64-linux-gnu/ld-2.27.so                              |
| libpthread-2.27.so | 0x7fc6a827a000 |  0x21b000 | /lib/x86_64-linux-gnu/libpthread-2.27.so                      |
| frida-agent-64.so  | 0x7fc6a6294000 | 0x17ba000 | /tmp/frida-7846ef0864a82f3695599c271bf7b0f1/frida-agent-64.so |
| libresolv-2.27.so  | 0x7fc6a6079000 |  0x219000 | /lib/x86_64-linux-gnu/libresolv-2.27.so                       |
|   libdl-2.27.so    | 0x7fc6a5e75000 |  0x204000 | /lib/x86_64-linux-gnu/libdl-2.27.so                           |
|   librt-2.27.so    | 0x7fc6a5c6d000 |  0x208000 | /lib/x86_64-linux-gnu/librt-2.27.so                           |
|    libm-2.27.so    | 0x7fc6a58cf000 |  0x39e000 | /lib/x86_64-linux-gnu/libm-2.27.so                            |
+--------------------+----------------+-----------+---------------------------------------------------------------+
"""

# Get the base address for specific module
>>> hex(process.modules['test2'].base)
0x557781b84000

# Or by glob
>>> process.modules['libc*']
<Module libc-2.27.so @ 0x7f282f7aa000>

# Or resolve address into corresponding module
>>> process.modules[0x7f282f7ab123]
<Module libc-2.27.so @ 0x7f282f7aa000>
```
### File Format Parsing In Memory
```python
# Grab elf parser for the given module (WIP)
>>> elf = process.modules['ls'].elf
```

### Symbols
```python
# Grab symbol address for main function in my_bin
>>> main = process.modules['my_bin'].symbols['main']
```

### Android
Android support is in development. That said, there's some basic support right now. All low-level interactions should be the same as interactions on any other system (see Memory/Threads/etc from above).

```python
from frida_util import Process, types, common, device_types

# Connect up to the android device (options)
>>> android = device_types.AndroidDevice(type="usb")
>>> android = device_types.AndroidDevice(id="emulator-5554")
<AndroidDevice emulator-5554>

# List processes
>>> android.device.enumerate_processes()
"""
<clip>
 Process(pid=1502, name="tombstoned"),
 Process(pid=1503, name="android.hardware.biometrics.fingerprint@2.1-service"),
 Process(pid=1506, name="iptables-restore"),
 Process(pid=1507, name="ip6tables-restore"),
 Process(pid=1604, name="dhcpclient"),
 Process(pid=1607, name="sh"),
 Process(pid=1608, name="sleep"),
 Process(pid=1619, name="ipv6proxy"),
 Process(pid=1622, name="hostapd"),
 Process(pid=1624, name="dhcpserver"),
 Process(pid=1633, name="system_server"),
 Process(pid=1740, name="com.android.inputmethod.latin"),
 Process(pid=1748, name="com.android.systemui"),
 Process(pid=1790, name="webview_zygote32"),
 Process(pid=1846, name="wpa_supplicant"),
 Process(pid=1851, name="com.android.phone"),
<clip>
"""

# List applications
>>> list(android.applications)
"""
<clip>
 Application(identifier="com.android.dialer", name="Phone", pid=2084),
 Application(identifier="com.android.gallery3d", name="Gallery"),
 Application(identifier="com.android.emulator.smoketests", name="Emulator Smoke Tests"),
 Application(identifier="android.ext.services", name="Android Services Library", pid=2566),
 Application(identifier="com.android.packageinstaller", name="Package installer"),
 Application(identifier="com.svox.pico", name="Pico TTS"),
 Application(identifier="com.android.proxyhandler", name="ProxyHandler"),
 Application(identifier="com.android.inputmethod.latin", name="Android Keyboard (AOSP)", pid=1740),
 Application(identifier="org.chromium.webview_shell", name="WebView Shell"),
 Application(identifier="com.android.managedprovisioning", name="Work profile setup"),
<clip>
"""

# Launch application and retrieve corresponding frida_util.Process instance
>>> p = android.spawn("com.android.email", gated=False, load_symbols="*dex")
<Process <pre-initialized>:4335>
>>> calc = android.applications['*calc*']
>>> p = android.spawn(calc, gated=False, load_symbols="*dex")
>>> # Or...
>>> p = android.attach("*calc*", load_symbols="*dex")

# Send a log to logcat
>>> log = p.java.classes['android.util.Log']
>>> log.w("Hello", "world!")()

# Unrandomize random
>>> Math = p.java.classes['java.lang.Math']
>>> Math.random.implementation = "function () { return 12; }"
>>> Math.random()()
12
>>> Math.random.implementation = None
>>> Math.random()()
0.8056030012322106

# Run adb command for your connected device
>>> android.adb("shell ps -ef")

# Install/Uninstall packages
>>> android.install("something.apk")
>>> android.uninstall("com.blerg.something")
>>> android.uninstall(android.applications['*something*'])

# Interact with shell on device
>>> android.shell()

# Batch Context (for performance/brute forcing)
>>> def on_message(messages):
        for item, ret in messages:
            if ret == 1234:
                print("Found " + item)

>>> with process.BatchContext(on_message=on_message) as context:
        for i in range(1024):
            some_call_here(args)(context=context)

# Attach to running MainActivity instance and run method
>>> MainActivity = p.java.classes[<main_activity>]
>>> MainActivity = p.java.find_active_instance(MainActivity)
>>> MainActivity.some_method()()
```
