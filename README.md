[![Build Status](https://travis-ci.org/bannsec/revenge.svg?branch=master)](https://travis-ci.org/bannsec/revenge)
[![PyPI Statistics](https://img.shields.io/pypi/dm/revenge.svg)](https://pypistats.org/packages/revenge)
[![Latest Release](https://img.shields.io/pypi/v/revenge.svg)](https://pypi.python.org/pypi/revenge/)
[![Coverage Status](https://coveralls.io/repos/github/bannsec/revenge/badge.svg?branch=master)](https://coveralls.io/github/bannsec/revenge?branch=master)
[![Documentation Status](https://readthedocs.org/projects/revenge/badge/?version=latest)](http://revenge.readthedocs.org/en/latest/?badge=latest)

# REVerse ENGineering Environment (revenge)
Attempting to make a centralized binary reverse engineering framework for
python. Initially, this makes heavy use of `frida` in the backend, but should
be expandable and has already gone beyond Frida in some ways.

# Install
```
pip3 install https://github.com/bannsec/revenge/archive/master.zip

# Or
pip3 install revenge
```

# Platforms
The goal is for this to be mostly platform independent. Since the backend is python and Frida, it should support Windows, Mac, Linux and Android. YMMV.

# Docs
Check out RTD for the documentation: http://revenge.readthedocs.org/en/latest/

# Examples

## Windows Messages (Temporarily broken)
Specifically watching Windows Messages handling

```bash
# Automatically discover Windows message handling locations and show event messages as they are handled.
revenge -I notepad.exe windows_messages notepad.exe

# Only show information about windows message WM_CHAR and WM_KEYDOWN from notepad.exe
revenge -I notepad.exe -rw windows_messages notepad.exe -wm WM_CHAR WM_KEYDOWN
```

## Stalking
Use Frida stalk to trace through things

```
# Only look at traces from notepad's Windows Message handler function
revenge stalk notepad.exe --include-function notepad.exe:0x3a50 -I notepad.exe
```

## Find
Find things in memory.

```
# Find where your string 'hello world' is in notepad (will check for char and wchar versions)
revenge find notepad.exe --string "Hello world"
{'0x55d78c422250': 'StringUTF8', '0x55d78c453820': 'StringUTF8'}
```

## IPython
Drop into an interactive shell from the command line
```
$ revenge ipython ls -f /bin/ls
Spawning file                   ... [ DONE ]
Attaching to the session        ... [ DONE ]
Enumerating modules             ... [ DONE ]
Python 3.6.7 (default, Oct 22 2018, 11:32:17)
Type 'copyright', 'credits' or 'license' for more information
IPython 7.5.0 -- An enhanced Interactive Python. Type '?' for help.

In [1]: process
Out[1]: <revenge.process.Process at 0x7fa036bc14e0>
```

## General Options
Replacing functions dynamically during execution
```
# Replace function located at offset 0x64a in a.out binary, returning value 0x123
revenge stalk ./a.out --resume -rf "a.out:0x64a?0x123"

# Disable alarm and ptrace functions
revenge stalk test2 -f ./test2 --resume -rf ":alarm?1" ":ptrace?1"
```
