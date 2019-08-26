=========
Functions
=========

Args and Return Types
=====================

In some cases, ``revenge`` will be able to identify (or guess) correctly the
arugment types and return types for the function. However, in some cases you
may need to tell it what to expect.

Examples
--------

.. code-block:: python3

    atof = process.memory[':atof']

    # Tell revenge what the return type should be
    atof.return_type = revenge.types.Double

    # Not needed in this case, but you can tell revenge explicitly the
    # parameter type
    atof.argument_types = revenge.types.StringUTF8


Calling Functions
=================

You can generically call native functions by first creating a memory object for
them. Once you have that object, you usually can call it directly. This is due
to some backend magic that attempts to identify argument and return types, and
if it fails it falls back to integers.

However, sometimes that's not enough, and you need to tell ``revenge`` what
types to send and/or expect back. Luckily, that's fairly strait forward.

Examples
--------

.. code-block:: python3

    import revenge
    process = revenge.Process("/bin/ls", resume=False, verbose=False)

    # Grab memory object for strlen
    strlen = process.memory[':strlen']

    # Call it directly on a string
    strlen("test")
    4

    # You can specify the arg types if you need to
    abs = process.memory[':abs']
    abs(types.Int(-12))
    12

    # Sometimes you need to define what you're expecting to get in return
    atof = process.memory[':atof']
    atof.return_type = revenge.types.Double
    atof('12.123')
    12.123

Function Hooking
================

You can hook and replace functions. For native functions, at the moment, you
can replace a function with any return value.

Examples
--------

.. code-block:: python3

    import revenge
    process = revenge.Process("/bin/ls", resume=False, verbose=False)

    # Replace function 'alarm' to do nothing and simply return 1
    alarm = process.memory[':alarm']
    alarm.replace = 1

    # Un-replace alarm, reverting it to normal functionality
    alarm.replace = None

Disassembly
===========

You can disassemble in memory using ``revenge`` via the memory object.

Examples
--------

.. code-block:: python3

    import revenge
    process = revenge.Process("a.out", resume=False, verbose=False)

    print(process.memory['a.out:main'].instruction_block)
    """
    0x804843a: lea        ecx, [esp + 4]
    0x804843e: and        esp, 0xfffffff0
    0x8048441: push       dword ptr [ecx - 4]
    0x8048444: push       ebp
    0x8048445: mov        ebp, esp
    0x8048447: push       ebx
    0x8048448: push       ecx
    0x8048449: sub        esp, 0x10
    0x804844c: call       0x8048360
    """

    # Or just analyze one instruction at a time
    process.memory['a.out:main'].instruction
    """<AssemblyInstruction 0x804843a lea ecx, [esp + 4]>"""
