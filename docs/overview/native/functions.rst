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

You can hook and replace functions. For native functions, you can either use an
integer (which simply replaces the entire function and returns that integer
instead), or a string that contains javascript that will be executed.

For the javascript replace, a special variable is created for you called
``original``. You can assume this variable will always be there and will always
be the original function you are replacing. This allows you to call down to the
original function if needed, either replacing arguments, return types, or
simply proxying the call.

To get data back from inside your replacement function, you need to define
replace_on_message. That variable needs to be a callable that takes in at least
one argument (the return from the script). Otherwise, all return sends will
simply be ignored.

Sometimes it's easier to just attach to the entry or exit of the function
rather than replacing it. You can do this via the ``on_enter`` method, in the
same way as you would for ``replace``. The only difference is that you do not
have to worry about calling the function, as that will be done automatically
after your code completes.

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

More examples in the code.

:meth:`revenge.memory.MemoryBytes.replace`

:meth:`revenge.memory.MemoryBytes.on_enter`

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

Building Functions With C
=========================
As of ``frida`` version 12.7, there is now support for injecting code simply as
C. The backend of ``frida`` takes care of compiling it and injecting.
``revenge`` now exports this in a super easy to use way through the
:meth:`~revenge.memory.Memory.create_c_function` method.

``revenge`` extends this also by making it easier to perform function calls
anywhere in process space. It does this by creating a run-time function
defition based on the current known address of the function. See example.

Examples
--------

    .. code-block:: python3

        add = process.memory.create_c_function(r"""
            int eq(int x, int y) { 
                return x==y;
            }""")

        assert add(4,1) == 5

        #
        # Runtime function calling 
        #

        # Suppose we want to call strlen, we need to export it as a callable
        # function. Since we're compiling C code, the compiler has no idea
        # where this function really is, and will throw an exception. However,
        # revenge allows you to easily tell the compiler where it is and run as
        # if you compiled with the application itself.

        # Grab the strlen address
        strlen = process.memory[':strlen']

        # Setup strlen's argument and return types
        strlen.argument_types = types.StringUTF8
        strlen.return_type = types.Int

        # Main difference is that we're adding a keyword arg to say
        # "export/link in strlen here". So long as you've defined the
        # MemoryBytes object, this can be anywhere, not just exported symbols.

        my_strlen = process.memory.create_c_function(r"""
            int my_strlen(char *s) { return strlen(s); }
            """, strlen=strlen)

        assert my_strlen("blerg") == 5
