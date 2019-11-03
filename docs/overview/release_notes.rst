=============
Release Notes
=============

Version 0.15
============

- Implemented ability to call native function in it's own thread, instead of
  from frida's core thread
  
  - This will be done transparently, but can be done manually by calling
    :meth:`revenge.memory.MemoryBytes._call_as_thread`
- Implemented :ref:`techniques-page` to make common sets of actions more
  generic
- ``InstructionTracer`` is now
  :class:`~revenge.techniques.tracer.NativeInstructionTracer`
- :class:`~revenge.techniques.tracer.NativeInstructionTracer`
  now supports two new options

  - ``include_function`` allows you to specify a specific function to trace.
    This will cause revenge to ignore any trace before or after that function
    call.
  - ``exclude_ranges`` allows you to specify ranges of memory to be ignored
    from the trace
- Created :class:`~revenge.native_error.NativeError` class to generically
  handle ``errno``.
- :class:`~revenge.techniques.Technique` mixin now also has optional method of
  :meth:`~revenge.techniques.Technique._technique_code_range` that will get
  passed any known revenge/frida specific code ranges that can be ignored
- :class:`~revenge.threads.Thread` changes

  - Implemented :meth:`~revenge.threads.Thread.join` to allow for retrieving
    thread exit codes
  - Threads will now have `pthread_id` attribute if they were spawned on Linux.
  - Bugfix in :meth:`~revenge.threads.Threads.create`
- Implemented ``batch_send`` js include to make it easier to handle pushing
  lots of data back

Version 0.14
============

- argv and envp options added to :class:`~revenge.Process` spawning
- Added :meth:`revenge.threads.Threads.create` to simplify kicking off a thread
- Simplified symbol resolution, you can now use ``process.memory['symbol']``
  directly as well as ``process.memory['symbol+offset']``
- threads is now a submodule
- Can now create dummy thread for hidden Frida thread
- CPUContexts have been moved to :mod:`revenge.cpu.contexts`
- Tracer assembly has been moved to :mod:`revenge.cpu.assembly`


Version 0.13
============

- Implemented Frida's new ``CModule`` support as
  :meth:`~revenge.memory.Memory.create_c_function`.

  - Also added support to make calling dynamic functions easier by passing them
    as kwargs to the constructor. See examples in code doc.

- Added ``js_include`` option to :meth:`~revenge.Process.run_script_generic` to
  enable javascript library/code reuse type things
- Implemented ``telescope.js`` and :class:`~revenge.types.Telescope` for
  initial telescoping variable support
- ``revenge.device_types`` is now called :mod:`~revenge.devices`.
- Added :meth:`~revenge.Process.quit` to enable closing the process explicitly.
- Travis test cases are a bit more stable now.
- Implemented :meth:`~revenge.memory.MemoryRange._from_frida_find_json` to
  allow for loading of MemoryRange objects directly from Frida json.

Version 0.12
============

- Added ``__call__`` to :class:`~revenge.symbols.Symbol` allowing for
  ``symbol()`` function call directly from the symbol class.
- Added Symbol :meth:`~revenge.symbols.Symbol.memory` as a shortcut to get the
  MemoryBytes object for said symbol.
- Implemented new type for :class:`~revenge.types.Struct`. It's now much easier
  to both define, set, and read memory structures.
- Implemented :class:`~revenge.memory.Memory` ``__setitem__``, allowing for
  setting memory implicitly based on type. Example:

    .. code-block:: python3

        process.memory[0x12345] = types.Int16(5)

- Implemented MemoryBytes :meth:`~revenge.memory.MemoryBytes.cast`, allowing
  for more programmatic retrieval based on type.
- Stability improvements

Version 0.11
=============

- Updated :meth:`revenge.threads.Threads.__repr__` to use descriptive addresses
- Added 0.5 second cache to :class:`~revenge.modules.Modules` to improve performance.
- Many updates to :meth:`revenge.tracer.instruction_tracer.Trace.__str__` to
  improve readabiliy (descriptive addrs, indentation, programmatic spacing)
- Implemented :meth:`~revenge.modules.Module.plt` to identify the base of the
  Procedure Lookup Table in ELF.
- Implemented and incorporated GOT and PLT symbols into
  :meth:`~revenge.modules.Module.symbols`. They will also now resolve on traces
  i.e.: symbol['got.printf'] or symbol['plt.printf']
- Symbols returned from :meth:`~revenge.modules.Module.symbols` are now
  actually an object: :class:`~revenge.symbols.Symbol`.
- Updated slice for :class:`~revenge.tracer.instruction_tracer.Trace` so that
  trace[:12], for instance, now returns a new Trace object with those
  instructions instead of just a list.
- entrypoint_rebased no longer exists. Now, just use
  :meth:`~revenge.Process.entrypoint`
- Tests/docs updates

Version 0.10
=============

- Added :meth:`revenge.memory.MemoryBytes.argument_types` to allow a single or
  list/tuple of argument types for the function
- Added :meth:`revenge.memory.MemoryBytes.replace` javascript string option.
  Now, you also have the option to set the replace to a javascript string that
  will replace the given function.
- Added ``original`` global variable for ``MemoryBytes.replace`` to allow you
  to more easily chain a call into the original native function.
- Aliased :meth:`revenge.memory.MemoryBytes.implementation` to 
  ``MemoryBytes.replace`` to standardize the naming convention with
  ``JavaClass.implementation``.
