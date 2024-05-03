=============
Release Notes
=============

Version 0.22
============

- Silly Path string bug for older version of python fixed

Version 0.21
============

- Lots changed while I was away. Slightly less broken now...
- Had to change how breaking on start works. Specifically, if you don't choose
  auto-resume on start, the process will be suspended instead of breakpointed
  at the entrypoint. This is due to changes in Frida.

Version 0.20
============

- Introducing new :class:`~revenge.plugins.angr.Angr` plugin that allows you to
  pick up an angr state at virtually any point in execution
- :class:`~revenge.threads.Thread` now shows breakpoint register information
  when at a breakpoint instead of actual internal state
- You can now register a plugin to specifically be a
  :class:`~revenge.threads.Thread` plugin the same way as modules
- Better Windows handling

  - Automatically breaks at process exit (like linux)
  - Unbuffers stdout (like linux)
  - Exposed :attr:`revenge.modules.Module.pe` to manually use PEFile
  - Implemented :attr:`~revenge.process.Process.entrypoint` finding
  - Properly handle radare2 not being installed

- Created :meth:`revenge.process.Process.resume` to generically allow resuming
  of all paused threads
- Created new technique for
  :class:`~revenge.techniques.native_instruction_counter.NativeInstructionCounter`
  to more easily allow counting instructions executed
- General updates and bug fixes

Version 0.19
============

- Added exception catching for the main thread. Any exceptions encountered will
  now be added to :attr:`~revenge.threads.Thread.exceptions`
- You can now expect output by supplying a string or bytes to 
  :meth:`~revenge.process.Process.stdout` or
  :meth:`~revenge.process.Process.stderr`
- Added ability to :meth:`~revenge.threads.Thread.kill` your thread more
  easily
- Modules can now have plugins registered with
  :meth:`~revenge.modules.Modules._register_plugin`
- The radare2 plugin is now a Module plugin
- Added initial DWARF decompiler
- All remote file loads will use a local cache, speeding up access times
- Backend updates to batch sending and timeless tracer
- Updated for frida api changing

Version 0.18
============

- Added ability to programmatically talk to
  :meth:`~revenge.process.Process.stdin`,
  :meth:`~revenge.process.Process.stdout`, and
  :meth:`~revenge.process.Process.stderr`
- Added new plugin for enhancing reversing with
  :class:`~revenge.plugins.radare2.Radare2`
  
  - Ability to :meth:`~revenge.plugins.radare2.Radare2.highlight` execution
    paths for view in `V` and `VV` modes
  - Integrated ghidra decompiler

- Added :class:`~revenge.plugins.decompiler.Decompiler` plugin to allow for
  requesting decompiled code and doing thing such as highlighting paths
- Added plugin to support enumerating/reading and writing to
  :class:`~revenge.plugins.handles.Handles`
- Added helper to discover what file an address belongs to as well as it's
  relative offset from the beginning of that file:
  :meth:`~revenge.modules.Modules.lookup_offset`

Version 0.17
============

- Added support for :class:`~revenge.cpu.contexts.arm.ARMContext` (Android on
  ARM emulator works now)
- Drastically improved performance for
  :class:`~revenge.techniques.native_timeless_tracer.NativeTimelessTracer`
- Updates to :mod:`~revenge.cpu.contexts`
  
  - Tracking changed registers in
    :attr:`~revenge.cpu.contexts.CPUContextBase.changed_registers`
  - Auto highlighting changed registers when printing cpu context
  - Consolidated and simplified handling of CPU contexts

- Lookups of the form "mod:sym:offset" work now
- New :class:`~revenge.devices.LocalDevice` class
- Bunch of restructuring to eventually support multiple engines


Version 0.16
============

- Initial
  :class:`~revenge.techniques.native_timeless_tracer.NativeTimelessTracer`
  implementation is here! For more information, checkout
  :ref:`NativeTimelessTracerTechnique-page`
- Exposed frida's :meth:`~revenge.memory.MemoryBytes.on_enter` to allow for
  more easily monitoring functions rather than replacing them
- Overhaul of :class:`~revenge.types.Telescope`

  - Implemented int/hex/bitand and rshift
  - Telescopes are now implemented via hash consing. This is drastically
    reduces the memory utilization when using the new NativeTimelessTracer.
  - Refactor of underlying js code for handling telescoping
- CPU Contexts now handle and print telescoping register values
- :class:`~revenge.native_exception.NativeException` now telescopes the CPU
  reigsters when returning an exception
- Updated travis tests to enable testing on Android 10
- Updated coveralls to merge results

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
