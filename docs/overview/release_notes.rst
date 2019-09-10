=============
Release Notes
=============

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
