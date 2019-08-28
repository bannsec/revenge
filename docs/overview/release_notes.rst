=============
Release Notes
=============

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
