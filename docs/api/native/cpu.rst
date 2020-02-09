===
CPU
===

CPUContextBase
==============

This is the base mix-in class when defining new CPUs to support.

.. autoclass:: revenge.cpu.contexts.CPUContextBase
    :members:
    :undoc-members:
    :show-inheritance:

CPUContext
==========

The CPUContext represents the state of the CPU. The following is the base
generator of contexts.

.. autofunction:: revenge.cpu.contexts.CPUContext

x64
---
.. autoclass:: revenge.cpu.contexts.x64.X64Context
    :members:
    :undoc-members:
    :show-inheritance:

x86
---
.. autoclass:: revenge.cpu.contexts.x86.X86Context
    :members:
    :undoc-members:
    :show-inheritance:

arm
---
.. autoclass:: revenge.cpu.contexts.arm.ARMContext
    :members:
    :undoc-members:
    :show-inheritance:

========
Assembly
========

Abstraction for the assembly instructions.

Assembly Instruction
====================

.. autoclass:: revenge.cpu.AssemblyInstruction
    :members:
    :undoc-members:
    :show-inheritance:

Assembly Block
==============

.. autoclass:: revenge.cpu.assembly.instruction.AssemblyBlock
    :members:
    :undoc-members:
    :show-inheritance:
