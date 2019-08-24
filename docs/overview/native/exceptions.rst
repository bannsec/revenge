==========
Exceptions
==========

Call Exceptions
===============

When using the memory.__call__ method to call a function, the call will be
wrapped in try/catch and will return objects of type
revenge.native_exception.NativeException.

:class:`revenge.native_exception.NativeException`

Examples
--------

.. code-block:: python3

    # Assuming that this threw an exception
    exception = process.memory[':some_function']('blerg')

    # Where did we except?
    exception.address

    # What type of exception?
    exception.type

    # Thread context at time of exception, containing registers and such
    exception.context
