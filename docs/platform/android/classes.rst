============
Java Classes
============

Class Enumeration
==================

Java classes are at the core of Android applications. ``revenge`` exposes a way
to enumerate the currently loaded classes.

``revenge`` performs reflective inspection of the java classes. This means you
will be able to use tab completion in ipython for methods and fields, as well
as see a definition of the method or field in it's ``__repr__``.

.. note::

    The loaded classes might change during program execution as the program
    itself loads and instantiates new classes. The classes method is always a
    snapshot of the currently loaded classes list.

Examples
--------

.. code-block:: python3

    # List all currently loaded classes
    process.java.classes

    # Grab the Math class specifically
    Math = process.java.classes['java.lang.Math']

    # Or use globs
    Math = process.java.classes['java.l*.Math']

    # See what fields/methods exist
    dir(Math)

Calling Methods
===============

``revenge`` makes directly calling methods from python easy.

Examples
--------

.. code-block:: python3

    # Grab the android logging class
    log = process.java.classes['android.util.Log']

    # Simply call the method with the required arguments
    # Ending with () tells revenge to actually do the call
    log.w("Hello", "world!")()


Method Override
===============

You can easily override any method's definition. This uses Frida and thus, you
will have to actually write your override in javascript.

Examples
--------

.. code-block:: python3

    # Grab the math class
    Math = process.java.classes['java.lang.Math']

    # Override the random implementation to be not-so-random
    Math.random.implementation = "function () { return 12; }"

    # Validate that it's our code
    Math.random()()
    12

    # Remove override and check that original functionality is back
    Math.random.implementation = None
    Math.random()()
    0.8056030012322106

Instantiated Classes
====================

If an application is saving state in the java class, you may want to interact
specifically with the class instance, rather than just a generic class. You can
do this by finding the instance.

Examples
--------

.. code-block:: python3

    # Grab the class
    MainActivity = process.java.classes['*myapp*MainActivity']

    # Find the active instance
    M = process.java.find_active_instance(MainActivity)

    # Call the method on that specific running instance
    M.some_method()()
    
Batch Calling
=============

Batch calling is the same concept as batch calling for the native process. The
idea is, since the time it takes to send commands from python into the
application and back can be rather slow, we open up a context where we can feed
in a bunch of commands at once. Instead of getting the results back one by one
per call, we get them back in bulk to a message handler that has the
resonsibility to deal with it.

To use batch contexts, you will need to instantiate them inside a ``with``
context. Then provide the context to the calling method so it knows to use that
context.

For CTFs, this is generally used on challenges that require some level of brute
foricing of the flag.

Examples
--------

Coming soon..
