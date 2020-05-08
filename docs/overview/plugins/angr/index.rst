====
angr
====

The angr plugin is being written to help expose features of angr to dynamic
reversing.

Requirements
============

The current requirements to use the `angr` plugin are:

- Having the base angr installed
- Having `angr-targets` installed

Setup
=====

You can install `angr` with:

.. code-block:: bash

    pip install angr
    pip install --process-dependency-links https://github.com/angr/angr-targets/archive/master.zip

angr also has pre-built docker containers available which alleviate build
issues.

Usage
=====

Thread Plugin
-------------

As a thread plugin, `angr` gets exposed as a property of
:class:`~revenge.threads.Thread`. The primary use case of this is to allow
seamless `Symbion <http://angr.io/blog/angr_symbion/>`_ integration. When
requesting objects, the plugin will automatically configure those objects to
use `revenge` as a concrete backer as well as provide additional relocation
support that isn't available directly by `Symbion`.

In English, this means you can execute to interesting points in your code using
`revenge`, then easily get an `angr` state object that will pick up right at
that point.

Basic Example
~~~~~~~~~~~~~

.. code-block:: python3

    # Set process breakpoint somewhere interesting
    process.memoery[interesting].breakpoint = True

    # Once you hit that interesting point, grab your thread
    thread = list(process.threads)[0]

    # Now easily grab an angr state as if angr was already at this point in
    # execution
    state = thread.angr.state

    assert state.pc == thread.pc

    # Other helpful things
    thread.angr.project
    thread.angr.simgr

For more info, see the :class:`~revenge.plugins.angr.Angr` API.
