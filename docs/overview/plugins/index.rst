=======
Plugins
=======

.. toctree::
    :maxdepth: 1
    :caption: Plugins
    :hidden:

    angr/index.rst
    decompiler/index.rst
    dwarf/index.rst
    radare2/index.rst

Plugins are a means for ``revenge`` to expose support in a general way. Plugins
are dynamically loaded at runtime based on the current engine and compatability
of the process for this plugin.

Building a Plugin
=================

To build a plugin, you must extend the :class:`~revenge.plugins.Plugin` class.
The general layout is:

- Create new submodule under ``revenge.plugins``. This will be the core of the
  plugin and should have __no__ dependencies on any specific engine
- Create a submodule under ``revenge.engines.<engine>``. This should extend the
  plugin class created above, and fill in any engine specific properties. NOTE:
  it's possible to create a plugin that is completely independent of any
  engine. In this case, the submodule here would simply extend the plugin class
  you created in step 1 and do nothing.
- Implement :attr:`~revenge.plugins.Plugin._is_valid`. This property is called
  after instantiation to allow the plugin to determine if it wants to register
  in the current environment or not.

That's it. You should now have a working plugin.

Registering a Plugin
====================

Your plugin will automatically register to the base process object if you
return True for `_is_valid`. However, you can also dynamically register your
plugin in a few different locations.

Registering a Module Plugin
---------------------------

Module plugins end up instantiated under Module.<plugin>. For instance:

.. code-block:: python
    
    # "plugin" here is where your plugin would end up
    # It will get instantiated with the module that it is called from
    process.modules['my_process'].plugin

If your plugin would likely be specific per module, you can register it as a
module plugin. To do this, simply call
:meth:`revenge.modules.Modules._register_plugin` with your class instantiator
as well as a name for the plugin. If successful, your plugin will now show up
under the module object.

Example of how to do this can be found in the API docs.

Registering a Thread Plugin
---------------------------

Thread plugin registration works exactly the same way that module registration
works. See :meth:`revenge.threads.Threads._register_plugin`.
