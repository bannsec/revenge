=======
Plugins
=======

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
