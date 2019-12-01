=======
Engines
=======

.. note::

    Engines concept is currently in development.

To support diversification and not be completely tied to one tool, ``revenge``
has introduced the concept of :mod:`~revenge.engines`. The ``engine`` is
basically the underlying driver that supports running ``revenge``. Initially,
this ``engine`` has been the impressive ``frida`` DBI. However, in some cases
either ``frida`` doesn't yet support what we would like to do, or other
technologies (such as an emulator), might be a better fit.

To select an engine, simply provide the ``engine`` keyword when instantiating
your :class:`~revenge.Process` object. This will tell ``revenge`` to use the
given engine.
