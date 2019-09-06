=====
Types
=====

``revenge`` defines it's own types to better understand what data it is
looking at. This means, while in many cases you can pass native python
types to methods and fields, sometimes you will need to pass an instantiated
type instead.

See :doc:`types doc <../../api/native/types>`.

Examples
========

.. code-block:: python3

    from revenge import types

    # Create some ints
    i = types.Int32(0)
    i2 = types.UInt64(12)

    # Create a struct
    my_struct = types.Struct()
    my_struct.add_member('member_1', types.Int)
    my_struct.add_member('member_2', types.Pointer)
