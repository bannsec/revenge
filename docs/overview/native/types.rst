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

    # You can optionally read memory as a type instead of using memory attributes
    assert process.memory[0x12345].cast(types.Int32) ==  process.memory[0x12345].int32


Structs
=======
The :class:`~revenge.types.Struct` type is a little different from the rest of
the types. Specifically, it defines a C structure, rather than a specific type.
A struct can be defined by itself first, and then "bound" to a memory address.

The behavior of structs is to be used like dictionary objects.

Examples
--------

.. code-block:: python3
    
    # Create a struct
    my_struct = types.Struct()
    my_struct.add_member('member_1', types.Int)
    my_struct.add_member('member_2', types.Pointer)

    # Alternatively, add them IN ORDER via dict setter
    my_struct = types.Struct()
    my_struct['member_1'] = types.Int
    my_struct['member_2'] = types.Pointer

    # Use cast to bind your struct to a location
    my_struct = process.memory[0x12345].cast(my_struct)

    # Or set memory property directly
    my_struct.memory = process.memory[0x12345]

    # Read out the values
    my_struct['member_1']
    my_struct['member_2']

    # Write in some new values (this will auto-cast based on struct def)
    my_struct['member_1'] = 12

    # Print out some detail about it
    print(my_struct)
    """
    struct {
      test1 = -18;
      test2 = 3;
      test3 = 26;
      test4 = 4545;
      test5 = 3;
      test6 = 5454;
    }
    """

