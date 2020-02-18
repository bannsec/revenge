
from ... import common

class DecompilerBase(object):
    def __init__(self, process):
        """Use this to decompile things.

        Examples:
            .. code-block:: python3

                # Attempt to get corresponding source code from address 0x12345
                process.decompiler[0x12345]

                # Decompile a function
                decomp = process.decompiler.decompile_function(0x12345)
                # Or alternatively, specify it as a string to getitem
                decomp = process.decompiler["my_func"]

                # Programmatically iterate through it
                for item in decomp:
                    x = decomp[item]
                    # stuff

                # Or print it out to the screen
                print(decomp)

                # See decomp.highlight() as well.
        """
        self._process = process

    @common.implement_in_engine()
    def decompile_address(self, address):
        """Lookup the corresponding decompiled code for a given address.

        Args:
            address (int): The address to look up decompiled code.

        Returns:
            revenge.plugins.decompiler.decompiled.Decompiled: Decompiled output
            or None if no corresponding decompile was found.
        """
        pass

    @common.implement_in_engine()
    def decompile_function(self, address):
        """Lookup the corresponding decompiled code for a given function.

        Args:
            address (int): The start of the function to decompile.

        Returns:
            revenge.plugins.decompiler.decompiled.Decompiled: Decompiled output
            or None if no corresponding decompile was found.
        """
        pass

    @common.validate_argument_types(item=(int,str))
    def __getitem__(self, item):
        if isinstance(item, int):
            return self.decompile_address(item)
        elif isinstance(item, str):
            return self.decompile_function(item)

DecompilerBase.__doc__ = DecompilerBase.__init__.__doc__
