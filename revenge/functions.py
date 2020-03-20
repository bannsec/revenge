import logging
from .common import validate_argument_types
from .memory import MemoryBytes

"""
This module holds the base classes for other classes that want to describe functions.

Functions class basically behaves like a dictionary but with "smarts".
"""

class Functions(object):
    def __init__(self, process):
        """Represents functions.

        Examples:
            .. code-block:: python
                
                # This is meant to be used like a dictionary

                # Lookup MemoryBlock for function main
                main = functions["main"]

                # Lookup what function an address belongs to
                assert functions[main.address] == b"main"

                # Add function info
                function["func1"] = process.memory[<func1 range here>]

                # Not sure why you'd want to do this, but you can
                function[0x1000:0x2000] = "some_function"
        """
        self._process = process

        # name: MemoryBytes
        self.__functions = {}

    @validate_argument_types(name=(str,bytes))
    def lookup_name(self, name):
        """Lookup MemoryBytes for a given name.

        Args:
            name (str, bytes): Name of function

        Returns:
            MemoryBytes: Corresponding MemoryBytes object or None.

        Examples:
            .. code-block:: python
                
                main = functions.lookup_name("main")
        """
        # Everything should be bytes
        if isinstance(name, str):
            name = name.encode('latin-1')

        return self.__functions[name] if name in self.__functions else None

    @validate_argument_types(address=(int, MemoryBytes))
    def lookup_address(self, address):
        """Lookup a function based on address.

        Args:
            address (int, MemoryBytes): Address to lookup

        Returns:
            bytes: Name of function or None

        Examples:
            .. code-block:: python

                functions.lookup_address(0x12345) == b"some_function"
        """
        if isinstance(address, MemoryBytes):
            address = address.address

        for name, func in self.__functions.items():
            if func.address == address:
                return name

            elif func.address_stop is not None and func.address <= address and func.address_stop >= address:
                return name

    @validate_argument_types(name=(str, bytes), memory_bytes=MemoryBytes)
    def set_function(self, name, memory_bytes):
        """Adds a function entry. Usually not done manually...

        Args:
            name (str, bytes): Name of function
            memory_bytes (MemoryBytes): MemoryBytes for function
        """
        # Everything should be bytes
        if isinstance(name, str):
            name = name.encode('latin-1')

        self.__functions[name] = memory_bytes

    def __getitem__(self, item):
        if isinstance(item, (str, bytes)):
            return self.lookup_name(item)

        elif isinstance(item, (int, MemoryBytes)):
            return self.lookup_address(item)

    def __setitem__(self, item, value):
        if isinstance(item, (str, bytes)):
            self.set_function(item, value)

        elif isinstance(item, MemoryBytes):
            self.set_function(value, item)

        elif isinstance(item, slice):
            self.set_function(value, self._process.memory[item])

    def __len__(self):
        return len(self.__functions)

    def __repr__(self):
        attrs = ["Functions", str(len(self))]
        return "<" + " ".join(attrs) + ">"

Functions.__doc__ = Functions.__init__.__doc__

LOGGER = logging.getLogger(__name__)
