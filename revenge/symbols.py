
import logging
logger = logging.getLogger(__name__)

class Symbol(object):
    """Represents a binary symbol.

    Args:
        process: Process object
        name (str, optional): Name of this symbol
        address (int, optional): Address of this symbol
    """

    def __init__(self, process, name=None, address=None):

        self._process = process
        self.name = name
        self.address = address

    def startswith(self, x):
        """Passthrough to check if the symbol name starts with some string.
        
        Returns:
            bool
        """
        return self.name.startswith(x)

    def __repr__(self):
        attrs = ['Symbol']

        if self.name is not None:
            attrs.append(self.name)
        
        if self.address is not None:
            attrs.append("@ " + hex(self.address))

        return "<" + ' '.join(attrs) + '>'

    def __str__(self):
        return self.name or ""

    def __int__(self):
        return self.address

    def __lt__(self, other):
        return self.address < other

    def __le__(self, other):
        return self.address <= other

    def __gt__(self, other):
        return self.address > other

    def __ge__(self, other):
        return self.address >= other

    def __sub__(self, other):
        return self.address - other

    def __add__(self, other):
        return self.address + other

    def __hex__(self):
        return hex(self.address)

    def __index__(self):
        return int(self.address)

    def __call__(self, *args, **kwargs):
        return self.memory(*args, **kwargs)

    @property
    def name(self):
        """str: Name of this symbol."""
        return self.__name

    @name.setter
    def name(self, name):

        if not isinstance(name, str):
            logger.error("Symbol name must be string.")
            return

        self.__name = name

    @property
    def address(self):
        """int: Address of this Symbol."""
        return self.__address

    @address.setter
    def address(self, address):
        
        if not isinstance(address, int):
            logger.error("Symbol address must be an integer.")
            return

        self.__address = types.Pointer(address)

    @property
    def memory(self):
        """revenge.memory.MemoryBytes: Convenience property to grab a memory object for this symbol."""
        return self._process.memory[self.address]

from . import types
