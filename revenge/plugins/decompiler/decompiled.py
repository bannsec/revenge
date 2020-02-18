
from ... import common
from pygments import highlight
from pygments.lexers import CLexer
from pygments.formatters import Terminal256Formatter
import colorama
from revenge.exceptions import *

BG_COLOR_OPTIONS = ['BLACK', 'BLUE', 'CYAN', 'GREEN', 'LIGHTBLACK_EX', 'LIGHTBLUE_EX', 'LIGHTCYAN_EX', 'LIGHTGREEN_EX', 'LIGHTMAGENTA_EX', 'LIGHTRED_EX', 'LIGHTWHITE_EX', 'LIGHTYELLOW_EX', 'MAGENTA', 'RED', 'WHITE', 'YELLOW']

class DecompiledItem(object):
    def __init__(self, process, address=None, src=None, highlight=None):
        """A single decompiled item.

        Args:
            address (int, optional): Address for this item.
            src (str, optional): Decompiled source
            highlight (str, optional): Color to highlight this item
        """
        self._process = process
        self.address = address
        self.src = src
        self.highlight = highlight

    def __repr__(self):
        attrs = ["DecompiledItem"]

        if self.address is not None:
            attrs.append(hex(self.address))

        if self.src is not None:
            attrs.append(self.src)

        return "<" + " ".join(attrs) + ">"

    def __str__(self):
        if self.highlight is not None:
            s = getattr(colorama.Back, self.highlight) + hex(self.address) + colorama.Style.RESET_ALL + ": "
        else:
            s = hex(self.address) + ": "

        if self.src is not None:
            s += highlight(self.src, CLexer(), Terminal256Formatter(style='monokai'))

        return s

    @property
    def highlight(self):
        """str: Color to highlight this instruction (or None).
        
        Valid options are: {}
        """
        return self.__highlight

    @highlight.setter
    @common.validate_argument_types(highlight=(str, type(None)))
    def highlight(self, highlight):
        if highlight is not None:
            highlight = highlight.upper()
            if highlight not in BG_COLOR_OPTIONS:
                raise RevengeInvalidArgumentType("Highlight select not in " + str(BG_COLOR_OPTIONS))
        self.__highlight = highlight

    @property
    def src(self):
        """str: Pseudo source for this instruction."""
        return self.__src

    @src.setter
    @common.validate_argument_types(src=(str, type(None)))
    def src(self, src):
        self.__src = src

    @property
    def address(self):
        """int: Address of this decompiled instruction."""
        return self.__address

    @address.setter
    @common.validate_argument_types(address=(int, type(None)))
    def address(self, address):
        self.__address = address

class Decompiled(object):
    def __init__(self, process):
        """Represents decompiled output.
        
        Examples:
            .. code-block:: python

                # Decompiled instruction at 123
                dec = process.decompiler[0x123]

                # dec is type Decompiled

                # Get the C source
                dec[0x123]

                # Print the decompiled things
                print(dec)

                # Same concept with functions
                dec = process.decompiler["my_func"]
                print(dec)
        """
        self._process = process

        # instruction: DecompiledItem
        self._decompiled = collections.defaultdict(lambda: DecompiledItem(self._process))

    @common.validate_argument_types(item=int)
    def __getitem__(self, item):

        if isinstance(item, int):
            return self._decompiled[item]

    @common.validate_argument_types(item=int, value=DecompiledItem)
    def __setitem__(self, item, value):
        self._decompiled[item] = value

    def __iter__(self):
        return sorted(self._decompiled.keys()).__iter__()

    def __len__(self):
        return len(self._decompiled)

    def __repr__(self):
        if len(self) == 1:
            addr = "address"
        else:
            addr = "addresses"
        return "<Decompiled Output " + str(len(self)) + " " + addr + ">"

    def __str__(self):
        return "\n".join(str(self[item]) for item in self)

import collections

DecompiledItem.highlight.__doc__ = DecompiledItem.highlight.__doc__.format(BG_COLOR_OPTIONS)
