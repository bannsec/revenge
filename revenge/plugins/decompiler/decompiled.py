
from ... import common
from pygments import highlight
from pygments.lexers import CLexer
from pygments.formatters import Terminal256Formatter
import colorama
from revenge.exceptions import *
from collections.abc import Iterable

BG_COLOR_OPTIONS = ['BLACK', 'BLUE', 'CYAN', 'GREEN', 'LIGHTBLACK_EX', 'LIGHTBLUE_EX', 'LIGHTCYAN_EX', 'LIGHTGREEN_EX', 'LIGHTMAGENTA_EX', 'LIGHTRED_EX', 'LIGHTWHITE_EX', 'LIGHTYELLOW_EX', 'MAGENTA', 'RED', 'WHITE', 'YELLOW']


class DecompiledItem(object):
    def __init__(self, process, file_name=None, address=None, src=None, highlight=None):
        """A single decompiled item.

        Args:
            file_name (str, optional): The file for which this decompiled item describes
            address (int, optional): Address for this item
            src (str, optional): Decompiled source
            highlight (str, optional): Color to highlight this item
        """
        self._process = process
        self._file_name = file_name
        self.address = address
        self.src = src
        self.highlight = highlight

    def __repr__(self):
        attrs = ["DecompiledItem"]

        if self.address is not None:
            attrs.append(hex(self.address))

        if self.src is not None:
            attrs.append(self.src.decode('latin-1'))

        return "<" + " ".join(attrs) + ">"

    def __str__(self):

        s = ""

        # Are we on the first line of this decompiled output?
        first = True

        if self.src is not None:
            src = self.src.decode('latin-1')

            for line in src.split("\n"):

                if first:
                    # Can't do adjustments since we don't know the name
                    if self._file_name is None:
                        saddr = "{:18s}".format(hex(self.address))
                    else:
                        # Adjust offset to make sense with our current binary
                        saddr = "{:18s}".format(hex(self._process.memory[self._file_name.decode('latin-1') + ":" + hex(self.address)].address))
                    
                    if self.highlight is not None:
                        s += getattr(colorama.Back, self.highlight) + saddr + colorama.Style.RESET_ALL + "| "
                    else:
                        s += saddr + "| "

                    s += highlight(line, CLexer(), Terminal256Formatter(style='monokai')).strip() + "\n"
                    first = False

                else:
                    saddr = " "*18

                    if self.highlight is not None:
                        s += getattr(colorama.Back, self.highlight) + saddr + colorama.Style.RESET_ALL + "| "
                    else:
                        s += saddr + "| "

                    s += highlight(line, CLexer(), Terminal256Formatter(style='monokai')).strip() + "\n"

        return s.strip()

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
    @common.validate_argument_types(src=(str, bytes, type(None)))
    def src(self, src):
        if src is None:
            self.__src = None
        else:
            self.__src = common.auto_bytes(src)

    @property
    def address(self):
        """int: Address of this decompiled instruction."""
        return self.__address

    @address.setter
    @common.validate_argument_types(address=(int, type(None)))
    def address(self, address):
        self.__address = address

    @property
    def _file_name(self):
        try:
            return self.__file_name
        except AttributeError:
            return None

    @_file_name.setter
    def _file_name(self, file_name):
        if file_name is None:
            self.__file_name = None
        else:
            self.__file_name = common.auto_bytes(file_name)

class Decompiled(object):
    def __init__(self, process, file_name=None):
        """Represents decompiled output.

        Args:
            file_name (str): Name of this binary.
        
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

        # Name for this binary
        self._file_name = file_name

        # instruction: DecompiledItem
        self._decompiled = collections.defaultdict(lambda: DecompiledItem(self._process, file_name=self._file_name))

        # Code that didn't end up assigned to an address at the end of the function
        self._footer = None

        self._header = None


    def highlight(self, thing, color=None):
        """Highlight everything in thing with color.

        Args:
            thing (int, list, tuple, trace): Addresses of things to highlight
            color (str, optional): Color to use (see DecopmiledItem.highlight)
                default: green

        Examples:
            .. code-block:: python

                # Create a timeless trace
                timeless = process.techniques.NativeTimelessTracer()
                timeless.apply()
                t = list(timeless)[0]

                # Decompile your function, this can be done at any time
                decomp = process.decompiler.decompile_function(0x12345)

                # Let your program run to grab the trace
                process.memory[process.entrypoint].breakpoint = False

                # Apply the trace to your decomp
                decomp.highlight(t)

                # You can keep the same decomp and apply traces from different timeless runs as well
                # For instance, if you had a second trace called t2, this would overlay that trace
                decomp.highlight(t2)

        The things to highlight here must be valid in the current instance of
        revenge. This means, if your binary has ASLR, these must be the CURRENT
        addresses, with ASLR applied. Highlight will adjust the locations as
        needed.
        """

        if color is None: color = "green"

        if isinstance(thing, int):
            thing = [int(thing)]

        elif isinstance(thing, str):
            thing = [self._process.memory[thing].address]

        if not isinstance(thing, Iterable):
            raise RevengeInvalidArgumentType("Invalid type for thing in highlight.")

        for x in thing:
            if not isinstance(x, int):
                if hasattr(x, "ip"):
                    x = x.ip
                elif hasattr(x, "context"):
                    x = x.context.ip
                else:
                    raise RevengeInvalidArgumentType("Invalid type for thing in highlight.")

            # x should be int now
            out = self._process.modules.lookup_offset(x)

            # If we can't find the map, ignore it
            if out is None:
                continue

            mod, off = out

            # Mismatch between name of decomp bin and this item
            if self._file_name is not None and mod.lower() != self._file_name.lower():
                continue

            # Finally, if the item exits, color it up!
            if off in self:
                self[off].highlight = color

    @common.validate_argument_types(item=int)
    def __getitem__(self, item):

        if isinstance(item, int):
            return self._decompiled[item]

    @common.validate_argument_types(item=int, value=DecompiledItem)
    def __setitem__(self, item, value):
        self._decompiled[item] = value

    def __iter__(self):
        #return sorted(self._decompiled.keys()).__iter__()
        return self._decompiled.__iter__()

    def __len__(self):
        return len(self._decompiled)

    def __repr__(self):
        if len(self) == 1:
            addr = "address"
        else:
            addr = "addresses"
        return "<Decompiled Output " + str(len(self)) + " " + addr + ">"

    def __str__(self):
        out = ""

        if self._header is not None:
            for line in self._header.split("\n"):
                out += "\n" + " "*18 + "| " + highlight(line, CLexer(), Terminal256Formatter(style='monokai')).strip()

        out += "\n"
        out += "\n".join(str(self[item]) for item in self)

        if self._footer is not None:
            for line in self._footer.split("\n"):
                out += "\n" + " "*18 + "| " + highlight(line, CLexer(), Terminal256Formatter(style='monokai')).strip()
        return out.rstrip()

import collections

DecompiledItem.highlight.__doc__ = DecompiledItem.highlight.__doc__.format(BG_COLOR_OPTIONS)
