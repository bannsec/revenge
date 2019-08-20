
import logging
logger = logging.getLogger(__name__)

from .. import common, types

class MemoryRange(object):

    def __init__(self, process, base, size, protection, file=None):
        self._process = process
        self.base = base
        self.size = size
        self.protection = protection
        self._file = file

    def __repr__(self):
        value = ["MemoryRange", hex(self.base), '-', hex(self.base+self.size), self.protection]
        if self.file is not None:
            value.append(self.file + ":" + hex(self.file_offset))
        return '<' + ' '.join(value) + '>'


    @property
    def file(self):
        """str: File backing this memory range, or None."""
        if self._file is None:
            return None

        return self._file['path']

    @property
    def file_offset(self):
        """int: Offset into backing file or None."""
        if self._file is None:
            return None

        return self._file['offset']

    @property
    def readable(self):
        """bool: Is this range readable?"""
        return self.protection[0] == 'r'

    @property
    def writable(self):
        """bool: Is this range writable?"""
        return self.protection[1] == 'w'

    @property
    def executable(self):
        """bool: Is this range executable?"""
        return self.protection[2] == 'x'

    @property
    def protection(self):
        """str: Protection for this range."""
        return self.__protection

    @protection.setter
    def protection(self, protection):
        assert type(protection) is str
        assert len(protection) == 3
        protection = protection.lower()

        # If we're setting for the first time, assume it's correct
        if not hasattr(self, '_MemoryRange__protection'):
            self.__protection = protection

        # Set protection if it's not already this
        elif protection != self.protection:
            self._process.run_script_generic("""Memory.protect({}, {}, '{}')""".format(
                self.base.js,
                hex(self.size),
                protection,
                ), raw=True, unload=True)

            self.__protection = protection

    @property
    def size(self):
        """int: Size for this range."""
        return self.__size

    @size.setter
    def size(self, size):
        self.__size = common.auto_int(size)

    @property
    def base(self):
        """int: Base address for this range."""
        return self.__base

    @base.setter
    def base(self, base):
        self.__base = types.Pointer(common.auto_int(base))
