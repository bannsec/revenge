
import logging
from ... import common

class Handle(object):
    def __init__(self, process, handle, name=None):
        """Describes a handle.

        Args:
            process (revenge.Process): Corresponding process.
            handle (int): The handle identifier.
            name (str, optional): File backing this handle.

        Examples:
            .. code-block::

                handle = process.handles[4]

                # What file/pipe/thing is this a handle to?
                print(handle.name)

                # Read 32 bytes from the beginning of the handle
                stuff = handle.read(32, 0)

                # Read 16 bytes from the current pointer
                stuff = handle.read(16)

                # Write something to the handle
                handle.write(b"something")

                # Write something to the handle at offset 4
                handle.write(b"something", 4)

                # Check the read/write ability on this handle
                handle.readable
                handle.writable
        """
        self._process = process
        self.handle = handle
        self.name = name
        self.__position = None

    def __repr__(self):
        attrs = ["Handle", hex(self.handle)]

        if self.name:
            attrs.append(self.name)

        rw = ""

        if self.readable:
            rw += "r"
        
        if self.writable:
            rw += "w"

        if rw != "":
            attrs.append(rw)

        if self.position is not None:
            attrs.append("pos:" + str(self.position))

        return "<" + " ".join(attrs) + ">"

    @common.validate_argument_types(n=int, position=(int, type(None)))
    def read(self, n, position=None):
        """Reads n bytes, optionally from a given position.
        
        Args:
            n (int): How many bytes to read?
            position (int, optional): Where to read from? Absolute.

        Returns:
            bytes: Data read from fd or None if there was an error

        When given position argument, this call will return the fd to it's original position after reading.
        """

        if self._process.device.platform == "linux":
            return linux.read_handle(self._process, self.handle, n, position)

        else:
            LOGGER.error("No support yet for platform " + self._process.device.platform)

    @common.validate_argument_types(thing=(str, bytes), position=(int, type(None)))
    def write(self, thing, position=None):
        """Writes thing into the handle, optionally from a given position.
        
        Args:
            thing (str, bytes): What to write
            position (int, optional): Where to write from? Absolute.

        Returns:
            int: Number of bytes written.
        """

        if self._process.device.platform == "linux":
            return linux.write_handle(self._process, self.handle, thing, position)

        else:
            LOGGER.error("No support yet for platform " + self._process.device.platform)

    @property
    def handle(self):
        """int: The actual handle identifier. This is what the OS uses to identify the handle."""
        return self.__handle

    @handle.setter
    @common.validate_argument_types(handle=int)
    def handle(self, handle):
        self.__handle = handle

    @property
    def name(self):
        """str: Name or path to file backing this handle."""
        return self.__name

    @name.setter
    def name(self, name):
        self.__name = name

    @property
    def readable(self):
        """bool: Is this handle readable?"""
        if self._process.device.platform == "linux":
            return linux.handle_is_readable(self._process, self.handle)

        else:
            LOGGER.error("No support yet for platform " + self._process.device.platform)

    @readable.setter
    @common.validate_argument_types(readable=bool)
    def readable(self, readable):

        if self._process.device.platform == "linux":
            LOGGER.error("POSIX does not support changing read/write permissions on existing file descriptors.")

        else:
            LOGGER.error("No support yet for platform " + self._process.device.platform)

    @property
    def writable(self):
        """bool: Is this handle writable?"""
        if self._process.device.platform == "linux":
            return linux.handle_is_writable(self._process, self.handle)

        else:
            LOGGER.error("No support yet for platform " + self._process.device.platform)

    @writable.setter
    @common.validate_argument_types(writable=bool)
    def writable(self, writable):
        if self._process.device.platform == "linux":
            LOGGER.error("POSIX does not support changing read/write permissions on existing file descriptors.")

        else:
            LOGGER.error("No support yet for platform " + self._process.device.platform)

    @property
    def position(self):
        """int: Current position in this handle."""
        if self._process.device.platform == "linux":
            return linux.handle_position(self._process, self.handle)

        else:
            LOGGER.error("No support yet for platform " + self._process.device.platform)

    @position.setter
    @common.validate_argument_types(position=int)
    def position(self, position):
        if self._process.device.platform == "linux":
            return linux.set_handle_position(self._process, self.handle, position)

        else:
            LOGGER.error("No support yet for platform " + self._process.device.platform)

from . import linux
from ...exceptions import *

LOGGER = logging.getLogger(__name__)
Handle.__doc__ = Handle.__init__.__doc__
