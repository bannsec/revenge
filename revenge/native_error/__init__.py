
import logging
logger = logging.getLogger(__name__)

class NativeError(object):

    def __init__(self, process, errno=None):
        """Represents a error as defined by the native operating system.
        
        Args:
            process (revenge.Process): Process object
            errno (int, optional): The error number for this error

        This object currently supports Linux type "errno" numbers.
        
        Examples:
            .. code-block:: python3
            
                # Normally you will be given the object, but you can
                # instantiate it yourself as well
                e = NativeError(process, 0)

                print(e)
                "Success"

                assert e.description == "Success"
        """
        self._process = process
        self.errno = errno

    def _resolve_description(self):
        """str: Resolves the string description for this error."""

        # Nothing to resolve
        if self.errno is None:
            return None

        if self._process.device_platform == 'linux':
            strerror = self._process.memory['strerror']
            strerror.argument_types = types.Int
            strerror.return_type = types.Pointer
            return self._process.memory[strerror(self.errno)].string_utf8

        else:
            logger.error("NativeError string resolve not supported yet for {}".format(self._process.device_platform))

    def __repr__(self):
        attr = ['NativeError']

        if self.errno is not None:
            attr.append(hex(self.errno))

        if self.description is not None:
            attr.append(self.description)

        return "<" + " ".join(attr) + ">"

    def __str__(self):
        return  self.description or ""

    @property
    def description(self):
        """str: String description of this error."""
        try:
            return self.__description
        except AttributeError:
            self.__description = self._resolve_description()

        return self.__description

    @property
    def errno(self):
        """int: Error number for this error."""
        return self.__errno

    @errno.setter
    def errno(self, errno):
        if not isinstance(errno, (int, type(None))):
            raise RevengeInvalidArgumentType("errno must be of type int or None. Got type {}".format(type(errno)))

        # Throw away the cache
        try:
            del self.__description
        except AttributeError:
            pass

        self.__errno = errno

NativeError.__doc__ = NativeError.__init__.__doc__

from .. import types
from ..exceptions import *
