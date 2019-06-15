
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

from .. import common, types

class Module(object):

    def __init__(self, util, name, base, size, path):
        self._util = util
        self.name = name
        self.base = base
        self.size = size
        self.path = path

    def __repr__(self):
        attrs = ['Module', self.name, '@', hex(self.base)]
        return "<{}>".format(' '.join(attrs))

    def __eq__(self, other):
        return self.name == other.name and self.base == other.base and self.path == other.path and self.size == other.size

    @property
    def name(self):
        """str: Module name."""
        return self.__name

    @name.setter
    def name(self, name):
        if type(name) is not str:
            error = "Name must be string, not {}".format(type(name))
            logger.error(error)
            raise Exception(error)

        self.__name = name

    @property
    def base(self):
        """int: Base address this module is loaded at."""
        return self.__base

    @base.setter
    def base(self, base):

        base = common.auto_int(base)

        if type(base) is int:
            base = types.Pointer(base)

        self.__base = base

    @property
    def path(self):
        """str: Module path."""
        return self.__path

    @path.setter
    def path(self, path):
        if type(path) is not str:
            error = "Path must be string, not {}".format(type(path))
            logger.error(error)
            raise Exception(error)

        self.__path = path
        
    @property
    def size(self):
        """int: Size of this module."""
        return self.__size

    @size.setter
    def size(self, size):
        self.__size = common.auto_int(size)
