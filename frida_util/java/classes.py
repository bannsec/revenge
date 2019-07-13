
import logging
logger = logging.getLogger(__name__)

from fnmatch import fnmatch

class JavaClasses(object):

    def __init__(self, process):
        """Handles enumerating the loaded Java classes for this JVM."""
        self._process = process

    def __repr__(self):
        attrs = ["JavaClasses", str(len(self)), "classes"]
        return "<" + ' '.join(attrs) + ">"

    def __iter__(self):
        return self.classes.__iter__()

    def __len__(self):
        return len(self.classes)

    def __getitem__(self, item):
        if isinstance(item, int):
            return JavaClass(self._process, list(self)[item])

        elif isinstance(item, str):
            match = [JavaClass(self._process, x) for x in self if fnmatch(x, item)]
            if len(match) > 1:
                return match
            if match == []:
                return None
            return match[0]

        else:
            logger.error("Unhandled item get of type {}".format(type(item)))
            return

    @property
    def classes(self):
        """list: The actual list of classes."""
        try:
            return self.__classes
        except AttributeError:
            self.__classes = self._process.java.run_script_generic(r"""send( Java.enumerateLoadedClassesSync() );""", raw=True, unload=True)[0][0]
            return self.__classes

from .java_class import JavaClass
