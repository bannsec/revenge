
import logging
logger = logging.getLogger(__name__)

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

    @property
    def classes(self):
        """list: The actual list of classes."""
        try:
            return self.__classes
        except AttributeError:
            self.__classes = self._process.java.run_script_generic(r"""send( Java.enumerateLoadedClassesSync() );""", raw=True, unload=True)[0][0]
            return self.__classes
