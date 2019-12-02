import logging
LOGGER = logging.getLogger(__name__)

from .....plugins.java import JavaClasses

class FridaJavaClasses(JavaClasses):

    @property
    def classes(self):

        try:
            return self.__classes
        except AttributeError:
            self.__classes = self._process.java.run_script_generic(
                    r"""send( Java.enumerateLoadedClassesSync() ); send("DONE");""",
                    raw=True,
                    unload=True,
                    timeout=0,
                    onComplete='DONE',
                    )[0][0]
            return self.__classes

#from .java_class import JavaClass
#from . import JavaClass
