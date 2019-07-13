
import logging
logger = logging.getLogger(__name__)

class JavaClass(object):
    def __init__(self, process, name=None, prefix=None):
        """Represents a Java class.

        Args:
            process (frida_util.Process): Process object
            name (str, optional): Full name for this class.
            prefix (str, optional): What needs to be prefixed on to this object
                This is generally done automatically.
        """
        self._process = process
        self.name = name
        self.prefix = prefix or ""

    def __repr__(self):
        attrs = ["JavaClass"]

        if self.name is not None:
            attrs.append(self.name)

        return "<" + " ".join(attrs) + ">"

    def __str__(self):

        # This is a direct class/method
        if self.name is not None:
            if not self.is_method:
                return "Java.use('" + self.name + "')"
            else:
                return self.prefix + "." + self.name
        else:
            # Name is none, just return prefix. We are probably drilled down.
            return self.prefix

    def __call__(self, *args, **kwargs):
        # Need quotes
        # TODO: This will need to be a method to standardize how we pass things.
        args = [repr(arg) for arg in args]

        # This is an actual call shorthand. We've made the line and want to run it.
        if self.prefix != "" and self.name is None:
            unload = kwargs.get('unload', True)
            command = "send(" + str(self) + ")"
            return self._process.java.run_script_generic(command, raw=True, unload=unload)[0][0]

        if not self.is_method:
            prefix = str(self) + ".$new(" + ",".join(args) + ")"
        else:
            prefix = str(self) + "(" + ",".join(args) + ")"

        return JavaClass(self._process, prefix=prefix)

    # Magic wrapper to drill down into methods
    def __getattr__(self, attr):
          return JavaClass(self._process, name=attr, prefix=str(self))

    @property
    def is_method(self):
        """bool: Does this object actually describe a method?"""
        return self.prefix != ""
