
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

    def _parse_call_args(self, args):
        """Given args list, standardize it so it's ready for use in a call.
        
        Returns:
            list where each item is ready for inclusion.
        """
        ret_list = []

        for arg in args:
            if type(arg) is str:
                # Quotes and such
                ret_list.append(repr(arg))
            else:
                # This should work for int/float/etc as well as JavaClass
                ret_list.append(str(arg))

        return ret_list

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

        args = self._parse_call_args(args)

        # This is an actual call shorthand. We've made the line and want to run it.
        if self.prefix != "" and self.name is None:
            unload = kwargs.pop('unload', True)
            context = kwargs.pop('context', None)

            # Only send this back directly if we're not using a context
            if context is None:
                command = "send(" + str(self) + ")"
            else:
                command = str(self)

            ret = self._process.java.run_script_generic(command, raw=True, unload=unload, context=context, **kwargs)

            #
            # What to return from this
            #

            if ret is None or ret[0] == []:
                return None

            else:
                return ret[0][0]


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

    @property
    def implementation(self):
        """str: Returns the over-written implementation for this method, or None if we have not over-written it.
        
        Examples:
            # Make random always return 5 (hey... it could be random?)
            process.java.classes['java.lang.Math'].random.implementation = "function (x) { return 5; }"
            assert process.java.classes['java.lang.Math'].random() == 5
            # Remove your overwrite so Random returns to normal
            process.java.classes['java.lang.Math'].random.implementation = None
        """
        try:
            return self._process.java._implementations[str(self)]
        except KeyError:
            return None


    @implementation.setter
    def implementation(self, implementation):
        assert isinstance(implementation, (str, type(None))), "Unhandled implementation type of {}. Must be str type.".format(type(implementation))

        #
        # Regardless of what we're doing, we need to unimplement first.
        #

        try:
            script_stuff = self._process.java._implementations.pop(str(self))
            script_stuff[1].unload()

        except KeyError:
            # We didn't have an implementation yet. All good.
            pass

        # If we're only removing, then we're done here.
        if implementation is None:
            return

        #
        # Add new implementation
        #

        self._process.java.run_script_generic("{jclass}.implementation = {implementation}".format(jclass=str(self), implementation=implementation), raw=True, unload=False, runtime='v8')
        
        # Save it off
        self._process.java._implementations[str(self)] = [implementation] + self._process._scripts.pop(0)
