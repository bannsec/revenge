
import logging
logger = logging.getLogger(__name__)

class JavaClass(object):
    def __init__(self, process, name=None, prefix=None, handle=None,
            full_description=None):
        """Represents a Java class.

        Args:
            process (frida_util.Process): Process object
            name (str, optional): Full name for this class, method or field
            prefix (str, optional): What needs to be prefixed on to this object
                This is generally done automatically.
            handle (int, optional): Handle to where this class is instantiated
                in memory. Otherwise, it will be instantiated when used.
            full_description (str, optional): Automatically set full
                description of this method. Don't manually set.
        """
        self._process = process
        self._name = name
        self._prefix = prefix or ""
        self._handle = handle
        self._full_description = full_description

        if not self.is_method:
            self._reflect_methods()

    def _reflect_methods(self):
        """Reflectively identify methods."""

        methods = self._process.java._cache_reflected_methods[self._name]

        # If we missed the cache, enumerate it now
        if methods == []:
            methods = self._process.java.run_script_generic("get_declared_methods.js", unload=True, replace={'FULL_CLASS_HERE': self._name})[0]

            # Save this off to the cache
            self._process.java._cache_reflected_methods[self._name] = methods

        for method in methods:
            name = method['name']
            full_description = method['full_description']

            # Just skipping unsafe names for now
            if not JavaClass._is_safe_method_name(name):
                continue

            # Create method instance
            setattr(self, name, getattr(self, name))
            getattr(self, name)._full_description = full_description
            

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
        
        if self._full_description is not None:
            attrs.append(self._full_description)

        elif self._name is not None:
            attrs.append(self._name)

        if self._handle is not None:
            attrs.append("Handle=" + str(self._handle))

        return "<" + " ".join(attrs) + ">"

    def __str__(self):

        # This is a direct class/method
        if self._name is not None:
            if not self.is_method:

                ret = "Java.use('" + self._name + "')"

                # Are we using an already instantiated instance?
                if self._handle is not None:
                    ret = "Java.cast(ptr('{}'), ".format(hex(self._handle)) + ret + ")"

                return ret

            else:
                return self._prefix + "." + self._name
        else:
            # Name is none, just return prefix. We are probably drilled down.
            return self._prefix

    def __call__(self, *args, **kwargs):

        args = self._parse_call_args(args)

        # This is an actual call shorthand. We've made the line and want to run it.
        if self._prefix != "" and self._name is None:
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
        return self._prefix != ""

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

    @staticmethod
    def _is_safe_method_name(name):
        safe = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_'
        return all(char in safe for char in name)
