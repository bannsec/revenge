
import logging
logger = logging.getLogger(__name__)

class JavaClass(object):
    _in_init = set()

    def __init__(self, process, name=None, prefix=None, handle=None,
            full_description=None, is_method=None, is_field=None):
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
            is_method (bool, optional): Is this a method
            is_field (bool, optional): Is this a field
        """

        JavaClass._in_init.add(id(self))

        self._reflection_done = False
        self._is_method = is_method
        self._is_field = is_field
        self._class = None
        self._process = process
        self._name = name
        self._prefix = prefix or ""
        self._handle = handle
        self._full_description = full_description

        # Assume no prefix means this is the base class
        if self._prefix == "" and self._name != "":
            # class in front is needed to separate java class from built-in class
            self._class = "class " + self._name

            # Always reflect fields and methods on base class
            self._reflect_things()
        
        JavaClass._in_init.remove(id(self))

    def _reflect_things(self):

        if self._reflection_done:
            return

        # Methods shouldn't have reflect called on them.
        if self._is_method:
            return

        # Not Java class.
        if self._class is None or not self._class.startswith("class "):
            return

        self._reflect_fields()
        self._reflect_methods()

        self._reflection_done = True

    def _reflect_fields(self):
        """Reflectively identify fields."""

        assert self._class.startswith("class "), "Unexpected Class type {}".format(type(self._class))
        this_klass = self._class[6:]

        fields = self._process.java._cache_reflected_fields[this_klass]

        # If we missed the cache, enumerate it now
        if fields == []:
            fields = self._process.java.run_script_generic("get_declared_fields.js", unload=True, replace={'FULL_CLASS_HERE': this_klass})[0]

            # Save this off to the cache
            self._process.java._cache_reflected_fields[this_klass] = fields

        for field in fields:
            name = field['name']
            full_description = field['full_description']
            klass = field['class']

            # Just skipping unsafe names for now
            if not JavaClass._is_safe_method_name(name):
                continue

            # Create method instance
            # TODO: Change this to use Class init instead of setting manually
            new_class = JavaClass(self._process, name=name, prefix=str(self),
                    full_description=full_description, is_method=False,
                    is_field=True)
            new_class._class = klass
            setattr(self, name, new_class)
            
    def _reflect_methods(self):
        """Reflectively identify methods."""

        assert self._class.startswith("class "), "Unexpected Class type {}".format(type(self._class))
        this_klass = self._class[6:]

        methods = self._process.java._cache_reflected_methods[this_klass]

        # If we missed the cache, enumerate it now
        if methods == []:
            methods = self._process.java.run_script_generic("get_declared_methods.js", unload=True, replace={'FULL_CLASS_HERE': this_klass})[0]

            # Save this off to the cache
            self._process.java._cache_reflected_methods[this_klass] = methods

        for method in methods:
            name = method['name']
            full_description = method['full_description']

            # Just skipping unsafe names for now
            if not JavaClass._is_safe_method_name(name):
                continue

            # Create method instance
            # TODO: Change this to use Class init instead of setting manually
            new_class = JavaClass(self._process, name=name, prefix=str(self),
                    full_description=full_description, is_method=True,
                    is_field=False)
            setattr(self, name, new_class)

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
            if not self._is_method and not self._is_field:

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


        if not self._is_method:
            prefix = str(self) + ".$new(" + ",".join(args) + ")"
        else:
            prefix = str(self) + "(" + ",".join(args) + ")"

        return JavaClass(self._process, prefix=prefix)

    def __getattribute__(self, name):

        # Attribute miss will trigger getattr via exception
        ret = object.__getattribute__(self, name)

        # If this class is initializing, ignore this
        if id(self) in JavaClass._in_init:
            return ret
        
        # Hold off reflection until the last minute to avoid recurion and 
        # load costs
        if isinstance(ret, JavaClass):
            ret._reflect_things()

        return ret

    # Magic wrapper to drill down into methods
    def __getattr__(self, attr):
        return JavaClass(self._process, name=attr, prefix=str(self))

    @property
    def _is_method(self):
        """bool: Does this object actually describe a method?"""
        # If we've been explicitly told that this is a method
        if self.__is_method is not None:
            return self.__is_method

        # Infer that it is
        return self._prefix != "" and not self.__is_field

    @_is_method.setter
    def _is_method(self, is_method):
        assert isinstance(is_method, (bool, type(None))), "Invalid is_method type of {}".format(type(is_method))
        self.__is_method = is_method

    @property
    def _is_field(self):
        """bool: Is this a field?"""
        if self.__is_field is not None:
            return self.__is_field

        # Infer it
        return self._prefix != "" and not self.__is_method

    @_is_field.setter
    def _is_field(self, is_field):
        assert isinstance(is_field, (bool, type(None))), "Invalid is_field type of {}".format(type(is_field))
        self.__is_field = is_field

    @property
    def _is_class(self):
        """bool: Does this object actually describe a class?"""
        # If we've been explicitly told that this is a method
        if self.__is_class is not None:
            return self.__is_class

        # Infer that it is
        return self._prefix == ""

    @_is_class.setter
    def _is_class(self, is_class):
        assert isinstance(is_class, (bool, type(None))), "Invalid is_class type of {}".format(type(is_class))
        self.__is_class = is_class

    @property
    def _class(self):
        """str: The class type for this object."""
        return self.__class

    @_class.setter
    def _class(self, klass):
        assert isinstance(klass, (type(None), str)), "Invalid _class type of {}".format(type(klass))

        self.__class = klass

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


from .. import config
