
from . import Colorer
import logging

logger = logging.getLogger(__name__)

import typing
import colorama
colorama.init()

import os
from termcolor import cprint, colored
from prettytable import PrettyTable

here = os.path.dirname(os.path.abspath(__file__))

class NativeBacktrace(object):
    def __init__(self, process, backtrace):
        """Represents a backtrace. I.e.: what called what.

        Args:
            backtrace (list): List of instruction pointers
        """
        self._backtrace = backtrace

class NativeException(object):

    TYPES = ['abort', 'access-violation', 'illegal-instruction', 'arithmetic',
             'breakpoint', 'system']

    def __init__(self, context, backtrace=None, type=None,
            memory_operation=None, memory_address=None):
        """Represent a native CPU exception.
        
        Args:
            context: revenge cpu context
            backtrace: native backtrace object
            type (str): What type of exception is this.
            memory_operation (str, optional): Type of memory operation
                (read/write/execute)
            memory_address (int, optional): Address that was accessed when
                exception occurred.
        """

        self.context = context
        self.backtrace = backtrace
        self.type = type
        self.memory_operation = memory_operation
        self.memory_address = memory_address

    def __repr__(self):
        attrs = ['NativeException',
                self._process.memory.describe_address(self.address),
                self.type]

        return '<' + ' '.join(attrs) + '>'

    def __str__(self):
        s = "Native Exception\n"
        s += "~~~~~~~~~~~~~~~~\n"
        s += self.type + " at " + self._process.memory.describe_address(self.address) + "\n"

        if self.memory_operation is not None:
            s += "Memory " + self.memory_operation + " " + hex(self.memory_address) + "\n\n"
        else:
            s += "\n"

        s += str(self.context)
        s += "\n"

        # If we can't execute the memory location, don't print it
        if self.memory_operation != "execute":
            s += "\n" + str(self._process.memory[self.address].instruction_block)

        return s

    @classmethod
    def _from_frida_dict(cls, process, exception, backtrace):
        """Build a NativeException object directly from a frida dict."""
        assert isinstance(exception, dict)
        assert isinstance(backtrace, list)

        backtrace = NativeBacktrace(process, backtrace)
        return cls(
            context = CPUContext(process, **exception['context']),
            backtrace = backtrace,
            type = exception['type'],
            memory_operation = exception['memory']['operation'] if 'memory' in exception else None,
            memory_address = common.auto_int(exception['memory']['address']) if 'memory' in exception else None,
        )

    @property
    def _process(self):
        return self.context._process

    @property
    def type(self):
        """str: What type of native exception? One of """
        return self.__type

    @type.setter
    def type(self, type):
        type = type.lower()
        assert type in NativeException.TYPES, 'Unexpected native exception type of {}'.format(type)
        self.__type = type

    @property
    def address(self):
        """int: Address of this exception."""
        return self.context.ip

    @property
    def memory_address(self):
        """int: Address of memory exception."""
        return self.__memory_address

    @memory_address.setter
    def memory_address(self, memory_address):
        assert isinstance(memory_address, (int, type(None)))
        self.__memory_address = memory_address

    @property
    def memory_operation(self):
        """str: Type of memory operation performed at exception.

        Enum: read, write, execute"""
        return self.__memory_operation

    @memory_operation.setter
    def memory_operation(self, memory_operation):

        if isinstance(memory_operation, str):
            memory_operation = memory_operation.lower()
        assert memory_operation in ['read', 'write', 'execute', None], "Unexpected memory_operation of '{}'".format(memory_operation)
        
        self.__memory_operation = memory_operation

from .cpu import CPUContext
from . import common

NativeException.type.__doc__ += ', '.join(NativeException.TYPES)
