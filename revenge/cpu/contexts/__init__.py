
import logging

logger = logging.getLogger(__name__)

import colorama

class CPUContextBase(object):

    __slots__ = ['_process', 'pc', 'sp', '__changed_registers']

    def __init__(self, process, diff=None, **registers):
        """Represents a CPU context.
        
        Args:
            diff (CPUContext, optional): Build this context as a diff from a
                previous context

        Example:
            CPUContext(process, rax=12, rbx=13, <etc>)
        """

        self._process = process
        self.__changed_registers = []

        if not isinstance(diff, (type(None), self.__class__)):
            raise RevengeInvalidArgumentType("diff must be either None or an instance of {}".format(self.__class__))

        # Copy over old diff first if need be
        if diff is not None:
            for reg in self.REGS:
                setattr(self, reg, getattr(diff, reg))

        # Generically set any registers we're given
        for key, val in registers.items():

            if diff:
                self.changed_registers.append(key)

            # If dict, assume it's telescope for now
            if isinstance(val, dict):
                setattr(self, key, types.Telescope(self._process, data=val))
            else:
                setattr(self, key, common.auto_int(val))

    @property
    def changed_registers(self):
        """list: What registers were changed with this step?"""
        return self.__changed_registers

    def __getattr__(self, attr):
        return eval(self.REGS_ALL[attr])

    def __str__(self):
        table = PrettyTable(["Register", "Value"])

        table.align = 'l'

        for reg in self.REGS:

            # Highlight changed registers
            if reg in self.changed_registers:
                reg_colored = colorama.Fore.YELLOW + reg + colorama.Style.RESET_ALL
            else:
                reg_colored = reg

            thing = getattr(self, reg)
            
            if isinstance(thing, types.Telescope):
                table.add_row([reg_colored, thing.description])

            else:
                table.add_row([reg_colored, hex(getattr(self, reg))])

        return str(table)

    def __hash__(self):
        # Don't hash as a generator!
        return hash(tuple(getattr(self, reg) for reg in self.REGS))


class CPUContext(object):
    
    def __new__(klass, process, *args, **kwargs):
        """Represents a CPU for this running process."""

        arch = process.arch
        
        if arch == "x64":
            return X64Context(process, *args, **kwargs)

        elif arch == "ia32":
            return X86Context(process, *args, **kwargs)

        elif arch == "arm":
            return ARMContext(process, *args, **kwargs)

        else:
            logger.error("Currently unsupported architecture of {}".format(arch))

from prettytable import PrettyTable
from .x64 import X64Context
from .x86 import X86Context
from .arm import ARMContext
from ... import types, common

