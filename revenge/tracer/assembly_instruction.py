
import logging
logger = logging.getLogger(__name__)

from termcolor import cprint, colored
import re

from prettytable import PrettyTable

from .. import types, common

class AssemblyBlock(object):
    """Represents an assembly block."""

    def __init__(self, process, address):
        self._process = process
        self.instructions = []
        self.address = address
        self._parse_block()

    def _parse_block(self):
        address = self.address
        end_block = ['ret', 'call', 'branch_relative']

        while True:
            self.instructions.append(AssemblyInstruction(self._process, address))

            for ender in end_block:
                if ender in self.instructions[-1].groups:
                    return
            
            address = self.instructions[-1].address_next

    def __getitem__(self, item):
        return self.instructions[item]

    def __str__(self):
        s = []
        for i in self.instructions:
            s.append(str(i))
        return '\n'.join(s)

    def __repr__(self):
        attrs = ['AssemblyBlock', str(len(self.instructions)), 'instructions']
        return '<' + ' '.join(attrs) + '>'


class AssemblyInstruction(object):
    """Represents an assembly instruction."""

    def __init__(self, process, address):
        """

        Args:
            process: Process object
            address (int): Address for this instruction. Will load from this address.
        """

        self._process = process
        self.address = address

    def _load_from_address(self):
        inst = self._process.run_script_generic("""send(Instruction.parse({}));""".format(self.address.js), raw=True, unload=True)[0][0]

        self.__address_next = types.Pointer(common.auto_int(inst['next']))
        self.__size = inst['size']
        self.__mnemonic = inst['mnemonic']
        self.__args_str = inst['opStr']
        self.__operands = inst['operands']
        self.__registers_read = inst['regsRead']
        self.__registers_written = inst['regsWritten']
        self.__groups = inst['groups']

    def __str__(self):
        return "{address} {mnemonic: <20}{args}".format(
                    address=colored(hex(self.address), attrs=['bold']) + ":",
                    mnemonic=colored(self.mnemonic, "cyan"),
                    args=colored(self.args_str_resolved, "cyan", attrs=['bold']),
                )

    def __repr__(self):
        attrs = ['AssemblyInstruction', hex(self.address), self.mnemonic, self.args_str]
        return '<' + ' '.join(attrs) + '>'

    @property
    def args_str_resolved(self):
        """str: Attempt to resolve addresses in the args str into symbols."""
        s = self.args_str
        
        things = re.findall('0x[0-9a-f]+', s)
        
        for thing in things:
            sym = self._process.modules.lookup_symbol(int(thing,16))
            if sym is not None:
                s = s.replace(thing, sym)

        return s

    @property
    def groups(self):
        """list: List of descriptive groups that this instruction belongs to."""
        return self.__groups

    @property
    def registers_written(self):
        """list: List of registers written by this instruction."""
        return self.__registers_written

    @property
    def registers_read(self):
        """list: List of registers that are read by this instruction."""
        return self.__registers_read

    @property
    def operands(self):
        """list: List of operands."""
        return self.__operands

    @property
    def args_str(self):
        """str: Operation arguments as a string."""
        return self.__args_str

    @property
    def mnemonic(self):
        """str: Operation mnemonic."""
        return self.__mnemonic

    @property
    def size(self):
        """int: Size of this instruction in bytes."""
        return self.__size

    @property
    def address_next(self):
        """Pointer: Address of instruction following this one."""
        return self.__address_next

    @property
    def address(self):
        """Pointer: Address where this instruction is located."""
        return self.__address

    @address.setter
    def address(self, address):
        self.__address = types.Pointer(common.auto_int(address))
        self._load_from_address()
