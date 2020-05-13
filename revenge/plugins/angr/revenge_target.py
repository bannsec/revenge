
import logging

from angr_targets import ConcreteTarget
from angr.errors import SimConcreteMemoryError, SimConcreteRegisterError
from angr_targets.memory_map import MemoryMap


class RevengeConcreteTarget(ConcreteTarget):

    def __init__(self, process, context):
        self._process = process
        self._context = context
        super(RevengeConcreteTarget, self).__init__()

    def read_memory(self, address, nbytes, **kwargs):
        """
        Reading from memory of the target

            :param int address: The address to read from
            :param int nbytes:  The amount number of bytes to read
            :return:        The memory read
            :rtype: str
            :raise angr.errors.SimMemoryError
        """
        LOGGER.debug("RevengeConcreteTarget read_memory at %x ", address)

        # Check if it's mapped
        if self._process.memory.maps[address] is None:
            error = "RevengeConcreteTarget can't read_memory at address {address}. Page is not mapped.".format(address=hex(address))
            LOGGER.error(error)
            raise SimConcreteMemoryError(error)

        try:
            out = self._process.memory[address:address + nbytes].bytes

        except Exception as e:
            error = "RevengeConcreteTarget can't read_memory at address {address}: {e}".format(address=hex(address), e=e)
            LOGGER.error(error)
            raise SimConcreteMemoryError(error)

        if out is None:
            error = "RevengeConcreteTarget can't read_memory at address {address}".format(address=hex(address))
            LOGGER.error(error)
            raise SimConcreteMemoryError(error)

        return out

    def write_memory(self, address, value, **kwargs):
        """
        Writing to memory of the target
            :param int address:   The address from where the memory-write should start
            :param bytes value:     The actual value written to memory
            :raise angr.errors.ConcreteMemoryError
        """

        assert type(value) is bytes, 'write_memory value is actually type {}'.format(type(value))

        # Stubbing this
        LOGGER.debug("RevengeConcreteTarget ignoring write_memory at %x value %s", address, value)

    def read_register(self, register, **kwargs):
        """"
        Reads a register from the target
            :param str register: The name of the register
            :return: int value of the register content
            :rtype int
            :raise angr.errors.ConcreteRegisterError in case the register doesn't exist or any other exception
        """

        LOGGER.debug("RevengeConcreteTarget read_register at %s", register)

        try:
            return getattr(self._context, register)
        except KeyError:
            LOGGER.debug("RevengeConcreteTarget can't read_register %s", register)
            raise SimConcreteRegisterError("RevengeConcreteTarget can't read register %s", register)

    def write_register(self, register, value, **kwargs):
        """
        Writes a register to the target
            :param str register:     The name of the register
            :param int value:        int value written to be written register
            :raise angr.errors.ConcreteRegisterError
        """
        LOGGER.debug('RevengeConcreteTarget ignoring write_register %s', register)

    def set_breakpoint(self, address, **kwargs):
        """Inserts a breakpoint

                :param optional bool hardware: Hardware breakpoint
                :param optional bool temporary:  Tempory breakpoint
                :param optional str regex:     If set, inserts breakpoints matching the regex
                :param optional str condition: If set, inserts a breakpoint with the condition
                :param optional int ignore_count: Amount of times the bp should be ignored
                :param optional int thread:    Thread cno in which this breakpoints should be added
                :raise angr.errors.ConcreteBreakpointError
        """
        LOGGER.debug("RevengeConcreteTarget ignoring set_breakpoint")

    def remove_breakpoint(self, address, **kwargs):
        LOGGER.debug("RevengeConcreteTarget ignoring remove_breakpoint")

    def set_watchpoint(self, address, **kwargs):
        """Inserts a watchpoint

                :param address: The name of a variable or an address to watch
                :param optional bool write:    Write watchpoint
                :param optional bool read:     Read watchpoint
                :raise angr.errors.ConcreteBreakpointError
        """
        LOGGER.debug("RevengeConcreteTarget ignoring set_watchpoint")

    def remove_watchpoint(self, address, **kwargs):
        """Removes a watchpoint

                :param address: The name of a variable or an address to watch
                :raise angr.errors.ConcreteBreakpointError
        """
        LOGGER.debug("RevengeConcreteTarget ignoring remove_watchpoint")

    def get_mappings(self):
        """Returns the mmap of the concrete process
        :return:
        """

        LOGGER.debug("RevengeConcreteTarget getting the vmmap of the concrete process")

        vmmap = []

        for map in self._process.memory.maps:
            vmmap.append(MemoryMap(map.base, map.base + map.size, map.file_offset or 0, map.file or "<anonymous>"))

        return vmmap

    def is_running(self):
        # This implementation is synchronous. We will not be running if this call is being made.
        return False

    def stop(self):
        # This implementation is synchronous. We will not be running if this call is being made.
        return

    def run(self):
        """
        Resume the execution of the target
        :return:
        """
        LOGGER.debug('RevengeConcreteTarget ignoring run')

    @property
    def architecture(self):
        return self._process.arch

    @property
    def bits(self):
        return self._process.bits


LOGGER = logging.getLogger(__name__)
