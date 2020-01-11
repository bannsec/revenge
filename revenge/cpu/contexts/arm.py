import logging
logger = logging.getLogger(__name__)

from . import CPUContextBase

class ARMContext(CPUContextBase):
    REGS = ['pc', 'sp', 'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'lr']
    REGS_ALL = {}

    __slots__ = REGS
