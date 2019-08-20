
import logging
logger = logging.getLogger(__name__)

from .. import common, types

class Tracer(object):

    def __init__(self, process):
        self._process = process

        # TID: Trace
        self._active_instruction_traces = {}

    def instructions(self, *args, **kwargs):
        """Start an instruction tracer."""
        return InstructionTracer(self._process, *args, **kwargs)

from . import InstructionTracer

# Fixup doc strings
Tracer.instructions.__doc__ = InstructionTracer.__init__.__doc__
