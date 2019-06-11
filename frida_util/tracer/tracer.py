
import logging
logger = logging.getLogger(__name__)

from .. import common, types

class Tracer(object):

    def __init__(self, util):
        self._util = util

    def instructions(self, *args, **kwargs):
        """Start an instruction tracer."""
        return InstructionTracer(self._util, *args, **kwargs)

from . import InstructionTracer
