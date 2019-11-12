
import logging
logger = logging.getLogger(__name__)


class NativeTimelessTraceItem(object):
    
    def __init__(self, process, context=None, depth=None):
        self._process = process
        self.context = context
        self.depth = depth

    def __repr__(self):
        attrs = ["NativeTimelessTraceItem"]
        attrs.append(str(self.context.pc.next.thing))

        return "<{}>".format(' '.join(attrs))

    @classmethod
    def from_snapshot(klass, process, snapshot):
        """Creates a NativeTimelessTraceItem from a snapshot returned by timeless_snapshot()"""

        if not isinstance(snapshot, dict):
            raise RevengeInvalidArgumentType("Invalid type for from_snapshot of {}. Expecting dict.".format(type(snapshot)))

        if "is_timeless_snapshot" not in snapshot or not snapshot["is_timeless_snapshot"]:
            raise RevengeInvalidArgumentType("from_snapshot does not appear to be timeless_snapshot dictionary.")

        context = snapshot["context"]
        depth = snapshot["depth"]
        return klass(process, context=context, depth=depth)

    @property
    def instruction(self):
        """Returns the assembly instruction object for this item."""
        return self.context.pc.next.thing

    @property
    def context(self):
        return self.__context

    @context.setter
    def context(self, context):

        # TODO: This is an assumption...
        if isinstance(context, dict):
            self.__context = CPUContext(self._process, **context)

        elif context is None:
            self.__context = None

        else:
            raise RevengeInvalidArgumentType("Unhandled context type of {}".format(type(context)))

from ...exceptions import *
from ...cpu import CPUContext
