
import logging
logger = logging.getLogger(__name__)

from ... import common

class NativeTimelessTraceItem(object):
    
    def __init__(self, process, context=None, depth=None, previous=None):
        """Class describing a single step of NativeTimelessTracing

        Args:
            process (revenge.Process): Process object
            context (dict): Dictionary describing this step's context
            depth (int): Current call depth
            previous (NativeTimelessTraceItem, optional): Previous timeless
                trace item to use for differential generation
        """
        self._process = process
        self._previous = previous
        self.context = context
        self.depth = depth

    def __repr__(self):
        attrs = ["NativeTimelessTraceItem"]
        attrs.append(str(self.context.pc.next.thing))

        return "<{}>".format(' '.join(attrs))

    @classmethod
    @common.validate_argument_types(snapshot=dict)
    def from_snapshot(klass, process, snapshot, previous=None):
        """Creates a NativeTimelessTraceItem from a snapshot returned by timeless_snapshot()
        
        Args:
            process (revenge.Process): Process object
            snapshot (dict): Timeless snapshot dictionary
            previous (NativeTimelessTraceItem, optional): Previous timeless
                trace item to use for differential generation
        """

        if "is_timeless_snapshot" not in snapshot or not snapshot["is_timeless_snapshot"]:
            raise RevengeInvalidArgumentType("from_snapshot does not appear to be timeless_snapshot dictionary.")

        context = snapshot["context"]
        depth = snapshot["depth"]
        return klass(process, context=context, depth=depth, previous=previous)

    @property
    def instruction(self):
        """Returns the assembly instruction object for this item."""
        return self.context.pc.next.thing

    @property
    def context(self):
        return self.__context

    @context.setter
    @common.validate_argument_types(context=(dict, type(None)))
    def context(self, context):
        diff = self._previous.context if self._previous is not None else None

        # TODO: This is an assumption...
        if isinstance(context, dict):
            self.__context = CPUContext(self._process, diff=diff, **context)

        elif context is None:
            self.__context = None

from ...exceptions import *
from ...cpu import CPUContext
