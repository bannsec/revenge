
import logging
logger = logging.getLogger(__name__)

from prettytable import PrettyTable
from .. import Technique

class NativeTimelessTracer(Technique):
    TYPE = "stalk"

    def __init__(self, process):
        """Performs timeless tracing.
        
        Examples:
            .. code-block:: python3
                
                #
                # Global apply
                #

                # Setup the tracer
                timeless = process.techniques.NativeTimelessTracer()
                timeless.apply()

                # Continue execution
                process.memory[process.entrypoint].breakpoint = False

                # Keep checking back to your trace
                print(timeless)

                # Grab your specific trace
                t = list(timeless)[0]
                print(t)
                print(t[-50:])

                # Look at the trace items individually
                ti = t[0]
                print(ti.context)
                print(ti.context.rax)

                #
                # Call apply
                #

                # Also can apply this per-call
                time = process.memory['time']
                time(0, techniques=timeless)

        """
        self._process = process
        self.traces = {}

    def apply(self, threads=None):
        
        if threads is None:
            threads = list(self._process.threads)

        if not isinstance(threads, (list, tuple)):
            threads = [threads]

        for thread in threads:
            # Resolve int/Thread/etc
            thread = self._process.threads[thread]
            self.traces[thread.id] = NativeTimelessTrace(self._process, thread.id)
            self.traces[thread.id].start()

    def remove(self):
        for tid, trace in self.traces.items():
            trace.stop()

    def _parse_timeless_snapshot(self, snapshot):
        """Takes the snapshot (dict) and returns a NativeTimelessTraceItem object from it.

        Args:
            snapshot (dict): The snapshot dict returned from timeless_snapshot js

        Returns: revenge.techniques.native_timeless_tracer.timeless_trace_item.NativeTimelessTraceItem
        """
        return NativeTimelessTraceItem.from_snapshot(self._process, snapshot)

    def __repr__(self):
        num_threads = len(self.traces)

        return "<NativeTimelessTracer {} {}>".format(
            num_threads,
            "Threads" if num_threads != 1 else "Thread"
        )

    def __str__(self):
        table = PrettyTable(['tid', 'count'])

        for tid, trace in self.traces.items():
            table.add_row([str(tid), str(len(trace))])

        return str(table)

    def __iter__(self):
        return self.traces.__iter__()

# doc fixup
NativeTimelessTracer.__doc__ = NativeTimelessTracer.__init__.__doc__

from .timeless_trace_item import NativeTimelessTraceItem
from .timeless_trace import NativeTimelessTrace
