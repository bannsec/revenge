
import logging
logger = logging.getLogger(__name__)

from termcolor import cprint, colored
from prettytable import PrettyTable

class NativeTimelessTrace(object):
    
    def __init__(self, process, thread):
        """Container for NativeTimelessTrace items

        Args:
            process (revenge.process.Process): Active process object.
            thread (int): Thread ID for this trace or Thread object
        """
        self._process = process
        self._thread = self._process.threads[thread]
        self._trace = [] # List of actual trace items
        self._script = None

    def start(self):
        """Start tracing."""
        s = "timeless_trace({})".format(self._thread.id)
        self._process.run_script_generic(s, 
                raw=True,
                include_js=("dispose.js", "send_batch.js", "stalk.js", "telescope.js", "timeless.js"),
                unload=False,
                on_message=self._parse_items_cb,
                runtime='v8'
        )

        self._script = self._process._scripts.pop(0)
        self._process.techniques._active_stalks[self._thread.id] = self

    def stop(self):
        """Stop tracing."""
        if self._script is not None:
            self._script[0].exports.unfollow()
            # As with NativeInstructionTracer, the script unload always causes a process crash for some reason
            # TODO: Figure out why the f that happens
            #self._script[0].unload()
            self._process.techniques._active_stalks.pop(self._thread.id)
            self._script = None

    def wait_for(self, address):
        """Don't return until the given address is hit in the trace."""
        address = self._process._resolve_location_string(address)

        # TODO: Optimize this so I don't keep checking the same IPs over and over
        while True:
            try:
                return next(x for x in self if int(x.context.pc) == address)
            except StopIteration:
                continue

    def __str__(self):

        table = PrettyTable(["inst"])
        table.border = False
        table.header = False
        table.align = 'l'
        
        for item in self:
            table.add_row([" "*item.depth + str(item.context.pc.next.thing)])

        return str(table)

    def __len__(self):
        return len(self._trace)

    def __repr__(self):
        l = len(self)
        return "<NativeTimelessTrace {} {}>".format(
                l,
                "item" if l == 1 else "items"
        )

    def __iter__(self):
        return self._trace.__iter__()

    def __getitem__(self, item):

        if isinstance(item, int):
            return self._trace.__getitem__(item)

        if isinstance(item, slice):
            ret = NativeTimelessTrace(self._process, self._thread)
            ret._trace = self._trace[item]
            return ret

        raise Exception("Unhandled getitem type of {}".format(type(item)))

    def __len__(self):
        return len(self._trace)

    def _parse_items_cb(self, items, data):
        """Parse incoming trace items.

        Args:
            items (list): List of dicts.
        
        This method will be called directly as a callback from the js.
        """

        if items["type"] == "error":
            logger.error("_parse_items_cb error: " + items["description"])

        else:
            for item in items["payload"]:
                self._trace.append(NativeTimelessTraceItem.from_snapshot(self._process, item))

from .timeless_trace_item import NativeTimelessTraceItem
