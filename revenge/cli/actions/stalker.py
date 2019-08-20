
import logging
logger = logging.getLogger(__name__)

import colorama
from termcolor import cprint, colored
from ... import common
import json
import frida
import collections
from time import sleep

class ActionStalker:
    """General stalking action."""

    def __init__(self, process, include_module=None, tid=None, call=False, ret=False, exec=False, block=False, compile=False, include_function=None, *args, **kwargs):
        """
        Args:
            process: Parent process instantiation
            include_module: What module to follow, specifically
            tid (int, optional): What Thread ID to specifically follow (default: All)
        """

        self._process = process
        self._scripts = []
        self.from_modules = include_module or []
        self.tid = tid

        self.include_function = include_function
        if include_function is not None:
            logger.error("Sorry, include_function not working again just yet.")
            exit()
            function_module, function_offset = include_function.split(":")
            function_offset = int(function_offset, 16)
            self.include_function = self._process.modules[function_module]['base'] + function_offset
            logger.debug("Include function at: " + hex(self.include_function))

        self.call = call
        self.ret = ret
        self.exec = exec
        self.block = block
        self.compile = compile

        """
        # This should basically be moved over into the actual stalker lib

        self._include_function_traces = collections.defaultdict(lambda :list()) # key = pid, value = list/trace
        self._include_function_traces_depth = {}

        self.call = True if self.include_function is not None else call
        self.ret = True if self.include_function is not None else ret
        self.exec = exec
        self.block = True if self.include_function is not None else block
        self.compile = compile
        """

    def run(self):
        self.action_stalk()

    def action_stalk(self):
        """Start the stalker."""

        def stalk_cb(tid, ti):
            print(ti)
        
        trace = self._process.tracer.instructions(
                threads = self.tid,
                from_modules = self.from_modules,
                call = self.call,
                ret = self.ret,
                exec = self.exec,
                block = self.block,
                compile = self.compile,
                callback = stalk_cb,
                )

        # Make sure we're not blocking
        for addr in list(self._process.memory._active_breakpoints):
            self._process.memory[addr].breakpoint = False

        while self._process.alive:
            sleep(0.1)

