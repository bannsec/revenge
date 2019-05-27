
import logging
logger = logging.getLogger(__name__)

import colorama
from termcolor import cprint, colored
from .. import common
import json

class ActionStalker:
    """General stalking action."""

    def __init__(self, stalker, include_module=None, tid=None, *args, **kwargs):
        """
        Args:
            stalker: Parent stalker instantiation
            include_module: What module to follow, specifically
            tid (int, optional): What Thread ID to specifically follow (default: All)
        """

        self._stalker = stalker
        self._scripts = []
        self.include_module = include_module
        self.tid = tid

    def run(self):
        self.action_stalk()

    def action_stalk(self):
        """Start the stalker."""
        
        def stalk_cb_call(message):
            """Specifically handle call stalk."""
            call_from = int(message['location'],16)
            call_to = int(message['target'], 16)
            depth = message['depth']
            #module_name = message['module']['name']
            
            module_from = self._stalker.get_module_by_addr(call_from) or "Unknown"
            if module_from == "Unknown":
                module_from_offset = 0
            else:
                module_from_offset = call_from - self._stalker.modules[module_from]['base']

            module_to = self._stalker.get_module_by_addr(call_to) or "Unknown"
            if module_to == "Unknown":
                module_to_offset = 0
            else:
                module_to_offset = call_to - self._stalker.modules[module_to]['base']

            print("{type: <10}{module_from}:{module_from_offset} -> {module_to}:{module_to_offset}".format(
                type = 'call',
                module_from = module_from,
                module_from_offset = hex(module_from_offset),
                module_to = module_to,
                module_to_offset = hex(module_to_offset)
                ))

        def stalk_cb(message, data):
            message = message['payload']

            if message['type'] == 'call':
                stalk_cb_call(message)
            
            else:
                logger.error('Unhandled type: ' + message['type'])
                print(message)

        # TODO: Add args for stalking other types of things
        # TODO: Print output for other types of calls

        stalk_js = self._stalker.load_js('stalk.js')
        stalk_js = stalk_js.replace("INCLUDE_MODULE_HERE", self.include_module)

        if self.tid == None:
            tid_list = self._stalker.threads.keys()
        else:
            tid_list = [self.tid]

        for tid in tid_list:
            stalk_js_replaced = stalk_js.replace("THREAD_ID_HERE", str(tid))
            script = self._stalker.session.create_script(stalk_js_replaced)
            script.on('message', stalk_cb)

            logger.debug("Starting stalker on TID: " + str(tid))
            script.load()

            # Save so that we don't GC it
            self._scripts.append(script)