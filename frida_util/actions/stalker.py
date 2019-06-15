
import logging
logger = logging.getLogger(__name__)

import colorama
from termcolor import cprint, colored
from .. import common
import json
import frida
import collections

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
        self.include_module = include_module or []
        self.tid = tid

        self.include_function = include_function
        if include_function is not None:
            function_module, function_offset = include_function.split(":")
            function_offset = int(function_offset, 16)
            self.include_function = self._process.modules[function_module]['base'] + function_offset
            logger.debug("Include function at: " + hex(self.include_function))

        self._include_function_traces = collections.defaultdict(lambda :list()) # key = pid, value = list/trace
        self._include_function_traces_depth = {}

        self.call = True if self.include_function is not None else call
        self.ret = True if self.include_function is not None else ret
        self.exec = exec
        self.block = True if self.include_function is not None else block
        self.compile = compile

    def run(self):
        self.action_stalk()

    def action_stalk(self):
        """Start the stalker."""
        
        def stalk_cb_call(message):
            """Specifically handle call stalk."""
            call_from = int(message['from_ip'],16)
            call_to = int(message['to_ip'], 16)

            if 'depth' in message:
                depth = message['depth']
            else:
                depth = None

            tid = int(message['tid'])
            type = message['type']

            module_from = message['from_module'] or "Unknown"

            if module_from == "Unknown":
                module_from_offset = 0
            else:
                module_from_offset = call_from - self._process.modules[module_from]['base']

            module_to = message['to_module'] or "Unknown"
            if module_to == "Unknown":
                module_to_offset = 0
            else:
                module_to_offset = call_to - self._process.modules[module_to]['base']

            record = {
                'type': type,
                'tid': tid,
                'from': {
                    'ip': module_from_offset,
                    'module': module_from
                    },
                'to': {
                    'ip': module_to_offset,
                    'module': module_to,
                    },
                'depth': depth
                }

            #
            # Downselecting into specific function
            # 

            if self.include_function is not None:
                # We're not in a trace and we're not starting now
                if tid not in self._include_function_traces and call_from != self.include_function:
                    return

                self._include_function_traces[tid].append(record)

                # Implicitly determining our depth
                # NOTE: Having to do this since Windows doesn't always directly call a function, sometimes it does jmp tricks.
                if tid not in self._include_function_traces_depth and type in ['call', 'ret']:
                    self._include_function_traces_depth[tid] = depth

                # If we're returning at our min depth, we're done.
                if type == 'ret' and depth == self._include_function_traces_depth[tid]:
                    self._include_function_traces_depth.pop(tid)
                    self._include_function_traces.pop(tid)


            print("{type: <10}{tid: <10}{module_from}:{module_from_offset} -> {module_to}:{module_to_offset} {depth}".format(
                type = type,
                tid = hex(tid),
                module_from = module_from,
                module_from_offset = hex(module_from_offset),
                module_to = module_to,
                module_to_offset = hex(module_to_offset),
                depth=depth
                ))


        def stalk_cb_exec(message):
            """Specifically handle exec stalk."""
            ip = int(message['ip'],16)
            tid = int(message['tid'])
            type = message['type']

            module_from = message['module'] or "Unknown"

            if module_from == "Unknown":
                module_from_offset = 0
            else:
                module_from_offset = ip - self._process.modules[module_from]['base']

            print("{type: <10}{tid: <10}{module_from}:{module_from_offset}".format(
                type = type,
                tid = hex(tid),
                module_from = module_from,
                module_from_offset = hex(module_from_offset),
                ))


        def stalk_cb(message, data):
            #print(message)
            messages = message['payload']
            #print('stalk_cb: ', message)

            for message in messages:
                
                if message['type'] in ['call', 'ret', 'block', 'compile']:
                    stalk_cb_call(message)

                elif message['type'] == 'exec':
                    stalk_cb_exec(message)

                else:
                    logger.error('Unhandled type: ' + message['type'])
                    print(message)

        # TODO: Add args for stalking other types of things
        # TODO: Print output for other types of calls

        stalk_js = self._process.load_js('stalk.js')
        stalk_js = stalk_js.replace("INCLUDE_MODULE_HERE", json.dumps(self.include_module))
        stalk_js = stalk_js.replace("STALK_CALL", json.dumps(self.call))
        stalk_js = stalk_js.replace("STALK_RET", json.dumps(self.ret))
        stalk_js = stalk_js.replace("STALK_EXEC", json.dumps(self.exec))
        stalk_js = stalk_js.replace("STALK_BLOCK", json.dumps(self.block))
        stalk_js = stalk_js.replace("STALK_COMPILE", json.dumps(self.compile))

        if self.tid == None:
            tid_list = self._process.threads.keys()
        else:
            tid_list = [self.tid]

        for tid in tid_list:
            stalk_js_replaced = stalk_js.replace("THREAD_ID_HERE", str(tid))
            script = self._process.session.create_script(stalk_js_replaced,  runtime='v8')
            script.on('message', stalk_cb)

            logger.debug("Starting stalker on TID: " + str(tid))
            try:
                script.load()
            except frida.TransportError:
                logger.error("Couldn't load stalker! Possibly due to Frida AVX2 dependency")
                logger.error("Check out issue for more info: https://github.com/frida/frida/issues/901")
                exit(1)

            # Save so that we don't GC it
            self._scripts.append(script)
