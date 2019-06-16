
import logging
logger = logging.getLogger(__name__)

import colorama
from termcolor import cprint, colored
from .. import common
import json

class ActionWindowsMessages:
    """Handle stalking Windows Messages."""

    def __init__(self, process, include_module=None, windows_message=None, *args, **kwargs):
        """
        Args:
            process: Parent process instantiation
        """
        self._process = process
        self.include_module = include_module or []
        self.windows_message = windows_message
        self._scripts = []

    def run(self):
        self.action_windows_messages()

    def action_windows_messages(self):
        """Stalk some windows messages."""

        self._known_windows_message_handlers = []

        def windows_cb(message, data):
            # REMINDER: The JavaScript is filtering out dups. We will only be getting each handler once.

            handler_ip = int(message['payload'], 16)
            handler_module = self._process.get_module_by_addr(handler_ip)
            handler_offset = handler_ip - self._process.modules[handler_module]['base']

            self._known_windows_message_handlers.append(handler_ip)

            # Allow downselection to this module
            if self.include_module == [] or handler_module in self.include_module:
                print("{: <32}".format("Found Message Handler") + colored(handler_module, 'cyan') + ":" + colorama.Style.BRIGHT + colored(hex(handler_offset), "cyan"))
                self._action_windows_messages_intercept(handler_module, handler_offset)

        if self._process.device_platform != 'windows':
            logger.error('This doesn\'t appear to be a Windows device...')
            exit(1)

        windows_js = self._process.load_js('windows_stalk_message_handlers.js')

        script = self._process.session.create_script(windows_js)
        script.on('message', windows_cb)

        logger.debug("Starting Windows Message monitor ... ")
        script.load()

        # Save so that we don't GC it
        self._scripts.append(script)

    def _action_windows_messages_intercept(self, module, offset):
        """Start watching for windows events on this handler."""

        def window_message_cb(message, data):
            Hwnd, Msg, wParam, lParam, module, context, tid, depth = message['payload']
            # context is dict of regs. i.e.: context['pc'], context['rax'], etc
            tid = int(tid)
            depth = int(depth)
            Hwnd = int(Hwnd,16)
            Msg = int(Msg,16)
            wParam = int(wParam,16)
            lParam = int(lParam,16)

            try:
                msg = ','.join(colored(x,'magenta') for x in common.windows_messages_by_id[Msg])
            except KeyError:
                msg = 'Unknown (' + hex(Msg) + ')'

            extra = ""
            if Msg in common.windows_messages_by_id and any(True for x in common.windows_messages_by_id[Msg] if x in ['WM_SYSKEYDOWN', 'WM_SYSKEYUP', 'WM_KEYUP', 'WM_KEYDOWN', 'WM_CHAR']):
                key = common.windows_keys_by_id[wParam]
                extra = key['Constant'] + ": " + key['Description']

            else:
                extra = 'wParam: {} lParam: {}'.format(hex(wParam), hex(lParam))

            print('{module: <32}{msg} {extra}'.format(
                module=module,
                msg=msg,
                extra=extra,
                ))


        js = self._process.load_js('windows_intercept_message_handler.js')

        js = js.replace("OFFSET_HERE", hex(offset))
        js = js.replace("MODULE_HERE", module)

        constraints = ""

        # Constrain what messages we're looking at
        if self.windows_message is not None:
            constraints += 'if (! {}.includes(Number(args[1]))) {{ return; }}\n'.format(json.dumps(self.windows_message))

        js = js.replace('CONSTRAINTS_HERE', constraints)

        script = self._process.session.create_script(js, runtime='v8')
        script.on('message', window_message_cb)
        script.load()

        # Save so that we don't GC it
        self._scripts.append(script)

