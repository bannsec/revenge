
import logging
logger = logging.getLogger(__name__)

from time import sleep

batch_context_script = r"""

var return_buffer = [];

function buffer_return(thing) {{
    return_buffer.push(thing);

    if ( return_buffer.length >= {return_buffer_size} ) {{
        flush();
        return_buffer = [];
    }}
}}

function flush () {{
    var message = {{
        'return_buffer': return_buffer
    }}
    send(message);
    recv('flush', flush);
}}

function handler (args) {{
    {handler_pre}

    args['list'].forEach( function (item) {{
        buffer_return([item, eval(item)]);
    }})

    {handler_post}
    
    // Notify parents context that's we're done.
    send({{'handler_completed': args['list'].length}})
    var recv_list = recv('list', handler);
    //recv_list.wait()
}}

function sleep(ms) {{
    return new Promise(resolve => setTimeout(resolve, ms));
}}

async function sleep_caller(ms) {{
    await sleep(60000);
}}

function generic_handler(args) {{
    if ( args['type'] == "list" ) {{
        handler(args);
    }}
    else if ( args['type'] == "flush" ) {{
        flush();
    }}
}}

var recv_list = recv('list', handler);
var recv_flush = recv('flush', flush);

// Setting up blocking recv-loop
// Blocking is sadly needed due to Java implementation...

/*
var receiver = recv(generic_handler)
while ( 1 ) {{
    receiver.wait()
    receiver = recv(generic_handler)
}}
*/


"""

class BatchContext(object):
    def __init__(self, process, send_buffer_size=None, return_buffer_size=None,
            on_message=None, run_script_generic=None, handler_pre=None,
            handler_post=None):
        """Represents a context used to send many commands to a frida thread.

        Args:
            process (frida_util.Process): Process this batch is running under.
            send_buffer_size (int, optional): How big of a buffer to have
                before sending. (default: 1024)
            return_buffer_size (int, optional): How big of a buffer to have
                before returning (default: 1024) If -1, do not return anything.
            on_message (callable, optional): Callable to be called when we
                recieve information back. By default, returned information
                will be dropped.
            run_script_generic (callable, optional): Which run_script_generic
                to use for calling? (default: process.run_script_generic)
            handler_pre (str, optional): Something to optionally run before
                iterating over the strings provided.
            handler_post (str, optional): Something to optionally run after
                iterating over the strings provided.

        Example:
            with process.BatchContext():
                for i in range(255):
                    do_something


        This Context will simply queue up a bunch of strings, which will be fed
        into the thread and executed sequentially.
        """

        self._process = process
        # Queue of things to send
        self.queue = []
        self.send_buffer_size = send_buffer_size or 1024
        self.return_buffer_size = return_buffer_size or 1024
        self.on_message = on_message
        self._script = None
        self._proxy_run_script_generic = run_script_generic or self._process.run_script_generic
        self._handler_pre = handler_pre or ""
        self._handler_post = handler_post or ""

        # How many things do we think the js side is still chewing on rn?
        self._num_pending_complete = 0

    def run_script_generic(self, script):
        """Handle calls to the run script generic.

        Args:
            script (str): This is the script that will be evaluated by js.
        
        This should be called from Process.run_script_generic since that will
        take care of the pre-processing for this.

        IF YOU CALL THIS DIRECTLY, IT'S ON YOU TO MAKE SURE THINGS ARE
        FORMATTED CORRECTLY! USE Process.run_script_generic INSTEAD!
        """

        # Process.run_script_generic gets called with this context
        # The script gets resolved and created in full by the run_script_generic
        # method. It then call this. When we're ready to run, we call
        # run_script_generic with NO context, but arguments will be for us.

        # Append this script to our list of things to run
        self.queue.append(script)

        # Not full enough buffer yet.
        if len(self.queue) < self.send_buffer_size:
            return

        self._send_buffer()

    def _flush_send(self):
        """Force a flush of the local send buffer. Pushing it to the Frida js."""
        self._send_buffer()

    def _flush_recieve(self):
        """Force a flush of the receiving buffer back to python."""

        if self._script is None:
            logger.error("Cannot find script to tell to flush!")
            return

        self._script[0].post({"type": "flush"})

    def _send_buffer(self):
        """Handles sending and emptying the buffer.

        This assumes that size checks have already been done."""

        if self._script is None:
            logger.error("Cannot find script to send my buffer to!")
            return

        batch_size = len(self.queue) # To not make assumptions on size

        if batch_size == 0:
            return

        logger.debug("Sending buffer of size " + str(batch_size))

        # Make sure to log what we just sent
        self._num_pending_complete += batch_size
        self._script[0].post({"type": 'list', "list": self.queue})
        self.queue = []
        
    def _context_on_message(self, message, data):
        """This is what actually gets called on_message.

        This allows the context to keep track of things and then pass on what
        needs to be passed on.
        """

        if message['type'] != "send":
            logger.error(str(message))
            return

        payload = message['payload']

        if isinstance(payload, dict):

            # Forward this data on to the on_message requested
            if "return_buffer" in payload and self.on_message is not None and payload['return_buffer'] != []:
                self.on_message(payload['return_buffer'])

            # Handle messages for us here...

            elif "handler_completed" in payload:
                # Mark down that this number have been completed
                self._num_pending_complete -= payload["handler_completed"]
        else:
            # This is probably something the user manually decided to send.
            if self.on_message is not None:
                self.on_message(payload)

    def _install_script(self):
        """Handles generating and starting the base script running."""

        # Clear out any of the old ones first
        self._unload_script()

        script = batch_context_script.format(
            return_buffer_size=self.return_buffer_size,
            handler_pre=self._handler_pre,
            handler_post=self._handler_post
        )
        
        self._proxy_run_script_generic(
                script,
                raw=True,
                unload=False,
                runtime='v8',
                timeout=0,
                on_message=self._context_on_message,
                )

        self._script = self._process._scripts.pop(0)

    def _unload_script(self):
        # TODO: This might be called before we're done processing...
        if self._script is None:
            return

        self._script[0].unload()
        self._script = None

    #################
    # Enable "with" #
    #################

    def __enter__(self):
        # Load up our script
        self._install_script()
        return self

    def __exit__(self, exception_type, exception_value, traceback):

        # Make sure we send the rest of our stuff over
        self._flush_send()

        # Spin until frida side is done
        while self._num_pending_complete != 0:
            self._flush_recieve()
            sleep(0.1)

        # TODO: There's a race condition here where the Frida js has finished
        # processing the things we've sent, but has not finished flushing data
        # back. Sleeping for now, but find a better way...
        sleep(0.2)

        # Done with this script.
        self._unload_script()

    def __del__(self):
        self._unload_script()


