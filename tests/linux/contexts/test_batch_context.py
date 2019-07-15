
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import os
import frida_util
types = frida_util.types

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "..", "bins")

def test_batch_basic():
    global count, msg
    count = 0
    msg = ""

    def on_message(messages):
        global count
        assert type(messages) is list
        assert messages != []
        count += len(messages)

    def on_message_mirror(messages):
        global msg
        msg = messages[0]

    basic_one = frida_util.Process(os.path.join(bin_location, 'basic_one'), resume=False, verbose=False)

    #
    # Sending just one
    #

    with basic_one.BatchContext(send_buffer_size=1, return_buffer_size=1, on_message=on_message) as context:
        context.run_script_generic("1")

    # Only one message
    assert count == 1
    assert context._num_pending_complete == 0
    assert context._script is None

    
    #
    # Sending many
    #
    count = 0

    with basic_one.BatchContext(send_buffer_size=1, return_buffer_size=1, on_message=on_message) as context:
        for i in range(2048):
            context.run_script_generic(str(i))

    assert count == 2048
    assert context._num_pending_complete == 0
    assert context._script is None


    #
    # Sending non-alignment with send buffer size
    #
    count = 0

    with basic_one.BatchContext(send_buffer_size=5, return_buffer_size=1, on_message=on_message) as context:
        for i in range(16):
            context.run_script_generic(str(i))

    assert count == 16
    assert context._num_pending_complete == 0
    assert context._script is None

    #
    # Sending non-alignment with recieve buffer size
    #
    count = 0

    with basic_one.BatchContext(send_buffer_size=5, return_buffer_size=4, on_message=on_message) as context:
        for i in range(15):
            context.run_script_generic(str(i))

    assert count == 15
    assert context._num_pending_complete == 0
    assert context._script is None

    #
    # Sending non-alignment with both
    #
    count = 0

    with basic_one.BatchContext(send_buffer_size=5, return_buffer_size=4, on_message=on_message) as context:
        for i in range(13):
            context.run_script_generic(str(i))

    assert count == 13
    assert context._num_pending_complete == 0
    assert context._script is None

    #
    # Testing C call shorthand
    #
    msg = ""
    strlen = basic_one.memory[':strlen']

    with basic_one.BatchContext(send_buffer_size=1, return_buffer_size=1, on_message=on_message_mirror) as context:
        strlen("Hello world!", context=context)

    assert msg[1] == "0xc"
    assert context._num_pending_complete == 0
    assert context._script is None

