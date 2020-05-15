import logging
logging.basicConfig(level=logging.DEBUG)

logger = logging.getLogger(__name__)

import os
import revenge
types = revenge.types

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "..", "..", "bins")

basic_one_path = os.path.join(bin_location, "basic_one_64.exe")


def test_native_instruction_counting_basic_x86_64():

    process = revenge.Process(basic_one_path, resume=False)

    # Grab the main thread
    t = next(thread for thread in process.threads if thread.state == "stopped")

    counters = process.techniques.NativeInstructionCounter(from_modules='basic*')
    counters.apply(t)
    counter = list(counters)[0]

    process.resume()

    # Not sure there's always going to be an exact number...
    # Just ballpark that we're counting something
    while counter.count < 500:
        continue

    counters.remove()

    """Run with func not yet supported on windows
    func = process.memory[0x00401560]

    # 5 instructions in func
    counters = process.techniques.NativeInstructionCounter(from_modules="basic*")

    # Call with technique
    func(techniques=counters)
    counter = list(counters)[0]
    while counter.count != 5:
        continue
    """

    process.quit()
