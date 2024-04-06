import logging
logging.basicConfig(level=logging.DEBUG)

logger = logging.getLogger(__name__)

import os
import revenge
types = revenge.types

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "..", "..", "bins")

basic_one_path = os.path.join(bin_location, "basic_one")
basic_one_ia32_path = os.path.join(bin_location, "basic_one_ia32")


def test_native_instruction_counting_basic_x86_64():

    process = revenge.Process(basic_one_path, resume=False)

    main = process.memory['basic_one:main']
    main.breakpoint = True
    process.resume()

    counters = process.techniques.NativeInstructionCounter()
    counters.apply()
    counter = list(counters)[0]

    process.resume()

    # Just an estimate
    while counter.count < 1000:
        continue

    counters.remove()

    basic = process.modules['basic*']
    func = basic.symbols['func'].memory

    # 5 instructions in func
    counters = process.techniques.NativeInstructionCounter(from_modules="basic*")

    # Call with technique
    func(techniques=counters)
    counter = list(counters)[0]
    while counter.count != 5:
        continue

    process.quit()


def test_native_instruction_counting_basic_ia32():

    process = revenge.Process(basic_one_ia32_path, resume=False)
    main = process.memory['basic_one_ia32:main']
    main.breakpoint = True
    process.resume()

    counters = process.techniques.NativeInstructionCounter(from_modules='basic*')
    counters.apply()
    counter = list(counters)[0]

    process.resume()

    # This seemed right and theoretically shouldn't change.
    while counter.count != 158:
        continue

    counters.remove()

    basic = process.modules['basic*']
    func = basic.symbols['func'].memory

    # 5 instructions in func
    counters = process.techniques.NativeInstructionCounter(from_modules="basic*")

    # Call with technique
    func(techniques=counters)
    counter = list(counters)[0]
    while counter.count != 9:
        continue

    process.quit()
