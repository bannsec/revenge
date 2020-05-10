
import logging
import os

import revenge

logging.basicConfig(level=logging.DEBUG)

logger = logging.getLogger(__name__)
types = revenge.types

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

basic_one_64_path = os.path.join(bin_location, "basic_one_64.exe")


def test_memory_basic():

    process = revenge.Process(basic_one_64_path, resume=False, load_symbols='basic_one_64.exe')
    process.engine.resume(process.pid)

    process.stdout("i8: ")
    assert process.memory[int(process.stdout("\n"), 16)].int8 == -13
    process.stdout("ui8: ")
    assert process.memory[int(process.stdout("\n"), 16)].uint8 == 13

    process.stdout("i16: ")
    assert process.memory[int(process.stdout("\n"), 16)].int16 == -1337
    process.stdout("ui16: ")
    assert process.memory[int(process.stdout("\n"), 16)].uint16 == 1337

    process.stdout("i32: ")
    assert process.memory[int(process.stdout("\n"), 16)].int32 == -1337
    process.stdout("ui32: ")
    assert process.memory[int(process.stdout("\n"), 16)].uint32 == 1337

    process.stdout("i64: ")
    assert process.memory[int(process.stdout("\n"), 16)].int64 == -1337
    process.stdout("ui64: ")
    assert process.memory[int(process.stdout("\n"), 16)].uint64 == 1337

    process.stdout("func: ")
    func = process.memory[int(process.stdout("\n"), 16)]
    assert func() == 12

    process.quit()
