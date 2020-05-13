
import logging
import os

import revenge

logging.basicConfig(level=logging.DEBUG)

logger = logging.getLogger(__name__)
types = revenge.types

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

basic_one_64_path = os.path.join(bin_location, "basic_one_64.exe")


def test_process_basic():

    process = revenge.Process(basic_one_64_path, resume=False)

    assert process.entrypoint == 0x00401500
    assert process.arch == "x64"
    assert process.bits == 64
    assert process.device.platform == "windows"
    assert process.endianness == "little"

    process.quit()
