
import logging
import os

import revenge

logging.basicConfig(level=logging.DEBUG)

logger = logging.getLogger(__name__)
types = revenge.types

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

basic_one_64_path = os.path.join(bin_location, "basic_one_64.exe")


def test_modules_basic():

    process = revenge.Process(basic_one_64_path, resume=False)

    strcpy = process.memory['strcpy']
    assert process.memory.describe_address(strcpy.address) == "ntdll.dll:strcpy"

    str(process.modules)
    repr(process.modules)
    list(process.modules)

    kernel32 = process.modules['kernel32.dll']
    assert kernel32.name.lower() == "kernel32.dll"

    assert "IsDebuggerPresent" in kernel32.symbols

    # New pointer each time
    assert kernel32.file is not kernel32.file
    assert kernel32.file.readable()
    assert not kernel32.file.writable()
    # Read twice to confirm we're getting a fresh version
    assert kernel32.file.read(2) == b"MZ"
    assert kernel32.file.read(2) == b"MZ"

    process.quit()
