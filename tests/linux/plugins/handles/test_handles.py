
import logging

logger = logging.getLogger(__name__)

import os
import pytest
import revenge
types = revenge.types

from revenge.plugins.handles import Handle

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "..", "..", "bins")

basic_one_path = os.path.join(bin_location, "basic_one")

def test_handles_basic():
    process = revenge.Process(basic_one_path, resume=False, verbose=False)
    opn = process.memory['open']
    close = process.memory['close']
    opn.return_type = types.Int32

    repr(process.handles)

    #
    # Read only
    #

    with open("/tmp/handles_test.txt","w") as f:
        f.write("Hello World!")

    # Open up a new handle
    fd = opn("/tmp/handles_test.txt", 0o100)

    assert fd != -1

    handle = process.handles[fd]
    str(handle)
    repr(handle)
    assert handle.readable
    assert not handle.writable
    assert handle.position == 0
    assert handle.write(b"test") == -1

    close(fd)

    #
    # Write only
    #

    # Open up a new handle
    fd = opn("/tmp/handles_test.txt", 0o101)

    assert fd != -1

    handle = process.handles[fd]
    str(handle)
    repr(handle)
    assert not handle.readable
    assert handle.writable
    assert handle.position == 0
    assert handle.read(12) == None

    close(fd)

    #
    # Read-write 
    #

    # Open up a new handle
    fd = opn("/tmp/handles_test.txt", 0o102)

    assert fd != -1

    handle = process.handles[fd]
    str(handle)
    repr(handle)
    assert handle.readable
    assert handle.writable
    assert handle.position == 0

    handle.position = 12
    assert handle.position == 12

    # Testing read
    handle.position = 0
    assert handle.read(12) == b"Hello World!"
    assert handle.position == 12
    assert handle.read(12,0) == b"Hello World!"
    assert handle.position == 12
    handle.position = 0
    # Read from offset should not affect current position
    assert handle.read(12,0) == b"Hello World!"
    assert handle.position == 0

    # Testing write
    handle.position = 0
    assert handle.write("31337") == 5
    assert handle.read(12,0) == b"31337 World!"
    assert handle.write(b"12345", 0) == 5
    assert handle.read(12,0) == b"12345 World!"
    assert handle.position == 5

    assert "handles_test.txt" in str(process.handles)
    close(fd)


    process.quit()

