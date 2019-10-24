
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import os
import revenge
NativeError = revenge.NativeError

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

basic_one_path = os.path.join(bin_location, "basic_one")

def test_basic_errors():

    process = revenge.Process(basic_one_path, resume=False, verbose=False)
    
    e = NativeError(process, 0)
    assert e.description == "Success"
    assert "0x0" in repr(e)
    assert e.description in repr(e)
    assert e.description == e._resolve_description()
    assert str(e) == e.description

    e.errno = 1
    assert e.description == "Operation not permitted"
    assert "0x1" in repr(e)
    assert e.description in repr(e)
    assert e.description == e._resolve_description()
    assert str(e) == e.description

    e = NativeError(process)
    repr(e)
    assert str(e) == ""

    process.quit()
