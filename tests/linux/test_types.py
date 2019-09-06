
from revenge import Colorer

import logging
logging.basicConfig(level=logging.DEBUG)

logger = logging.getLogger(__name__)

import os
import random
import pytest

import revenge

types = revenge.types

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

basic_one_path = os.path.join(bin_location, "basic_one")
basic_one_ia32_path = os.path.join(bin_location, "basic_one_ia32")


def test_sizeof():
    basic_one = revenge.Process(basic_one_path, resume=False, verbose=False, load_symbols='basic_one')
    basic_one_ia32 = revenge.Process(basic_one_ia32_path, resume=False, verbose=False, load_symbols='basic_one_ia32')

    assert types.Int8.sizeof == 8
    assert types.Int8(0).sizeof == 8
    assert types.UInt8.sizeof == 8
    assert types.UInt8(0).sizeof == 8
    assert types.Char.sizeof == 8
    assert types.Char(0).sizeof == 8
    assert types.UChar.sizeof == 8
    assert types.UChar(0).sizeof == 8

    assert types.Int16.sizeof == 16
    assert types.Int16(0).sizeof == 16
    assert types.UInt16.sizeof == 16
    assert types.UInt16(0).sizeof == 16
    assert types.Short.sizeof == 16
    assert types.Short(0).sizeof == 16
    assert types.UShort.sizeof == 16
    assert types.UShort(0).sizeof == 16

    assert types.Int32.sizeof == 32
    assert types.Int32(0).sizeof == 32
    assert types.UInt32.sizeof == 32
    assert types.UInt32(0).sizeof == 32
    assert types.Int.sizeof == 32
    assert types.Int(0).sizeof == 32
    assert types.UInt.sizeof == 32
    assert types.UInt(0).sizeof == 32

    assert types.Int64.sizeof == 64
    assert types.Int64(0).sizeof == 64
    assert types.UInt64.sizeof == 64
    assert types.UInt64(0).sizeof == 64
    assert types.Long.sizeof == 64
    assert types.Long(0).sizeof == 64
    assert types.ULong.sizeof == 64
    assert types.ULong(0).sizeof == 64

    assert types.Float.sizeof == 4
    assert types.Float(0).sizeof == 4
    assert types.Double.sizeof == 8
    assert types.Double(0).sizeof == 8

    with pytest.raises(revenge.exceptions.RevengeProcessRequiredError):
        types.Pointer().sizeof

    x = types.Pointer()
    x._process = basic_one
    assert x.sizeof == 64
    x._process = basic_one_ia32
    assert x.sizeof == 32

    with pytest.raises(revenge.exceptions.RevengeProcessRequiredError):
        types.StringUTF8().sizeof

    x = types.StringUTF8()
    x._process = basic_one
    assert x.sizeof == 64
    x._process = basic_one_ia32
    assert x.sizeof == 32

    with pytest.raises(revenge.exceptions.RevengeProcessRequiredError):
        types.StringUTF16().sizeof

    x = types.StringUTF16()
    x._process = basic_one
    assert x.sizeof == 64
    x._process = basic_one_ia32
    assert x.sizeof == 32

    with pytest.raises(revenge.exceptions.RevengeProcessRequiredError):
        types.Struct().sizeof

    #
    # Struct sizeof
    #

    x = types.Struct()
    x._process = basic_one
    assert x.sizeof == 0
    x._process = basic_one_ia32
    assert x.sizeof == 0

    x.add_member('test', types.Int32)
    assert x.sizeof == 32
    x.add_member('test2', types.Int8(4))
    assert x.sizeof == 40
    x.add_member('test3', types.Pointer)
    x._process = basic_one
    assert x.sizeof == 104
    x._process = basic_one_ia32
    assert x.sizeof == 72

def test_js_attr():
    
    for t in types.all_types:
        i = random.randint(1,0xff)
        x = t(i)

        if issubclass(type(x), types.Pointer):
            assert x.js == "ptr('{}')".format(hex(int(x)))

        elif issubclass(type(x), types.Int64):
            assert x.js == "int64('{}')".format(hex(int(x)))

        elif issubclass(type(x), types.UInt64):
            assert x.js == "uint64('{}')".format(hex(int(x)))

        else:
            assert x.js == str(x)

def test_types_attr():
    
    for t in types.all_types:
        if t in [types.StringUTF8, types.StringUTF16]:
            continue

        i = random.randint(1,0xff)
        x = t(i)
        assert type(x + 3) == type(x)

        # Not sure exactly what to do with this rn
        print("Type: " + x.type)

    for t in [types.StringUTF8, types.StringUTF16]:
        x = t("something here")

