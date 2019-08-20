
from revenge import Colorer

import logging
logging.basicConfig(level=logging.DEBUG)

logger = logging.getLogger(__name__)

import os
import random

import revenge

types = revenge.types

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

