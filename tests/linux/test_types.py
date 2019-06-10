
from frida_util import Colorer

import logging
logging.basicConfig(level=logging.DEBUG)

logger = logging.getLogger(__name__)

import os
import random

import frida_util

types = frida_util.types

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
        i = random.randint(1,0xff)
        x = t(i)

        # Not sure exactly what to do with this rn
        print("Type: " + x.type)
