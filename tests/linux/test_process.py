
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import os
import frida_util
types = frida_util.types

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

# 
# Basic One
#

basic_one_path = os.path.join(bin_location, "basic_one")
basic_one_i8_addr = 0x201010
basic_one_ui8_addr = 0x201011
basic_one_i16_addr = 0x201012
basic_one_ui16_addr = 0x201014
basic_one_i32_addr = 0x201018
basic_one_ui32_addr = 0x20101C
basic_one_i64_addr = 0x201020
basic_one_ui64_addr = 0x201028
basic_one_string_addr = 0x724
basic_open_func_addr = 0x64A

basic_one = frida_util.Util(action="find", target="basic_one", file=basic_one_path, resume=False, verbose=False)

basic_one_ia32_path = os.path.join(bin_location, "basic_one_ia32")
basic_one_ia32 = frida_util.Util(action="find", target="basic_one_ia32", file=basic_one_ia32_path, resume=False, verbose=False)

def test_process_arch():

    assert basic_one.arch == "x64"
    assert basic_one_ia32.arch == "ia32"
