
from frida_util import Colorer

import logging
logging.basicConfig(level=logging.DEBUG)

logger = logging.getLogger(__name__)

import os
import frida_util

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

def test_common_auto_int():

    assert frida_util.common.auto_int(1) == 1
    assert frida_util.common.auto_int('1') == 1
    assert frida_util.common.auto_int('0x1') == 1
    assert frida_util.common.auto_int('0x10') == 16
    assert frida_util.common.auto_int(1.1) == 1.1
    assert frida_util.common.auto_int(None) == None
