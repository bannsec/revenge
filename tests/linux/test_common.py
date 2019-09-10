
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import os
import revenge

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "bins")

def test_common_auto_int():

    assert revenge.common.auto_int(1) == 1
    assert revenge.common.auto_int('1') == 1
    assert revenge.common.auto_int('0x1') == 1
    assert revenge.common.auto_int('0x10') == 16
    assert revenge.common.auto_int(1.1) == 1.1
    assert revenge.common.auto_int(None) == None

def test_common_load_file():

    process = revenge.Process(os.path.join(bin_location, 'basic_one'), resume=False, verbose=False, load_symbols=['basic_one'])

    with open("/bin/ls","rb") as f:
        ls = f.read()

    #
    # Local read
    #

    ls_local = revenge.common.load_file(process, "/bin/ls")
    assert ls_local.read() == ls
    assert revenge.common.load_file(process, "/notreallyhere") is None

    #
    # Remote ELF read
    #

    process.device.type = 'remote'

    ls_remote = revenge.common.load_file(process, "/bin/ls")
    assert ls_remote.read() == ls
    assert revenge.common.load_file(process, "/notreallyhere") is None

    #
    # Bad platform
    #

    #process.device_platform = 'not_a_real_platform'
    #assert revenge.common.load_file(process, "/bin/ls") is None

    process.quit()
