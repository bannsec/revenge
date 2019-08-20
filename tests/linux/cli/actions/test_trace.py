

import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import os
import random
import numpy as np
import time
from copy import copy
import re
import subprocess

import revenge
types = revenge.types

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "..", "..", "bins")

# 
# Basic One
#

basic_one_path = os.path.join(bin_location, "basic_one")

def test_basic_tests():

    # TODO: Probably add more tests..

    find_action = ["revenge", "stalk", basic_one_path, "--call", "-I", "basic_one"]

    out = subprocess.check_output(find_action).decode()
    assert ":__libc_start_main" in out
    assert ":_init" in out
    assert ":frame_dummy" in out
    assert ":func" in out
