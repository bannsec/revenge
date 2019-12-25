
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import os
import revenge
from revenge.engines.unicorn import UnicornEngine
from revenge.engines.frida import FridaEngine

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "..", "bins")

def test_engine_init():

    d = revenge.devices.LocalDevice(engine='unicorn')
    eng = revenge.engines.Engine._from_string('unicorn', device=d)
    assert isinstance(eng, UnicornEngine)
    assert isinstance(eng.memory, revenge.memory.Memory)

    d = revenge.devices.LocalDevice(engine='frida')
    eng = revenge.engines.Engine._from_string('frida', device=d)
    assert isinstance(eng, FridaEngine)
    assert isinstance(eng.memory, revenge.memory.Memory)
