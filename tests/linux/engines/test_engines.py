
import logging
logging.basicConfig(level=logging.WARN)

logger = logging.getLogger(__name__)

import os
import revenge
from revenge.engines.pseudo import PseudoEngine
from revenge.engines.frida import FridaEngine

here = os.path.dirname(os.path.abspath(__file__))
bin_location = os.path.join(here, "..", "bins")

def test_engine_init():

    process = revenge.Process(os.path.join(bin_location, 'basic_one'), resume=False, verbose=False, load_symbols=['basic_one'])

    isinstance(revenge.engines.Engine._from_string(process, 'pseudo'), PseudoEngine)
    isinstance(revenge.engines.Engine._from_string(process, 'frida'), FridaEngine)

    process.quit()
