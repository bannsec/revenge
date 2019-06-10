
import logging
logging.basicConfig(level=logging.DEBUG)

logger = logging.getLogger(__name__)

import os
import json

here = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(here, 'windows_messages_by_name.json')) as f:
    windows_messages_by_name = json.loads(f.read())

with open(os.path.join(here, 'windows_messages_by_id.json')) as f:
    windows_messages_by_id = json.loads(f.read())
    # JSON doesn't support int keys
    windows_messages_by_id = {int(x):y for x,y in windows_messages_by_id.items()}

with open(os.path.join(here, 'windows_keys_by_id.json')) as f:
    windows_keys_by_id = json.loads(f.read())
    # JSON doesn't support int keys
    windows_keys_by_id = {int(x):y for x,y in windows_keys_by_id.items()}

def auto_int(x):
    """Sometimes frida returns ints as a string instead of int. Just auto detect and return as int."""
    if type(x) is int:
        return x

    if type(x) is str:
        return int(x,0)

    # Accepting this as OK for now.
    if type(x) is float:
        return x

    logger.error("Unhandled auto_int type of {}".format(type(x)))

def parse_location_string(s):
    """Parse location string <[module:offset]|symbol> into (module, offset, symbol)."""

    assert type(s) == str, "Unexpected argument type of {}".format(type(s))

    module, offset_or_symbol = s.split(":")
    
    try:
        offset = hex(int(offset_or_symbol,0))
        symbol = ""
    except ValueError:
        offset = "0"
        symbol = offset_or_symbol

    return module, offset, symbol


