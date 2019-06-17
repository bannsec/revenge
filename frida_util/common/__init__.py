
import logging
logging.basicConfig(level=logging.DEBUG)

logger = logging.getLogger(__name__)

import os
import json
import io

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
    if isinstance(x, int):
        return x

    if isinstance(x, str):
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

def load_file_remote(process, file_path):
    """Attempt to load the file with file_path remotely, returning it in full as a BytesIO object."""

    if process.device_platform == 'linux':


        fopen = process.memory[':fopen']
        fseek = process.memory[':fseek']
        ftell = process.memory[':ftell']
        fread = process.memory[':fread']
        fclose = process.memory[':fclose']
        malloc = process.memory[':malloc']
        free = process.memory[':free']

        fp = fopen(file_path, 'r')

        # If we couldn't open it, fail gracefully
        if fp == 0:
            logger.debug("Couldn't load file: " + file_path)
            return

        fseek(fp, 0, 2)
        size = ftell(fp)
        fseek(fp, 0, 0)
        
        malloc_ptr = malloc(size)
        mem = process.memory[malloc_ptr:malloc_ptr+size]
        fread(malloc_ptr, size, 1, fp)

        elf_io = io.BytesIO(mem.bytes)
        free(malloc_ptr)
        fclose(fp)

        return elf_io

    else:
        logger.error("No remote file load support yet for: " + process.device_platform)
