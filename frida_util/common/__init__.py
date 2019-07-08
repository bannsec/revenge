
import logging
logger = logging.getLogger(__name__)

import os
import json
import io
import requests
import tempfile
import bs4
import lzma

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

def load_file(process, file_path):
    """Attempt to load the file with file_path. Use local loading if connection is local, and remote otherwise."""

    if process.device.device.type == 'local':
        return load_file_local(process, file_path)
    else:
        return load_file_remote(process, file_path)

def load_file_local(process, file_path):

    if not os.path.isfile(file_path):
        logger.debug("Couldn't load file: " + file_path)
        return

    return open(file_path, "rb")


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

def download_frida_server(os, arch):
    """Download frida server of arch to a temporary file. Returns temporary file location.
    
    Examples:
        download_frida_server('android', 'x86_64')
        download_frida_server('android', 'arm')
    """

    os = os.lower()
    arch = arch.lower()
    valid_os = ['android', 'ios', 'windows', 'macos']
    valid_arch = ['arm64', 'x86_64', 'x86', 'arm']

    assert os in valid_os, "Invalid OS selected. Must be in: " + str(valid_os)
    assert arch in valid_arch, "Invalid arch selected. Must be in: " + str(valid_arch)

    download_url = "https://github.com/frida/frida/releases/latest"

    r = requests.get(download_url)
    html = bs4.BeautifulSoup(r.text, features="html.parser")
    download_links = set([x['href'] for x in html("a") if 'download' in x['href']])
    server_download_links = set([x for x in download_links if "frida-server" in x])

    look_for = "{os}-{arch}.".format(os=os, arch=arch)
    server_download_link = [x for x in server_download_links if look_for in x]

    if server_download_link == []:
        error = "Couldn't find a download link for {} {}!".format(os, arch)
        logger.error(error)
        raise Exception(error)

    if len(server_download_link) > 1:
        error = "Found multiple download links for {} {}!".format(os, arch)
        logger.error(error)
        raise Exception(error)

    server_download_link = "https://github.com" + server_download_link[0]
    print("Downloading " + server_download_link, flush=True)
    r = requests.get(server_download_link)
    server_bin = lzma.decompress(r.content)

    with tempfile.NamedTemporaryFile(delete=False) as fp:
        file_name = fp.name
        fp.write(server_bin)

    logger.debug("Server downloaded to: " + file_name)

    return file_name
    
