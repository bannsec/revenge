
import logging
logger = logging.getLogger(__name__)

import os
import shutil
import json
import io
import requests
import tempfile
import bs4
import lzma
import pprint
import functools
import inspect
import re
from types import FunctionType, MethodType

from revenge.exceptions import *

import atexit

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

def int_to_signed(i, n):
    """Takes int i and bits n, and converts to signed."""

    if n > 2**n -1:
        raise RevengeInvalidArgumentType("Int i is greater than the size n.")

    mask = 1 << (n-1)
    return (i^mask) - mask


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

    if ":" in s:
        module, offset_or_symbol = s.split(":")
    else:
        module = ""
        offset_or_symbol = s
    
    try:
        offset = int(offset_or_symbol,0)
        symbol = ""
    except ValueError:
        offset = 0
        symbol = offset_or_symbol

    # This must be a specified offset
    if "+" in symbol:
        symbol, more_offset = symbol.split("+")
        offset += int(more_offset,0)

    return module, hex(offset), symbol

def load_file(process, file_path):
    """Attempt to load the file with file_path. Use local loading if connection is local, and remote otherwise."""

    # Fucking import hell..
    if process.device.__class__.__name__ == "LocalDevice":
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

    # file cache dir so that we don't re-download expensive things
    global file_cache_dir

    try:
        file_cache_dir
    except:
        file_cache_dir = tempfile.mkdtemp()
        atexit.register(shutil.rmtree, file_cache_dir, ignore_errors=True)

    # Check cache first
    cache_name = os.path.join(file_cache_dir, os.path.basename(file_path))
    
    if os.path.isfile(cache_name):
        return open(cache_name, "rb")

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

        # Save off a copy to our cache
        with open(cache_name, "wb") as f:
            f.write(elf_io.read())
            elf_io.seek(0)

        #return elf_io
        return open(cache_name, "rb")

    else:
        logger.error("No remote file load support yet for: " + process.device_platform)

def download_frida_server(os, arch, release=None):
    """Download frida server of arch to a temporary file. Returns temporary file location.

    Args:
        os (str): What OS to download, i.e.: ios, android, linux, windows, macos
        arch (str): What arch to download, i.e.: x86, x86_64, arm, arm64
        release (str, optional): What release to download (default to latest)
            Example: 12.6.11
    
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

    if release is None:
        download_url = "https://github.com/frida/frida/releases/latest"
    else:
        download_url = "https://github.com/frida/frida/releases/tag/" + release

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

def on_msg_print(m, d, TAG=None):
    """Generic on message handler to simply print it out."""

    if TAG is None:
        TAG = ''
    else:
        TAG = TAG + ": "

    if m['type'] == 'error':
        logger.error(TAG + "Script Run Error: " + pprint.pformat(m['description']))
        logger.debug(pprint.pformat(m))
        return
    
    print("on_message: {}".format([m,d]))

#
# Decorators
#

class implement_in_engine(object):
    """Decorator to require a method to be implemented in the engine"""

    def __call__(self, func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            raise NotImplementedError(func.__name__ + ": not yet implemented in " + args[0].__class__.__name__ + ".")

        return wrapper

class validate_argument_types(object):
    """Standard way to check arguments are the right type.
    
    Example:
        @validate_argument_types(arg1=int, arg2=(int, float))
    """

    def __init__(self, **kwargs):
        self.validators = kwargs
        pass

    def __call__(self, func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            #raise NotImplementedError(func.__name__ + ": not yet implemented in " + args[0].__class__.__name__ + ".")
            argspec = inspect.getfullargspec(func).args
            
            if argspec[0] == 'self':
                class_name = args[0].__class__.__name__ + "."
            else:
                class_name = ""

            func_name = class_name + func.__name__

            # Loop through things we want to validate
            for arg, t in self.validators.items():

                # Standardize t into a list
                if isinstance(t, list):
                    t = tuple(t)

                if not isinstance(t, tuple):
                    t = (t,)

                # If this is positional, what is it's position?
                argindex = argspec.index(arg)

                # If the arg was passed in as a kwarg
                if arg in kwargs:
                    input_arg = kwargs[arg]

                elif len(args) > argindex:
                    input_arg = args[argindex]

                else:
                    # This validator wasn't hit
                    continue

                if not isinstance(input_arg, t):
                    raise RevengeInvalidArgumentType(func_name + ": Invalid type for argument '{arg}'. Expected type in {expect}. Got type {got}.".format(
                        arg = arg,
                        expect = t,
                        got = type(input_arg),
                        ))

            # Pass it through
            return func(*args, **kwargs)

        return wrapper

class require_imp(object):
    """Simple wrapper to require that the imp property is not None. If it's None, wrapper will return None."""
    def __call__(self, func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if args[0].imp is None:
                return None
            return func(*args, **kwargs)
    
        return wrapper


class retry_on_exception(object):
    """Decorator to retry the given function up to retry times if an
    exception is caught from the given list/tuple.

    Args:
        exceptions (tuple): What exceptions should trigger a retry?
        retry (int, optional): How many times to retry? Default: 5
    """

    def __init__(self, exceptions, retry=5):

        if isinstance(exceptions, (list, tuple)):
            self.exceptions = tuple(exceptions)
        else:
            self.exceptions = (exceptions,)

        self.retry = retry

    def __call__(self, func):

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            while True:
                try:
                    return func(*args, **kwargs)
                except self.exceptions as e:
                    if self.retry >= 0:
                        logger.warning("Caught retry-able error '{}'. Retrying.".format(str(e)))
                        self.retry -= 1
                        continue
                    else:
                        logger.error("Ran out of retries... {}".format(str(e)))
                        raise
        return wrapper

@validate_argument_types(s=(str,bytes))
def strip_ansi_escapes(s):
    """Remove any ansi color escapes."""
    if isinstance(s, str):
        return ansi_escape.sub('', s)
    else:
        return ansi_escape_bytes.sub(b'', s)

@validate_argument_types(x=(str,bytes))
def auto_bytes(x):
    """Converts str to bytes. If already bytes, just returns bytes."""
    if isinstance(x, str):
        x = x.encode('latin-1')

    return x

ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
ansi_escape_bytes = re.compile(br'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
