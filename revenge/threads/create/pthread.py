
import logging
logger = logging.getLogger(__name__)

def init():
    global pthread_id_cache
    global pthread_create_cache

    # Since we need to give pthread a place to put the thread_id each time
    # save some time and only make it once
    pthread_id_cache = {}
    pthread_create_cache = {}

def create_pthread(process, callback):
    global pthread_id

    # Caching for speed
    if process not in pthread_id_cache:
        pthread_id_cache[process] = process.memory.alloc(8)
    
        pthread_create = process.memory[':pthread_create']
        pthread_create.argument_types = types.Pointer, types.Pointer, types.Pointer, types.Pointer
        pthread_create.return_type = types.Int32
        pthread_create_cache[process] = pthread_create

    pthread_create = pthread_create_cache[process]
    ret = pthread_create(pthread_id_cache[process].address, 0, callback, 0);

    if ret != 0:
        e = NativeError(process, abs(ret))
        err = "pthread_create failed! " + str(e)
        logger.error(err)
        raise RevengeThreadCreateError(err)

    # Return the pthread id
    return process.memory[pthread_id_cache[process].address].int64

try:
    pthread_id_cache
except:
    init()

from ... import types
from ...native_error import NativeError
