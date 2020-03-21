
import logging
from revenge import types, common

SEEK_SET = 0
SEEK_CUR = 1

O_RDONLY = 0
O_WRONLY = 1
O_RDWR = 2

F_GETFL = 3
F_SETFL = 4

def write_handle(process, fd, thing, position=None):

    # Not using alloc_string since we don't want to add the null terminator at the end
    alloc = process.memory.alloc(len(thing))

    thing = common.auto_bytes(thing)
    alloc.bytes = thing
    
    # write
    if position is None:
        write = process.memory['write']
        write.return_type = types.Int64 if process.bits == 64 else types.Int32
        ret = write(fd, alloc, alloc.size)

    # pwrite
    else:
        pwrite = process.memory['pwrite']
        pwrite.return_type = types.Int64 if process.bits == 64 else types.Int32
        ret = pwrite(fd, alloc, alloc.size, position)

    alloc.free()
    return ret

def read_handle(process, fd, n, position=None):

    alloc = process.memory.alloc(n)
    
    # read
    if position is None:
        read = process.memory['read']
        read.return_type = types.Int64 if process.bits == 64 else types.Int32
        num_read = read(fd, alloc, n)

    # pread
    else:
        pread = process.memory['pread']
        pread.return_type = types.Int64 if process.bits == 64 else types.Int32
        num_read = pread(fd, alloc, n, position)

    out = alloc.bytes
    alloc.free()

    # Something went wrong reading
    if num_read < 0: return None
    return out

def set_handle_position(process, fd, position):
    lseek = process.memory['lseek']
    lseek(fd, position, SEEK_SET)

def handle_position(process, fd):
    lseek = process.memory['lseek']
    lseek.return_type = types.Int64 if process.bits == 64 else types.Int32
    out = lseek(fd, 0, SEEK_CUR)
    if out >= 0: return out

def handle_is_readable(process, fd):
    fcntl = process.memory['fcntl']
    fstatus = fcntl(fd, F_GETFL)
    return fstatus & O_WRONLY == 0

def handle_is_writable(process, fd):
    fcntl = process.memory['fcntl']
    fstatus = fcntl(fd, F_GETFL)
    return fstatus & O_WRONLY > 0 or fstatus & O_RDWR > 0

def enumerate_handles(process):

    opendir = process.memory['opendir']
    readdir = process.memory['readdir'] 
    readlink = process.memory['readlink'] 
    closedir = process.memory['closedir']

    alloc = process.memory.alloc(256) 

    dirp = opendir("/proc/self/fd/") 

    if dirp == 0:
        LOGGER.error("Cannot open /proc/self/fd. Bailing.")
        return {}

    dirent = types.Struct()
    dirent['d_ino'] = types.Pointer
    dirent['d_off'] = types.Pointer
    dirent['d_reclen'] = types.UInt16
    dirent['d_type'] = types.UInt8
    dirent['d_name'] = types.StringUTF8

    handles = {}

    while True:
        # From man page: (This structure may be statically allocated; do not attempt to free(3) it.)
        entry = readdir(dirp)

        if entry == 0:
            break
        
        d = process.memory[entry].cast(dirent)

        if d['d_name'] in ['.', '..']:
            continue

        fd = int(d['d_name'],10)

        if d['d_type'] == 10:
            readlink("/proc/self/fd/" + str(fd), alloc, alloc.size)
            name = alloc.string_utf8
            alloc.bytes = b'\x00' * alloc.size

        else:
            name = None

        handles[fd] = Handle(process, handle=fd, name=name)

    closedir(dirp)
    alloc.free()
    return handles

from .handle import Handle
LOGGER = logging.getLogger(__name__)
