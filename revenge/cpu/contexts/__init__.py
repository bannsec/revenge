
import logging

logger = logging.getLogger(__name__)

from .x64 import X64Context
from .x86 import X86Context

def CPUContext(process, *args, **kwargs):
    """Build context from args. Will auto discover context type.
    
    Example:
        context = Context(process, eax=1, ebx=2, ...)
    """

    arch = process.arch
    
    if arch == "x64":
        return X64Context(process, *args, **kwargs)

    elif arch == "ia32":
        return X86Context(process, *args, **kwargs)

    else:
        logger.error("Currently unsupported architecture of {}".format(arch))
