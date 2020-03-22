
import logging
logger = logging.getLogger(__name__)

class RevengeError(Exception):
    pass

class RevengeProcessRequiredError(RevengeError):
    """Raised when a Process class is required but not found."""
    pass

class RevengeInvalidArgumentType(RevengeError):
    pass

class RevengeSymbolLookupFailure(RevengeError):
    pass

class RevengeThreadCreateError(RevengeError):
    pass

class RevengeImmutableError(RevengeError):
    pass

class RevengeMemoryError(RevengeError):
    pass

class RevengeMemoryReadError(RevengeMemoryError):
    pass

class RevengeModuleError(RevengeError):
    pass

class RevengeModulePluginAlreadyRegistered(RevengeModuleError):
    pass

class RevengeDecompilerError(RevengeError):
    pass

class RevengeDecompilerAlreadyRegisteredError(RevengeDecompilerError):
    pass
