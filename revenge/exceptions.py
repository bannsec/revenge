
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
