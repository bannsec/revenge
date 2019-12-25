
import logging
logger = logging.getLogger(__name__)

import frida
import subprocess
import shlex
import os
import platform
from .. import common

# Standardize for Frida conventions
uname_standard = {
    "x86_64": "x86_64",
    "i686": "x86",
    "armv7l": "arm",
    "armv6l": "arm",
    "i386": "x86_64",
    "arm64": "arm64"
}

class BaseDevice:

    @common.implement_in_engine()
    def Process(self, *args, **kwargs):
        pass

    @common.implement_in_engine()
    def suspend(self, pid):
        """Suspend a given process."""
        pass

    @common.implement_in_engine()
    def resume(self, pid):
        """Resume a given process."""
        pass

    @property
    @common.implement_in_engine()
    def platform(self):
        """str: What platform is this?"""
        pass

    @property
    @common.implement_in_engine()
    def processes(self):
        """list: Currently running processes"""
        pass


from .android import AndroidDevice
from .local import LocalDevice
