
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
    def spawn(self, argv):
        """Spawn a new process.

        Args:
            argv (list, str): Process to spawn or argv list.

        Returns:
            revenge.process.Process object
        """
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


from ..engines import Engine
from .android import AndroidDevice
from .local import LocalDevice
