
import logging
from collections.abc import Iterable
from ... import common
from .. import Plugin

# TODO: For now, if you use both process.radare2 and module[main_object].radare2,
# you will open up a duplicate r2 session. This shouldn't hurt anything
# but it's definitely not optimal

class Radare2(Plugin):

    def __init__(self, process, module=None):
        """Use radare2 to enrich reversing information.

        Examples:
            .. code-block:: python

                #
                # Normal enrichment works without connection
                # Radare2 plugin can enrich a remote instance of r2 with more
                # information as well.

                # In different window, open r2
                # r2 -A /bin/ls
                # Start up web server
                # =h& 12345

                # Connect up to it with revenge
                process.radare2.connect("http://127.0.0.1:12345")
                
                # Highlight paths that have executed
                timeless = process.techniques.NativeTimelessTracer()
                timeless.apply()
                
                # Do whatever
                t = list(timeless)[0]

                process.radare2.highlight(t)
        """
        self._process = process
        self._module = module or list(self._process.modules)[0]
        self._r2 = None
        self._find_r2()

        try:
            self._process.modules._register_plugin(Radare2._modules_plugin, "radare2")
        except RevengeModulePluginAlreadyRegistered:
            # This will error out if we're already registered
            pass

        self._load_file()

        # Register myself as a decompiler if Ghidra plugin is present
        if isinstance(self.decompiler, GhidraDecompiler):
            try:
                self._process.decompiler._register_decompiler(self.decompiler, 70)
            except RevengeDecompilerAlreadyRegisteredError:
                pass

        # Always clean ourselves up at exit
        self._process._register_cleanup(self.disconnect)

        # TODO: Add base information about file

    def analyze(self):
        """Ask radare2 to run some auto analysis on this file.

        Note:
            This is NOT run by default due to the fact that it may take a while
            to run. If you connect to a remote session that has already run
            analysis, you do NOT need to run this.
        """
        if self._r2 is None:
            return False

        self._r2.cmd("aaa")
        return True

    def _load_file(self):
        """Attempt to load this revenge file."""

        """
        if not os.path.isfile(self._process.argv[0]):
            LOGGER.warning("Cannot find file to load.")
            return
        """

        self._r2 = r2pipe.open(common.load_file(self._process, self._module.path).name)

        try:
            self._r2.cmd('i')

        except BrokenPipeError:
            self._r2 = None
            LOGGER.error("Error opening file " + self._module.name + " with r2.")

    def _find_r2(self):
        """Locate and save what radare2 we're dealing with."""
        r2_names = ["radare2", "r2", "radare2.exe", "r2.exe"]
        self._r2exe = None

        for name in r2_names:
            path = shutil.which(name)
            if path is not None:
                self._r2exe = path
                LOGGER.debug("Found r2 at: " + path)
                return

        LOGGER.debug("Couldn't find r2...")

    @classmethod
    def _modules_plugin(klass, module):
        return klass(module._process, module)

    @common.validate_argument_types(address=int, color=str)
    def _highlight_address(self, address, color):
        """Highlights this address with the given color.

        Args:
            address (int): What address to color?
            color (str): What to color?

        The address will NOT be adjusted nor checked for correctness. This is
        meant to be called from highlight. Color can be found in r2 by typing
        "ecs".
        """
        if self._r2 is None:
            LOGGER.warning("Can't find connected r2 instance...")
            return
        
        # First gotta clear any existing color
        # ecH- is broken atm. ecHi __should__ overwrite it though...
        #self._r2.cmd("ecH-@" + hex(address))
        
        # Now add the new color
        self._r2.cmd("ecHi " + color + "@" + hex(address))

    def highlight(self, what):
        """Highlights an instruction or list of instructions.

        Args:
            what (int, list, tuple): Address to highlight.

        Note:
            The addresses should be instantiated from this revenge process.
            Highlight will determine the correct offset to use for highlighting
            automatically.

        This is likely only useful when you have connected to a remote r2
        session as you won't see the color locally.
        """
        
        # Standardize to list
        if not isinstance(what, Iterable):
            what = [what]

        # Standardize addrs
        addrs = []

        for thing in what:
            if isinstance(thing, int):
                addrs.append(int(thing))
            elif hasattr(thing, 'context'):
                addrs.append(int(thing.context.ip))
            else:
                LOGGER.error("Unhandled thing type of " + type(thing))

        # Color-up
        for addr in addrs:

            out = self._process.modules.lookup_offset(addr)

            # Addr didn't end up in something mapped...
            if out is None:
                continue

            name, addr = out

            # Don't both coloring things that aren't in our opened binary...
            if name != self.file:
                continue

            self._highlight_address(self.base_address + addr, "cyan")

    @common.validate_argument_types(web_server=str)
    def connect(self, web_server):
        """Connect to a separate session to work in tandem.

        Args:
            web_server (str): Web server to connect to.

        Examples:
            .. code-block:: python
            
                # On existing r2 instance, start web listener on port 12345
                # =h& 12345

                # Now tell this r2 plugin to connect to it
                process.radare2.connect("http://127.0.0.1:12345")
        """

        orig_r2 = self._r2

        # Can't have trailing slash
        web_server = web_server.rstrip("/")

        print("Connecting to " + web_server + " ... ", end='', flush=True)

        self._r2 = r2pipe.open(web_server)

        # r2pipe doesn't actually error on open, we gotta check
        if self._r2.cmd('i') is None:
            cprint("[ Error ]", color='red')
            self._r2.quit()
            self._r2 = orig_r2

        else:
            # We've got a good connection, kill the old
            if orig_r2 is not None:
                orig_r2.quit()

            # Verify name
            if self.file.lower() != self._process.file_name.lower():
                cprint("[ File Names Differ! ]", color='yellow')
            else:
                cprint("[ OK ]", color='green')

    def disconnect(self):
        """Disconnect from web server."""

        if self._r2 is not None:
            try:
                self._r2.quit()
            except ConnectionResetError:
                pass
            self._r2 = None

    def __repr__(self):
        return "<Radare2 Plugin>"

    @property
    def _is_valid(self):
        return self._r2exe is not None

    @property
    def _has_ghidra(self):
        """bool: Does this instance of r2 have the ghidra decompiler?"""
        return "Ghidra" in self._r2.cmd('pdg?')

    @property
    def decompiler(self):
        """Either returns an instance of a decompiler (if one is valid) or None."""
        try:
            return self.__decompiler
        except AttributeError:
            pass

        if self._r2 is not None:
            if self._has_ghidra:
                self.__decompiler = GhidraDecompiler(self)
            else:
                self.__decompiler = None

        else:
            self.__decompiler = None

        return self.__decompiler

    @decompiler.setter
    @common.validate_argument_types(decompiler=str)
    def decompiler(self, decompiler):
        if decompiler.lower() == "ghidra":
            self.__decompiler = GhidraDecompiler(self)
        else:
            raise RevengeInvalidArgumentType("Radare2 Invalid decompiler selected. Options are: ghidra")

    @property
    def file(self):
        if self._r2 is None:
            return

        return os.path.basename(self._r2.cmdj("ij")['core']['file'])

    @property
    def base_address(self):
        if self._r2 is None:
            return

        return self._r2.cmdj('ij')['bin']['baddr']

import os
import shutil
import r2pipe
from termcolor import colored, cprint

from ...exceptions import *
from .decompilers import GhidraDecompiler

LOGGER = logging.getLogger(__name__)
Radare2.__doc__ = Radare2.__init__.__doc__
