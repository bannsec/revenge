
import os
import logging

from ... import common

from revenge.plugins.decompiler.decompiled import Decompiled, DecompiledItem
from revenge.plugins.decompiler import DecompilerBase

class DwarfDecompiler(DecompilerBase):
    SOURCE_DIRECTORIES = [b'.']

    def __init__(self, process, dwarf):
        super().__init__(process)
        self._dwarf = dwarf

    @common.validate_argument_types(path=(str,bytes))
    def add_source_path(self, path):
        """Adds the given path to the list of directories to look for source
        code in.

        Args:
            path (str, bytes): Path to add to our search
        """
        path = os.path.abspath(path)

        if not os.path.isdir(path):
            LOGGER.error("path either does not exist or is not a directory.")
            return

        if type(path) is str:
            path = path.encode('latin-1')

        DwarfDecompiler.SOURCE_DIRECTORIES.append(path)

    def _get_line_from_file(self, line, filename):
        """Attempt to open and return the given line from the given file.

        Args:
            line (int): What line to return
            filename (str): Name of the file

        Returns:
            bytes: Source from file or None if couldn't find.
        """

        for src_dir in DwarfDecompiler.SOURCE_DIRECTORIES:
            path = os.path.join(src_dir, filename)

            if os.path.isfile(path):

                try:
                    with open(path, "rb") as f:
                        src = f.read()
                except:
                    # Something went wrong opening the file...
                    continue

                try:
                    return src.split(b"\n")[line-1]
                except IndexError:
                    # Found the file but couldn't find the line...
                    # Maybe it's a different file with the same name?
                    continue

        LOGGER.warning("Found debugging information, but cannot find path for '" + filename.decode('latin-1') + "'. Try adding it with:")
        LOGGER.warning("    - process.modules['" + self._dwarf._module.name + "'].dwarf.add_source_path('<path_here>')")

    @common.validate_argument_types(address=int)
    def decompile_address(self, address):
        if not self._dwarf.has_debug_info:
            return None

        filename, line = self._dwarf.lookup_file_line(address)

        # Couldn't lookup file line
        if filename is None:
            return None

        src_line = self._get_line_from_file(line, filename)
        
        # src lookup failed
        if src_line is None:
            return None

        decomp = Decompiled(self._process, self._dwarf._module.name)
        decomp[address].address = address - self._dwarf._module.base - self._dwarf.base_address
        decomp[address].src = src_line

        return decomp

LOGGER = logging.getLogger(__name__)
