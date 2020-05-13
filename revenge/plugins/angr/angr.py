
import logging

LOGGER = logging.getLogger(__name__)

try:
    import angr
    LOGGER.debug("angr found and successfully imported.")

    from .revenge_target import RevengeConcreteTarget
    LOGGER.debug("RevengeConcreteTarget found and successfully imported.")
    ANGR_OK = True
except ModuleNotFoundError:
    ANGR_OK = False
    LOGGER.debug("angr not found or required lib not successfully imported.")

from revenge.exceptions import *
from revenge import common
from .. import Plugin


class Angr(Plugin):

    def __init__(self, process, thread=None):
        """Use angr to enrich your reversing.

        Examples:
            .. code-block:: python3

                # Grab current location
                thread = list(process.threads)[0]

                # Load options and state options can be configured
                # They use the same name but are exposed as attributes here
                # If you SET any of these, the project will be re-loaded next
                # time you ask for an object. It will NOT affect the current
                # object instance you have.
                thread.angr.load_options
                thread.angr.support_selfmodifying_code
                thread.angr.use_sim_procedures
                thread.angr.add_options

                # Ask for a simgr for this location
                simgr = thread.angr.simgr

                # Whoops, we wanted self modifying code!
                thread.angr.support_selfmodifying_code = True
                simgr = thread.angr.simgr

                # Use this as you normally would
                simgr.explore(find=winner)
        """

        self._process = process
        self._thread = thread
        self.__project = None
        self.__sim_procedures_resolved = False

        self.load_options = {'auto_load_libs': False}
        self.support_selfmodifying_code = False
        self.use_sim_procedures = True
        self.exclude_sim_procedures_list = []
        self.add_options = set([])
        self.remove_options = set([])

        if ANGR_OK:
            try:
                self._process.threads._register_plugin(Angr._thread_plugin, "angr")
            except RevengeModulePluginAlreadyRegistered:
                # This will error out if we're already registered
                pass

    @property
    def load_options(self):
        """angr load_options"""
        return self.__load_options

    @load_options.setter
    def load_options(self, load_options):
        self.__load_options = load_options
        # Invalidate the project
        self.__project = None

    @property
    def exclude_sim_procedures_list(self):
        """bool: Which procedures should angr not wrap?"""
        return self.__exclude_sim_procedures_list

    @exclude_sim_procedures_list.setter
    def exclude_sim_procedures_list(self, exclude_sim_procedures_list):
        self.__exclude_sim_procedures_list = exclude_sim_procedures_list
        # Invalidate the project
        self.__project = None

    @property
    def use_sim_procedures(self):
        """bool: Should angr use sim procedures?"""
        return self.__use_sim_procedures

    @use_sim_procedures.setter
    def use_sim_procedures(self, use_sim_procedures):
        self.__use_sim_procedures = use_sim_procedures
        # Invalidate the project
        self.__project = None

    @property
    def support_selfmodifying_code(self):
        """bool: Should angr support self modifying code?"""
        return self.__support_selfmodifying_code

    @support_selfmodifying_code.setter
    def support_selfmodifying_code(self, support_selfmodifying_code):
        self.__support_selfmodifying_code = support_selfmodifying_code
        # Invalidate the project
        self.__project = None

    @property
    def _is_valid(self):
        # Not registering this as a process plugin for now.
        return False

    @classmethod
    def _thread_plugin(klass, thread):
        return klass(thread._process, thread=thread)

    @property
    def project(self):
        """Returns the angr project for this file."""
        if self.__project is not None:
            return self.__project

        # Original path might not be our final path
        # For example: loading angr on a remote android project
        orig_path = self._process.modules[self._thread.pc].path
        new_path = common.load_file(self._process, orig_path).name

        self.__project = angr.Project(
            new_path,
            load_options=self.load_options,
            concrete_target=self._concrete_target,
            use_sim_procedures=self.use_sim_procedures,
            exclude_sim_procedures_list=self.exclude_sim_procedures_list,
            support_selfmodifying_code=self.support_selfmodifying_code)

        self.__sim_procedures_resolved = False
        return self.__project

    @property
    def state(self):
        """Returns a state object for the current thread state."""
        if self._thread.breakpoint and self._thread.pc in self._process.threads._breakpoint_original_bytes:

            LOGGER.warning("Overwriting current breakpoint in memory so it doesn't trip up angr.")
            LOGGER.warning("This has the side-effect of disabling this breakpoint. You can re-enable manually.")

            orig_bytes = self._process.threads._breakpoint_original_bytes[self._thread.pc]
            self._process.memory[self._thread.pc:self._thread.pc + len(orig_bytes)].bytes = orig_bytes

        state = self.project.factory.entry_state(
            add_options=self.add_options, remove_options=self.remove_options)

        if self._concrete_target is not None:
            state.concrete.sync()

            if not self.__sim_procedures_resolved:

                LOGGER.debug("Attempting to resolve angr sim procs")

                # Fixup angr's Sim Procedures since it cannot handle PIC
                me = self._process.modules[self._thread.pc]
                imports = [rel.symbol.name for rel in self.project.loader.main_object.relocs if rel.symbol is not None and rel.symbol.is_import]

                for imp in imports:
                    try:
                        # Try to find the plt first
                        imp_addr = me.symbols["plt." + imp].address
                    except KeyError:
                        # Fallback to trying to find the actual resolved function symbol
                        try:
                            imp_addr = self._process.memory[imp].address
                        except RevengeSymbolLookupFailure:
                            # Give up
                            continue

                    self.project.rehook_symbol(imp_addr, imp, True)

                self.__sim_procedures_resolved = True

        return state

    @property
    def simgr(self):
        """Returns an angr simgr object for the current state."""
        return self.project.factory.simgr(self.state)

    @property
    def _concrete_target(self):
        """Returns a concrete target for this context or None."""
        if self._thread is not None:
            return RevengeConcreteTarget(self._process, self._thread.context)


# doc fixup
Angr.__doc__ = Angr.__init__.__doc__
