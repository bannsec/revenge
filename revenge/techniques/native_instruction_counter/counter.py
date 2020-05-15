
import logging

from revenge import common


class Counter:
    def __init__(self, thread, script):
        self._thread = thread
        self.count = 0

        # frida script that is running this
        self._script = script

        # Register auto-cleanup on exit
        self._process._register_cleanup(self.stop)

    def stop(self):
        """Stop tracing."""

        if self._script is not None:
            self._script[0].exports.unfollow()
            # Unload at this point causes frida to hang. Same issue as with InstructionTracer
            # self._script[0].unload()
            self._process.techniques._active_stalks.pop(self._thread.id)
            self._script = None

    def __repr__(self):
        return "<Counter " + str(self.count) + " instructions>"

    @property
    def _process(self):
        return self._thread._process

    @property
    def count(self):
        """int: Number of instructions executed."""
        return self.__count

    @count.setter
    @common.validate_argument_types(count=int)
    def count(self, count):
        self.__count = count


LOGGER = logging.getLogger(__name__)
