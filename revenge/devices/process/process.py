import logging
logger = logging.getLogger(__name__)

class Process:
    
    def __init__(self, name, pid):
        """Describes a process on this device.

        Args:
            name (str): What is the name of this process
            pid (int): Process ID
        """

        self.name = name
        self.pid = pid

    def __repr__(self):
        attrs = [
                "name:" + self.name,
                "pid:" + str(self.pid),
                ]
        return "<Process " + " ".join(attrs) + ">"

    @property
    def name(self):
        """str: Process name."""
        return self.__name

    @name.setter
    def name(self, name):
        self.__name = name

    @property
    def pid(self):
        """int: Process ID"""
        return self.__pid

    @pid.setter
    def pid(self, pid):
        self.__pid = pid

Process.__doc__ = Process.__init__.__doc__
