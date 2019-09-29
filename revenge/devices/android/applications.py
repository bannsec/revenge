
import logging
logger = logging.getLogger(__name__)

from fnmatch import fnmatch

class AndroidApplications:
    def __init__(self, android):
        self._android = android

    def __iter__(self):
        return self._android.device.enumerate_applications().__iter__()

    def __len__(self):
        return len(list(self.__iter__()))

    def __getitem__(self, item):
        if isinstance(item, int):
            return list(self)[item]

        elif isinstance(item, str):
            match = [x for x in self if fnmatch(x.identifier, item) or fnmatch(x.name, item)]
            if len(match) > 1:
                return match
            if match == []:
                return None
            return match[0]

        else:
            logger.error("Unhandled item get of type {}".format(type(item)))
            return

    def __repr__(self):
        attrs = ["AndroidApplications", str(len(self)), "installed"]

        return "<" + " ".join(attrs) + ">"
