import logging
logger = logging.getLogger(__name__)

from .. import Engine

class PseudoEngine(Engine):

    def __init__(self, *args, **kwargs):
        kwargs['klass'] = self.__class__
        super().__init__(*args, **kwargs)

    def _at_exit(self):
        pass

import os

Engine = PseudoEngine 
here = os.path.dirname(os.path.abspath(__file__))
