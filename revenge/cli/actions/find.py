
import logging
logger = logging.getLogger(__name__)

import colorama
from termcolor import cprint, colored
from ... import common, types

import binascii
import time
import struct

class ActionFind:
    """Handle finding things in memory."""

    def __init__(self, process, include_module=None, string=None, uint8=None, 
            int8=None, uint16=None, int16=None, uint32=None, int32=None,
            uint64=None, int64=None, number=None, *args, **kwargs):
        """
        Args:
            process: Parent process instantiation
        """
        self._process = process
        self.include_module = include_module or []
        self.string = string
        self.uint8 = number if number else uint8
        self.int8 = number if number else int8
        self.uint16 = number if number else uint16
        self.int16 = number if number else int16
        self.uint32 = number if number else uint32
        self.int32 = number if number else int32
        self.uint64 = number if number else uint64
        self.int64 = number if number else int64
        self.number = number

        # Couple sanity checks
        if self._process.bits < 64:
            self.uint64 = None
            self.int64 = None

        if self._process.bits < 32:
            self.uint32 = None
            self.int32 = None

        self.discovered_locations = {}

    def run(self):
        # Sync
        self.action_find()

    def record_results(self, results, the_type):
        for r in results:
            self.discovered_locations[r] = the_type

    def action_find(self):

        if self.string is not None:
            r = self._process.memory.find(types.StringUTF16(self.string))
            r.sleep_until_completed()
            self.record_results(r, 'StringUTF16')

            r = self._process.memory.find(types.StringUTF8(self.string))
            r.sleep_until_completed()
            self.record_results(r, 'StringUTF8')

        if self.uint64 is not None:
            try:
                r = self._process.memory.find(types.UInt64(self.uint64))
                r.sleep_until_completed()
                self.record_results(r, 'UInt64')
            except struct.error:
                if self.number is None:
                    raise

        if self.int64 is not None:
            try:
                r = self._process.memory.find(types.Int64(self.int64))
                r.sleep_until_completed()
                self.record_results(r, 'Int64')
            except struct.error:
                if self.number is None:
                    raise

        if self.uint32 is not None:
            try:
                r = self._process.memory.find(types.UInt32(self.uint32))
                r.sleep_until_completed()
                self.record_results(r, 'UInt32')
            except struct.error:
                if self.number is None:
                    raise

        if self.int32 is not None:
            try:
                r = self._process.memory.find(types.Int32(self.int32))
                r.sleep_until_completed()
                self.record_results(r, 'Int32')
            except struct.error:
                if self.number is None:
                    raise

        if self.uint16 is not None:
            try:
                r = self._process.memory.find(types.UInt16(self.uint16))
                r.sleep_until_completed()
                self.record_results(r, 'UInt16')
            except struct.error:
                if self.number is None:
                    raise

        if self.int16 is not None:
            try:
                r = self._process.memory.find(types.Int16(self.int16))
                r.sleep_until_completed()
                self.record_results(r, 'Int16')
            except struct.error:
                if self.number is None:
                    raise

        # Ignoring exceptions when we're blanket searching for some 'number'
        if self.uint8 is not None:
            try:
                r = self._process.memory.find(types.UInt8(self.uint8))
                r.sleep_until_completed()
                self.record_results(r, 'UInt8')
            except struct.error:
                if self.number is None:
                    raise

        if self.int8 is not None:
            try:
                r = self._process.memory.find(types.Int8(self.int8))
                r.sleep_until_completed()
                self.record_results(r, 'Int8')
            except struct.error:
                if self.number is None:
                    raise

