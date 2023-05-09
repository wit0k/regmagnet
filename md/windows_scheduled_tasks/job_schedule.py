# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

from md.windows_scheduled_tasks import tstime
class JobSchedule(KaitaiStruct):

    class TimeMode(Enum):
        one_time = 0
        daily = 1
        weekly = 2
        days_in_months = 3
        days_in_weeks_in_months = 4

    class DayOfWeek(Enum):
        sunday = 1
        monday = 2
        tuesday = 4
        wednesday = 8
        thursday = 16
        friday = 32
        saturday = 64

    class Months(Enum):
        january = 1
        february = 2
        march = 4
        april = 8
        may = 16
        june = 32
        july = 64
        august = 128
        september = 256
        october = 512
        november = 1024
        december = 2048
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.start_boundary = tstime.Tstime(self._io)
        self.end_boundary = tstime.Tstime(self._io)
        self.unknown0 = tstime.Tstime(self._io)
        self.repetition_interval_seconds = self._io.read_u4le()
        self.repetition_duration_seconds = self._io.read_u4le()
        self.execution_time_limit_seconds = self._io.read_u4le()
        self.mode = KaitaiStream.resolve_enum(JobSchedule.TimeMode, self._io.read_u4le())
        self.data1 = self._io.read_u2le()
        self.data2 = self._io.read_u2le()
        self.data3 = self._io.read_u2le()
        self.pad0 = self._io.read_u2le()
        self.stop_tasks_at_duration_end = self._io.read_u1()
        self.is_enabled = self._io.read_u1()
        self.pad1 = self._io.read_u2le()
        self.unknown1 = self._io.read_u4le()
        self.max_delay_seconds = self._io.read_u4le()
        self.pad2 = self._io.read_u4le()


