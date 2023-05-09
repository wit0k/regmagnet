# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

from md.windows_scheduled_tasks import optional_settings
from md.windows_scheduled_tasks import tstime
from md.windows_scheduled_tasks import user_info
from md.windows_scheduled_tasks import aligned_bstr_expand_size
from md.windows_scheduled_tasks import aligned_u1
from md.windows_scheduled_tasks import bstr
from md.windows_scheduled_tasks import aligned_bstr
from md.windows_scheduled_tasks import job_schedule
from md.windows_scheduled_tasks import aligned_u4
class Triggers(KaitaiStruct):

    class JobBucketFlags(Enum):
        run_only_if_idle = 2
        restart_on_idle = 4
        stop_on_idle_end = 8
        disallow_start_if_on_batteries = 16
        stop_if_going_on_batteries = 32
        start_when_available = 64
        run_only_if_network_available = 128
        allow_start_on_demand = 256
        wake_to_run = 512
        execute_parallel = 1024
        execute_stop_existing = 2048
        execute_queue = 4096
        execute_ignore_new = 8192
        logon_type_s4u = 16384
        logon_type_interactivetoken = 65536
        logon_type_password = 262144
        logon_type_interactivetokenorpassword = 524288
        enabled = 4194304
        hidden = 8388608
        runlevel_highest_available = 16777216
        task = 33554432
        version = 67108864
        token_sid_type_none = 134217728
        token_sid_type_unrestricted = 268435456
        interval = 536870912
        allow_hard_terminate = 1073741824

    class SessionState(Enum):
        console_connect = 1
        console_disconnect = 2
        remote_connect = 3
        remote_disconnect = 4
        session_lock = 5
        session_unlock = 6
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.header = Triggers.Header(self._io, self, self._root)
        self.job_bucket = Triggers.JobBucket(self._io, self, self._root)
        self.triggers = []
        i = 0
        while not self._io.is_eof():
            self.triggers.append(Triggers.Trigger(self._io, self, self._root))
            i += 1


    class WnfStateChangeTrigger(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.generic_data = Triggers.GenericTriggerData(self._io, self, self._root)
            self.state_name = self._io.read_bytes(8)
            self.len_data = aligned_u4.AlignedU4(self._io)
            self.data = self._io.read_bytes(self.len_data.value)


    class ValueQuery(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.name = aligned_bstr_expand_size.AlignedBstrExpandSize(self._io)
            self.value = aligned_bstr_expand_size.AlignedBstrExpandSize(self._io)


    class EventTrigger(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.generic_data = Triggers.GenericTriggerData(self._io, self, self._root)
            self.subscription = aligned_bstr_expand_size.AlignedBstrExpandSize(self._io)
            self.unknown0 = self._io.read_u4le()
            self.unknown1 = self._io.read_u4le()
            self.unknown2 = aligned_bstr_expand_size.AlignedBstrExpandSize(self._io)
            self.len_value_queries = aligned_u4.AlignedU4(self._io)
            self.value_queries = []
            for i in range(self.len_value_queries.value):
                self.value_queries.append(Triggers.ValueQuery(self._io, self, self._root))



    class IdleTrigger(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.generic_data = Triggers.GenericTriggerData(self._io, self, self._root)


    class JobBucket(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.flags = aligned_u4.AlignedU4(self._io)
            self.crc32 = aligned_u4.AlignedU4(self._io)
            if self._root.header.version.value >= 22:
                self.principal_id = aligned_bstr.AlignedBstr(self._io)

            if self._root.header.version.value >= 23:
                self.display_name = aligned_bstr.AlignedBstr(self._io)

            self.user_info = user_info.UserInfo(self._io)
            self.optional_settings = optional_settings.OptionalSettings(self._io)


    class LogonTrigger(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.generic_data = Triggers.GenericTriggerData(self._io, self, self._root)
            self.user = user_info.UserInfo(self._io)


    class SessionChangeTrigger(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.generic_data = Triggers.GenericTriggerData(self._io, self, self._root)
            self.state_change = KaitaiStream.resolve_enum(Triggers.SessionState, self._io.read_u4le())
            self.padding = self._io.read_bytes(4)
            self.user = user_info.UserInfo(self._io)


    class RegistrationTrigger(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.generic_data = Triggers.GenericTriggerData(self._io, self, self._root)


    class GenericTriggerData(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.start_boundary = tstime.Tstime(self._io)
            self.end_boundary = tstime.Tstime(self._io)
            self.delay_seconds = self._io.read_u4le()
            self.timeout_seconds = self._io.read_u4le()
            self.repetition_interval_seconds = self._io.read_u4le()
            self.repetition_duration_seconds = self._io.read_u4le()
            self.repetition_duration_seconds_2 = self._io.read_u4le()
            self.stop_at_duration_end = self._io.read_u1()
            self.padding = self._io.read_bytes(3)
            self.enabled = aligned_u1.AlignedU1(self._io)
            self.unknown = self._io.read_bytes(8)
            if self._root.header.version.value >= 22:
                self.trigger_id = bstr.Bstr(self._io)

            if self._root.header.version.value >= 22:
                self.pad_to_block = self._io.read_bytes(((8 - (self.trigger_id.len + 4)) % 8))



    class TimeTrigger(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.job_schedule = job_schedule.JobSchedule(self._io)
            if self._root.header.version.value >= 22:
                self.trigger_id = bstr.Bstr(self._io)

            if self._root.header.version.value >= 22:
                self.padding = self._io.read_bytes(((8 - (self.trigger_id.len + 4)) % 8))



    class Header(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.version = aligned_u1.AlignedU1(self._io)
            self.start_boundary = tstime.Tstime(self._io)
            self.end_boundary = tstime.Tstime(self._io)


    class BootTrigger(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.generic_data = Triggers.GenericTriggerData(self._io, self, self._root)


    class Trigger(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.magic = aligned_u4.AlignedU4(self._io)
            _on = self.magic.value
            if _on == 34952:
                self.properties = Triggers.RegistrationTrigger(self._io, self, self._root)
            elif _on == 43690:
                self.properties = Triggers.LogonTrigger(self._io, self, self._root)
            elif _on == 65535:
                self.properties = Triggers.BootTrigger(self._io, self, self._root)
            elif _on == 30583:
                self.properties = Triggers.SessionChangeTrigger(self._io, self, self._root)
            elif _on == 61166:
                self.properties = Triggers.IdleTrigger(self._io, self, self._root)
            elif _on == 52428:
                self.properties = Triggers.EventTrigger(self._io, self, self._root)
            elif _on == 56797:
                self.properties = Triggers.TimeTrigger(self._io, self, self._root)
            elif _on == 26214:
                self.properties = Triggers.WnfStateChangeTrigger(self._io, self, self._root)



