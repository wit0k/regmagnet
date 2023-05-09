# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

from md.windows_scheduled_tasks import tstimeperiod
from md.windows_scheduled_tasks import aligned_u4
class OptionalSettings(KaitaiStruct):

    class Privilege(Enum):
        se_create_token_privilege = 4
        se_assign_primary_token_privilege = 8
        se_lock_memory_privilege = 16
        se_increase_quota_privilege = 32
        se_machine_account_privilege = 64
        se_tcb_privilege = 128
        se_security_privilege = 256
        se_take_ownership_privilege = 512
        se_load_driver_privilege = 1024
        se_system_profile_privilege = 2048
        se_systemtime_privilege = 4096
        se_profile_single_process_privilege = 8192
        se_increase_base_priority_privilege = 16384
        se_create_pagefile_privilege = 32768
        se_create_permanent_privilege = 65536
        se_backup_privilege = 131072
        se_restore_privilege = 262144
        se_shutdown_privilege = 524288
        se_debug_privilege = 1048576
        se_audit_privilege = 2097152
        se_system_environment_privilege = 4194304
        se_change_notify_privilege = 8388608
        se_remote_shutdown_privilege = 16777216
        se_undock_privilege = 33554432
        se_sync_agent_privilege = 67108864
        se_enable_delegation_privilege = 134217728
        se_manage_volume_privilege = 268435456
        se_impersonate_privilege = 536870912
        se_create_global_privilege = 1073741824
        se_trusted_cred_man_access_privilege = 2147483648
        se_relabel_privilege = 4294967296
        se_increase_working_set_privilege = 8589934592
        se_time_zone_privilege = 17179869184
        se_create_symbolic_link_privilege = 34359738368
        se_delegate_session_user_impersonate_privilege = 68719476736
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.len = aligned_u4.AlignedU4(self._io)
        if self.len.value > 0:
            self.idle_duration_seconds = self._io.read_u4le()

        if self.len.value > 0:
            self.idle_wait_timeout_seconds = self._io.read_u4le()

        if self.len.value > 0:
            self.execution_time_limit_seconds = self._io.read_u4le()

        if self.len.value > 0:
            self.delete_expired_task_after = self._io.read_u4le()

        if self.len.value > 0:
            self.priority = self._io.read_u4le()

        if self.len.value > 0:
            self.restart_on_failure_delay = self._io.read_u4le()

        if self.len.value > 0:
            self.restart_on_failure_retries = self._io.read_u4le()

        if self.len.value > 0:
            self.network_id = self._io.read_bytes(16)

        if self.len.value > 0:
            self.padding0 = self._io.read_bytes(4)

        if  ((self.len.value == 56) or (self.len.value == 88)) :
            self.privileges = KaitaiStream.resolve_enum(OptionalSettings.Privilege, self._io.read_u8le())

        if self.len.value == 88:
            self.periodicity = tstimeperiod.Tstimeperiod(self._io)

        if self.len.value == 88:
            self.deadline = tstimeperiod.Tstimeperiod(self._io)

        if self.len.value == 88:
            self.exclusive = self._io.read_u1()

        if self.len.value == 88:
            self.padding1 = self._io.read_bytes(3)



