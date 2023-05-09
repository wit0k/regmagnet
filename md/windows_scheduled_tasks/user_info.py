# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

from md.windows_scheduled_tasks import aligned_u4
from md.windows_scheduled_tasks import aligned_buffer
from md.windows_scheduled_tasks import aligned_u1
from md.windows_scheduled_tasks import aligned_bstr
class UserInfo(KaitaiStruct):

    class SidType(Enum):
        user = 1
        group = 2
        domain = 3
        alias = 4
        well_known_group = 5
        deleted_account = 6
        invalid = 7
        unknown = 8
        computer = 9
        label = 10
        logon_session = 11
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.skip_user = aligned_u1.AlignedU1(self._io)
        if self.skip_user.value == 0:
            self.skip_sid = aligned_u1.AlignedU1(self._io)

        if  ((self.skip_user.value == 0) and (self.skip_sid.value == 0)) :
            self.sid_type = aligned_u4.AlignedU4(self._io)

        if  ((self.skip_user.value == 0) and (self.skip_sid.value == 0)) :
            self.sid = aligned_buffer.AlignedBuffer(self._io)

        if self.skip_user.value == 0:
            self.username = aligned_bstr.AlignedBstr(self._io)



