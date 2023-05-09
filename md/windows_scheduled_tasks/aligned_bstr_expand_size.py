# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

from md.windows_scheduled_tasks import aligned_u4
class AlignedBstrExpandSize(KaitaiStruct):
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.string_length = aligned_u4.AlignedU4(self._io)
        if self.string_length.value > 0:
            self.content = (self._io.read_bytes(self.byte_count)).decode(u"utf-16le")

        if self.string_length.value > 0:
            self.padding = self._io.read_bytes(((8 - (self.byte_count % 8)) % 8))


    @property
    def byte_count(self):
        if hasattr(self, '_m_byte_count'):
            return self._m_byte_count

        self._m_byte_count = ((self.string_length.value * 2) + 2)
        return getattr(self, '_m_byte_count', None)


