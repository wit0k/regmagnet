# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

from md.windows_scheduled_tasks import bstr
class Actions(KaitaiStruct):
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.version = self._io.read_u2le()
        if self.version == 3:
            self.context = bstr.Bstr(self._io)

        self.actions = []
        i = 0
        while not self._io.is_eof():
            self.actions.append(Actions.Action(self._io, self, self._root))
            i += 1


    class ComHandlerProperties(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.clsid = self._io.read_bytes(16)
            self.data = bstr.Bstr(self._io)


    class EmailTaskProperties(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            # self.from = bstr.Bstr(self._io)
            self.to = bstr.Bstr(self._io)
            self.cc = bstr.Bstr(self._io)
            self.bcc = bstr.Bstr(self._io)
            self.reply_to = bstr.Bstr(self._io)
            self.server = bstr.Bstr(self._io)
            self.subject = bstr.Bstr(self._io)
            self.body = bstr.Bstr(self._io)
            self.num_attachment_filenames = self._io.read_u4le()
            self.attachment_filenames = []
            for i in range(self.num_attachment_filenames):
                self.attachment_filenames.append(bstr.Bstr(self._io))

            self.num_headers = self._io.read_u4le()
            self.headers = []
            for i in range(self.num_headers):
                self.headers.append(Actions.KeyValueString(self._io, self, self._root))



    class KeyValueString(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.key = bstr.Bstr(self._io)
            self.value = bstr.Bstr(self._io)


    class ExeTaskProperties(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.command = bstr.Bstr(self._io)
            self.arguments = bstr.Bstr(self._io)
            self.working_directory = bstr.Bstr(self._io)
            if self._root.version == 3:
                self.flags = self._io.read_u2le()



    class MessageboxTaskProperties(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.caption = bstr.Bstr(self._io)
            self.content = bstr.Bstr(self._io)


    class Action(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.magic = self._io.read_u2le()
            self.id = bstr.Bstr(self._io)
            _on = self.magic
            if _on == 26214:
                self.properties = Actions.ExeTaskProperties(self._io, self, self._root)
            elif _on == 30583:
                self.properties = Actions.ComHandlerProperties(self._io, self, self._root)
            elif _on == 34952:
                self.properties = Actions.EmailTaskProperties(self._io, self, self._root)
            elif _on == 39321:
                self.properties = Actions.MessageboxTaskProperties(self._io, self, self._root)



