import logging
import zipfile
import os.path

logger = logging.getLogger('regmagnet')

class archive(object):



    def _unzip(FilePath):

        extracted_files = []
        logger.debug('Decompress: %s' % FilePath)

        file = os.path.basename(FilePath)

        archive = zipfile.ZipFile(FilePath)
        for archive_member in archive.infolist():
            if not archive_member.is_dir():
                with archive.open(archive_member) as archive_item:
                    file_path = f'{FilePath}_{str(archive_member.filename).replace("/", "_")}.tmp'
                    tmp_file = open(file_path, "wb")
                    tmp_file.write(archive_item.read())
                    tmp_file.close()
                    logger.debug('Unzipped: %s to %s' % (file + '/' + str(archive_member.filename), file_path))
                    extracted_files.append(file_path)

        return extracted_files

    SUPPORTED_FORMAT = {
        ".ZIP": {"sig": b'\x50\x4b\x03\x04', "siglen": 4, "callback": _unzip},
    }

    def _is_supported(self, FilePath):

        if not os.path.isfile(FilePath):
            return False

        file_extension = os.path.splitext(FilePath)[1].upper()

        try:
            archive_sig, archive_sig_len = self.SUPPORTED_FORMAT[file_extension]["sig"], \
                                           self.SUPPORTED_FORMAT[file_extension]["siglen"]

            with open(FilePath, 'rb') as f:
                file_sig = f.read(archive_sig_len)

            if archive_sig == file_sig:
                return True

        except KeyError:
            return False

    def supported_archive_extensions(self):

        extensions = []
        for ext in self.SUPPORTED_FORMAT:
            extensions.append(ext)

        return extensions

    def decompress(self, FilePath):

        result = self._is_supported(FilePath)
        if result:
            file_extension = os.path.splitext(FilePath)[1].upper()
            decompress_func = self.SUPPORTED_FORMAT[file_extension]["callback"]

            try:
                _result = decompress_func(FilePath)
            except Exception as msg:
                logger.error(msg)
                _result = None

            return []
        else:
            return []
