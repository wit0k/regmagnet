"""
References:

- https://dfir.ru/2018/12/02/the-cit-database-and-the-syscache-hive/
- https://gist.github.com/msuhanov/356b724f9a44030596671427adb6cfc6

"""
import logging
from md.plugin import plugin
from md.args import build_registry_handler

logger = logging.getLogger('regmagnet')

QUERY_KEY_LIST = [
        r"Microsoft\Windows NT\CurrentVersion\AppCompatFlags\CIT\System\*"
    ]

QUERY_VALUE_LIST = [
]

class cit(plugin):
    """ cit - RegMagnet plugin  """

    """ Standard expected variables  """
    author = 'wit0k'
    name = 'cit'
    description = 'Enumerates and decode CIT database related entries'
    config_file = ''  # IF it's empty/None, the config_data dictionary would not be auto-loaded

    """ Variables initialized by the plugin manager """
    args = None  # Holds plugin related arguments
    parser = None  # Represents the registry_parser object
    config_data = {}  # Contains the json data loaded from config_file (If any was specified and properly created)

    """ Plugin specific variables """
    supported_hive_types = ['SOFTWARE']  # Hive type must be upper case


    class custom_registry_handlers:

        class ntfs_decompress:

            decription = 'Original code author: Maxim Suhanov (yarp) - Re-used by wit0k to read CIT database entries'

            def NTFSDecompressUnit(Buffer):
                """Decompress NTFS data from Buffer (a single compression unit) using the LZNT1 algorithm."""

                from io import BytesIO
                from struct import unpack


                NTFS_CLUSTER_SIZE = 4096
                NTFS_COMPRESSION_UNIT_SIZE = 16 * NTFS_CLUSTER_SIZE

                def is_valid_write_request(offset, length):
                    return offset + length <= 2 * 1024 * 1024 * 1024  # Reject obviously invalid write requests.

                if len(Buffer) > NTFS_COMPRESSION_UNIT_SIZE or len(Buffer) < NTFS_CLUSTER_SIZE:
                    return b''  # Invalid length of input data.

                LZNT1_COMPRESSION_BITS = []

                offset_bits = 0
                y = 16

                # Taken from: CyXpress.pyx
                if len(LZNT1_COMPRESSION_BITS) == 0:
                    LZNT1_COMPRESSION_BITS = [0] * 4096

                    for x in range(0, 4096):
                        LZNT1_COMPRESSION_BITS[x] = 4 + offset_bits
                        if x == y:
                            y = y * 2
                            offset_bits += 1
                # End


                src_index = 0
                dst_index = 0
                dbuf_obj = BytesIO()

                while src_index < len(Buffer):
                    header_bytes = Buffer[src_index: src_index + 2]
                    src_index += 2

                    if len(header_bytes) < 2:
                        break  # Truncated header.

                    header, = unpack('<H', header_bytes)

                    if header == 0:
                        break  # End of the buffer.

                    if header & 0x7000 != 0x3000:
                        break  # Invalid signature.

                    if header & 0x8000 == 0:
                        # Not a compressed block, copy literal data.
                        block_size = (header & 0x0FFF) + 1

                        if not is_valid_write_request(dst_index, block_size):
                            break  # Bogus data.

                        dbuf_obj.seek(dst_index)
                        bytes_ = Buffer[src_index: src_index + block_size]
                        dbuf_obj.write(bytes_)

                        if len(bytes_) == block_size:
                            src_index += block_size
                            dst_index += block_size
                            continue
                        else:
                            break  # Truncated literal data.

                    # A compressed block.
                    dst_chunk_start = dst_index
                    src_chunk_end = src_index + (header & 0x0FFF) + 1

                    bogus_data = False
                    while src_index < src_chunk_end and src_index < len(Buffer) and not bogus_data:
                        flags = Buffer[src_index]
                        if type(flags) is not int:
                            flags = ord(flags)

                        src_index += 1

                        for token in range(0, 8):
                            if src_index >= src_chunk_end:
                                break

                            if src_index >= len(Buffer):
                                # Truncated chunk.
                                break

                            flag = flags & 1
                            flags = flags >> 1

                            if flag == 0:
                                # A literal byte, copy it.
                                if not is_valid_write_request(dst_index, 1):
                                    # Bogus data.
                                    bogus_data = True
                                    break

                                dbuf_obj.seek(dst_index)
                                bytes_ = Buffer[src_index: src_index + 1]
                                dbuf_obj.write(bytes_)

                                if len(bytes_) == 1:
                                    dst_index += 1
                                    src_index += 1
                                    continue
                                else:
                                    # Truncated chunk.
                                    bogus_data = True
                                    break

                            # A compression tuple.
                            table_idx = dst_index - dst_chunk_start
                            try:
                                length_bits = 16 - LZNT1_COMPRESSION_BITS[table_idx]
                            except IndexError:
                                # Bogus data.
                                bogus_data = True
                                break

                            length_mask = (1 << length_bits) - 1

                            ctuple_bytes = Buffer[src_index: src_index + 2]
                            src_index += 2

                            if len(ctuple_bytes) < 2:
                                # Truncated chunk.
                                bogus_data = True
                                break

                            ctuple, = unpack('<H', ctuple_bytes)
                            back_off_rel = (ctuple >> length_bits) + 1
                            back_off = dst_index - back_off_rel
                            back_len = (ctuple & length_mask) + 3

                            if back_off < dst_chunk_start:
                                # Bogus compression tuple.
                                bogus_data = True
                                break

                            for i in range(0, back_len):
                                # Decompress data.
                                dbuf_obj.seek(back_off)
                                bytes_ = dbuf_obj.read(1)
                                if len(bytes_) != 1:
                                    # Invalid offset.
                                    bogus_data = True
                                    break

                                if not is_valid_write_request(dst_index, 1):
                                    # Bogus data.
                                    bogus_data = True
                                    break

                                dbuf_obj.seek(dst_index)
                                dbuf_obj.write(bytes_)

                                dst_index += 1
                                back_off += 1

                            if bogus_data:
                                break

                    if bogus_data:
                        break

                dbuf = dbuf_obj.getvalue()
                dbuf_obj.close()

                return dbuf

            def ntfs_decompress(input_data):

                NTFS_CLUSTER_SIZE = 4096
                NTFS_COMPRESSION_UNIT_SIZE = 16 * NTFS_CLUSTER_SIZE

                if input_data:

                    if len(input_data) < 8:
                        return input_data

                    input_data = input_data[8:]

                    if len(input_data) < NTFS_CLUSTER_SIZE:
                        input_data += b'\x00' * (NTFS_CLUSTER_SIZE - len(input_data))

                    if isinstance(input_data, bytes):
                        result = cit.custom_registry_handlers.ntfs_decompress.NTFSDecompressUnit(Buffer=input_data)
                        #result = RegistryHelpers.NTFSDecompressUnit(Buffer=input_data)
                        input_data = result

                    return input_data

                return input_data

    def run(self, hive, registry_handler=None, args=None) -> list:

        if not hive:
            logger.warning('Unsupported hive file')
            return []

        #  Load required registry provider
        self.load_provider()

        logger.debug('Plugin: %s -> Run(%s)' % (self.name, hive.hive_file_path))

        if not self.is_hive_supported(hive=hive):
            logger.warning('Unsupported hive type: %s' % hive.hive_type)
            return []

        items = []

        _plugin_reg_handler = build_registry_handler(registry_parser=self.parser,
                                                     registry_handlers='nothing<field>value_raw_data,ntfs_decompress<field>value_raw_data,cit_dump<field>value_raw_data<rfield>value_content',
                                                     custom_handlers=cit.custom_registry_handlers)

        registry_handler = self.choose_registry_handler(main_reg_handler=registry_handler, plugin_reg_handler=_plugin_reg_handler)

        _items = self.parser.query_key_wd(key_path=QUERY_KEY_LIST, hive=hive, plugin_name=self.name, reg_handler=registry_handler)

        if _items:
            items.extend(_items)

        return items
