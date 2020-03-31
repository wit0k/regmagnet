"""
References:

https://outflank.nl/blog/2018/01/16/hunting-for-evil-detect-macros-being-executed/
http://az4n6.blogspot.com/2016/02/more-on-trust-records-macros-and.html

"""

import logging
import struct
from datetime import datetime
from datetime import timedelta

from md.plugin import plugin
from md.args import build_registry_handler

from datetime import datetime

logger = logging.getLogger('regmagnet')

QUERY_KEY_LIST = [
        r"Software\Microsoft\Office\*\*\Security\Trusted Documents\TrustRecords"
    ]

QUERY_VALUE_LIST = [
]

class macro(plugin):
    """ macro - RegMagnet plugin  """

    """ Standard expected variables  """
    author = 'wit0k'
    name = 'macro'
    description = 'Enumerates Office related locations useful for Forensics'
    config_file = ''  # IF it's empty/None, the config_data dictionary would not be auto-loaded

    """ Variables initialized by the plugin manager """
    args = None  # Holds plugin related arguments
    parser = None  # Represents the registry_parser object
    config_data = {}  # Contains the json data loaded from config_file (If any was specified and properly created)

    """ Plugin specific variables """
    supported_hive_types = ["NTUSER"]  # Hive type must be upper case

    def __init__(self, params=None, parser=None):

        self.parser = parser
        self.add_format_fields(field_names=['evaluation'])

    class custom_registry_handlers:

        class macro_executed:

            decription = 'macro_execution -> Based on bytes pattern, sets the value_content to Macro Executed or Not executed'

            def macro_executed(input_data):

                def getFileTime(buffer): #wit0k, previous function

                    _filetime = int.from_bytes(input_data[0:8], byteorder='little', signed=True)
                    _datetime = datetime.utcfromtimestamp((_filetime - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS)
                    _datetime_str = _datetime.strftime('%Y-%m-%d %H:%M:%S.%f')

                    return _datetime_str

                def convert_filetime_to_systemtime(filetime):
                    EPOCH_AS_FILETIME = 116444736000000000;
                    HUNDREDS_OF_NANOSECONDS = 10000000
                    ft_dec = struct.unpack('>Q', filetime)[0]
                    dt = datetime.utcfromtimestamp((ft_dec - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS)
                    return dt.strftime('%Y-%m-%d %H:%M:%S.%f')

                def convert_filetime_str_to_systemtime(filetime_str):
                    filetime_bytes = bytes.fromhex(filetime_str)
                    return convert_filetime_to_systemtime(filetime_bytes)

                def time_difference(filetime1, filetime2):
                    filetime1_bytes = bytes.fromhex(filetime1)
                    filetime2_bytes = bytes.fromhex(filetime2)
                    time_limit = bytes.fromhex('FFFFFFFFFFFFFFFF')
                    ft1_dec = struct.unpack('>Q', filetime1_bytes)[0]
                    ft2_dec = struct.unpack('>Q', filetime2_bytes)[0]
                    ft_limit_dec = struct.unpack('>Q', time_limit)[0]
                    res = ft1_dec - ft2_dec
                    # two's complement?
                    res = ft_limit_dec - res + 1
                    res = struct.pack('>Q', res)
                    return res

                def estimate_access_time(access_time):
                    HUNDREDS_OF_NANOSECONDS = 10000000
                    access_time = b'\x00\x00\x00\x00' + access_time
                    multiplier = bytearray.fromhex('E5109EC205D7BEA7')
                    access_time_dec = struct.unpack('>Q', access_time)[0]
                    multiplier_dec = struct.unpack('>Q', multiplier)[0]
                    access_time_dec = access_time_dec << (64 + 29)
                    access_time_dec = access_time_dec // multiplier_dec
                    access_time_dec /= HUNDREDS_OF_NANOSECONDS
                    return datetime.utcfromtimestamp(access_time_dec).strftime('%Y-%m-%d %H:%M:%S.%f')

                def get_time_zone(timezone):
                    HUNDREDS_OF_NANOSECONDS = 10000000
                    ft_zone_dec = struct.unpack('>q', timezone)[0]
                    res = ft_zone_dec // HUNDREDS_OF_NANOSECONDS
                    return timedelta(seconds=res)

                # https://gist.github.com/Mostafa-Hamdy-Elgiar/9714475f1b3bc224ea063af81566d873
                EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
                HUNDREDS_OF_NANOSECONDS = 10000000

                if input_data:
                    if isinstance(input_data, bytes):

                        bin_data = bytes(reversed(input_data))
                        created_time = convert_filetime_to_systemtime(bin_data[16:])
                        created_time_zone = get_time_zone(bin_data[8:16])
                        estimated_access_time = estimate_access_time(bin_data[4:8])
                        # flag_int = struct.unpack('>I', bin_data[:4])[0]

                        if input_data.endswith(b'\xff\xff\xff\x7f'):
                            return 'Macro: Executed | Created %s | Estimated_access_time: %s | Timezone: %s ' % (created_time, estimated_access_time, created_time_zone)
                        else:
                            return 'Macro: NOT Executed | Created %s | Estimated_access_time: %s | Timezone: %s ' % (created_time, estimated_access_time, created_time_zone)

                    return input_data

                return input_data
    def run(self, hive, registry_handler=None) -> list:
        """ Execute plugin specific actions on the hive file provided
                    - The return value should be the list of registry_provider.registry_item objects """

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
                                                     registry_handlers="utf8_dump<field>value_name,unescape_url<field>value_name,str_replace<param>file:\/\/\/|file:\/\/<field>value_name,macro_executed<field>value_content",
                                                     custom_handlers=macro.custom_registry_handlers)

        registry_handler = self.choose_registry_handler(main_reg_handler=registry_handler, plugin_reg_handler=_plugin_reg_handler)

        _items = self.parser.query_key_wd(key_path=QUERY_KEY_LIST, hive=hive, plugin_name=self.name, reg_handler=registry_handler)

        if _items:
            items.extend(_items)

        return items
