"""
References:

https://outflank.nl/blog/2018/01/16/hunting-for-evil-detect-macros-being-executed/
http://az4n6.blogspot.com/2016/02/more-on-trust-records-macros-and.html

"""

import logging
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

                # https://gist.github.com/Mostafa-Hamdy-Elgiar/9714475f1b3bc224ea063af81566d873
                EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
                HUNDREDS_OF_NANOSECONDS = 10000000

                if input_data:
                    if isinstance(input_data, bytes):

                        _filetime = int.from_bytes(input_data[0:8], byteorder='little',signed=True)
                        _datetime = datetime.utcfromtimestamp((_filetime - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS)
                        _datetime_str = _datetime.strftime('%Y-%m-%d %H:%M:%S.%f')

                        if input_data.endswith(b'\xff\xff\xff\x7f'):
                            return 'Macro: Executed | Created: %s' % _datetime_str
                        else:
                            return 'Macro: NOT Executed | Created %s' % _datetime_str

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
