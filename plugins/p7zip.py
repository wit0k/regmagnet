"""
References:
https://twitter.com/CyberRaiju/status/1265945158417215488
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
]

QUERY_VALUE_LIST = [
    r"Software\7-Zip\Compression\CopyHistory",
    r"Software\7-Zip\Extraction\PathHistory",
    r"Software\7-Zip\FM\CopyHistory",
    r"Software\7-Zip\FM\FolderHistory"
]

class p7zip(plugin):
    """ macro - RegMagnet plugin  """

    """ Standard expected variables  """
    author = 'wit0k'
    name = '7zip'
    description = 'Enumerates 7zip related locations useful for Forensics'
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

    def run(self, hive, registry_handler=None, args=None) -> list:
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
                                                     registry_handlers="cit_dump<field>value_content,unescape_url<field>value_content",
                                                     )

        registry_handler = self.choose_registry_handler(main_reg_handler=registry_handler, plugin_reg_handler=_plugin_reg_handler)

        _items = self.parser.query_value_wd(value_path=QUERY_VALUE_LIST, hive=hive, plugin_name=self.name, reg_handler=registry_handler)

        if _items:
            items.extend(_items)

        return items
