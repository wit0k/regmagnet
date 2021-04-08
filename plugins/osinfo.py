"""
References:
https://github.com/gtworek/PSBits/blob/master/DFIR/GetDynamicTaskInfo.ps1
"""

import logging
import struct
from datetime import datetime
from datetime import timedelta
from io import BytesIO

from md.plugin import plugin
from md.args import build_registry_handler
from providers.provider import registry_provider

from datetime import datetime

logger = logging.getLogger('regmagnet')

QUERY_KEY_LIST = [
    r"Microsoft\Windows NT\CurrentVersion"
]

QUERY_VALUE_LIST = [
    r"Microsoft\Windows NT\CurrentVersion\ProductName"
]

class osinfo(plugin):
    """ volprofile - RegMagnet plugin  """

    """ Standard expected variables  """
    author = 'wit0k'
    name = 'osinfo'
    description = 'Prints OS version, which can be used to search for Volatility profile, or other tasks. Use -ffa evaluation'
    config_file = ''  # IF it's empty/None, the config_data dictionary would not be auto-loaded

    """ Variables initialized by the plugin manager """
    args = None  # Holds plugin related arguments
    parser = None  # Represents the registry_parser object
    config_data = {}  # Contains the json data loaded from config_file (If any was specified and properly created)

    """ Plugin specific variables """
    supported_hive_types = ["SOFTWARE"]  # Hive type must be upper case

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

        registry_handler = self.choose_registry_handler(main_reg_handler=registry_handler, plugin_reg_handler=None)

        _items = self.parser.query_key_wd(
            key_path=QUERY_KEY_LIST,
            hive=hive,
            plugin_name=self.name,
            reg_handler=registry_handler
        )

        OsVersion = {}
        for reg_item in _items:
            if reg_item.has_values:
                for reg_value in reg_item.values:
                    if reg_value.value_name in ['CurrentMajorVersionNumber', 'CurrentMinorVersionNumber', 'BuildLab']:
                        OsVersion[reg_value.value_name] = reg_value.value_content


        # Build evaluation field
        Version = [OsVersion.get('CurrentMajorVersionNumber', ''), OsVersion.get('CurrentMinorVersionNumber', ''), OsVersion.get('BuildLab', '')[:OsVersion.get('BuildLab', '').index('.')]]
        Version = list(map(str, Version))
        Version = '.'.join(Version)

        _items_org = self.parser.query_value_wd(value_path=QUERY_VALUE_LIST, hive=hive, plugin_name=self.name, reg_handler=registry_handler)

        if len(_items_org) > 0:
            setattr(_items_org[0], 'evaluation', Version)

        if _items_org:
            items.extend(_items_org)

        if _items:
            items.extend(_items)

        # Set additional format field
        if args:
            if 'evaluation' not in args.fields_to_print:
                args.fields_to_print.append('evaluation')

        return items
