"""

HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default
-> The list of entries from Remote Desktop Connection Computer box (Entries appear as MRUnumber in registry)

"""

import logging
from md.plugin import plugin
from md.args import build_registry_handler

logger = logging.getLogger('regmagnet')


QUERY_KEY_LIST = [
    r'Comm\Security\CredMan\Creds\*'  # I think it would apply to NET 6.0 Devices only (Aka Windows CE)
]

QUERY_VALUE_LIST = [
    r'Software\Microsoft\Terminal Server Client\Servers\*\UsernameHint',
    r'Software\Microsoft\Terminal Server Client\Default\regex(MRU[0-9]{1,})'
]

class rdp(plugin):
    """ macro - RegMagnet plugin  """

    """ Standard expected variables  """
    author = 'wit0k'
    name = 'rdp'
    description = 'Enumerates RDP related locations useful for Forensics'
    config_file = ''  # IF it's empty/None, the config_data dictionary would not be auto-loaded

    """ Variables initialized by the plugin manager """
    args = None  # Holds plugin related arguments
    parser = None  # Represents the registry_parser object
    config_data = {}  # Contains the json data loaded from config_file (If any was specified and properly created)

    """ Plugin specific variables """
    supported_hive_types = ['NTUSER','SYSTEM']  # Hive type must be upper case


    def __init__(self, params=None, parser=None):
        pass

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

        _plugin_reg_handler = None

        registry_handler = self.choose_registry_handler(main_reg_handler=registry_handler, plugin_reg_handler=_plugin_reg_handler)

        items.extend(self.parser.query_value_wd(value_path=QUERY_VALUE_LIST, hive=hive, plugin_name=self.name, reg_handler=registry_handler))

        #  For now i do not query keys, as the only one i have is for Windows CE
        # items.extend(self.parser.query_key_wd(key_path=QUERY_KEY_LIST, hive=hive, plugin_name=self.name,reg_handler=registry_handler))

        return items
