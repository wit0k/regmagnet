import logging
from md.plugin import plugin
from md.args import build_registry_handler

logger = logging.getLogger('regmagnet')

QUERY_VALUE_LIST = [
    r'WOW6432Node\TeamViewer\regex([a-zA-Z]+PasswordAES|[a-zA-Z]+KeyAES|[a-zA-Z]+PasswordExported)',
    r'TeamViewer\regex([a-zA-Z]+PasswordAES|[a-zA-Z]+KeyAES|[a-zA-Z]+PasswordExported)',
    r'TeamViewer\Temp\SecurityPasswordExported',
    r'WOW6432Node\TeamViewer\Version',
    r'WOW6432Node\TeamViewer\OwningManagerAccountName',
    r'TeamViewer\OwningManagerAccountName',
    r'TeamViewer\BuddyLoginName',
    r'WOW6432Node\TeamViewer\BuddyLoginName',
    r'WOW6432Node\TeamViewer\Proxy_IP',
    r'WOW6432Node\TeamViewer\ProxyUsername',
    r'TeamViewer\Proxy_IP',
    r'TeamViewer\ProxyUsername',
]

QUERY_KEY_LIST = [
]

class teamviewer(plugin):
    """ Example RegMagnet plugin  """

    """ Standard expected variables  """
    author = 'wit0k'
    name = 'teamviewer'
    description = 'Enumerates and decrypts TeamViewer sensible data'
    config_file = ''  # IF it's empty/None, the config_data dictionary would not be auto-loaded

    """ Variables initialized by the plugin manager """
    args = None  # Holds plugin related arguments
    parser = None  # Represents the registry_parser object
    config_data = {}  # Contains the json data loaded from config_file (If any was specified and properly created)

    def run(self, hive, registry_handler=None) -> list:
        """ Execute plugin specific actions on the hive file provided
                    - The return value should be the list of registry_provider.registry_item objects """

        if not hive:
            logger.warning('Unsupported hive file')
            return []

        #  Load required registry provider
        self.load_provider()

        logger.debug('Plugin: %s -> Run(%s)' % (self.name, hive.hive_file_path))

        items = []

        _plugin_reg_handler = build_registry_handler(registry_parser=self.parser,
                                                     registry_handlers='decrypt_teamviewer<field>value_content<rfield>value_content')

        registry_handler = self.choose_registry_handler(main_reg_handler=registry_handler,
                                                        plugin_reg_handler=_plugin_reg_handler,
                                                        merge=True)

        #items.extend(self.parser.query_key_wd(key_path=QUERY_KEY_LIST, hive=hive, plugin_name=self.name, reg_handler=registry_handler))
        items.extend(self.parser.query_value_wd(value_path=QUERY_VALUE_LIST, hive=hive, plugin_name=self.name, reg_handler=registry_handler))

        return items
