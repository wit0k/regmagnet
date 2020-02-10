import logging
from md.plugin import plugin

logger = logging.getLogger('regmagnet')

QUERY_VALUE_LIST = [
]

QUERY_KEY_LIST = [
    r"Software\Microsoft\Office\*\*\File MRU",
    r"Software\Microsoft\Office\*\*\File MRU",
    r"Software\Microsoft\Office\*\*\Reading Locations",
    r"Software\Microsoft\Office\*\*\Resiliency"
]

class office(plugin):
    """ Example RegMagnet plugin  """

    """ Standard expected variables  """
    author = 'wit0k'
    name = 'office'
    description = 'Enumerates Office related locations useful for Forensics'
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

        registry_handler = self.choose_registry_handler(main_reg_handler=registry_handler, plugin_reg_handler=None)

        items.extend(self.parser.query_key_wd(key_path=QUERY_KEY_LIST, hive=hive, plugin_name=self.name, reg_handler=registry_handler))
        #items.extend(self.parser.query_value_wd(value_path=QUERY_VALUE_LIST, hive=_hive_obj, plugin_name=self.name))

        return items
