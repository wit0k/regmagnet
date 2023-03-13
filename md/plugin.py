import json
import logging
import argparse

from md.registry_parser import registry_provider
from md.args import build_registry_handler

from md.errors import *
from os.path import isfile

logger = logging.getLogger('regmagnet')

class plugin(object):
    """ RegMagnet plugin class  """

    author = 'wit0k'
    name = ''
    description = ''
    config_file = ''    # IF it's empty/None, the config_data dictionary would not be auto-loaded
    baseline_file = ''  # IF it's empty/None, the self.baseline_enabled would ramin set to False, and all matched items
                        # will be returned.

    baseline_fields = ['plugin_name', 'hive_type', 'key_path', 'value_name', 'value_content']
    baseline_db = None
    baseline_enabled = False

    """ Variables initialized by the plugin manager """
    args = None  # Holds plugin related arguments
    parser = None  # Represents the registry_parser object
    config_data = {}  # Contains the json data loaded from config_file (If any was specified and properly created)

    """ Plugin specific variables """
    supported_hive_types = []  # Hive type must be upper case
    supported_providers = []  # Plugin may support more than one registry provider, or a specific one, empty would use default one
    loaded_hives = []

    def __init__(self, params=None, parser=None):

        self.parser = parser

        argsparser = argparse.ArgumentParser(usage=argparse.SUPPRESS,
                                             description='Plugin: "%s" - %s' % (self.name, self.description))

        """ Argument groups """
        plugin_args = argsparser.add_argument_group('Plugin arguments', "\n")

        """ Script arguments """

        plugin_args.add_argument("-b", "--baseline", action='store_true', dest='baseline_enabled',
                                 required=False, default=False,
                                 help="Print or export items which are not part of baseline")

        plugin_args.add_argument("-rh", "--registry-handler", type=str, action='store', dest='registry_handlers',
                                 required=False,
                                 help="...")

        plugin_args.add_argument("-rhdp", "--registry-handler-decode-param", type=str, action='store',
                                 dest='rh_decode_param',
                                 required=False, default=None,
                                 help="...")

        self.parsed_args = argsparser.parse_args(args=params)
        argc = params.__len__()

        #  Convert required parameters to list
        self.format_parsed_args()

        #  Load Baseline file according to parameters specified
        self.load_baseline()


    def run(self, hive, registry_handler=None, args=None) -> list:
        """ Execute plugin specific actions on the hive object  provided
            - The return value should be the list of registry_provider.registry_item objects """

        if not hive:
            logger.warning('Unsupported hive file')
            return []

        logger.debug('Plugin: %s -> Run(%s)' % (self.name, hive.hive_file_path))

        # Set the right reg_handler, if plugin's handler is available
        registry_handler = self.choose_registry_handler(main_reg_handler=registry_handler, pluugin_reg_handler=None)

        #  Load required registry provider
        self.load_provider()

        # Start your code here, remember to return registry_item

    def format_parsed_args(self):
        """ Exposes standard parameters related to baseline and registry handlers etc.
            - Meant to be used in plugins which have no specific plugin parameters
        """
        if self.parsed_args:

            if self.parsed_args.baseline_enabled:
                self.baseline_enabled = True

            if self.parsed_args.registry_handlers:

                self.parsed_args.registry_handlers = build_registry_handler(
                    registry_handlers=self.parsed_args.registry_handlers.strip("'"), registry_parser=self.parser,
                    decode_param_from=self.parsed_args.rh_decode_param)

    def is_hive_supported(self, hive):
        if len(self.supported_hive_types) > 0:
            if hive.hive_type in self.supported_hive_types:
                return True
            else:
                return False
        else:
            # Supported hives not specified, always return True
            return True

    def choose_registry_handler(self, main_reg_handler, plugin_reg_handler=None, merge=False):

        # If plugin's reg_hander is set, return it regardless the main_reg_handler
        if isinstance(plugin_reg_handler, registry_provider.registry_reg_handler) and isinstance(main_reg_handler, registry_provider.registry_reg_handler) and not merge:
            return plugin_reg_handler
        elif isinstance(plugin_reg_handler, registry_provider.registry_reg_handler) and isinstance(main_reg_handler, registry_provider.registry_reg_handler) and merge:
            plugin_reg_handler.functions.extend(main_reg_handler.functions)
            return plugin_reg_handler
        elif isinstance(plugin_reg_handler, registry_provider.registry_reg_handler):
            return plugin_reg_handler
        #  Use the registry handler specified in regmagent main, if none is specified in the plugin
        elif not plugin_reg_handler and isinstance(main_reg_handler, registry_provider.registry_reg_handler):
            return main_reg_handler

        elif plugin_reg_handler is None and main_reg_handler is None:
            return None
        else:
            logger.error('Unable to determine the right registry handler. Contact wit0k!')
            return None



    def set_default_format_fields(self, fields):

        if isinstance(fields, list):
            if fields:
                logger.info('Setting new default Format Fields...')
                logger.info('Previous Fields: %s' % self.parser.default_format_fields)
                logger.info('New Fields: %s' % fields)
                self.parser.default_format_fields = fields

    def add_format_fields(self, field_names=None):

        """ If the plugin creates new format fields, this function shall be called with appropriate param """
        if not field_names:
            field_names = self.config_data.get('new_format_fields', None)

        if field_names:
            logger.debug('Plugin: %s -> Adding new format fields ...' % self.name)
            if isinstance(field_names, list):
                for _field_name in field_names:
                    self.parser.add_format_field(field_name=_field_name)
            elif isinstance(field_names, str):
                self.parser.add_format_field(field_name=field_names)
            else:
                logger.error('Unsupported field name: %s' % field_names)

    def ingest_config(self):

        if self.config_data:
            logger.info('Ingesting config file: "%s" ...' % self.config_file)
            for key, value in self.config_data.items():

                if 'default_format_fields' in key:
                    self.set_default_format_fields(value)
                else:
                    setattr(self, key, value)
        else:
            logger.info('Nothing to ingest')

    def load_provider(self):

        #  IF supported_providers list is empty, return default provider
        if not self.supported_providers:
            return self.parser.reg

        #  Return first supported provider
        for provider_name in self.supported_providers:
            _provider = self.parser.provider.get(provider_name)
            if _provider is None:
                continue
            else:
                self.parser.reg = _provider
                return _provider


    def load_config(self):

        if self.config_file == "":
            logger.info('This plugin does not require config file')
            return True

        if self.config_file:
            logger.info('Attempt to load_config(%s)' % self.config_file)

            if isfile(self.config_file):

                with open(self.config_file, 'r') as file:
                    try:
                        vendor_config = json.load(file)
                        if vendor_config:
                            logger.debug('Successfully loaded JSON data')
                            self.config_data = vendor_config
                            return True
                        else:
                            logger.error('Failed to load config data. Contact plugin developer ')
                            return False
                    except Exception as msg:
                        logger.error('Failed to load config data. Contact plugin developer. Error: %s ' % str(msg))
                        return False

            else:
                logger.error('Config file not found!')
                return False

    def load_baseline(self):

        if self.baseline_file:
            if self.baseline_enabled:
                logger.info('Loading baseline database: %s' % self.baseline_file)
                if isfile(self.baseline_file):
                    print(CYELLOW + '[+] %s: Loading baseline: %s' % (self.name, self.baseline_file) + CEND)
                    self.baseline_db = registry_provider.registry_database(file_path=self.baseline_file, _items=None,
                                                                           baseline_fields=self.baseline_fields)
                else:
                    logger.error('The baseline database is not found: %s ' % self.baseline_file)
                    logger.warning('Disable baseline for this plugin...')
                    self.baseline_enabled = False

    def exclude_baseline_items(self, items):

        if not self.baseline_db:
            # 'Baseline is not initialized, option -b would not take any effect'
            return items

        if items:
            _items = []

            items = self.parser.dedup_items(items=items)
            # items = self.parser.items_to_list_of_dict(items)
            logger.info('Match deduplicated items against the baseline ...')

        if items:
            for _item in items:

                baseline_item = {}

                # After dedup each item shall have only 1 value (if any)... in general 1 entry, hence i can [0]
                _item_dict = _item.items()[0]

                baseline_hash = self.baseline_db.get_baseline_hash(item=_item_dict, columns=self.baseline_fields)
                baseline_item = {'baseline_hash': baseline_hash}

                _result = self.baseline_db.query_by_value("items", [baseline_item])

                if _result == []:
                    _items.append(_item)

            logger.info('Remaining items: [%d]' % len(_items))
            return _items

        return items

    def return_items(self, items):

        if self.baseline_enabled:
            return self.exclude_baseline_items(items=items)
        else:
            return items
