import time
import md.mem_profile as mem

import logging
import argparse

from md.args import build_registry_handler
from md.args import param_to_list_old as param_to_list
from providers.provider import registry_provider

from md.plugin import plugin

logger = logging.getLogger('regmagnet')

class anomaly(plugin):
    """ Search plugin - Responsible for querying and searching registry values  """

    """ Standard expected variables  """
    author = 'wit0k'
    name = 'anomaly'
    description = 'Searches for registry anomalies in registry values'
    config_file = 'plugins/anomaly.py.conf'  # IF it's empty/None, the config_data dictionary would not be auto-loaded
    baseline_file = 'baseline/anomaly.bl'

    """ Variables initialized by the plugin manager """
    args = None  # Holds plugin related arguments
    parser = None  # Represents the registry_parser object
    config_data = {}  # Contains the json data loaded from config_file (If any was specified and properly created)

    attribute_names_type_mapping = {
        'entropy_level': registry_provider.search_pattern.Type.VALUE_CONTENT_ENTROPY
    }

    EXCLUDED_KEYS = []

    def format_parsed_args(self):

        if self.parsed_args:

            if self.parsed_args.baseline_enabled:
                self.baseline_enabled = True

            for attr in self.attribute_names_type_mapping.keys():
                attr_current_value = getattr(self.parsed_args, attr)
                attr_current_value = param_to_list(attr_current_value, strip_char='"', join_list=False)
                setattr(self.parsed_args, attr, attr_current_value)


            if self.parsed_args.registry_handlers:

                self.parsed_args.registry_handlers = build_registry_handler(
                    registry_handlers=self.parsed_args.registry_handlers.strip('"'), registry_parser=self.parser,
                    decode_param_from=self.parsed_args.rh_decode_param)

    def __init__(self, params, parser):

        self.parser = parser
        argsparser = argparse.ArgumentParser(usage=argparse.SUPPRESS,
                                             description='Plugin: "%s" - Allows searching and querying offline registry '
                                                         'hives' % self.name)

        """ Argument groups """
        plugin_args = argsparser.add_argument_group('Plugin arguments', "\n")

        """ Script arguments """

        plugin_args.add_argument('-b', '--baseline', action='store_true', dest='baseline_enabled',
                                 required=False, default=False,
                                 help="Print or export only the items which are not part of baseline")

        plugin_args.add_argument("-rh", "--registry-handler", type=str, action='store', dest='registry_handlers',
                                 required=False,
                                 help="Registry handler string: handler_name<field>input_field<param>param_n<rfield>result_field like -rh 'b64_encode<field>value_name;value_content' [Note: Input fields and params must be ; separated]")

        plugin_args.add_argument("-rhdp", "--registry-handler-decode-param", type=str, action='store',
                                 dest='rh_decode_param',
                                 required=False, default=None,
                                 help='Allow to specify the handler parameters in any of supported encodings: "base64"')

        plugin_args.add_argument("-e", "--entropy", type=float, action='store', required=True, dest='entropy_level',
                                 default=3.5, help='...')


        self.parsed_args = argsparser.parse_args(args=params)
        argc = params.__len__()

        #  Convert required parameters to list
        self.format_parsed_args()

        #  Load Baseline file according to parameters specified
        self.load_baseline()


    def search_pattern_eval_func(self, plugin_name, hive, key, search_pattern, reg_handler, case_sensitive, search_create_item):

        skip = False

        key_values = key.values()
        key_path = key.path()

        for _key in self.EXCLUDED_KEYS:
            if _key in key_path:
                skip = True

        if not skip:
            # Next, process value related patterns
            if key_values:

                _registry_values = []

                for value in key_values:

                    # Entropy check
                    if search_pattern.VALUE_CONTENT_ENTROPY:
                        value_entropy = search_pattern.eval(input_data=value.raw_data(), pattern_table=search_pattern.VALUE_CONTENT_ENTROPY, case_sensitive=case_sensitive)

                        if value_entropy:
                            yield search_create_item(plugin_name=plugin_name, hive=hive, key=key, values=[value],
                                                  reg_handler=reg_handler, custom_fields={'entropy': value_entropy})


    def run(self, hive, registry_handler=None, args=None) -> list:

        if not hive:
            logger.warning('Unsupported hive file')
            return []

        #  Load required registry provider
        self.load_provider()

        logger.debug('Plugin: %s -> Run(%s)' % (self.name, hive.hive_file_path))

        items = []
        registry_handler = self.choose_registry_handler(main_reg_handler=registry_handler,
                                                        plugin_reg_handler=self.parsed_args.registry_handlers)

        # _search_pattern = self.parser.reg.search_pattern()
        _search_pattern = registry_provider.search_pattern()

        _case_sensitive = False

        # Update search_pattern object
        for attr in self.attribute_names_type_mapping.keys():
            _attr = getattr(self.parsed_args, attr)

            if _attr:
                _search_pattern_type = self.attribute_names_type_mapping.get(attr)
                _search_pattern.add(pattern=_attr, pattern_type=_search_pattern_type)

        #  Search only when at least 1 valid search pattern is found
        if any([True if len(pattern) > 0 else False for pattern in _search_pattern.PATTERN_MAPPING.values()]):

            #  Print requested search patterns
            _search_pattern.print()

            #  Decrase the size of original search pattern object, just use only required attributes in a new object
            _search_pattern = _search_pattern.compile()

            if self.parser.verbose_mode:

                print(' [*] Memory (Before): {} Mb'.format(mem.memory_usage_psutil()))
                t1 = time.clock()

            print(' [*] Executing Recursive Search...')
            items.extend(self.parser.reg.Search(hive=hive, key=hive.hive_obj.root(), search_pattern_eval_func=self.search_pattern_eval_func,
                                                search_pattern=_search_pattern, reg_handler=registry_handler,
                                                case_sensitive=_case_sensitive, plugin_name=self.name))
        else:
            logger.error('Insufficient search pattern. Cancelling the registry scan')

        # Return items according to baseline settings
        if self.parser.verbose_mode:
            t2 = time.clock()
            print(' [*] Memory (After): {} Mb'.format(mem.memory_usage_psutil()))
            print(' [*] The Search took {} Seconds'.format(t2 - t1))

        return self.return_items(items)
