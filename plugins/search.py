import time
#import md.mem_profile as mem

import logging
import argparse

from md.args import build_registry_handler
from md.args import param_to_list_old as param_to_list
#from md.args import param_to_list
from providers.provider import registry_provider

from md.plugin import plugin

logger = logging.getLogger('regmagnet')

class search(plugin):
    """ Search plugin - Responsible for querying and searching registry values  """

    """ Standard expected variables  """
    author = 'wit0k'
    name = 'search'
    description = 'Searches for registry key or values matching given pattern'
    config_file = 'plugins/search.py.conf'  # IF it's empty/None, the config_data dictionary would not be auto-loaded
    baseline_file = 'baseline/search.bl'

    """ Variables initialized by the plugin manager """
    args = None  # Holds plugin related arguments
    parser = None  # Represents the registry_parser object
    config_data = {}  # Contains the json data loaded from config_file (If any was specified and properly created)

    attribute_names_type_mapping = {
        'key_string_pattern': registry_provider.search_pattern.Type.KEY_STRING_PATTERN,
        'key_regex_pattern': registry_provider.search_pattern.Type.KEY_REGEX_PATTERN,
        'key_date_pattern': registry_provider.search_pattern.Type.KEY_DATE_TIMESTAMP_PATTERN,
        'key_regex_timestamp_pattern': registry_provider.search_pattern.Type.KEY_REGEX_TIMESTAMP_PATTERN,
        'key_bin_pattern': registry_provider.search_pattern.Type.KEY_BINARY_PATTERN,
        'key_owner_regex_pattern': registry_provider.search_pattern.Type.KEY_REGEX_OWNER_PATTERN,
        'key_permissions_regex_pattern': registry_provider.search_pattern.Type.KEY_REGEX_PERMISSIONS_PATTERN,
        'value_name_string_pattern': registry_provider.search_pattern.Type.VALUE_NAME_STRING_PATTERN,
        'value_name_regex_pattern': registry_provider.search_pattern.Type.VALUE_NAME_REGEX_PATTERN,
        'value_name_bin_pattern': registry_provider.search_pattern.Type.VALUE_NAME_BINARY_PATTERN,
        'value_data_string_pattern': registry_provider.search_pattern.Type.VALUE_CONTENT_STRING_PATTERN,
        'value_data_regex_pattern': registry_provider.search_pattern.Type.VALUE_CONTENT_REGEX_PATTERN,
        'value_data_bin_pattern': registry_provider.search_pattern.Type.VALUE_CONTENT_BINARY_PATTERN,
        'value_data_size_pattern': registry_provider.search_pattern.Type.VALUE_SIZE_PATTERN

    }

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

        #  Key params
        plugin_args.add_argument('-ks', '--key-string', type=str, action='store', dest='key_string_pattern',
                                 required=False, default=None, help=r"Comma separated String patterns, example: -ks '\Run,\RunOnce' would search for all keys having given string anywhere in their key path string")

        plugin_args.add_argument('-kr', '--key-regex', type=str, action='store', dest='key_regex_pattern',
                                 required=False, default=None,
                                 help=r"Comma separated Regex patterns, example: -kr '\\RunMRU$,\\RunOnce$' would search for all keys which ends with '\Run' string")

        plugin_args.add_argument('-kd', '--key-date', type=str, action='store', dest='key_date_pattern',
                                 required=False, default=None,
                                 help="Comma separated Date time patterns: [datetime]..[datetime] or [Operator][datetime], where opertor is one of: '=', '>', '<'. Example: -kd '2014-09-04 13:12:19..2014-09-04 13:12:25.703125,>2014-09-04'")

        plugin_args.add_argument('-kb', '--key-bin', type=str, action='store', dest='key_bin_pattern',
                                 required=False, default=None, help=r"Comma separated Binary patterns expressed in UTF8 escaped hex string, example: -kb '\x5C\x52\x75\x6E' would search for all keys having given sequence of bytes anywhere their key path bytes")

        plugin_args.add_argument('-kt', '--key-timestamp', type=str, action='store', dest='key_regex_timestamp_pattern',
                                 required=False, default=None,
                                 help="Comma separated regex date patterns: -kr '2014-09-04 09:50,2013|2014' would search for all keys modified in 2014-09-04 at 09:50 and on 2013 or 2014")

        plugin_args.add_argument('-ko', '--key-owner', type=str, action='store', dest='key_owner_regex_pattern', required=False, default=None,
                                 help="Comma separated regex patterns matching the owner of the key")

        plugin_args.add_argument('-kp', '--key-permissions', type=str, action='store', dest='key_permissions_regex_pattern',
                                 required=False, default=None,
                                 help="Comma separated regex patterns matching the key permissions")

        # Value params
        plugin_args.add_argument('-vs', '--value-string', type=str, action='store', dest='value_name_string_pattern',
                                 required=False, default=None,
                                 help="Comma separated string patterns: example: -vs 'ctfmon' would search for all values having given string anywhere in their value name")

        plugin_args.add_argument('-vr', '--value-regex', type=str, action='store', dest='value_name_regex_pattern',
                                 required=False, default=None,
                                 help="Comma separated regex patterns: example: -vr 'ctfmon\.exe$' would search for all values having given string anywhere in their value name")

        plugin_args.add_argument('-vb', '--value-bin', type=str, action='store', dest='value_name_bin_pattern',
                                 required=False, default=None,
                                 help="Comma separated Binary patterns expressed in UTF8 escaped hex string, example: -vb '\\x63\\x74\\x66\\x6D\\x6F\\x6E' would search for all values having given sequence of bytes anywhere their name bytes")

        plugin_args.add_argument('-ds', '--data-string', type=str, action='store', dest='value_data_string_pattern',
                                 required=False, default=None,
                                 help="Comma separated String patterns: example: -ds 'CTF' would search for all values having given string anywhere in their data value")

        plugin_args.add_argument('-dr', '--data-regex', type=str, action='store', dest='value_data_regex_pattern',
                                 required=False, default=None,
                                 help="Comma separated Regex patterns: example: -dr '^CTF' would search for all values whose data starts with 'CTF' string")

        plugin_args.add_argument('-db', '--data-bin', type=str, action='store', dest='value_data_bin_pattern',
                                 required=False, default=None,
                                 help="Comma separated Binary patterns: expressed in UTF8 escaped hex string, example: -db '\\x43\\x54\\x46' would search for all values having given sequence of bytes anywhere their data bytes")

        plugin_args.add_argument('-dl', '--data-size', type=str, action='store', dest='value_data_size_pattern',
                                 required=False, default=None,
                                 help="Comma separated Data size patterns: [int]..[int] or [Operator][int], where operator is one of: '>', '<' or '='. Example: -dl '3000..3225','=3226'")

        self.parsed_args = argsparser.parse_args(args=params)
        argc = params.__len__()

        #  Convert required parameters to list
        self.format_parsed_args()

        #  Load Baseline file according to parameters specified
        self.load_baseline()


    def run(self, hive, registry_handler=None, args=None) -> list:

        t1 = 0
        t2 = 0

        if not hive:
            logger.warning('Unsupported hive file')
            return []

        #  Load required registry provider
        self.load_provider()

        logger.debug('Plugin: %s -> Run(%s)' % (self.name, hive.hive_file_path))

        items = []
        registry_handler = self.choose_registry_handler(main_reg_handler=registry_handler,
                                                        plugin_reg_handler=self.parsed_args.registry_handlers)

        #_search_pattern = self.parser.reg.search_pattern()
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

                #print(' [*] Memory (Before): {} Mb'.format(mem.memory_usage_psutil()))
                t1 = time.clock()

            print(' [*] Executing Recursive Search...')
            items.extend(self.parser.search(hive=hive, search_pattern=_search_pattern, reg_handler=registry_handler,
                               case_sensitive=_case_sensitive, plugin_name=self.name))
        else:
            logger.error('Insufficient search pattern. Cancelling the registry scan')

        # Return items according to baseline settings
        if self.parser.verbose_mode:
            t2 = time.clock()
            #print(' [*] Memory (After): {} Mb'.format(mem.memory_usage_psutil()))
            print(' [*] The Search took {} Seconds'.format(t2 - t1))

        return self.return_items(items)
