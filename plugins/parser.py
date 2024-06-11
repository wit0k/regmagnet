import logging
import argparse

from md.args import build_registry_handler
from md.args import param_to_list_old as param_to_list

from md.plugin import plugin
from md.registry_parser import registry_action

logger = logging.getLogger('regmagnet')

class parser(plugin):
    """ Parser plugin - Responsible for querying and searching registry values  """

    """ Standard expected variables  """
    author = 'wit0k'
    name = 'parser'
    description = 'Enumerates Office related locations useful for Forensics'
    config_file = 'plugins/parser.py.conf'  # IF it's empty/None, the config_data dictionary would not be auto-loaded
    baseline_file = 'baseline/parser.bl'

    """ Variables initialized by the plugin manager """
    args = None  # Holds plugin related arguments
    parser = None  # Represents the registry_parser object
    config_data = {}  # Contains the json data loaded from config_file (If any was specified and properly created)

    def format_parsed_args(self):

        if self.parsed_args:

            if self.parsed_args.baseline_enabled:
                self.baseline_enabled = True

            self.parsed_args.keys_to_query = param_to_list(self.parsed_args.keys_to_query, strip_char='"', join_list=True)
            self.parsed_args.values_to_query =param_to_list(self.parsed_args.values_to_query, strip_char='"', join_list=True)

            self.parsed_args.keys_to_query_w = param_to_list(self.parsed_args.keys_to_query_w, strip_char='"', join_list=True)
            self.parsed_args.values_to_query_w = param_to_list(self.parsed_args.values_to_query_w, strip_char='"',join_list=True)

            if self.parsed_args.registry_handlers:

                self.parsed_args.registry_handlers = build_registry_handler(
                    registry_handlers=self.parsed_args.registry_handlers.strip('"'), registry_parser=self.parser,
                    decode_param_from=self.parsed_args.rh_decode_param)

            if self.parsed_args.key_info:
                self.parsed_args.key_info = param_to_list(self.parsed_args.key_info,strip_char='"')[0]

    def __init__(self, params, parser):

        self.parser = parser
        argsparser = argparse.ArgumentParser(usage=argparse.SUPPRESS,
                                             description='Plugin: "%s" - Allows querying offline registry hives'
                                                         'hives' % self.name)

        """ Argument groups """
        plugin_args = argsparser.add_argument_group('Plugin arguments', "\n")

        """ Script arguments """

        plugin_args.add_argument("-b", "--baseline", action='store_true', dest='baseline_enabled',
                                 required=False, default=False,
                                 help="Print or export items which are not part of baseline")

        plugin_args.add_argument("-rh", "--registry-handler", type=str, action='store', dest='registry_handlers',
                                 required=False,
                                 help="Registry handler string: handler_name<field>input_field<param>param_n<rfield>result_field like -rh 'b64_encode<field>value_name;value_content' [Note: Input fields and params must be ; separated]")

        plugin_args.add_argument("-rhdp", "--registry-handler-decode-param", type=str, action='store',
                                 dest='rh_decode_param',
                                 required=False, default=None,
                                 help='Allow to specify the handler parameters in any of supported encodings: "base64"')

        plugin_args.add_argument("-qk", "--query-key", type=str, action='store', dest='keys_to_query', required=False,
                                 nargs="+", help="Query given comma separated registry keys, example: "
                                                 "-qk 'Software\\Microsoft\\Windows\\CurrentVersion\\Run,Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce' (Would print all values as well)")

        plugin_args.add_argument("-qv", "--query-value", type=str, action='store', dest='values_to_query', required=False,
                                 nargs="+", help='Query given comma separated registry values, example: -qv "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\ctfmon.exe" (only the queried value would be printed)')

        plugin_args.add_argument("-qkw", "--query-key-wildcard", type=str, action='store', dest='keys_to_query_w', required=False,
                                 nargs="+", help="Regex and String Wildcard enabled -qk like: -qkw 'Software\\Microsoft\\Windows\\*\\Run' or -qkw 'Software\\Microsoft\\Windows\\regex(CurrentVersion)\\Run' CAUTION: Do not mix * with Regex(pattern) in the -qkw parameters")

        plugin_args.add_argument("-qvw", "--query-value-wildcard", type=str, action='store', dest='values_to_query_w', required=False,
                                 nargs="+", help="Regex and String Wildcard enabled -qv like: -qvw 'Software\\Microsoft\\Windows\\*\\Run\\ctfmon.exe' or -qvw 'Software\\Microsoft\\Windows\\regex(CurrentVersion)\\Run\ctfmon.exe' CAUTION: Do not mix * with Regex(pattern) in the -qkw parameters")

        plugin_args.add_argument("--hive-info", "-hi", action='store_true', dest='print_hive_info',
                                 required=False, default=False, help="Print basic information about loaded hives like: -hi")

        plugin_args.add_argument("--key-info", "-ki", type=str, action='store', dest='key_info',
                                 required=False, help="Print basic information about given registry key and its subkeys like: -ki 'Software\Microsoft\Windows\CurrentVersion\Run'")


        self.parsed_args = argsparser.parse_args(args=params)
        argc = params.__len__()

        #  Convert required parameters to list
        self.format_parsed_args()

        #  Load Baseline file according to parameters specified
        self.load_baseline()

    def run(self, hive, registry_handler=None, args=None) -> list:

        # Debug - Testing new query
        # return self.parser.query(action=registry_action.QUERY_KEY, path='CLSID\*\LocalServer32', hive=hive, reg_handler=registry_handler)  # -> 16 items
        # return self.parser.query(action=registry_action.QUERY_KEY, path='CLSID\*\*', hive=hive, reg_handler=registry_handler) # -> 150 items
        # return self.parser.query(action=registry_action.QUERY_KEY, path='*\\regex(.{1,})\\regex(.{2,})', hive=hive,reg_handler=registry_handler)  # -> 150 items
        # return self.parser.query(action=registry_action.QUERY_VALUE, path='.3fr\\OpenWithProgids\\AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h', hive=hive, reg_handler=registry_handler)
        # return self.parser.query(action=registry_action.QUERY_VALUE, path='*\\OpenWithProgids\\AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h', hive=hive, reg_handler=registry_handler)
        # return self.parser.query(action=registry_action.QUERY_VALUE, path='*\\OpenWithProgids\\regex(AppX[c-d][c-d]h38jxzbcberv50vxg2tg4k84kfnewn)', hive=hive, reg_handler=registry_handler)
        return self.parser.query(action=registry_action.QUERY_VALUE, path='regex(.*)\\regex(.*)\\regex(AppX[c-d][c-d]h38jxzbcberv50vxg2tg4k84kfnewn)', hive=hive, reg_handler=registry_handler)

        if not hive:
            logger.warning('Unsupported hive file')
            return []

        #  Load required registry provider
        self.load_provider()

        logger.debug('Plugin: %s -> Run(%s)' % (self.name, hive.hive_file_path))

        items = []
        registry_handler = self.choose_registry_handler(main_reg_handler=registry_handler,
                                                        plugin_reg_handler=self.parsed_args.registry_handlers)

        if self.parsed_args.print_hive_info:
                print(*self.parser.hive_info(hive=hive, reg_handler=registry_handler), sep='\n')

        if self.parsed_args.key_info:
            print(*self.parser.key_info(hive=hive, key_path=self.parsed_args.key_info,
                                 reg_handler=registry_handler), sep='\n')

        if self.parsed_args.keys_to_query:
            items.extend(self.parser.query_key(key_path=self.parsed_args.keys_to_query, hive=hive, plugin_name=self.name,
                                                  reg_handler=registry_handler))

        if self.parsed_args.values_to_query:
            items.extend(self.parser.query_value(value_path=self.parsed_args.values_to_query, hive=hive, plugin_name=self.name,
                                                    reg_handler=registry_handler))

        if self.parsed_args.keys_to_query_w:
            items.extend(self.parser.query_key_wd(key_path=self.parsed_args.keys_to_query_w, hive=hive, plugin_name=self.name,
                                                  reg_handler=registry_handler))

        if self.parsed_args.values_to_query_w:
            items.extend(self.parser.query_value_wd(value_path=self.parsed_args.values_to_query_w, hive=hive, plugin_name=self.name,
                                                    reg_handler=registry_handler))

        # Return items according to baseline settings
        return self.return_items(items)


