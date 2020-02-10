__version__ = '0.0.0.2'

import logging
import argparse
import sys

from os import chdir
from os.path import abspath, dirname

from md.errors import *
from md.registry_parser import registry_parser
from md.pluginmgr import plugin_manager
from md.config import __version__, __author__
from md.args import parse_args
from md.logger import Logger

# Init logging
_Logger = Logger()
logger = logging.getLogger('regmagnet')

""" Set working directory so the script can be executed from any location/symlink """
chdir(dirname(abspath(__file__)))

""" 
    Plugins\Handlers:
    - forensics plugin: https://www.dfir.training/resources/downloads/windows-registry
    
    Enhancements: 
    - Continue working on security_descriptor, to obtain the key_sddl field 
    - Make sure that regex, cannot be used in conjunction with *
    - Use the list of registry_item objects to create winreg data and sqlite data (instead of a list of dicts, coming from registry_item.items())
    - Add json output format
    - ...
"""


def main(argv):

    argsparser = argparse.ArgumentParser(usage=argparse.SUPPRESS,
                                         description='RegMagnet - Working with Microsoft Offline Registry Hives')

    """ Argument groups """
    script_args = argsparser.add_argument_group('Script arguments', "\n")

    """ Script arguments """

    script_args.add_argument("-rp", "--registry-provider", action='store', dest='default_registry_provider', required=False,
                             default='python_registry', help='Specify the default registry provider to load (Default: -rp "python_registry")')

    script_args.add_argument("-v", "--verbose", action='store_true', dest='verbose_mode', default=False,
                             required=False, help="Enables verbose logging")

    script_args.add_argument("-s", "--hives", type=str, action='store', dest='input_hives',
                             required=True, help="Registry hive fie or folder containing registry hives")

    script_args.add_argument("-r", "--recursive", action='store_true', dest='recursive_hive_load', default=False,
                             required=False, help="Recursively scan the input folder")

    script_args.add_argument("--disable-unzip", action='store_false', dest='auto_unzip', default=True,
                             required=False, help="Skip supported archives")

    script_args.add_argument("-o", "--output", type=str, action='store', dest='output_file',
                             required=False, help="Output file path")

    script_args.add_argument("-f", "--output-format", type=str, action='store', dest='output_format',
                             required=False, default='csv', help='Output format: "cs" | "tab" | "winreg" | "sqlite" ')

    script_args.add_argument("-ff", "--output-fields", type=str, action='store', dest='fields_to_print',
                             required=False, default=["plugin_name", "hive_mapping", "key_timestamp","key_subkey_count","key_value_count",
                              "hive_user","key_path","value_name","value_content"], help='Comma separated list of output format fields like: -ff "value_path,value_content_str"')

    script_args.add_argument("-ffa", "--output-field-append", type=str, action='store', dest='extra_fields_to_print',
                             required=False, default=[], help="Append a format field to output format fields list")

    script_args.add_argument("-oek", "--output-empty-keys", action='store_true', dest='output_empty_keys',
                             required=False, default=False,
                             help="Include the empty registry keys in the output")

    script_args.add_argument("-rh", "--registry-handler", type=str, action='store', dest='registry_handlers',
                             required=False,
                             help='Registry handler string: "handler_name<field>input_field<param>param_n<rfield>result_'
                                  'field" like -rh "b64_encode<field>value_name;value_content" [Note: Input fields and params must be ; separated]')

    script_args.add_argument("-rhdp", "--registry-handler-decode-param", type=str, action='store',
                             dest='rh_decode_param',
                             required=False, default=None,
                             help='Allow to specify the handler parameters in any of supported encodings: "base64"')

    script_args.add_argument("-p", "--plugins", type=str, action='store', dest='plugins_to_execute', default=[],
                             required=False, help='The list of comma separated plugins to execute with thier params like: -p "autoruns,macro,plugin_name"', nargs="+")

    script_args.add_argument("-pff", "--print-format-fields", action='store_true', dest='print_format_fields',
                             required=False, default=False,
                             help="Print available output format fields")

    script_args.add_argument("-prh", "--print-registry-handlers", action='store_true', dest='print_reg_handlers',
                             required=False, default=False,
                             help="Print available registry handlers")

    args = argsparser.parse_args()
    argc = argv.__len__()

    logger.info('Starting RegMagnet - ver: %s [Made by: %s]' % (__version__, __author__))
    ###########################################################################
    #  Load parser and selected registry provider (Only one can be selected)  #
    parser = registry_parser(registry_provider_name=args.default_registry_provider, verbose_mode=args.verbose_mode)

    # If parser is not initialized, Exit.
    if not parser:
        logger.error('Unable to load the parser object')
        exit(ERR_REGPROVIDER_LOAD_FAILED)

    ###########################################################################
    #  Parse arguments to expected format                                     #
    args = parse_args(args, parser, _Logger)

    ###########################################################################
    #  Load the Plugin Manager                                                #
    pluginmgr = plugin_manager(parser_obj=parser)

    ###########################################################################
    #  Handle input files and load supported hives                            #
    input_files = parser.get_input_files(input_path=args.input_hives, recursive=args.recursive_hive_load,
                                         unzip_archives=args.auto_unzip)
    input_hives = parser.parse_input_files(input_files=input_files)

    logger.info('Loaded %d hives' % len(input_hives))

    ###########################################################################
    #  Load requested Plugins                                                 #
    for _plugin in args.plugins_to_execute:
        _plugin_name, _, _plugin_args = _plugin.partition(' ')
        pluginmgr.load(plugin_name=_plugin_name.strip(), plugin_params=_plugin_args.strip())

    ###########################################################################
    #  Execute Plugins on loaded hives
    print(CYELLOW + '[+] Executing plugins ...' + CEND)                                        #
    if input_hives:
        #  Run loaded plugins
        items = []
        for _plugin in pluginmgr.plugins.items():

            for _entry in input_hives.values():
                hive = _entry.get('hive')
                # Execute specific plugin for each _hive_file
                _result = pluginmgr.run(plugin=_plugin, registry_hive=hive, registry_handler=args.registry_handlers)
                if _result:
                    items.extend(_result)

        ###########################################################################
        #  Print results                                                          #
        if not args.output_file:
            parser.print(items=items, format=args.output_format, print_empty_keys=args.output_empty_keys,
                         format_fields=args.fields_to_print)  # args.fields_to_print

        ###########################################################################
        #  Export results                                                          #
        if args.output_file:
            parser.export(items=items, output_path=args.output_file, format=args.output_format,
                          format_fields=args.fields_to_print)
    else:
        logger.error('The parser could not find any hives to process ...')

if __name__ == "__main__":
    main(sys.argv)






