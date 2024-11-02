import logging
import argparse
import sys
from os import chdir
from os.path import abspath, dirname

""" Set working directory so the script can be executed from any location/symlink """
chdir(dirname(abspath(__file__)))
sys.path.insert(0, dirname(abspath(__file__)))

from md.errors import *
from md.registry_parser import registry_parser
from md.pluginmgr import plugin_manager
from md.config import __version__, __author__
from md.args import parse_args
from md.logger import Logger

# Init logging
_Logger = Logger()
logger = logging.getLogger('regmagnet')



""" 
    Plugins\\Handlers:
    - forensics plugin: https://www.dfir.training/resources/downloads/windows-registry
    - -p recentdocs 

    Enhancements: 
    - Implement --version
    - office/macro: Implement remaining stuff: https://ad-pdf.s3.amazonaws.com/Microsoft_Office_2007-2010_Registry_ArtifactsFINAL.pdf
    - Use the list of registry_item objects to create winreg data and sqlite data (instead of a list of dicts, coming from registry_item.items())
    - Onboard provider: https://github.com/EricZimmerman/Registry/
    - It could make sense to create a plugin for https://github.com/microsoft/AppModelSamples/tree/master, https://www.tmurgent.com/TmBlog/?p=3618, https://github.com/nasbench/Misc-Research/blob/main/Other/UWP-Applications-Persistence.md
    - Add CSV delimiter to parameters
    - Add a plugin that analyse the file extensions (including HKCU, and printing their handlers)
     -- Based on https://github.com/hackthebox/business-ctf-2024/blob/main/forensics/%5BHard%5D%20Counter%20Defensive/README.md
    - Fix logging level issue
    - A plugin for https://learn.microsoft.com/en-us/windows/win32/shell/app-registration
    - Plugin for CurrentControlSet\\Control\\Session Manager\\AppCompatCache
    - Fix the issue:
    WARNING - THREAD-8056 - 2024-11-02 11:33:58,449 - registry_parser.py - dedup_items - Failed to get attribute: 253 from reg_item: grvopen\shell\open\command
    WARNING - THREAD-8056 - 2024-11-02 11:33:58,449 - registry_parser.py - dedup_items - Failed to get attribute: () from reg_item: grvopen\shell\open\command
    
    -- root_cause: def get_field_names(self): possibly returns unexpected attributes...
"""


def main(argv):

    argsparser = argparse.ArgumentParser(usage=argparse.SUPPRESS,
                                         description='RegMagnet - Working with Microsoft Offline Registry Hives')

    """ Argument groups """
    script_args = argsparser.add_argument_group('Script arguments', "\n")

    """ Script arguments """

    script_args.add_argument("-rp", "--registry-provider", action='store', dest='default_registry_provider', required=False,
                             default='python_registry', help='Specify the default registry provider to load (Default: -rp "python_registry")')

    script_args.add_argument("--version", action='store_true', dest='print_version', default=False,
                             required=False, help="Prints info about the tool")

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

    script_args.add_argument("-eek", "--output-empty-keys", action='store_false', dest='output_empty_keys',
                             required=False, default=True,
                             help="Exclude keys without values from the output")

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

    script_args.add_argument("-wif", "--winreg-import-file", action='store', dest='winreg_import_file',
                             required=False, default='',
                             help="The buffer to be imported into .reg file")

    script_args.add_argument("-wft", "--winreg-import-file-type", action='store', dest='winreg_import_file_type',
                             required=False, default='REG_BIN',
                             help="The buffer to be imported into .reg file")

    script_args.add_argument("-wdp", "--winreg-destination-path", action='store', dest='destination_key_value_path',
                             required=False, default='HKEY_CURRENT_USER\\SOFTWARE\\SubKey\\BinaryValue',
                             help="Full Windows Registry Key/Value path")

    args = argsparser.parse_args()
    argc = argv.__len__()

    logger.info('Starting RegMagnet - ver: %s [Made by: %s]' % (__version__, __author__))
    ###########################################################################
    #  Print tool info (if requested)
    if args.print_version:
        print(CYELLOW + '%s -> ver: %s' % ('RegMagnet', __version__) + CEND)
        exit(0)

        #  Load parser and selected registry provider (Only one can be selected)  #
    parser = registry_parser(registry_provider_name=args.default_registry_provider, verbose_mode=args.verbose_mode)

    # If parser is not initialized, Exit.
    if not parser:
        logger.error('Unable to load the parser object')
        exit(ERR_REGPROVIDER_LOAD_FAILED)

    ###########################################################################
    #  Parse arguments to expected format                                     #
    args = parse_args(args, parser, _Logger)

    #  Process WinReg Helpers
    if args.winreg_import_file:
        from helpers.winreg import buffer_to_winreg

        buffer_to_winreg(args.winreg_import_file, args.winreg_import_file_type, args.destination_key_value_path, args.output_file)

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
                _result = pluginmgr.run(plugin=_plugin, registry_hive=hive, registry_handler=args.registry_handlers, args=args, loaded_hives=input_hives.values())
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
        logger.error('The parser could not find any hives to process.....')

if __name__ == "__main__":
    main(sys.argv)






