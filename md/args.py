import re
import logging
from os.path import isdir, isfile
from md.errors import *

logger = logging.getLogger('regmagnet')

def build_registry_handler(registry_parser, registry_handlers, decode_param_from=None, custom_handlers=None):

    _registry_handlers = None
    registry_handlers = param_to_list(registry_handlers)
    _registry_handlers = registry_parser.reg.registry_reg_handler(recipes=registry_handlers, decode_param_from=decode_param_from,
                                                                  custom_handlers=custom_handlers)

    return _registry_handlers

def parse_args(args, registry_parser, _logger):
    """ The args parsing section for main script """
    if args:

        print(CYELLOW + '[+] Parsing script arguments' + CEND)

        if args.verbose_mode:
            _logger.SetLoggingLevel('DEBUG')

        if args.print_reg_handlers:
            registry_parser.print_registry_handlers()

        if args.input_hives:
            if not isfile(args.input_hives) and not isdir(args.input_hives):
                logger.error('-s: The input must be either existing folder or a file')
                exit(ERR_REGPARSER_INPUT_NOT_FOUND)

        if args.output_format:
            args.output_format = args.output_format.lower()

        if args.fields_to_print:
            args.fields_to_print = param_to_list(args.fields_to_print, strip_char="'")
            args.fields_to_print = list(map(str.lower, args.fields_to_print))
            args.fields_to_print = list(map(str.strip, args.fields_to_print))

        if args.extra_fields_to_print:
            args.extra_fields_to_print = param_to_list(args.extra_fields_to_print, strip_char="'")
            args.extra_fields_to_print = list(map(str.lower, args.extra_fields_to_print))
            args.extra_fields_to_print = list(map(str.strip, args.extra_fields_to_print))

            args.fields_to_print.extend(args.extra_fields_to_print)

        if args.registry_handlers:
            args.registry_handlers = build_registry_handler(
                registry_handlers=args.registry_handlers.strip("'"), registry_parser=registry_parser,
                decode_param_from=args.rh_decode_param)

        if args.plugins_to_execute:
            #  Convert plugins_to_execute to a list
            # Test
            args.plugins_to_execute = " ".join(args.plugins_to_execute)
            args.plugins_to_execute = param_to_list(args.plugins_to_execute)

        if args.print_format_fields:
            registry_parser.print_format_fields()

    return args


def prepare_plugin_args(params):

    #  Find All single quoted params

    sq_params = re.findall(r"('.+?')", params, re.IGNORECASE)
    _param = ''

    for _param in sq_params:

        if _param:
            _param = _param.strip()

            if _param.startswith(r"'") and _param.endswith(r"'"):

                if " " in _param:
                    _param_content = _param[1:-1]
                    new_param = '"' + _param_content + '"'

                    #  Replace , with ","
                    #  new_param = new_param.replace(",", '","')

                    old_param = _param
                    params = params.replace(old_param, new_param)

                else:
                    old_param = _param
                    new_param = _param.replace("'", '')

                    if ',' in new_param:
                        new_param = '"' + new_param + '"'

                    params = params.replace(old_param, new_param)

    # Split params
    params_new = []
    if '"' in params:
        sdq_params = re.split(r'(".+?")', params, re.IGNORECASE)

        for _p in sdq_params:

            if _p:
                _p = _p.strip()
                if '"' in _p:
                    params_new.append(_p)
                else:
                    params_new.extend(_p.split(' '))
    else:
        params_new = params.split(' ')

    #  Make sure that there is no empty strings in the list
    params_new = [param for param in params_new if param !='']

    return params_new


def param_to_list_old(param, separator=",", strip_char=None, join_list=False):

        items = []
        if param:
            if isinstance(param, bytes):
                return [param]

            if isinstance(param, float):
                return [param]

            if join_list:
                param = " ".join(param)

            if separator in param:
                for _param in param.split(separator):
                    if strip_char:
                        items.append(_param.strip().strip(strip_char))
                    else:
                        items.append(_param.strip())
            else:
                param = param.strip(strip_char)
                return [param]

        return items

def param_to_list(param, separator=",", strip_char=None):
    """ Supports single and double quotes """
    items = []
    if param:

        if isinstance(param, list):
            return param

        if isinstance(param, bytes):
            return [param]

        if separator in param:
            # Each time it finds a comma, the lookahead scans the entire remaining string, making sure there's an even
            # number of single-quotes and an even number of double-quotes. (Single-quotes inside double-quoted fields,
            # or vice-versa, are ignored.) If the lookahead succeeds, the semicolon is a delimiter.

            items = re.split(''',(?=(?:[^'"]|'[^']*'|"[^"]*")*$)''', param)

        else:
            if strip_char:
                param = param.strip(strip_char)

            return [param]

    return items