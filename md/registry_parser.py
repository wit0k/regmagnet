#import time
#import md.mem_profile as mem

import logging
import csv
import re
import os
import glob
import platform as _os

from md.errors import *
from md.reg_handlers import handlers
from providers.provider import registry_provider
from os.path import isfile, isdir, splitext, dirname
from md.hasher import get_hash
from md.archive import archive
from md.plugin import plugin
from sys import exit
from sys import stdout
from enum import Flag, auto

stdout.reconfigure(encoding='utf8')

logger = logging.getLogger('regmagnet')

class registry_action(object):

    QUERY_KEY = 1
    QUERY_VALUE = 2
    QUERY_KEY_CLASS = 3

class registry_action_settings(Flag):

    IGNORECASE = auto()
    PRINT_EMPTY = auto()
    RECURSIVE = auto()

    DEFAULT_KEY = IGNORECASE | PRINT_EMPTY
    DEFAULT_VALUE = IGNORECASE | PRINT_EMPTY
    DEFAULT_CLASS = IGNORECASE | PRINT_EMPTY

class registry_parser(object):

    """ Class registry_parser """
    name = "parser"
    reg = None
    supported_output_format = ['csv', 'tab', 'winreg']
    format_fields = []  # Keeps the list of currently loaded format fields
    default_format_fields = ['plugin_name', 'hive_mapping', 'key_timestamp','key_subkey_count','key_value_count','hive_user','key_path','value_name',
                             'value_content']

    hives = {
        'hash': {  # hash is the md5 of loaded hive_file
            'hive': None,
            'hive_sig': None
            }
        }

    registry_cache = {
        'hash': {  # hash is the md5 of loaded hive_file
            'hive': None,
            'hive_sig': None
            }
        }

    basline_cache = {

    }


    def __init__(self, registry_provider_name, verbose_mode):

        print(CYELLOW + '[+] Loading Registry Provider: %s' % registry_provider_name + CEND)
        self.verbose_mode = verbose_mode

        if self.verbose_mode:
            logger.setLevel(level=logging.DEBUG)
        else:
            logger.setLevel(level=logging.INFO)

        self.reg = None
        self.provider = self.load_provider(provider_name=registry_provider_name)

        if not self.provider:
            logger.error('Unable to find registry provider: "%s"' % registry_provider_name)
            exit(ERR_REGPROVIDER_LOAD_FAILED)
        else:
            self.reg = self.provider.provider
            self.baseline_fields = plugin.baseline_fields

        if not self.reg:
            logger.error('Unable to load the registry provider: "%s"' % registry_provider_name)
            exit(ERR_REGPROVIDER_LOAD_FAILED)

        self.load_format_fields()

    """ ------------------------------------------------------------------------------------------------------------- 
                                    Parser Functions
        ------------------------------------------------------------------------------------------------------------- 
    """
    def dedup_items(self, items):

        _items = []

        if items:

            _len = len(items)
            logger.info('Initial items count: [%d]...' % _len)
            logger.info('Decomposing registry items ...')
            #  Decompose the registry_item values to separate registry items
            for _item in items:
                if _item.has_values:

                    fields = {'has_values': True}

                    for _attribute_name in _item.get_field_names():
                        _v = getattr(_item, _attribute_name, None)
                        if _v is not None:
                            fields[_attribute_name] = _v
                        else:
                            logger.warning('Failed to get attribute: %s from reg_item: %s' % (_attribute_name,_item.get_path()))
                            fields[_attribute_name] = '%s - NOT FOUND' % _attribute_name

                    # Make sure there is 1 value per registry item ...
                    for value in _item.values:
                        _registry_item = registry_provider.registry_item()
                        #_registry_item.add(_plugin_name=plugin_name, _registry_hive=hive, _registry_key=key, _registry_values=value, _custom_fields=custom_field)
                        fields['values'] = [value]
                        _registry_item.add_named_fields(fields=fields)
                        _items.append(_registry_item)
                else:
                    # The item has no values, hence can be directly added
                    _items.append(_item)

            _len = len(_items)
            logger.info('All single items count: [%d]...' % _len)
            logger.info('Deduplicate items...')
            _items = list(dict.fromkeys(_items))
            logger.debug('Deduplicating items [%d -> %d]...' % (_len, len(_items)))

            return _items

    def items_to_list_of_dict(self, items):

        _items = []
        for reg_item in items:
            _items.extend(reg_item.items())

        return _items

    def load_provider(self, provider_name):
        """ Load the registry provider like python-registry and its wrapper which would support parser's functions """

        logger.debug('Loading registry provider: "%s"' % provider_name)
        try:
            _provider = registry_provider(provider_name)
        except Exception:
            _provider = None

        return _provider

    def load_hive(self, hive_file_path, hive_file_log=None, skip_hive_cache=False) -> registry_provider.registry_hive:

        if hive_file_log is None: hive_file_log = []

        if self.reg:
            if isfile(hive_file_path):
                _hive_md5 = get_hash(input_data=hive_file_path, hash_type='md5')

                if _hive_md5 in self.hives.keys() and skip_hive_cache == False:
                    logger.debug('Loading hive: "%s" from CACHE' % hive_file_path)
                    _hive = self.hives.get(_hive_md5).get('hive')

                    if _hive:
                        return _hive
                    else:
                        return None
                else:
                    _hive = self.reg.load_hive(hive_file_path=hive_file_path, hive_transaction_logs=hive_file_log)
                    if _hive:
                        _hive.hive_md5 = _hive_md5
                        self.hives[_hive_md5] = {'hive': _hive}
                        return _hive
                    else:
                        return None

            else:
                logger.warning('Unable to find hive file: %s' % hive_file_path)
                return None
        else:
            logger.error('The registry provider is null')
            return None

    def get_input_files(self, input_path, recursive=False, unzip_archives=True):

        hive_files = []

        if input_path:

            print(CYELLOW + '[+] Searching for input files' + CEND)

            _archive = archive()
            _supported_archive_extensions = _archive.supported_archive_extensions()

            EXCLUDED_EXTENSIONS = (
                ".ZIP",
                ".7Z",
                ".DS_STORE",
                ".REG",
                "DOC",
                "DOCX",
                "TXT"
            )

            #  Case: The input_path is an existing file
            if isfile(input_path):
                file_name, _, file_extension = input_path.rpartition('.')
                file_extension = '.' + file_extension.upper()

                if file_extension in _supported_archive_extensions:
                    if unzip_archives:
                        hive_files.extend(_archive.decompress(input_path))
                else:
                    if (file_extension not in EXCLUDED_EXTENSIONS) or (not file_extension):
                        hive_files.append(input_path)

            #  Case: The input_path is a folder to lookup
            elif isdir(input_path):

                # Make sure tha the folder path is finished with / or \, hence the glob ** would work properly
                if 'Darwin' in _os.platform() or 'Linux' in _os.platform():
                    if not input_path[:-1] == r'/':
                        input_path += r'/'

                elif 'Windows' in _os.platform():
                    if not input_path[:-1] == '\\':
                        input_path += '\\'

                if recursive:
                    logger.debug('Enable recursive search')
                    pattern = input_path + '**'
                else:
                    pattern = input_path + '*'

                for _path in glob.glob(pattern, recursive=recursive):

                    #  Add only supported hives
                    if isfile(_path):
                        file_name, _, file_extension = _path.rpartition('.')
                        file_extension = '.' + file_extension.upper()

                        if file_extension in _supported_archive_extensions:
                            if unzip_archives:
                                hive_files.extend(_archive.decompress(_path))

                        if (file_extension not in EXCLUDED_EXTENSIONS) or (not file_extension):
                            hive_files.append(_path)

            hive_files = set(hive_files)
            hive_files = list(hive_files)

        logger.info('Selected [%d] files for further hive pre-parsing' % len(hive_files))

        return hive_files

    def parse_input_files(self, input_files, skip_print=False, skip_hive_cache=False):

        hive_root_entry = {}

        if input_files:

            if not skip_print: print(CYELLOW + '[+] Parsing input hives' + CEND)

            for _hive_file in input_files:

                hive_child_entry = {}

                # Calculate the md5 hash of the hive:
                md5 = get_hash(input_data=_hive_file, hash_type='md5')

                if md5 in hive_root_entry.keys():
                    logger.debug('Entry: [%s] already in the Hive Cache...' % md5)
                    continue

                # Get the file signature
                with open(_hive_file, 'rb') as _file:
                    try:
                        hive_sig = str(_file.read(8))
                    except Exception:
                        hive_sig = 'NULL or too short'

                    hive_child_entry['hive_sig'] =  hive_sig

                # Get the hive_obj
                hive_obj = self.load_hive(hive_file_path=_hive_file, skip_hive_cache=skip_hive_cache)
                if hive_obj:
                    hive_child_entry['hive'] = hive_obj
                else:
                    logger.error('Unable to load hive -> Sig: %s -> File: %s' % (hive_sig, _hive_file))
                    continue

                hive_root_entry[md5] = hive_child_entry

        return hive_root_entry

    def build_registry(self, input_files):
        """ Not finished yet """
        computer_registry = {}

        if input_files:

            for _hive_file in input_files:

                #  Add support to situation, where hive is specified with a log file as a tuple
                if isinstance(_hive_file, tuple):
                    _hive_file_path = _hive_file[0]
                    hive_file_log = _hive_file[1]
                else:
                    _hive_file_path = _hive_file
                    hive_file_log = None


                _hive_obj = self.load_hive(hive_file_path=_hive_file_path, hive_file_log=hive_file_log)

                if _hive_obj:
                    _objects = computer_registry.get(_hive_obj.hive_type, [])
                    _objects.append(_hive_obj)
                    computer_registry[_hive_obj.hive_type] = _objects

            return computer_registry

        return None



    """ ------------------------------------------------------------------------------------------------------------- 
                                    Format Fields
        ------------------------------------------------------------------------------------------------------------- 
    """
    def get_current_format_fields(self, _format_fields):

        current_fields = []

        if _format_fields is None:
            current_fields = self.default_format_fields
            return current_fields

        if isinstance(_format_fields, list):

            if _format_fields == []:
                current_fields = self.default_format_fields

            elif 'all' in _format_fields[0]:
                current_fields = self.format_fields
            else:
                current_fields = _format_fields
        else:
            logger.error('Unsupported input format! Output the default format fields')
            current_fields = self.default_format_fields

        return current_fields

    def add_format_field(self, field_name, obj_name='item'):
        """ The function is supposed to be used by plugins, which plan to add new format fields prior to execution """

        obj_name = obj_name.lower()
        logger.debug('Add new format field: %s' % field_name)
        if not obj_name in registry_provider.item_classes.keys():
            logger.error('The class: "%s" cannot be edited!' % obj_name)
            return None

        if not isinstance(field_name, list):
            field_name = [field_name]

        for _name in field_name:
            _class_obj = registry_provider.item_classes.get(obj_name, None)

            if _class_obj:
                setattr(_class_obj, _name, None)
                setattr(_class_obj.attributes, _name, _name)

        self.load_format_fields()

    def load_format_fields(self):

        logger.debug('Loading format fields')
        self.format_fields = []

        for _attributes in [
                            self.reg.registry_item.attributes.__dict__.items(),
                            self.reg.registry_hive.attributes.__dict__.items(),
                            self.reg.registry_key.attributes.__dict__.items(),
                            self.reg.registry_value.attributes.__dict__.items()
                            ]:

            #  Would print all attributes
            for field, field_name in _attributes:
                field_name = str(field_name)
                if not True in [field_name.startswith(prefix) for prefix in ['(', '__', '<', 'providers.', 'None']]:
                    if not re.match(r'^\d', field_name):
                        self.format_fields.append(field_name)

        logger.debug('Loaded: %s' % self.format_fields)

    """ ------------------------------------------------------------------------------------------------------------- 
                                    Print Functions
        ------------------------------------------------------------------------------------------------------------- 
    """
    def _print(self, items, sep):
        """ _print - Used to debug printing problems when necessary """

        for _item in items:
            _item = _item.replace('\r\n', ';')
            print(_item)



    def print(self, items, format='tab', format_fields=None, print_empty_keys=True, enable_baseline=False):

        if items:
            logger.info('Print items')
            logger.info('Items count: [%d]' % len(items))
            logger.info('Deduplicate items')
            items = self.dedup_items(items)

            logger.info('Items count: [%d]' % len(items))

            if not print_empty_keys:
                logger.info('Print only registry items having registry values')
                items = [_item for _item in items if _item.has_values]
                logger.info('Items count: [%d]' % len(items))

            current_fields = self.get_current_format_fields(format_fields)

            if format == 'csv':
                print(CYELLOW + '[+] Printing CSV formatted data' + CEND)
                self._print(self.convert_to_pseudo_csv(items=items, _format_fields=current_fields), sep='\n')

            elif format == 'winreg':
                print(CYELLOW + '[+] Printing WinReg formatted data' + CEND)
                self._print(self.convert_to_winreg(items=items), sep='\n')

            elif format == 'tab':
                print(CYELLOW + '[+] Printing Tab formatted data' + CEND)
                print(CRED + ' [+] NOTE: ' + CEND + CYELLOW + 'IF value_content is printed, the output might be inaccurate...' + CEND)
                print(CYELLOW + '  [+] Workaround: -rh "rslice<param>-120<field>value_content"' + CEND)
                self._print(self.convert_to_tab_output(items=items, _format_fields=current_fields), sep='\n')

            elif format == 'sqlite':
                logger.error('[+] It is impossible to print in SQLite format, switching to CSV...')
                print(CYELLOW + '[+] Printing CSV formatted data' + CEND)
                self._print(self.convert_to_pseudo_csv(items=items, _format_fields=current_fields), sep='\n')

            elif format == 'json':
                print(CYELLOW + '[+] Printing JSON formatted data' + CEND)
                self._print(self.convert_to_json(items=items, _format_fields=current_fields), sep='\n')

        else:
            print(CRED + '[+] There was nothing to print' + CEND)

    def print_format_fields(self):

        CYELLOW = '\33[33m'
        CEND = '\033[0m'

        print(CYELLOW + 'Format Fields:' + CEND)

        for _field in self.format_fields:
            print(' [+] ' + _field)

    def print_registry_handlers(self):

        _handlers_help = handlers.get_handlers_help()
        print(CYELLOW + 'Registry Handlers:' + CEND)

        for _reg_handler, help_message in _handlers_help.items():
            print(' [+] ' + CRED + _reg_handler + CEND,'-',help_message)

    """ ------------------------------------------------------------------------------------------------------------- 
                                    Search Functions
        ------------------------------------------------------------------------------------------------------------- 
    """

    def search(self, hive, search_pattern, reg_handler=None, case_sensitive=False, plugin_name='search') -> list:
        """ Search withing entire registry for keys and values matching given search criteria """

        try:
            hive_root = hive.hive_obj.root()
        except AttributeError:
            hive_root = hive.hive_obj.root_key()

        return self.reg.search(hive=hive, key=hive_root, search_pattern=search_pattern, reg_handler=reg_handler,
                        case_sensitive=case_sensitive, plugin_name=plugin_name)


    """ ------------------------------------------------------------------------------------------------------------- 
                                    QUERY Functions (NEW)
        ------------------------------------------------------------------------------------------------------------- 
    """
    def query(self, action: int, path: list, hive: registry_provider.registry_hive, reg_handler=None, settings=None, items=None, plugin_name=None, depth=None):
        """ The query function allows querying for keys and values (according to given parameters)
        - path: A list of path to query (may include path pattern(s))
        """

        # Set Defaults
        if depth is None: depth = 0
        if isinstance(path, str): path = [path]
        if items is None: items = []
        if plugin_name is None: plugin_name = 'parser'

        depth += 1
        logger.debug('registry_parser.query: %s -> Depth: %s' % (path, depth))

        # Query Key
        if action == registry_action.QUERY_KEY:
            if settings is None: settings = registry_action_settings.DEFAULT_KEY

        # Query Value
        if action == registry_action.QUERY_VALUE:
            if settings is None: settings = registry_action_settings.DEFAULT_VALUE

        # Query Key Class
        if action == registry_action.QUERY_KEY:
            if settings is None: settings = registry_action_settings.DEFAULT_CLASS

        paths = {}
        _path = ''

        # Helper functions
        def split(s: str, delimiter, escape_char='\\\\'):
            out = []
            if escape_char in s:
                s = s.replace(escape_char, '<escape>')

            s = s.split(delimiter)

            for p in s:
                if p.startswith('<escape>'):
                    p = p.replace('<escape>', '')

                if '<escape>' in p:
                    p = p.replace('<escape>', delimiter)

                out.append(p)

            return out

        def replace(s: str, old, new, escape_char='\\\\'):
            s = re.sub(r'\\\\(?!\\)', '<escape>', s)
            while old in s:
                s = s.replace('%s' % old, '%s' % new)

            if '<escape>' in s:
                s = s.replace('<escape>', '')
            return s

        lindex = 1

        for _path in path:
            # print('-- %s of %s in %s -> Path: %s' % (lindex, len(path), hive.hive_file_path, _path))
            lindex+=1

            ##- Wildcard is found:
            if any([s for s in [r'(?<!\\\\)regex\(', r'(?<!\\)\\\*', r'^\*\\'] if re.search(s, _path, re.IGNORECASE)]):
                # Replace wildcard with regex equivalent, and fill the root key (if needed)
                if _path.startswith('*\\'):
                    _path = '%s%s' % ('regex(.*)', _path[1:])
                    if '\\' in _path:
                        _path = '%s\\%s' % (hive.hive_root, _path)
                    else:
                        _path = hive.hive_root
                if _path.endswith('*'):
                    _path = '%s%s' % (_path[:-1], 'regex(.*)')
                if '\\*\\' in _path:
                    _path = replace(_path, old='\\*\\', new='\\regex(.*)\\', escape_char='\\\\')

                _path_elements = split(s=_path, delimiter='\\', escape_char='\\\\')

                # Build key paths
                current_path = []

                for _path_item in _path_elements:

                    regex_pattern = re.search(pattern=r"regex\((.*)\)", string=_path_item, flags=re.IGNORECASE)
                    if regex_pattern is None:
                        if '*' == _path_item: # Probably not necessary
                            print('-------------   Actually necessary !!!')
                            _path_item = '\\\\*'

                        current_path.append(_path_item)
                    else:
                        if regex_pattern.group(1):

                            if action == registry_action.QUERY_VALUE:
                                if len(current_path) == len(_path_elements) - 1:
                                    _dyn_path = '\\'.join(current_path + ['\\\\%s' % _path_elements[-1]])
                                    self.query(action=action, path=_dyn_path, hive=hive, reg_handler=reg_handler, items=items, depth=depth, settings=settings, plugin_name=plugin_name)
                                    continue
                                    # return self.query(action=action, path=_dyn_path, hive=hive, reg_handler=reg_handler, items=items, depth=depth, settings=settings)

                            key_pattern = regex_pattern.group(1)
                            macro_pattern = regex_pattern.group(0)
                            # Proceed to get matching keys
                            # ERROR need to handle the escape char ...
                            matching_subkeys =  self.reg.enum_key_subkeys(key_path=hive.hive_root if len(current_path) == 0 else '\\'.join(current_path), hive=hive, reg_handler=reg_handler, key_name_pattern=key_pattern)
                            sub_key_count = len(matching_subkeys.get('\\'.join(current_path), []))
                            if sub_key_count == 0:
                                sub_key_count = len(matching_subkeys.get(hive.hive_root, []))
                                sub_key_names = matching_subkeys.get(hive.hive_root, [])
                            else:
                                sub_key_names = matching_subkeys.get('\\'.join(current_path), [])

                            sub_key_index = 0

                            if sub_key_count > 0:
                                for sub_key in sub_key_names:
                                    sub_key_index += 1
                                    # Escape the key having same name as a wildcard or macro pattern (Edge use-case, anti-infinite loop trick)
                                    if sub_key == '*':
                                        sub_key = '\\\\*'
                                    if sub_key.lower() == macro_pattern.lower():
                                        sub_key = '\\\\%s' % sub_key

                                    _dyn_path = '\\'.join(current_path + [sub_key] + _path_elements[len(current_path)+1:])
                                    if sub_key_index >= sub_key_count:
                                        self.query(action=action, path=_dyn_path, hive=hive, reg_handler=reg_handler, items=items, depth=depth, settings=settings, plugin_name=plugin_name)
                                        continue
                                        #return self.query(action=action, path=_dyn_path, hive=hive, reg_handler=reg_handler, items=items, depth=depth, settings=settings)
                                    else:
                                        self.query(action=action, path=_dyn_path, hive=hive, reg_handler=reg_handler, items=items, depth=depth, settings=settings, plugin_name=plugin_name)
                            else:
                                logger.debug('Path Not Found or Empty Key - %s' % '\\'.join(current_path + ['%s' % key_pattern]))
                                break
                        else:
                            if '*' == _path_item:
                                _path_item = '\\\\*'

                            current_path.append(_path_item)
                ##- No wildcard:
            else:
                _path = _path.replace('\\\\*', '*')
                _path = _path.replace('%s\\' % hive.hive_root, '')
                logger.debug('registry_parser.get: %s -> Depth: %s' % (path, depth))
                #- Wildcard NOT found
                # Query Key
                if action == registry_action.QUERY_KEY:
                    # Use case - Query Key / _path recursively
                    if registry_action_settings.RECURSIVE in settings:
                        item = self.query_key_recursive(key_path=_path, hive=hive, reg_handler=reg_handler)
                    else:
                        # Use case - Query Key
                        try:
                            item = self.query_key(key_path=_path, hive=hive, reg_handler=reg_handler, plugin_name=plugin_name)
                        except Exception as msg:
                            logger.error('Error: Unable to QueryKey: "%s" - Exception: %s' % (_path, str(msg)))
                            item = None

                    if item:
                        items.extend(item)

                # Query Value - Ignores the option registry_action_settings.RECURSIVE (since it applies to query key)
                if action == registry_action.QUERY_VALUE:

                    if any([s for s in [r'regex\('] if re.search(s, _path, re.IGNORECASE)]):
                        regex_pattern = re.search(pattern=r"regex\((.*)\)", string=_path, flags=re.IGNORECASE)
                        value_pattern = regex_pattern.group(1)
                        _dyn_path = '\\'.join(_path.split('\\')[0:-1])
                        _dyn_path = _dyn_path[0:-2] if _dyn_path.endswith('\\\\') else _dyn_path
                        _dyn_path = _dyn_path[0:-1] if _dyn_path.endswith('\\') else _dyn_path

                        for reg_item in self.query_key(key_path=_dyn_path, hive=hive, reg_handler=reg_handler, plugin_name=plugin_name):
                            if reg_item.has_values:
                                for _reg_value in reg_item.values:
                                    if re.search(pattern=value_pattern, string=_reg_value.value_name, flags=re.IGNORECASE):
                                        items.extend(self.query_value(value_path=_reg_value.value_path, hive=hive, reg_handler=reg_handler, plugin_name=plugin_name))
                    else:
                        item = self.query_value(value_path=_path, hive=hive, reg_handler=reg_handler, plugin_name=plugin_name)

                        if item:
                            items.extend(item)

        return items



    """ ------------------------------------------------------------------------------------------------------------- 
                                    QUERY Functions
        ------------------------------------------------------------------------------------------------------------- 
    """

    def query_key_wd(self, key_path: str, hive, reg_handler=None, plugin_name='parser') -> list:
        """ Use it to query a static key_path or a dynamic key_path containing a wildcard """

        output_keys = []
        item = []

        #  Check if both hive and key_path were given
        if key_path and hive:
            if not isinstance(key_path, list):
                key_path = [key_path]

        for _key_path in key_path:
            logger.debug('QUERY: %s' % _key_path)

            if _key_path:

                regex_wildcards = re.findall(pattern=r"(regex\([^\(]+\))", string=_key_path, flags=re.IGNORECASE)
                wildcard_count = _key_path.count(r'\*') + _key_path.count(r'\*\\') + (1 if _key_path.startswith('*\\') else 0)

                # Case: The key_path does not contain any wildcard
                if wildcard_count == 0 and len(regex_wildcards) == 0:
                    item = self.query_key(key_path=_key_path, hive=hive, reg_handler=reg_handler, plugin_name=plugin_name)
                    if item:
                        output_keys.extend(item)
                        continue
                else:
                    #  Case: The key_path ends on \*\ - Query only the key named "*"
                    if wildcard_count == 1 and _key_path[-3:] == '\\*\\':
                        item = self.query_key(key_path=_key_path[:-1], hive=hive, reg_handler=reg_handler, plugin_name=plugin_name)
                        if item:
                            output_keys.extend(item)

                    #  Case: The key_path ends on \* - Query all sub-keys of key_path before \*
                    elif wildcard_count == 1 and _key_path[-2:] == '\\*':
                        items = []
                        key_obj = self.reg.get_key_obj(hive=hive, key_path=_key_path[:-2])
                        if key_obj:
                            items = self.reg.query_key_recursive(key_obj=key_obj, hive=hive, reg_handler=reg_handler, plugin_name=plugin_name)
                        if items:
                            output_keys.extend(items)
                            continue

                    #  Case: The he key_path starts with *\, so need to enumerate hive's root
                    elif wildcard_count == 1 and _key_path[0:2] == '*\\':
                        # REMARK: Fix it ... enum_root_subkeys supports the regex patter, no need to do it twice
                        _subkeys = self.reg.enum_root_subkeys(key_path=_key_path, hive=hive, reg_handler=reg_handler)
                        _keys = self.expand_wildcard(_key_path=_key_path, _subkeys=_subkeys, hive=hive, reg_handler=reg_handler)

                        if _keys:
                            item = self.query_key(key_path=_keys, hive=hive, reg_handler=reg_handler, plugin_name=plugin_name)

                        if item:
                            output_keys.extend(item)
                    else:

                        #  Case: The regex wildcard "regex(...)" is used at least once
                        if regex_wildcards:

                            #  Case: The key_path starts from regex wildcard
                            if _key_path.startswith('regex('):

                                #  We know that the key_path starts from a regex wildcard, hence we can directly use
                                #  regex_wildcards[0], to get the regex pattern out of the first wildcard
                                key_name_pattern = re.findall(pattern=r"regex\((.+)\)", string=regex_wildcards[0], flags=re.IGNORECASE)

                                if key_name_pattern:
                                    key_name_pattern = key_name_pattern[0]
                                else:
                                    logger.error('Syntax Error. Unable to determine the key_name_pattern! - Regex '
                                                 'marker: %s, Key: %s' % (regex_wildcards[0], _key_path))
                                    continue

                                #  Get all subkeys from the hive's root, matching the pattern
                                # _subkeys = self.reg.enum_root_subkeys(key_path=hive.hive_root, hive=hive, reg_handler=reg_handler, key_name_pattern=key_name_pattern)
                                _subkeys = self.reg.enum_root_subkeys(key_path=hive.hive_root, hive=hive, reg_handler=reg_handler,
                                                                      key_name_pattern=key_name_pattern)

                                # Probably not needed:
                                #  Expand regex wildcard. Get the list of matching keys. Since the wildcard starts from
                                #  Because the _key_path starts with the wildcard, we assume we are querying the root
                                #  REMARK: Entire function requires a re-design
                                # _keys = self.expand_regex(_key_path=hive.hive_root, _subkeys=_subkeys, hive=hive, reg_handler=reg_handler, regex_wildcards=regex_wildcards)

                                if len(_subkeys.get(hive.hive_root, [])) > 0:
                                    #  Query all expanded keys
                                    item = self.query_key(key_path=_subkeys[hive.hive_root], hive=hive, reg_handler=reg_handler,
                                                          plugin_name=plugin_name)

                                if len(item) > 0:
                                    output_keys.extend(item)

                            else:
                                # Case: The key_path does not start from the pattern, however the pattern is present
                                _keys = []
                                #  Expand regex wildcard. Get the list of matching keys
                                _keys = self.expand_regex(_key_path=_key_path, hive=hive, reg_handler=reg_handler,
                                                          regex_wildcards=regex_wildcards)

                                #  Query all expanded keys
                                if _keys:
                                    item = self.query_key(key_path=_keys, hive=hive, reg_handler=reg_handler,
                                                          plugin_name=plugin_name)

                                if item:
                                    output_keys.extend(item)

                        #  Case: No regex wildcard, more than 1 occurrence of * wildcard
                        else:

                            _keys = []
                            # Case: The key path ends with *\ (To be investigated)
                            if _key_path[0:2] == '*\\':
                                _subkeys = self.reg.enum_root_subkeys(key_path=_key_path, hive=hive,
                                                                       reg_handler=reg_handler)
                                _keys = self.expand_wildcard(_key_path=_key_path, _subkeys=_subkeys, hive=hive,
                                                             reg_handler=reg_handler)

                                for _key_path in _keys:

                                    if '*' in _key_path:
                                        item = self.query_key_wd(key_path=_key_path, hive=hive, reg_handler=reg_handler,
                                                                 plugin_name=plugin_name)
                                    else:
                                        item = self.query_key(key_path=_keys, hive=hive, reg_handler=reg_handler,
                                                      plugin_name=plugin_name)

                                    if item:
                                        output_keys.extend(item)

                            else:
                                _keys = self.expand_wildcard(_key_path=_key_path, hive=hive, reg_handler=reg_handler)

                                if _keys:
                                    item = self.query_key(key_path=_keys, hive=hive, reg_handler=reg_handler, plugin_name=plugin_name)
                                if item:
                                    output_keys.extend(item)

        return output_keys

    def query_key(self, key_path, hive, reg_handler=None, plugin_name='parser') -> list:
        """ Use it to query a static key_path """
        return self.reg.query_key(key_path=key_path, hive=hive, reg_handler=reg_handler, plugin_name=plugin_name)

    def query_key_recursive(self, hive, key_path, reg_handler=None) -> list:
        """ Use it to recursively query a key object """
        key_obj = self.reg.get_key_obj(hive=hive, key_path=key_path)
        return self.reg.query_key_recursive(hive=hive, key_obj=key_obj, reg_handler=reg_handler)

    def query_value_wd(self, value_path, hive, reg_handler=None, plugin_name='parser') -> list:

        output_items = []

        #  Check if both hive and key_path were given
        if value_path and hive:
            if not isinstance(value_path, list):
                value_path = [value_path]

            for _value_path in value_path:

                #  Get the key_path portion and value name
                if "\\" in _value_path:
                    _key_path, __, _value_name = _value_path.rpartition('\\')
                else:
                    _key_path = None
                    _value_name = _value_path

                # Determine how many times the * wildcard is used:
                wildcard_count =_value_path.count(r'\*\\') + (
                    1 if _value_path.startswith('*\\') else 0) + (
                    1 if _value_path.endswith('\\*') else 0) + (
                    1 if _value_name == '*' and not _value_path.endswith('\\*') else 0)

                # Get all regex markers with their corresponding wildcards
                regex_wildcards = re.findall(pattern=r"(regex\([^\(]+\))", string=_key_path, flags=re.IGNORECASE)
                value_name_wildcard = re.findall(pattern=r"(regex\([^\(]+\))", string=_value_name, flags=re.IGNORECASE)

                #  Case: Directly query a value (No wildcard used)
                if wildcard_count == 0 and regex_wildcards == [] and value_name_wildcard == []:
                    item = self.query_value(value_path=_value_path, hive=hive, reg_handler=reg_handler,
                                            plugin_name=plugin_name)
                    if item:
                        output_items.extend(item)
                        continue

                #  Case: The _value_path ends on \*\ - Query only the value named "*"
                elif wildcard_count == 1 and _value_path[-3:] == '\\*\\':
                    item = self.query_value(value_path=_value_path[:-1], hive=hive, reg_handler=reg_handler,
                                            plugin_name=plugin_name)
                    if item:
                        output_items.extend(item)
                        continue

                # Case: value_path ends with \* (Means pull all values) ... Similar to query_key
                elif wildcard_count == 1 and _value_name == "*":
                    item = self.query_key(key_path=_key_path, hive=hive, reg_handler=reg_handler,
                                          plugin_name=plugin_name)

                    if item:
                        output_items.extend(item)
                        continue

                #  Case: The he key_path starts with *\, so need to enumerate hive's root
                elif wildcard_count == 1 and _value_path[0:2] == '*\\':
                    _subkeys = self.reg.enum_root_subkeys(key_path=_value_path, hive=hive,
                                                           reg_handler=reg_handler)
                    _keys = self.expand_wildcard(_key_path=_key_path, _subkeys=_subkeys, hive=hive,
                                                 reg_handler=reg_handler)

                    #  Append the value_name to the list of expanded keys
                    for _key in _keys:
                        _keys[_keys.index(_key)] = _key + '\\' + _value_name

                    item = self.query_value(value_path=_keys, hive=hive, reg_handler=reg_handler,
                                          plugin_name=plugin_name)
                    if item:
                        output_items.extend(item)
                        continue

                # Case: The regex wildcard "regex(...)" is used at least once
                else:

                    #  Regex wildcard
                    if regex_wildcards or value_name_wildcard:

                        #  Case: _value_path ends with regex wildcard (There is only 1 wildcard)
                        if len(regex_wildcards) == 0 and len(value_name_wildcard) == 1:

                            value_name_pattern = re.findall(pattern=r"regex\((.+)\)",
                                                          string=value_name_wildcard[0], flags=re.IGNORECASE)


                            item = self.reg.query_value_regex(key_path=_key_path, value_name_pattern=value_name_pattern[0],
                                                          hive=hive, reg_handler=reg_handler, plugin_name=plugin_name)

                            if item:
                                output_items.extend(item)

                        #  Case: The _key_path starts from regex wildcard
                        elif _key_path.startswith('regex('):

                            #  We know that the _key_path starts from a regex wildcard, hence we can directly use
                            #  regex_wildcards[0], to get the regex pattern out of the first wildcard
                            key_name_pattern = re.findall(pattern=r"regex\((.+)\)",
                                                          string=regex_wildcards[0], flags=re.IGNORECASE)

                            if key_name_pattern:
                                key_name_pattern = key_name_pattern[0]
                            else:
                                logger.error(
                                    'Syntax Error. Unable to determine the key_name_pattern! - Regex '
                                    'marker: %s, Key: %s' % (regex_wildcards[0], _value_path))
                                continue

                            #  Get the subkeys from the hive's root
                            _subkeys = self.reg.enum_root_subkeys(key_path=_value_path, hive=hive,
                                                                   reg_handler=reg_handler,
                                                                   key_name_pattern=key_name_pattern)

                            #  Expand regex wildcard. Get the list of matching keys. Since the wildcard starts from
                            #  the begining of the key_path, we need to feed it with all matched subkeys
                            _keys = self.expand_regex(_key_path=_key_path, _subkeys=_subkeys, hive=hive,
                                                      reg_handler=reg_handler,
                                                      regex_wildcards=regex_wildcards)

                            #  Append the value_name to the list of expanded keys
                            for _key in _keys:
                                _keys[_keys.index(_key)] = _key + '\\' + _value_name

                            #  Query all expanded values (We need to use _wd version since the _value_name might still
                            #  contain a wildcard)
                            item = self.query_value_wd(value_path=_keys, hive=hive, reg_handler=reg_handler, plugin_name=plugin_name)

                            if item:
                                output_items.extend(item)

                        else:
                            #  Case: There regex wildcard is not at the beginning of the key_path
                            _keys = []

                            #  Expand regex wildcard. Get the list of matching keys
                            _keys = self.expand_regex(_key_path=_key_path, hive=hive,
                                                      reg_handler=reg_handler,
                                                      regex_wildcards=regex_wildcards)

                            #  Append the value_name to the list of expanded keys
                            for _key in _keys:
                                _keys[_keys.index(_key)] = _key + '\\' + _value_name

                            #  Query all expanded keys with _wd, because value_name could be a regex wilcard
                            item = self.query_value_wd(value_path=_keys, hive=hive, reg_handler=reg_handler,
                                                  plugin_name=plugin_name)

                            if item:
                                output_items.extend(item)

                    #  * wildcard
                    else:
                        #  Case: No regex wildcard, more than 1 occurrence of * wildcard
                        _keys = []

                        if _value_path[0:2] == '*\\':
                            _subkeys = self.enum_root_subkeys(key_path=_value_path, hive=hive,
                                                                   reg_handler=reg_handler)
                            _keys = self.expand_wildcard(_value_path=_value_path, _subkeys=_subkeys, hive=hive,
                                                         reg_handler=reg_handler)

                            for _value_path in _keys:

                                if '*' in _value_path:
                                    item = self.query_key_wd(key_path=_value_path, hive=hive,
                                                             reg_handler=reg_handler,
                                                             plugin_name=plugin_name)
                                else:
                                    item = self.query_key(key_path=_keys, hive=hive,
                                                          reg_handler=reg_handler,
                                                          plugin_name=plugin_name)

                                if item:
                                    output_items.extend(item)
                                    continue

                        else:
                            _value_key_paths = self.expand_wildcard(_key_path=_value_path, hive=hive,
                                                         reg_handler=reg_handler)
                            item = []
                            if _value_key_paths:
                                item = self.query_value(value_path=_value_key_paths, hive=hive, reg_handler=reg_handler, plugin_name=plugin_name)
                                _value_key_paths = []

                            if item:
                                output_items.extend(item)
                                continue

        return output_items

    def query_value(self, value_path, hive, reg_handler=None, plugin_name='parser') -> list:
        """ Use it to query a static value_path """
        return self.reg.query_value(value_path=value_path, hive=hive, reg_handler=reg_handler, plugin_name=plugin_name)

    """ ------------------------------------------------------------------------------------------------------------- 
                                    Regex and Wildcard Functions
        ------------------------------------------------------------------------------------------------------------- 
    """

    def expand_regex(self, _key_path, hive, regex_wildcards, reg_handler=None, _subkeys=None, output_keys=None):
        """ Returns the list of expanded key_path strings """

        if output_keys is None: output_keys = []
        if _subkeys is None: _subkeys = []

        #  Since the regex wildcard might be different each time, we need to split accordingly
        for regex_wildcard in regex_wildcards:

            _key_parts = _key_path.split(regex_wildcard, 1)  # Split at the first occurrence

            #  Get the searched key regex pattern
            key_name_pattern = re.findall(pattern=r"regex\((.+)\)", string=regex_wildcard, flags=re.IGNORECASE)

            if key_name_pattern:
                key_name_pattern = key_name_pattern[0]
            else:
                logger.error('Syntax error. Unable to determine the key_name_pattern!')
                return None

            if '.tmp' in _key_path and '2003724_USRCLASS.DAT' in hive.hive_file_path:
                pass


            #  Get the first element of the key_path (The one before the wildcard)
            for _key_part in _key_parts[0:1]:

                #  Enumerate all sub-keys of they key_path (before the wildcard)
                if _subkeys is not None:
                    if isinstance(_subkeys, dict):
                        if _key_path in _subkeys.keys():
                            # enum_root_subkeys(self, key_path, hive, reg_handler=None, key_name_pattern=None)
                            _key_part_subkeys = self.reg.enum_root_subkeys(key_path='root', hive=hive)
                        elif len(_subkeys.keys()) == 0:
                            if _key_part == '':
                                _key_part_subkeys = self.reg.enum_root_subkeys(key_path='root', hive=hive)
                            else:
                                pass
                        else:
                            _key_part_subkeys = _subkeys
                    else:
                        _remaining_key_part = "".join(_key_parts[1:])
                        _key_part_subkeys = {_key_part: _subkeys}

                #else:
                #    _key_part_subkeys = self.reg.enum_key_subkeys(key_path=_key_part, hive=hive, reg_handler=reg_handler, key_name_pattern=key_name_pattern)
                #    _remaining_key_part = "".join(_key_parts[_key_parts.index(_key_part) + 1:])

                # Quick fix - not sure why it happens
                if _key_part_subkeys is None:
                    print('Error -> expand_regex -> ', _key_part, 'in', _key_path)
                    _key_part_subkeys = {_key_part: []}

                #  Proceed only when there are sub-keys:
                if len(_key_part_subkeys.get(_key_part, [])) > 0:

                    #  Create new_key_path out of: key_path (before the wildcard) + (subkey) + key_path(after wildcard)
                    for _key_part_subkey in _key_part_subkeys[_key_part]:

                        if not _key_part == hive.hive_root:
                            _new_key = _key_part + _key_part_subkey + _remaining_key_part
                        else:
                            _new_key = _key_part_subkey + _remaining_key_part

                        #  If key_path(after wildcard) contains another wildcard, do recursive call to resolve it
                        if 'regex(' in _new_key:
                            self.expand_regex(_key_path=_new_key, hive=hive, reg_handler=reg_handler,
                                              regex_wildcards=regex_wildcards[regex_wildcards.index(regex_wildcard) + 1:],
                                              output_keys=output_keys)

                            #regex_wildcards.remove(regex_wildcard)
                            return output_keys
                        else:
                            logger.debug('Expanded KEY: %s' % _new_key)
                            output_keys.append(_new_key)

                else:
                    #  Cut the expansion. There are no subkeys or they do not match the subkey pattern
                    logger.debug('Exit the expansion. There are no such subkey(s), or there is no match for the pattern: "%s\\%s"' % (_key_part, key_name_pattern))
                    #_remaining_key_part = "".join(_key_parts[_key_parts.index(_key_part) + 1:])
                    #_new_key = _key_part + _remaining_key_part
                    #output_keys.append(_new_key.replace('\\\\', '\\'))

        return output_keys

    def expand_wildcard(self, _key_path, hive, reg_handler=None, key_name_pattern=None, split_by='*', _subkeys=None, output_keys=None):
        """ Returns the list of expanded key_path strings """

        if output_keys is None: output_keys = []
        if _subkeys is None: _subkeys = []

        #  Case: When wildcard is used 1 or more times, but not at the end of the key_path
        _key_parts = _key_path.split(split_by, 1)  # Split at the first occurrence

        #  Get the first element of the key_path (The one before the wildcard)
        for _key_part in _key_parts[0:1]:

            #  Enumerate all sub-keys of they key_path (before the wildcard)
            if _subkeys:
                _key_part_subkeys = _subkeys
                _key_part = 'root'
                _remaining_key_part = "".join(_key_parts[1:])
            else:
                _key_part_subkeys = self.reg.enum_key_subkeys(key_path=_key_part, hive=hive, reg_handler=reg_handler)
                _remaining_key_part = "".join(_key_parts[_key_parts.index(_key_part) + 1:])

            #  Proceed only when there are sub-keys
            if _key_part_subkeys:

                #  Create new_key_path out of: key_path (before the wildcard) + (subkey) + key_path(after wildcard)
                for _key_part_subkey in _key_part_subkeys[_key_part]:

                    if not _key_part == 'root':
                        _new_key = _key_part + _key_part_subkey + _remaining_key_part
                    else:
                        _new_key = _key_part_subkey + _remaining_key_part

                    #  If key_path(after wildcard) contains another wildcard, do recursive call to resolve it
                    if _key_path.lower() == _new_key.lower():
                        output_keys.append(_new_key)
                    elif r'\*\\' in _new_key:
                        self.expand_wildcard(_key_path=_new_key, hive=hive, reg_handler=reg_handler, output_keys=output_keys)
                    else:
                        output_keys.append(_new_key)

            else:
                _remaining_key_part = "".join(_key_parts[_key_parts.index(_key_part) + 1:])
                _new_key = _key_part + _remaining_key_part
                output_keys.append(_new_key.replace('\\\\', '\\'))

        return output_keys

    """ ------------------------------------------------------------------------------------------------------------- 
                                    ENUM Functions
        ------------------------------------------------------------------------------------------------------------- 
    """

    def hive_info(self, hive, reg_handler=None):

        result = []
        CRED = '\033[91m'
        CYELLOW = '\33[33m'
        CEND = '\033[0m'

        if hive:
            result.append('---------------------------------------------------------')
            result.append(CRED + 'Mapping: ' + CEND + hive.hive_mapping)
            result.append(CRED + 'Root Key: ' + CEND + hive.hive_root)
            result.append(CRED + 'Hive: ' + CEND + hive.hive_file_path)
            result.append(CRED + 'Hive type: ' + CEND + hive.hive_type)
            result.append(CRED + 'Subkeys: ' + CEND)

            _result = self.reg.enum_root_subkeys(key_path='root', hive=hive, reg_handler=reg_handler)

            if _result.get('root', []):
                result.append(' [*] ' + hive.hive_root + ':')
                for _res in _result:
                    for _subk_key in _result[_res]:
                        result.append('     [+] ' + _subk_key)
            elif _result.get('root', []) == []:
                result.append(' [*] ' + hive.hive_root + ' -> ' + CYELLOW + 'NO SUBKEYS FOUND' + CEND)
            else:
                result.append(' [*] ' + hive.hive_root + ' -> ' + CYELLOW + 'ROOT KEY NOT FOUND' + CEND)

            result.append('---------------------------------------------------------')
        else:
            logger.error('Hive is not initialized')

        if result:
            return result
        else:
            return []

    def key_info(self, hive, key_path, reg_handler=None):

        result = []
        CRED = '\033[91m'
        CYELLOW = '\33[33m'
        CEND = '\033[0m'


        if key_path:

            result.append('---------------------------------------------------------')
            result.append(CRED + 'Mapping: ' + CEND + hive.hive_mapping)
            result.append(CRED + 'Root Key: ' + CEND + key_path)
            result.append(CRED + 'Hive: ' + CEND + hive.hive_file_path)
            result.append(CRED + 'Hive type: ' + CEND + hive.hive_type)
            result.append(CRED + 'Subkeys: ' + CEND)

            _result = self.reg.enum_key_subkeys(key_path=key_path, hive=hive, reg_handler=reg_handler)

            if _result.get(key_path, []):
                result.append(' [*] ' + key_path + ':')
                for _res in _result:
                    for _subk_key in _result[_res]:
                        result.append('     [+] ' + _subk_key)
            elif _result.get(key_path, []) == []:
                result.append(' [*] ' + key_path + ' -> ' + CYELLOW + 'NO SUBKEYS FOUND' + CEND)
            else:
                result.append(' [*] ' + key_path + ' -> ' + CYELLOW + 'KEY NOT FOUND' + CEND)

            result.append('---------------------------------------------------------')

        else:
            logger.error('key_path cannot be empty')

        if result:
            return result
        else:
            return []

    """ ------------------------------------------------------------------------------------------------------------- 
                                    EXPORT Functions
        ------------------------------------------------------------------------------------------------------------- 
    """

    def export(self, items, output_path, format='csv', format_fields=None):
        """ Use it to export registry_item(s) """
        logger.info('Export items')

        print(CYELLOW + '[+] Exporting registry items' + CEND)

        items = self.dedup_items(items)

        if items:
            self.save_output(items, output_path=output_path, format=format, format_fields=format_fields)
        else:
            print(CRED + '[+] Nothing to export' + CEND)

    def save_output(self, items, output_path, format, format_fields=None):

        current_fields = self.get_current_format_fields(format_fields)
        logger.info('Export to: %s' % output_path)
        if items:
            if format == 'winreg':
                self.export_to_winreg(items=items, output_path=output_path)
            elif format == 'csv':
                self.export_to_csv(items=items, output_path=output_path, _format_fields=current_fields)
            elif format == 'tab':
                self.export_to_tab(items=items, output_path=output_path, _format_fields=current_fields)
            elif format == 'sqlite':
                self.export_to_sqlite(items=items, output_path=output_path, _format_fields=current_fields)
            elif format == 'json':
                self.export_to_json(items=items, output_path=output_path, _format_fields=current_fields)

    def convert_to_tab_output(self, items, _format_fields=None):

        _tab_items = []

        if items:
            logger.debug('Converting registry items to "TAB" format')

            _items = []
            _items_max_len = {}

            current_fields = self.get_current_format_fields(_format_fields)

            #  Move only required items to _items as per current_fields
            for _item in items:
                for _dict_item in _item.items():
                    row = {}
                    for _field_name in current_fields:
                        row[_field_name] = _dict_item.get(_field_name, '')

                    _items.append(row)

            #  Determine max len for every field
            for _field_name in current_fields:
                _len = max([len(str(x.get(_field_name, ''))) for x in _items])

                if _len > _items_max_len.get(_field_name, 0):
                    _items_max_len[_field_name] = _len

            for _item in _items:
                row = ''
                for _field_name in current_fields:
                    _field_name_len = _items_max_len.get(_field_name, 0)
                    row += str(str(_item.get(_field_name, '')).ljust(_field_name_len)) + '  '

                _tab_items.append(row)

        return _tab_items

    def convert_to_json(self, items, _format_fields=None):

        rows = []
        for item in items:
            _result = {}
            _item_list = item.items()

            for _item in _item_list:
                for field in _format_fields:
                    _result[field] = str(_item.get(field, ''))

                rows.append(str(_result))

        return rows

    def convert_to_pseudo_csv(self, items, _format_fields=None):

        logger.debug('Converting registry items to pseudo "CSV" format')
        if items:
            current_fields = self.get_current_format_fields(_format_fields)

        _csv_items = []

        for reg_item in items:
            _items = reg_item.items()
            for _item in _items:
                row = []
                for _field_name in current_fields:
                    row.append(str(_item.get(_field_name, '')))

                _csv_items.append(','.join(row))

        return _csv_items

    def convert_to_winreg(self, items, insert_registry_header=False):

        logger.debug('Converting registry items to "WINREG" format')

        reg_exporter = registry_provider.registry_export()
        items = self.dedup_items(items)
        items = self.items_to_list_of_dict(items)

        return reg_exporter.convert2winreg(items=items, insert_registry_header=insert_registry_header)

    def export_to_json(self, items, output_path, _format_fields=None):

        rows = self.convert_to_json(items=items, _format_fields=_format_fields)

        with open(output_path, 'w') as out_file:
            for row in rows:
                out_file.write(row + '\n')

    def export_to_winreg(self, items, insert_registry_header=True, save_output=True, output_path=None):

        logger.debug('Saving registry items in "WINREG" format')
        logger.info('IF the count of items [%d] is huge, the export can take a long time ... just saying.' % len(items))
        reg_exporter = registry_provider.registry_export()
        items = self.dedup_items(items)
        items = self.items_to_list_of_dict(items)

        return reg_exporter.convert2winreg(items=items, insert_registry_header=insert_registry_header, save_output=save_output,
                                           output_path=output_path)

    def export_to_csv(self, items, output_path, _format_fields=None, delimiter=';'):

        logger.debug('Saving registry items in "CSV" format')
        write_mode = 'a'
        if items:
            current_fields = self.get_current_format_fields(_format_fields)

            #  Detect if the csv header is present
            if isfile(output_path):

                with open(output_path, encoding='utf-16le', mode='r') as file:
                    try:
                        _header = str(file.readline()).replace('\n', '')
                    except UnicodeDecodeError:
                        logger.error('The output file might be corrupted')
                        logger.error(' [+] Forcing the overwrite mode...')
                        write_mode = 'w'
                        _header = ''

                    _expected_header = f'{delimiter}'.join(current_fields)
                    if _header == _expected_header:
                        write_csv_header = False
                    else:
                        write_csv_header = True
            else:
                write_csv_header = True

            for reg_item in items:
                for _item in reg_item.items():
                    row = []
                    for _field_name in current_fields:
                        row.append(str(_item.get(_field_name, '')).replace("\\\\", "\\"))
                    try:
                        # encoding="utf-16le"
                        with open(output_path, encoding="utf-16le", mode=write_mode, newline='') as file:
                            csvwriter = csv.writer(file, delimiter=delimiter, escapechar='\\', quotechar='"', doublequote=True)

                            if write_csv_header:
                                csvwriter.writerow(current_fields)
                                write_csv_header = False

                            csvwriter.writerow(row)
                            file.close()
                    except FileNotFoundError:
                        logger.error(f"ERROR: No such file or directory: {self.output_file}")
                        continue
                    except UnicodeEncodeError:
                        logger.error(f"Unexpected UnicodeEncodeError - Please send the hive file to wit0k")
                        continue

    def export_to_sqlite(self, items, output_path, _format_fields=None):

        logger.debug('Saving registry items in "SQLite" format')

        if items:
            current_fields = self.get_current_format_fields(_format_fields)

            items = self.items_to_list_of_dict(items)

            reg_db = registry_provider.registry_database(file_path=output_path, _items=items, _columns=current_fields,
                                                         baseline_fields=self.baseline_fields)
            reg_db.insert('items', _items=items, _columns=current_fields)

            #print(*reg_db.query_all('items'), sep='\n')
            #print(*reg_db.query_by_field('items', ['key_path','value_name']))
            #print(*reg_db.query_by_value('items', [{'key_path': r'Microsoft\Windows\CurrentVersion\Run', 'value_name': 'Greenshot'}]))

    def export_to_tab(self, items, output_path, _format_fields=None):

        logger.debug('Saving registry items in "TAB" format')

        if items:
            current_fields = self.get_current_format_fields(_format_fields)

            # encoding="utf-16le"
            with open(output_path, encoding="utf8", mode="a") as file:
                _lines = self.convert_to_tab_output(items=items, _format_fields=current_fields)
                _lines = [_line + '\n' for _line in _lines]
                file.writelines(_lines)

    """ ------------------------------------------------------------------------------------------------------------- 
                                    ACTIONS Functions
        ------------------------------------------------------------------------------------------------------------- 
    """

    actions = {
        'python-registry': {
            'query_key_wd': query_key_wd,
            'query_key': query_key,
            'query_key_recursive': query_key_recursive,
            'query_value': query_value,
            'query_value_wd': query_value_wd,
            'hive_info': hive_info,
            'key_info': key_info,
            'export': export,
            'print': print
        },
        'yarp': {
            'query_key_wd': query_key_wd,
            'query_key': query_key,
            'query_key_recursive': query_key_recursive,
            'query_value': query_value,
            'query_value_wd': query_value_wd,
            'hive_info': hive_info,
            'key_info': key_info,
            'export': export,
            'print': print
        }
    }

    def exec_action(self, action_name, parameters=tuple()):

        _provider_name = self.reg.name
        _actions = self.actions.get(_provider_name, None)

        if _actions:
            if action_name in _actions.keys():

                if parameters:
                    try:
                        return _actions[action_name](*parameters)
                    except Exception as msg:
                        logger.error(
                            '%s -> Unable to execute action: "%s". Error: %s' % (_provider_name, action_name, str(msg)))
                else:
                    try:
                        return _actions[action_name]
                    except Exception as msg:
                        logger.error(
                            '%s -> Unable to execute action: "%s". Error: %s' % (_provider_name, action_name, str(msg)))
            else:
                logger.error(
                    '%s -> Unsupported action: "%s"' % (_provider_name, action_name))
                exit(ERR_REGPARSER_ACTIONS_UNSUPPORTED_ACTION)

        else:
            logger.error('Unable to load actions array for: "%s" provider' % self.actions.get(self.reg.name, None))
            # exit(ERR_REGPARSER_ACTIONS_LOAD_FAILED)










