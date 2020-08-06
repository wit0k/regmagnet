from hashlib import blake2b
import logging
import base64
import glob
import re

import string
import sys
import math

from md.errors import *

from os.path import isdir, isfile
from os import getcwd
from dateutil import parser as date_parser # pip install python-dateutil

from re import match, IGNORECASE
from importlib import import_module
from Registry import Registry

from md.reg_handlers import handlers
from md.config import __default_registry_provider__

#from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import MetaData, Table, Column, String, Integer, create_engine, literal_column, distinct
from sqlalchemy.orm import mapper, create_session, load_only
from sqlalchemy.exc import OperationalError, IntegrityError, ArgumentError

logger = logging.getLogger('regmagnet')

class registry_provider(object):

    name = None
    provider = None

    class registry_key(object):

        """ CAUTION: IF YOU ADD NEW FIELD, ADD IT TO BOTH INIT DEF AND ATTRIBUTES CLASS """
        class attributes(object):

            key_path = 'key_path'
            key_path_unicode = "key_path_unicode"
            key_timestamp = "key_timestamp"
            key_subkey_count = "key_subkey_count"
            key_value_count = "key_value_count"

            key_owner = "key_owner"
            key_group = "key_group"
            key_permissions = "key_permissions"
            key_sddl = "key_sddl"

        def __init__(self, _key_path, _key_path_unicode, _key_timestamp, _key_subkey_count, _key_value_count,
                         _key_owner='', _key_group='', _key_permissions='', _key_sddl=''):

            self.key_path = _key_path
            self.key_path_unicode = _key_path_unicode
            self.key_timestamp = _key_timestamp
            self.key_subkey_count = _key_subkey_count
            self.key_value_count = _key_value_count

            self.key_owner = _key_owner
            self.key_group = _key_group
            self.key_permissions = _key_permissions
            self.key_sddl = _key_sddl


        def dict(self):

            dict_reg_key = {}

            for _attribute in self.attributes.__dict__.items():
                if isinstance(_attribute[1], str):
                    if not True in [_attribute[1].startswith(prefix) for prefix in ['<', 'providers.', 'None']]:
                        _attribute_value = getattr(self, _attribute[1])
                        dict_reg_key.update({_attribute[1]: _attribute_value})

            return dict_reg_key

        def __hash__(self):
            return hash((self.key_path))

        def __eq__(self, other):
            return self.__dict__ == other.__dict__

    class registry_value(object):
        """ Classes below contains format field names """

        """ CAUTION: IF YOU ADD NEW FIELD, ADD IT TO BOTH INIT DEF AND ATTRIBUTES CLASS """
        class attributes(object):

            value_path = "value_path"
            value_name = "value_name"
            value_name_unicode = "value_name_unicode"
            value_type = "value_type"
            value_type_str = "value_type_str"
            value_content = "value_content"
            value_content_str = "value_content_str"
            value_content_unicode = "value_content_unicode"
            value_size = "value_size"
            value_raw_data = "value_raw_data"

        def __init__(self, _value_path, _value_name, _value_name_unicode, _value_type, _value_type_str, _value_content,
                     _value_content_str, _value_content_unicode, _value_size, _value_raw_data):

            self.value_path = _value_path
            self.value_name = _value_name
            self.value_name_unicode = _value_name_unicode
            self.value_type = _value_type
            self.value_type_str = _value_type_str
            self.value_content = _value_content
            self.value_content_str = _value_content_str
            self.value_content_unicode = _value_content_unicode
            self.value_size = _value_size
            self.value_raw_data = _value_raw_data

        def dict(self):

            dict_reg_value = {}

            for _attribute in self.attributes.__dict__.items():
                if isinstance(_attribute[1], str):
                    if not True in [_attribute[1].startswith(prefix) for prefix in ['<', 'providers.', 'None']]:
                        _attribute_value = getattr(self, _attribute[1])
                        dict_reg_value.update({_attribute[1]: _attribute_value})

            return dict_reg_value

        def empty(self):
            """ Returns a dict with all keys initiated to an empty string """
            dict_reg_value = {}

            for _attribute in self.attributes.__dict__.items():
                if isinstance(_attribute[1], str):
                    if not True in [_attribute[1].startswith(prefix) for prefix in ['<', 'providers.', 'None']]:
                        dict_reg_value.update({_attribute[1]: ''})

            return dict_reg_value

        def __hash__(self):
            return hash((str(self.value_name), str(self.value_content)))

        def __eq__(self, other):
            return self.__dict__ == other.__dict__

    class registry_hive(object):
        """ registry_hive """
        """ CAUTION: IF YOU ADD NEW FIELD, ADD IT TO BOTH INIT DEF AND ATTRIBUTES CLASS """
        class attributes(object):

            hive_header = 'hive_header'
            hive_file_path = 'hive_file_path'
            hive_file_name = 'hive_file_name'
            hive_obj = "hive_obj"
            hive_root = 'hive_root'
            hive_type = 'hive_type'
            hive_size = 'hive_size'
            hive_md5 = 'hive_md5'
            hive_user = 'hive_user'
            hive_mapping = 'hive_mapping'

        def __init__(self, hive_header, hive_file_path, hive_file_name, hive_type, hive_root, hive_size, hive_mapping, hive_user='',
                     hive_obj=None):

            self.hive_header = hive_header
            self.hive_file_path = hive_file_path
            self.hive_file_name = hive_file_name
            self.hive_obj = hive_obj
            self.hive_root = hive_root
            self.hive_type = hive_type
            self.hive_size = hive_size
            self.hive_md5 = ''
            self.hive_user = hive_user
            self.hive_mapping = hive_mapping


        def dict(self) -> dict():
            """ Output the hive information as dict """

            dict_reg_hive = {}

            for _attribute in self.attributes.__dict__.items():
                if isinstance(_attribute[1], str):
                    if not True in [_attribute[1].startswith(prefix) for prefix in ['<', 'providers.', 'None']]:
                        _attribute_value = getattr(self, _attribute[1])
                        dict_reg_hive.update({_attribute[1]: _attribute_value})

            return dict_reg_hive

        def __hash__(self):
            return hash((self.hive_md5))

        def __eq__(self, other):
            return self.__dict__ == other.__dict__

    class registry_item(object):

        class attributes(object):

            plugin_name = 'plugin_name'
            hive = 'hive'
            key = 'key'
            values = 'values'

        def __init__(self):

            self.plugin_name = None
            self.custom_field = None
            self.hive = None
            self.key = None
            self.values = None
            self.has_values = None
            self.values_hash = ''
            self.skip = None

        def add_named_fields(self, **fields):

            if fields:
                for field_name, field_data in fields.items():
                    if field_data:
                        for field, value in field_data.items():
                            setattr(self, field, value)

                #  Calculate key.values hash
                if self.values:
                    all = []
                    for _val in self.values:
                        all.append(str(_val.__hash__()))

                    self.values_hash = hash("".join(all))
        def add(self, _plugin_name, _registry_hive, _registry_key, _registry_values=None, **custom_fields):

            if _registry_values is None: _registry_values = []

            self.plugin_name = _plugin_name
            # self.custom_field = _custom_field
            self.hive = _registry_hive
            self.key = _registry_key
            self.values = _registry_values
            self.values_hash = ''

            #  Add custom fields
            if custom_fields:
                for field_name, field_data in custom_fields.items():
                    if field_data:
                        for field, value in field_data.items():
                            setattr(self, field, value)

            if not self.values:
                self.values = []

            #  Convert values to a list
            if not isinstance(self.values, list):
                self.values = [self.values]

            if len(self.values) > 0:
                self.has_values = True
            else:
                self.has_values = False

            #  Calculate key.values hash
            if self.values:
                all = []
                for _val in self.values:
                    all.append(str(_val.__hash__()))

                self.values_hash = hash("".join(all))

        def add_old(self, _plugin_name, _registry_hive, _registry_key, _registry_values=None, _custom_field=None):

            if _registry_values is None: _registry_values = []

            self.plugin_name = _plugin_name
            self.custom_field = _custom_field
            self.hive = _registry_hive
            self.key = _registry_key
            self.values = _registry_values
            self.values_hash = ''

            if not self.values:
                self.values = []

            #  Convert values to a list
            if not isinstance(self.values, list):
                self.values = [self.values]

            if len(self.values) > 0:
                self.has_values = True
            else:
                self.has_values = False

            #  Calculate key.values hash
            if self.values:
                all = []
                for _val in self.values:
                    all.append(str(_val.__hash__()))

                self.values_hash = hash("".join(all))

        def __eq__(self, other):
            return self.__dict__ == other.__dict__

        def __hash__(self):
            try:
                return hash((self.plugin_name, self.hive.hive_md5, self.key.key_path, self.values_hash))
            except Exception as msg:
                return 0

        def items(self):

            items = []
            # Convert registry_item to dict(s)
            # - IF registry_item has multiple values, create registry_item for each value respectively

            if not self.has_values:

                item = {}
                for _attribute in self.get_field_names():

                    field = getattr(self, _attribute, None)

                    if type(field) in [registry_provider.registry_key, registry_provider.registry_hive]:
                        item.update(field.dict())
                    else:
                        item[_attribute] = field

                item.update(registry_provider.registry_value.empty(registry_provider.registry_value))

                items.append(item)

            elif len(self.values) > 0:

                for value in self.values:
                    item = {}
                    for _attribute in self.get_field_names():

                        field = getattr(self, _attribute, None)

                        if type(field) in [registry_provider.registry_key, registry_provider.registry_hive]:
                            item.update(field.dict())
                        else:
                            item[_attribute] = field

                    item.update(value.dict())
                    items.append(item)

            return items

        def items_old(self):

            items = []

            # Create items
            item = {'plugin_name': self.plugin_name}
            item.update(self.hive.dict())
            item.update(self.key.dict())

            for _registry_value in self.values:
                _item = item.copy()
                _item.update(_registry_value.dict())

                if self.custom_field:
                    _item.update(self.custom_field)

                items.append(_item)

            # IF the key has no values, create empty values for all corresponding format fields
            if not self.has_values:
                if self.custom_field:
                    item.update(self.custom_field)

                item.update(registry_provider.registry_value.empty(registry_provider.registry_value))

                items.append(item)

            return items

        def get_field_names(self):

            format_fields = []

            for _attributes in [
                self.attributes.__dict__.items()
            ]:
                #  Would print all attributes
                for field, field_name in _attributes:
                    field_name = str(field_name)
                    if not True in [field_name.startswith(prefix) for prefix in ['<', 'providers.', 'None']]:
                        format_fields.append(field_name)

            return format_fields

    class registry_reg_handler(object):

        def __init__(self, recipes, decode_param_from=None, custom_handlers=None):
            """ recipes - Contains a list of functions to execute on registry key or value objects """

            if not recipes or not isinstance(recipes, list):
                logger.error('Unsupported _functions type! Something went wrong!')

            # Get required functions
            self.functions = []  # {func: func_obj, func_params: (params), fields=[]}

            for _func in recipes:
                #  Check the syntax of provided function

                # Case: handler_name
                if match(r'(^[a-zA-Z0-9_-]{3,20}$)', _func, IGNORECASE):
                    pass

                # Case: handler_name<param>XyZ<field>AbC
                elif match(r'(^[a-zA-Z0-9_-]{3,20}<param>.{1,512}<field>.{1,512})$', _func, IGNORECASE):
                    pass

                # Case: handler_name<param>XyZ<field>AbC<rfield>YzX
                elif match(r'(^[a-zA-Z0-9_-]{3,20}<param>.{1,512}<field>.{1,512}<rfield>.{1,512})$', _func, IGNORECASE):
                    pass

                # Case: handler_name<param>XyZ
                elif match(r'(^[a-zA-Z0-9_-]{3,20}<param>.{1,512})$', _func, IGNORECASE):
                    pass

                # Case: handler_name<field>AbC
                elif match(r'(^[a-zA-Z0-9_-]{3,20}<field>.{1,512})$', _func, IGNORECASE):
                    pass

                # Case: handler_name<param>AbC<rfield>XXX
                elif match(r'(^[a-zA-Z0-9_-]{3,20}<param>.{1,512}<rfield>.{1,512})$', _func, IGNORECASE):
                    pass

                # Case: handler_name<field>AbC<rfield>XXX
                elif match(r'(^[a-zA-Z0-9_-]{3,20}<field>.{1,512}<rfield>.{1,512})$', _func, IGNORECASE):
                    pass

                # Case: handler_name<rfield>ABCD
                elif match(r'(^[a-zA-Z0-9_-]{3,20}<rfield>.{1,512})$', _func, IGNORECASE):
                    pass

                # Case: Syntax error
                else:
                    logger.error('Syntax Error. Function: %s' % _func)
                    logger.error(
                        'The example syntax of registry handler function shuld be: \n"-rh function_name<param>param1<param>param2<field>field_name_to_process<rfield>output_field_name" (<param>,<field> and <rfield> are optional and depends on given function)\nUse -prh for more details')
                    exit(ERR_PROVIDER_INCORRECT_FUNCTION_SYNTAX)


                _func_name = ''
                _func_params = None
                _func_fields = None
                _func_output_fields = None

                #  Get function, parameter(s) and fields (if specified)
                #  Get _func_name
                _func_name, separator, _ = _func.partition('<')
                _func_name = _func_name.lower()

                if '<rfield>' in _func:
                    _func, _,  _func_output_fields = _func.partition('<rfield>')
                    _func_output_fields = _func_output_fields.split(';')
                    map(str.strip, _func_output_fields)

                if '<field>' in _func:
                    _func, _,  _func_fields = _func.partition('<field>')
                    _func_fields = _func_fields.split(';')
                    map(str.strip, _func_fields)

                if '<param>' in _func:
                    _func, _,  _func_params = _func.partition('<param>')
                    _func_params = _func_params.split(';')
                    map(str.strip, _func_params)

                    if decode_param_from:
                        if decode_param_from.lower() == 'base64':
                            _func_params = list(map(base64.b64decode, _func_params))
                            _func_params = list(map(bytes.decode, _func_params))
                        else:
                            logger.error('Unable to create a registry handler: "%s"\n'
                                         'Function: "%s"\n'
                                         'Unsupported param encoding: "%s"' %
                                         (_func_name, _func, decode_param_from))
                            return None

                    _func_params = tuple(_func_params)

                try:
                    if not custom_handlers:
                        func_class = getattr(handlers, _func_name)
                    else:
                        try:
                            func_class = getattr(handlers, _func_name)
                        except AttributeError:
                            func_class = getattr(custom_handlers, _func_name)

                    func_obj = getattr(func_class, _func_name)

                    # if _func_output_fields is None:
                        # _func_output_fields = _func_fields
                        # pass

                    self.functions.append({'func': func_obj, 'func_params': _func_params, 'func_fields': _func_fields,
                                           'result_fields': _func_output_fields})

                except Exception as msg:
                    logger.warning('Unable to get function object for: %s. Error: %s' % (_func_name, msg))
                    logger.error('Unsupported Registry Handler: "%s"' % _func_name)

            self.default_fields = [registry_provider.registry_value.attributes.value_content]

        def process_fields(self, registry_obj, reg_item_obj):

            #  Registry key, value and item are currently supported
            if isinstance(registry_obj, registry_provider.registry_key) or \
                    isinstance(registry_obj, registry_provider.registry_value):

                #  Iterate trough all functions/recipes and apply them
                for _func in self.functions:

                    #  Get the input and output fields for given function (_func)
                    fields = _func.get('func_fields', None)
                    result_fields = _func.get('result_fields', None)

                    #  Set the default field(s), if non specified by the user
                    if not fields:
                        fields = self.default_fields
                    else:
                        if not isinstance(fields, list):
                            fields = [fields]

                    #  Get object attribute by filed name, either from processed object or from registry_item
                    for _field_name in fields:
                        try:
                            _attribute = getattr(registry_obj, _field_name)
                        except AttributeError:
                            try:
                                _attribute = getattr(reg_item_obj, _field_name)
                            except AttributeError:
                                #logger.error('Incorrect field name: "%s" or not initialized properly' % _field_name)
                                continue

                        #  Get the function object and parameters
                        _func_obj = _func.get('func')
                        _func_params = _func.get('func_params')

                        try:
                            #  Execute registry handler function on specified field
                            if _func_params:
                                _params = (_attribute,) + _func_params
                                _attribute = _func_obj(*_params)
                            else:
                                _attribute = _func_obj(_attribute)

                            #  Save the returned data back to the initial field or to a specific return field (if specified)
                            if result_fields:
                                for _rfield in result_fields:
                                    setattr(registry_obj, _rfield, _attribute)
                            else:
                                setattr(registry_obj, _field_name, _attribute)

                        except TypeError as msg:
                            logger.error('Probably an incorrect syntax for the registry handler function. Error: %s' % msg)
                        except Exception as msg:
                            logger.error('Unable to call the function. Error: %s' % msg)

            return registry_obj

    class registry_export(object):

        def __init__(self):

            self.fields = ['hive_file_path', 'hive_mapping', 'key_path', 'value_name', 'value_content', 'value_type']

        def save_winreg_data_to_file(self, file_path, winreg_data, insert_header=False):

            logger.debug('Saving winreg data to file: %s' % file_path)
            _header = u"\ufeffWindows Registry Editor Version 5.00\r\n\r\n".encode("utf-16le")
            if not isinstance(winreg_data, list):
                winreg_data = [winreg_data]

            for _winreg_data in winreg_data:
                with open(file_path, mode="a+b") as file:
                    if insert_header:
                        file.write(_header)
                        insert_header = False

                    file.write(_winreg_data.encode("utf-16le"))
                    file.close()

        def convert2winreg(self, items, insert_registry_header=False, save_output=False, output_path=None):

            win_reg_items = []
            #reg_format_header = u"\ufeffWindows Registry Editor Version 5.00\r\n\r\n".encode("utf-16le")
            reg_format_header = u"\ufeffWindows Registry Editor Version 5.00\r\n\r\n"

            if insert_registry_header:
                win_reg_items.append(reg_format_header)

            if not isinstance(items, list):
                logger.error('Unexpected input type %s.' % items)
                exit(ERR_PROVIDER_UNEXPECTED_INPUT_TYPE)

            logger.debug('Converting [%d] registry items to winreg data' % len(items))

            #  Get unique hive_file_path entries
            hive_file_paths = set([_item.get('hive_file_path', '') for _item in items])

            for hive_file_path in hive_file_paths:
                logger.debug('Parsing hive: %s' % hive_file_path)
                #  Get all items related to given hive_file_path
                _items = [_item for _item in items if _item.get('hive_file_path','') == hive_file_path]

                if not _items:
                    logger.warning('No items found for given hive: %s' % hive_file_path)
                    continue
                else:
                    _hive_mapping = _items[0].get('hive_mapping', 'Unknown')

                #  Get all unique key_paths
                _items_key_paths = set([_item.get('key_path', '') for _item in _items])

                for _key_path in _items_key_paths:
                    #  Get all values (Might be slow when there are many items)
                    _key_path_items = [_item for _item in _items if _item.get('key_path', '') == _key_path]

                    _winreg_item = self.get_winreg_item(hive_mapping=_hive_mapping, key_path=_key_path,
                                                        values=_key_path_items)

                    win_reg_items.append(_winreg_item)

                #  Save the winreg output to a .reg file
                if save_output:
                    logger.debug('Saving winreg data..')

                    if r'/' in hive_file_path:
                        _, __, _winreg_file_name = hive_file_path.rpartition('/')
                    elif '\\' in hive_file_path:
                        _, __, _winreg_file_name = hive_file_path.rpartition('\\')

                    _winreg_file_name = _winreg_file_name + '.reg'
                    _file_path = getcwd() + '/' + _winreg_file_name

                    if output_path:
                        if isdir(output_path):
                            _file_path = output_path + '/' + _winreg_file_name
                        elif isfile(output_path):
                            _file_path = output_path
                        else:
                            _file_path = output_path

                    self.save_winreg_data_to_file(file_path=_file_path, winreg_data=win_reg_items)


            return win_reg_items

        def get_winreg_item(self, hive_mapping, key_path, values):

            ret = list()
            ret.append(u"[{prefix}\{path}]".format(prefix=hive_mapping, path=key_path))

            if not isinstance(values, list):
                values = [values]

            for value in values:

                _value_name = value.get('value_name', '')
                _value_type = value.get('value_type', '')
                _value_content = value.get('value_content', '')

                if not _value_type:
                    continue

                try:
                    _value = self.winreg_format_item(value_type=_value_type, item=value)
                except Exception as msg:
                    logger.error('Data parsing error. Message: %s. Data: %s' % (msg, _value_content))
                    continue

                row = "\"{name}\"={value}".format(name=_value_name, value=_value)

                if not row in ret:
                    ret.append(row)

            ret.append("\r\n")
            # return u"\r\n".join(ret).encode("utf-16le")
            return u"\r\n".join(ret)

        def _reg_sz(self, item) -> str:
            return "\"{value}\"".format(value=item.get('value_content', ''))

        def _reg_qword(self, item) -> str:

            s = ""
            try:
                # value_raw_data
                #for c in value.raw_data():
                for c in item.get('value_raw_data', b''):
                    s += ("%02x" % c) + ","
            except TypeError:
                return ERR_REGISTRY_VALUE_TYPE_ERROR

            s = "hex(b):" + s

            # Strips "," if it's last char
            if s[-1:] == ",":
                s = s[:-1]

            return s + "\r\n"

        def _reg_dword(self, item) -> str:
            return "dword:%08x" % (item.get('value_content', ''))

        def _reg_bin(self, item) -> str:
            """
            The function exports the value to binary format supported by Windows Registry Editor Version 5.00

            - Example result (First line 79 chars, remaining lines <=78 chars):

            "test_bin"=hex:e7,e7,89,59,55,93,50,32,05,59,32,69,39,76,36,93,44,38,34,96,34,\  <- 79 chars
              96,36,93,96,39,63,93,46,4e,f8,f9,f4,09,6f,96,69,6d,9f,59,92,65,40,f9,fe,f5,\   <- 78 chars
              f0,dd,28,c2,4c,0a,c0,c2,06                                                     <- X remaining chars (<=78)
            """
            ret = []
            s = ""

            try:
                for c in item.get('value_content', b''):
                    s += ("%02x" % c) + ","
            except TypeError:
                return ERR_REGISTRY_VALUE_TYPE_ERROR

            # Strips "," if it's last char
            if s[-1:] == ",":
                s = s[:-1]

            if item.get('value_type', '') == Registry.RegBin:
                s = "hex:" + s
            else:
                s = "hex(%d):" % (item.get('value_type', '')) + s

            """ Prepare export data """
            name_len = len(item.get('value_name', '')) + 2 + 1 + 1  # name + 2 * '"' + 1 * '=' + 1 * '\'
            split_index = 80 - name_len
            while len(s) > 0:
                if len(s) > split_index:
                    # split on a comma
                    while s[split_index] != ",":
                        split_index -= 1
                    ret.append(s[:split_index + 1] + "\\")
                    s = "  " + s[split_index + 1:]
                else:
                    ret.append(s)
                    s = ""
                split_index = 78  # 80 - 2 * " " <- From 2nd line, the beginning of the line, starts from two empty spaces

            return "\r\n".join(ret)

        def _reg_msz(self, item) -> str:
            """
            REG_MULTI_SZ A sequence of null-terminated strings, terminated by an empty string (\0).
            - Virus\0Malware\0\0 -> 56,00,69,00,72,00,75,00,73,00,00,00,4d,00,61,00,6c,00,77,\
            00,61,00,72,00,65,00,00,00,00,00
            """
            s = ""
            ret = []

            try:
                for c in item.get('value_raw_data', b''):
                    s += ("%02x" % c) + ","
            except TypeError:
                return ERR_REGISTRY_VALUE_TYPE_ERROR

            # Strips "," if it's last char
            if s[-1:] == ",":
                s = s[:-1]

            s = "hex(%d):" % (item.get('value_type', '')) + s

            """ Prepare export data """
            name_len = len(item.get('value_name', '')) + 2 + 1 + 1  # name + 2 * '"' + 1 * '=' + 1 * '\'
            split_index = 80 - name_len
            while len(s) > 0:
                if len(s) > split_index:
                    # split on a comma
                    while s[split_index] != ",":
                        split_index -= 1
                    ret.append(s[:split_index + 1] + "\\")
                    s = "  " + s[split_index + 1:]
                else:
                    ret.append(s)
                    s = ""
                split_index = 78  # 80 - 2 * " " <- From 2nd line, the beginning of the line, starts from two empty spaces

            return "\r\n".join(ret)

        def winreg_format_item(self, value_type, item):
            try:
                return {
                    Registry.RegSZ: self._reg_sz,
                    Registry.RegExpandSZ: self._reg_sz,
                    Registry.RegBin: self._reg_bin,
                    Registry.RegDWord: self._reg_dword,
                    Registry.RegQWord: self._reg_qword,
                    Registry.RegMultiSZ: self._reg_msz
                }[value_type](item)
            except KeyError:
                logger.error(f'ERROR - reg_format_value -> KeyError: {value_type}')

    class registry_database(object):

        class columns(object):

            class items(object):

                def dict(self):

                    dict_items = {}
                    _attributes = self.__dict__.items()
                    for _attribute in _attributes:
                        if isinstance(_attribute[1], str):
                            if not True in [_attribute[1].startswith(prefix) for prefix in ['<', 'providers.', 'None']]:
                                _attribute_value = getattr(self, _attribute[0])
                                _key = _attribute[0]
                                dict_items[_key] = _attribute_value

                    return dict_items

                def __repr__(self):

                    dict_items = {}

                    _attributes = self.__dict__.items()
                    for _attribute in _attributes:
                        if isinstance(_attribute[1], str):
                            if not True in [_attribute[1].startswith(prefix) for prefix in ['<', 'providers.', 'None']]:
                                _attribute_value = getattr(self, _attribute[0])
                                _key = _attribute[0]
                                dict_items[_key] = _attribute_value

                    return str(dict_items)

        def __init__(self, file_path, _items=None, _columns=None, baseline_fields=None):

            if _items is None: _items = []
            if _columns is None: _columns = []

            self.engine = None
            self.sql_metadata = None
            self.session = None
            self.mapper = None
            self.baseline_fields = baseline_fields

            if _items:
                # Convert all items to str
                for _item in _items:
                    for key, value in _item.items():
                        _item[key] = str(value)

            #  Get the engine
            self.engine = self.open_db(file_path)

            if self.engine:

                #  Refresh SQL metadata (get existing table names etc)
                self.sql_metadata = MetaData(bind=self.engine)
                try:
                    self.sql_metadata.reflect(self.engine)
                except Exception:
                    logger.error('Unable to reflect the database ... Might be a permission issue!')

                # Get the session
                self.session = create_session(bind=self.engine, autocommit=False, autoflush=True)

                if _items:
                    self.mapper = self.create_db(file_path=file_path, _items=_items, columns=_columns)
                else:
                    self.connect(file_path)

            else:
                logger.error('Unable to initialize thedatabasee engine')

        def get_baseline_hash(self, item, columns):

            item_values = self._concatenate_values(item=item, columns=columns)
            return self._hash(data=item_values)


        def _concatenate_values(self, item, columns):

            #  Get a list of selected column's values
            column_values = []
            for _col in columns:
                column_values.append(str(item[_col]))

            return "".join(column_values)


        def _hash(self, data):

            if data:
                if isinstance(data, str):
                    data = data.encode()

                _hash = blake2b(digest_size=20)
                _hash.update(data)

                return _hash.hexdigest()

        def open_db(self, file_path, in_memory=False):

            if isfile(file_path):
                logger.debug('Database: "%s" already exist ...' % file_path)
            else:
                logger.debug('Opening new database: "%s"' % file_path)

            if in_memory:
                engine = create_engine('sqlite:///:memory:', echo=False)
            else:
                engine = create_engine('sqlite:///%s' % file_path, echo=False)

            if engine:
                return engine
            else:
                return None

        def query_by_field(self, table_name, fields_to_query=None):

            if fields_to_query is None: fields_to_query = []
            if self.engine:
                if fields_to_query:
                    logger.debug('SELECT %s FROM %s' % (fields_to_query, table_name))

                    table = self.sql_metadata.tables[table_name]
                    if table is not None:
                        result = self.session.query(self.mapper).options(load_only(*fields_to_query)).all()
                        for l in result:
                            print(l.dict())
                        return result

        def query_by_value_like(self, table_name, fields_value_mappings):
            """ Function not finished yet, need to find out how to make _and and _or """

            if self.engine:
                result = []
                if fields_value_mappings:
                    table = self.sql_metadata.tables[table_name]
                    if table is not None:
                        _class = self.mapper.class_
                        _query = self.session.query(_class)

                for field_value_mapping in fields_value_mappings:
                    for attr, value in field_value_mapping.items():
                        _result = _query.filter(getattr(_class, attr).like("%%%s%%" % value))

                        if _result is None:
                            continue
                        else:
                            for _i in _result.all():
                                result.append(_i.__dict__)

                return result

        def query_by_value(self, table_name, fields_value_mappings=None):
            """ The logic _and between multiple fields is used """

            if fields_value_mappings is None: fields_value_mappings = {}

            if self.engine:

                result = []
                if fields_value_mappings:
                    table = self.sql_metadata.tables[table_name]
                    if table is not None:
                        _class = self.mapper.class_
                        _query = self.session.query(_class)

                        for field_value_mapping in fields_value_mappings:
                            if isinstance(field_value_mapping, dict):
                                _result = _query.filter_by(**field_value_mapping)

                                if _result is None:
                                    continue
                                else:
                                    for _i in _result.all():
                                        result.append(_i.__dict__)

                    return result

        def query_all(self, table_name):

            logger.debug('Query_ALL: "%s"' % table_name)

            if self.engine:
                table = self.sql_metadata.tables[table_name]
                if table is not None:
                    return self.session.query(table).all()

        def insert(self, table_name, _items, _columns=None, bulk_mode=True):
            """ ... """

            logger.debug('Insert [%d] items' % len(_items))
            insert_all = False

            if _columns is None: _columns = []

            if self.engine:
                table = self.sql_metadata.tables[table_name]
                if table is not None:

                    if _columns == []:
                        insert_all = True
                        _columns = _items.keys()

                    if not self.baseline_fields:
                        self.baseline_fields = _columns

                    #  Calculate baseline_hash [hash of the values inserted] for each item
                    for item in _items:
                        baseline_hash = self.get_baseline_hash(item=item, columns=self.baseline_fields)

                        # Update the item entry with expected baseline_hash filed (which is indexed in db)
                        item['baseline_hash'] = baseline_hash

                    # Make sure that this required column is inserted
                    _columns.append('baseline_hash')

                    if bulk_mode:
                        self.session.bind_table(table, self.engine)
                        if insert_all:  # Insert all fields
                            self.session.bulk_insert_mappings(mapper=self.mapper, mappings=_items, render_nulls=True)
                        else:  # Insert only required fields

                            for item in _items:
                                db_item = {}
                                for field in _columns:
                                    db_item[field] = item[field]

                                try:
                                    self.session.bulk_insert_mappings(mapper=self.mapper, mappings=[db_item], render_nulls=True)
                                    self.session.commit()
                                except IntegrityError:
                                    #  Case: The primary key must be unique
                                    self.session.rollback()

                        return True
                    else:
                        # Make a commit after every insert
                        if table is not None:
                            for _item in _items:
                                # insert data into the table, it does the auto commit ...
                                table.insert().values(**_item).execute()

                            return True
                else:
                    logger.debug('Unable to find the table: %s' % table_name)
                    return False

        def connect(self, file_path):

            logger.debug('Connecting to DB file: %s' % file_path)
            try:
                table = self.sql_metadata.tables['items']
                self.mapper = mapper(registry_provider.registry_database.columns.items, table)
                return True
            except KeyError:
                logger.error('Unable to find table: "items"')
                return None

        def create_db(self, file_path, _items, columns=None):

            logger.debug('Connecting to DB file: %s' % file_path)

            if columns is None: columns = []

            table = None
            logger.debug('Updating SQL metadata...')

            for _item in _items[0:1]:

                # Check for column mismatch
                if not columns:
                    columns = list(_item.keys())

                # Get original column names before static assignment
                try:
                    table = self.sql_metadata.tables['items']
                except KeyError:
                    table = None

                if table is not None:  # Table items exist
                    _table_columns = table.columns
                    _table_columns = [str(col).replace('items.', '') for col in _table_columns]

                    all_good = True
                    for col in columns:

                        if not col in _table_columns:
                            all_good = False
                            break

                    if all_good:
                        logger.warning(
                            'The table already exist, and has the same column set as input items data')
                    else:
                        logger.error(
                            'The table "items" already exist, but DOES NOT have required columns referenced by input items data. Review the format_fields! or remove the database file')
                        logger.debug('Database columns: %s' % _table_columns)
                        logger.debug('Items data columns: %s' % columns)
                        self.engine = None
                        return None

                else:  # Table does not exist
                    _table_columns = None

                    # Create the table and custom columns
                    table = Table('items', self.sql_metadata,
                                  Column('baseline_hash', String, primary_key=True, index=True),
                                  *(Column(col_name, String()) for col_name in columns))

                    try:
                        table.create()
                    except OperationalError as msg:
                        logger.error('Unable to create table: "%s". Error: %s' % ('items', str(msg)))
                        self.engine = None
                        return None


            try:
                _mapper = mapper(registry_provider.registry_database.columns.items, table)
            except ArgumentError:
                _mapper = mapper(registry_provider.registry_database.columns.items, table, non_primary=True)

            return _mapper

    class search_pattern(object):

        def __init__(self):

            # Make sure that every time new object is called, the patterns are refreshed
            for key, pattern in self.PATTERN_MAPPING.items():
                self.PATTERN_MAPPING[key] = []

            pass

        # Standard key_path patterns
        KEY_STRING_PATTERN = []
        KEY_REGEX_PATTERN = []
        KEY_BINARY_PATTERN = []

        # key_timestamp patterns
        KEY_REGEX_TIMESTAMP_PATTERN = []
        KEY_DATE_TIMESTAMP_PATTERN = []

        # key_owner and key_permissions patterns
        KEY_STRING_OWNER_PATTERN = []
        KEY_REGEX_OWNER_PATTERN = []
        KEY_STRING_PERMISSIONS_PATTERN = []
        KEY_REGEX_PERMISSIONS_PATTERN = []

        # Standard value_name patterns
        VALUE_NAME_STRING_PATTERN = []
        VALUE_NAME_REGEX_PATTERN = []
        VALUE_NAME_BINARY_PATTERN = []

        # Standard value_content patterns
        VALUE_CONTENT_STRING_PATTERN = []
        VALUE_CONTENT_REGEX_PATTERN = []
        VALUE_CONTENT_BINARY_PATTERN = []

        # value_size patterns
        VALUE_SIZE_PATTERN = []

        # value_content entropy
        VALUE_CONTENT_ENTROPY = []

        class Type(object):

            KEY_STRING_PATTERN = 1
            KEY_REGEX_PATTERN = 2
            KEY_BINARY_PATTERN = 3

            # key_timestamp patterns
            KEY_REGEX_TIMESTAMP_PATTERN = 4
            KEY_DATE_TIMESTAMP_PATTERN = 5

            # key_owner and key_permissions patterns
            KEY_REGEX_OWNER_PATTERN = 7
            KEY_REGEX_PERMISSIONS_PATTERN = 9

            # Standard value_name patterns
            VALUE_NAME_STRING_PATTERN = 10
            VALUE_NAME_REGEX_PATTERN = 11
            VALUE_NAME_BINARY_PATTERN = 12

            # Standard value_content patterns
            VALUE_CONTENT_STRING_PATTERN = 13
            VALUE_CONTENT_REGEX_PATTERN = 14
            VALUE_CONTENT_BINARY_PATTERN = 15

            # value_size patterns
            VALUE_SIZE_PATTERN = 16

            # value entropy
            VALUE_CONTENT_ENTROPY = 17

        class date_timestamp_pattern:

            name = 'Date Time pattern'

            patterns = {
                "range_pattern": r'(^\d{4}[\/-]\d{2}[\/-]\d{2}.*)(..{1})(\d{4}[\/-]\d{2}[\/-]\d{2}.*)',
                "inequality_pattern_b": r'(^[>]{1})(\d{4}[\/-]\d{2}[\/-]\d{2}.*)',
                "inequality_pattern_s": r'(^[<]{1})(\d{4}[\/-]\d{2}[\/-]\d{2}.*)',
                "equality_patern": r'(^[=]{1})(\d{4}[\/-]\d{2}[\/-]\d{2}.*)' # Pattern is good, but match does not work well, better to use -tm for it anyway.
            }

            def __init__(self, param_str=None, case_sensitive=False):

                self.start_date = None
                self.end_date = None
                self.operator = None
                self.initialized = None
                self.case_sensitive = case_sensitive

                if param_str:
                    if self.import_param(param_str):
                        self.pattern = param_str
                        self.initialized = True

            def __repr__(self):

                return '%s, %s, Case-sensitive: %s' % (self.name, self.pattern, self.case_sensitive)

            def check_param(self, param_str):
                """ Return True if param_str match a pattern """
                param_groups = None
                """ Initial param cosmetic adjustment  """
                param_str = param_str.strip()

                """ Cherck the param syntax """
                for key, pattern in self.patterns.items():
                    param_groups = re.fullmatch(pattern, param_str)
                    if param_groups:
                        return True
                return False

            def match(self, key_timestamp, case_sensitive):

                if self.initialized:
                    if self.operator == "..":
                        if key_timestamp >= self.start_date and key_timestamp <= self.end_date:
                            return True

                    if self.operator == ">":
                        if key_timestamp > self.start_date:
                            return True

                    if self.operator == "<":
                        if key_timestamp < self.start_date:
                            return True

                    if self.operator == "=":
                        if key_timestamp == self.start_date:
                            return True

                return False

            def import_param(self, param_str):
                """ Return True if import is successful  """
                param_groups = None
                """ Initial param cosmetic adjustment  """
                # re.sub(r"\s+", "", param, flags=re.UNICODE)  #  Removes all white spaces
                param_str = param_str.strip()

                """ Cherck the param syntax """
                for key, pattern in self.patterns.items():
                    param_groups = re.findall(pattern, param_str)
                    if param_groups:
                        # Range
                        if len(param_groups[0]) == 3:
                            self.start_date = date_parser.parse(param_groups[0][0])
                            self.operator = param_groups[0][1]
                            self.end_date = date_parser.parse(param_groups[0][2])
                        else:
                            # Other equality, inequality
                            self.operator = param_groups[0][0]
                            self.start_date = date_parser.parse(param_groups[0][1])


                        return True

                logger.error('Supported minimal date format is: <operator>YYYY-MM-DD lile ">2016-12-31"')
                return False

        class data_size_pattern:

            name = 'Data Size pattern'

            patterns = {
                "range_pattern": r'(^\d+)(..{1})(\d+)',
                "inequality_pattern_b": r'(^[>]{1})(\d+)',
                "inequality_pattern_s": r'(^[<]{1})(\d+)',
                "equality_patern": r'(^[=]{1})(\d+)'
            }

            def __init__(self, param_str=None, case_sensitive=False):

                self.first_number = None
                self.second_number = None
                self.operator = None
                self.initialized = None
                self.case_sensitive = case_sensitive

                if param_str:
                    if self.import_param(param_str):
                        self.pattern = param_str
                        self.initialized = True

            def __repr__(self):

                return '%s, %s, Case-sensitive: %s' % (self.name, self.pattern, self.case_sensitive)

            def check_param(self, param_str):
                """ Return True if param_str match a pattern """
                param_groups = None
                """ Initial param cosmetic adjustment  """
                param_str = param_str.strip()

                """ Cherck the param syntax """
                for key, pattern in self.patterns.items():
                    param_groups = re.fullmatch(pattern, param_str)
                    if param_groups:
                        return True
                return False

            def match(self, data_size, case_sensitive):

                if self.initialized:
                    if self.operator == "..":
                        if data_size >= self.first_number and data_size <= self.second_number:
                            return True

                    if self.operator == ">":
                        if data_size > self.first_number:
                            return True

                    if self.operator == "<":
                        if data_size < self.first_number:
                            return True

                    if self.operator == "=":
                        if data_size == self.first_number:
                            return True

                return False

            def import_param(self, param_str):
                """ Return True if import is successful  """
                param_groups = None
                """ Initial param cosmetic adjustment  """
                # re.sub(r"\s+", "", param, flags=re.UNICODE)  #  Removes all white spaces
                param_str = param_str.strip()

                """ Cherck the param syntax """
                for key, pattern in self.patterns.items():
                    param_groups = re.findall(pattern, param_str)
                    if param_groups:
                        # Range
                        if len(param_groups[0]) == 3:
                            self.first_number = int(param_groups[0][0])
                            self.operator = param_groups[0][1]
                            self.second_number = int(param_groups[0][2])
                        else:
                            # Other equality, inequality
                            self.operator = param_groups[0][0]
                            self.first_number = int(param_groups[0][1])

                        return True

                return False

        class string_pattern:

            name = 'String pattern'

            def __init__(self, pattern, case_sensitive):

                self.initialized = None
                self.case_sensitive = case_sensitive

                if pattern:
                    if case_sensitive:
                        self.pattern = pattern
                        self.case_sensitive = True
                    else:
                        self.pattern = pattern.upper()
                        self.case_sensitive = False

                    self.initialized = True

            def match(self, input_string, case_sensitive):

                if not self.case_sensitive:
                    input_string = input_string.upper()

                if self.pattern in input_string:
                    return True

            def __repr__(self):

                return '%s, %s, Case-sensitive: %s' % (self.name, self.pattern, self.case_sensitive)

        class regex_pattern:

            name = 'Regex pattern'

            def __init__(self, pattern, case_sensitive):

                self.initialized = None
                self.case_sensitive = case_sensitive

                try:
                    if case_sensitive:
                        self.pattern = re.compile(pattern)
                    else:
                        self.pattern = re.compile(pattern, flags=re.IGNORECASE)

                    if self.pattern:
                        self.initialized = True

                except Exception as msg:
                    logger.error('Faild to create Key Regex pattern')
                    self.initialized = False

            def match(self, str_data, case_sensitive):

                if self.pattern.search(str(str_data)):
                    return True

            def __repr__(self):

                return '%s, %s, Case-sensitive: %s' % (self.name, self.pattern, self.case_sensitive)

        class bin_pattern:

            name = 'Binary pattern'
            def __init__(self, pattern, case_sensitive):

                self.initialized = None
                self.case_sensitive = case_sensitive

                try:
                    self.pattern = bytes(pattern, "utf-8").decode('unicode-escape').encode("utf-16le")
                    self.pattern_str = self.pattern.decode('utf-16le', 'ignore')

                    if self.pattern:
                        self.initialized = True

                except Exception as msg:
                    logger.error('Failed to create Key Binary pattern')
                    self.initialized = False


            def match(self, key_path, case_sensitive):

                if self.pattern in key_path:
                    return True

            def __repr__(self):

                return '%s, %s, Case-sensitive: %s' % (self.name, self.pattern, self.case_sensitive)

        class entropy_pattern:
            """ Instead of Boolean, returns the value entropy """
            name = 'Entropy pattern'

            #  Functions taken from: https://github.com/DidierStevens/DidierStevensSuite/blob/2a7f11d5f75ded45b7312e547b34be156c762e1d/strings.py
            def C2IIP2(self, data):
                if sys.version_info[0] > 2:
                    return data
                else:
                    return ord(data)

            #  Functions taken from: https://github.com/DidierStevens/DidierStevensSuite/blob/2a7f11d5f75ded45b7312e547b34be156c762e1d/strings.py
            def entropy(self, data, dPrevalence=None):

                averageConsecutiveByteDifference = None
                if dPrevalence == None:
                    dPrevalence = {iter: 0 for iter in range(0x100)}
                    sumDifferences = 0.0
                    previous = None
                    if len(data) > 1:
                        for byte in data:
                            byte = handlers.entropy.C2IIP2(byte)
                            dPrevalence[byte] += 1
                            if previous != None:
                                sumDifferences += abs(byte - previous)
                            previous = byte
                        averageConsecutiveByteDifference = sumDifferences / float(len(data) - 1)

                sumValues = sum(dPrevalence.values())

                entropy = 0.0
                for iter in range(0x100):
                    if dPrevalence[iter] > 0:
                        prevalence = float(dPrevalence[iter]) / float(sumValues)
                        entropy += - prevalence * math.log(prevalence, 2)

                return entropy

            def __init__(self, pattern, case_sensitive):

                self.initialized = None
                self.case_sensitive = case_sensitive

                try:
                    self.pattern = float(pattern)
                    self.pattern_str = str(self.pattern)

                    if self.pattern:
                        self.initialized = True

                except Exception as msg:
                    logger.error('Failed to create Entropy Binary pattern')
                    self.initialized = False

            def match(self, value_raw_bytes, case_sensitive):

                if isinstance(value_raw_bytes, bytes):
                    value_entropy = self.entropy(data=value_raw_bytes)  # value.raw_data()

                    if value_entropy > self.pattern:
                        return value_entropy

            def __repr__(self):

                return '%s, %s, Case-sensitive: %s' % (self.name, self.pattern_str, self.case_sensitive)

        PATTERN_NAMES = [
            'KEY_STRING_PATTERN',
            'KEY_REGEX_PATTERN',
            'KEY_BINARY_PATTERN',
            'KEY_REGEX_TIMESTAMP_PATTERN',
            'KEY_DATE_TIMESTAMP_PATTERN',
            'KEY_REGEX_OWNER_PATTERN',
            'KEY_REGEX_PERMISSIONS_PATTERN',
            'VALUE_NAME_STRING_PATTERN',
            'VALUE_NAME_REGEX_PATTERN',
            'VALUE_NAME_BINARY_PATTERN',
            'VALUE_CONTENT_STRING_PATTERN',
            'VALUE_CONTENT_REGEX_PATTERN',
            'VALUE_CONTENT_BINARY_PATTERN',
            'VALUE_SIZE_PATTERN',
            'VALUE_CONTENT_ENTROPY'

        ]

        PATTERN_MAPPING = {
            Type.KEY_STRING_PATTERN: KEY_STRING_PATTERN,
            Type.KEY_REGEX_PATTERN: KEY_REGEX_PATTERN, # ...
            Type.KEY_BINARY_PATTERN: KEY_BINARY_PATTERN,
            Type.KEY_REGEX_TIMESTAMP_PATTERN: KEY_REGEX_TIMESTAMP_PATTERN,
            Type.KEY_DATE_TIMESTAMP_PATTERN: KEY_DATE_TIMESTAMP_PATTERN,
            Type.KEY_REGEX_OWNER_PATTERN: KEY_REGEX_OWNER_PATTERN,
            Type.KEY_REGEX_PERMISSIONS_PATTERN: KEY_REGEX_PERMISSIONS_PATTERN,
            Type.VALUE_NAME_STRING_PATTERN: VALUE_NAME_STRING_PATTERN,
            Type.VALUE_NAME_REGEX_PATTERN: VALUE_NAME_REGEX_PATTERN,
            Type.VALUE_NAME_BINARY_PATTERN: VALUE_NAME_BINARY_PATTERN,
            Type.VALUE_CONTENT_STRING_PATTERN: VALUE_CONTENT_STRING_PATTERN,
            Type.VALUE_CONTENT_REGEX_PATTERN: VALUE_CONTENT_REGEX_PATTERN,
            Type.VALUE_CONTENT_BINARY_PATTERN: VALUE_CONTENT_BINARY_PATTERN,
            Type.VALUE_SIZE_PATTERN: VALUE_SIZE_PATTERN,
            Type.VALUE_CONTENT_ENTROPY: VALUE_CONTENT_ENTROPY
        }

        PATTERN_NAME_MAPPING = {
            Type.KEY_STRING_PATTERN: "KEY_STRING_PATTERN",
            Type.KEY_REGEX_PATTERN: "KEY_REGEX_PATTERN", # ...
            Type.KEY_BINARY_PATTERN: "KEY_BINARY_PATTERN",
            Type.KEY_REGEX_TIMESTAMP_PATTERN: "KEY_REGEX_TIMESTAMP_PATTERN",
            Type.KEY_DATE_TIMESTAMP_PATTERN: "KEY_DATE_TIMESTAMP_PATTERN",
            Type.KEY_REGEX_OWNER_PATTERN: "KEY_REGEX_OWNER_PATTERN",
            Type.KEY_REGEX_PERMISSIONS_PATTERN: "KEY_REGEX_PERMISSIONS_PATTERN",
            Type.VALUE_NAME_STRING_PATTERN: "VALUE_NAME_STRING_PATTERN",
            Type.VALUE_NAME_REGEX_PATTERN: "VALUE_NAME_REGEX_PATTERN",
            Type.VALUE_NAME_BINARY_PATTERN: "VALUE_NAME_BINARY_PATTERN",
            Type.VALUE_CONTENT_STRING_PATTERN: "VALUE_CONTENT_STRING_PATTERN",
            Type.VALUE_CONTENT_REGEX_PATTERN: "VALUE_CONTENT_REGEX_PATTERN",
            Type.VALUE_CONTENT_BINARY_PATTERN: "VALUE_CONTENT_BINARY_PATTERN",
            Type.VALUE_SIZE_PATTERN: "VALUE_SIZE_PATTERN",
            Type.VALUE_CONTENT_ENTROPY: "VALUE_CONTENT_ENTROPY"
        }

        pattern_object_mapping = {
            Type.KEY_STRING_PATTERN: string_pattern,  # -ks
            Type.KEY_REGEX_PATTERN: regex_pattern,  # -kr
            Type.KEY_DATE_TIMESTAMP_PATTERN: date_timestamp_pattern,  # -kd
            Type.KEY_BINARY_PATTERN: bin_pattern,  # -kb
            Type.KEY_REGEX_TIMESTAMP_PATTERN: regex_pattern,  # -kt
            Type.KEY_REGEX_OWNER_PATTERN: regex_pattern,  # -ko
            Type.KEY_REGEX_PERMISSIONS_PATTERN: regex_pattern,  # -kp
            Type.VALUE_NAME_STRING_PATTERN: string_pattern,  # -vs
            Type.VALUE_NAME_REGEX_PATTERN: regex_pattern,  # -vr
            Type.VALUE_NAME_BINARY_PATTERN: bin_pattern,  # -vb
            Type.VALUE_CONTENT_STRING_PATTERN: string_pattern,  # -ds
            Type.VALUE_CONTENT_REGEX_PATTERN: regex_pattern,  # -dr
            Type.VALUE_CONTENT_BINARY_PATTERN: bin_pattern,  # -db
            Type.VALUE_SIZE_PATTERN: data_size_pattern,  # -dl
            Type.VALUE_CONTENT_ENTROPY: entropy_pattern  # Custom: For entropy plugin
        }

        def _update_pattern_table(self, pattern, pattern_type):

            if pattern:
                pattern_table = self.PATTERN_MAPPING.get(pattern_type, None)
                if pattern_table is not None:
                    # pattern_table.append(pattern)
                    self.PATTERN_MAPPING[pattern_type].append(pattern)

                    # Update associated list
                    pattern_name = self.PATTERN_NAME_MAPPING[pattern_type]
                    pattern_list = getattr(self, pattern_name)

                    pattern_list.append(pattern)

        def eval(self, input_data, pattern_table, case_sensitive=None):

            for pattern in pattern_table:
                result = pattern.match(input_data, case_sensitive)
                if result:
                    return result

        def add(self, pattern, pattern_type, case_sensitive=False):

            pattern_obj = None

            if not isinstance(pattern, list):
                pattern = [pattern]

            for _pattern in pattern:

                #  Get mapped object
                pattern_obj = self.pattern_object_mapping.get(pattern_type, None)

                if pattern_obj:

                    pattern_obj = pattern_obj(_pattern, case_sensitive)

                    if pattern_obj.initialized:
                        self._update_pattern_table(pattern=pattern_obj, pattern_type=pattern_type)

        class compiled_search_pattern:

            def __init__(self):
                pass


            def eval(self, input_data, pattern_table, case_sensitive=None):

                for pattern in pattern_table:
                    result = pattern.match(input_data, case_sensitive)
                    if result:
                        return result

        def compile(self):

            _compiled_pattern = registry_provider.search_pattern.compiled_search_pattern()

            for name in self.PATTERN_NAMES:

                try:
                    pattern = getattr(self, name)
                    setattr(_compiled_pattern, name, pattern)
                except:
                    pass

            return _compiled_pattern

        def print(self):

            print(' [*] Compiled Search Patterns:')

            for pattern_id, pattern in self.PATTERN_MAPPING.items():

                if pattern:

                    pattern_name = self.PATTERN_NAME_MAPPING.get(pattern_id, "")

                    if isinstance(pattern, list):
                        for _pattern in pattern:
                            print('  [-] %s -> %s' % (pattern_name, _pattern))
                    else:
                        print('  [-] %s -> %s' % (pattern_name, pattern))

    def get_file_header(self, file_path, size=8) -> str:

        """ By default gets 8 bytes from the header of specified file and returns a string """
        file_header = None
        try:
            with open(file_path, 'rb') as _file:
                file_header = _file.read(size)
        except Exception:
            logger.error('Unable to retrieve the file header')
        return file_header

    def exclude_file_by_extensions(self, file_path, unsupported_extensions=[]):

        if unsupported_extensions:
            _, __, _ext = file_path.rpartition('.')

            if _ext.lower() in unsupported_extensions:
                return True
            else:
                return False
        else:
            return None

    #  Would be used by plugins to make string to obj mapping
    item_classes = {
        'hive': registry_hive,
        'key': registry_key,
        'value': registry_value,
        'item': registry_item
    }

    def load(self, provider_name):

        _provider = None
        try:
            _provider = getattr(import_module('providers.%s' % provider_name), provider_name)
            _provider = _provider()  # Init the object

        except Exception as msg:
            logger.error('Unable to initialize the provider: "%s". Error: %s' % (provider_name, str(msg)))
            return None

        return _provider

    def get(self, provider_name):

        try:
            return self.providers[provider_name]
        except KeyError:
            return None



    def __init__(self, provider_name):

        self.provider = None
        self.providers = {}

        # Load specific provider only
        if provider_name:
            if provider_name == 'python_registry':
                _provider = self.load(provider_name)
                if _provider:
                    self.providers[provider_name] = _provider

            if provider_name == 'yarp':
                _provider = self.load(provider_name)
                if _provider:
                    self.providers[provider_name] = _provider

            self.provider = self.providers[provider_name]

        else:
            # Load all available providers
            for _path in glob.glob('providers/*', recursive=False):

                _, __, provider_name = _path.rpartition('/')
                provider_name = provider_name.replace('.py', '')

                if isfile(_path) and provider_name not in ['provider']:
                    _provider = self.load(provider_name)

                    if _provider:
                        self.providers[provider_name] = _provider
                        self.name = provider_name

            # Load the default provider
            self.provider = self.providers[__default_registry_provider__]
            self.name = __default_registry_provider__


