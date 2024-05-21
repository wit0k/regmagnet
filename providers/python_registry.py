import logging
from math import e
import os.path
import re

from os.path import getsize
import struct

from providers.provider import registry_provider
from md.security_descriptor import security_descriptor, windows_security_descriptor

from Registry import Registry
from struct import unpack

logger = logging.getLogger('regmagnet')

# UNSUPPORTED_EXTENSIONS = ['ds_store', 'rar', '7z', 'txt']

class python_registry(registry_provider):

    name = 'python_registry'

    def __init__(self):
        pass

    def get_winreg_mapping(self, hive_type, hive_file=None):
        # Hives are stored in HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\hivelist
        # Hive names explained in: https://msdn.microsoft.com/en-us/library/windows/desktop/ms724877(v=vs.85).aspx

        if isinstance(hive_type, Registry.HiveType):
            hives_mapping = {
                Registry.HiveType.SYSTEM: r"HKEY_LOCAL_MACHINE\SYSTEM",
                Registry.HiveType.SOFTWARE: r"HKEY_LOCAL_MACHINE\SOFTWARE",
                Registry.HiveType.DEFAULT: r"HKEY_USERS\.Default",
                Registry.HiveType.NTUSER: r"HKEY_CURRENT_USER",
                Registry.HiveType.SAM: r"HKEY_LOCAL_MACHINE\SAM",
                Registry.HiveType.SECURITY: r"HKEY_LOCAL_MACHINE\SECURITY",
                Registry.HiveType.USRCLASS: r"HKEY_CURRENT_USER\Software\Classes",
                Registry.HiveType.BCD: r"HKEY_LOCAL_MACHINE\BCD00000000"
            }
        elif isinstance(hive_type, str):
            hives_mapping = {
                'SYSTEM': r"HKEY_LOCAL_MACHINE\SYSTEM",
                'SOFTWARE': r"HKEY_LOCAL_MACHINE\SOFTWARE",
                'DEFAULT': r"HKEY_USERS\.Default",
                'NTUSER': r"HKEY_CURRENT_USER",
                'SAM': r"HKEY_LOCAL_MACHINE\SAM",
                'SECURITY': r"HKEY_LOCAL_MACHINE\SECURITY",
                'USRCLASS': r"HKEY_CURRENT_USER\Software\Classes",
                'BCD': r"HKEY_LOCAL_MACHINE\BCD00000000"
            }

        if hive_type in hives_mapping:
            return hives_mapping[hive_type]
        else:
            if hive_file:
                if 'UsrClass' in hive_file:
                    return r"HKEY_CURRENT_USER\Software\Classes"

            return 'Unknown'

    def load_hive(self, hive_file_path, hive_transaction_logs=None, load_hive_object=False) -> registry_provider.registry_hive:

        logger.debug('Loading hive: %s' % hive_file_path)

        _hive_file_name = os.path.basename(hive_file_path)
        _hive_header = self.get_file_header(hive_file_path)

        try:
            _hive_obj = Registry.Registry(hive_file_path)
        except:
            logger.warning('Unable to load hive: %s -> Header: %s' % (hive_file_path, _hive_header))
            return None

        _hive_type = _hive_obj.hive_type()
        _hive_mapping = self.get_winreg_mapping(_hive_type, hive_file_path)

        if _hive_type:
            _, __, _hive_type = str(_hive_type).rpartition('.')

        try:
            _hive_root = _hive_obj.root().path()
        except Exception:
            return None

        _hive_size = getsize(hive_file_path)

        _user_sid = ''
        if _hive_type == 'NTUSER':
            try:
                _user_sid = _hive_obj.open("Software\Microsoft\Protected Storage System Provider").subkeys()[0].path()
            except Registry.RegistryKeyNotFoundException:
                user_sid = ""
            except Exception:
                user_sid = ""
            finally:
                _key_path, _, _value_name = _user_sid.rpartition("\\")

                if _value_name:
                    _user_sid = _value_name

        hive_buffer = _hive_obj._buf

        # hive_header, hive_file_path, hive_file_name, hive_type, hive_root, hive_size, hive_obj=None, meta_data={}
        _hive = registry_provider.registry_hive(hive_header=_hive_header, hive_file_path=hive_file_path,
                                               hive_file_name=_hive_file_name, hive_type=_hive_type, hive_root=_hive_root,
                                               hive_size=_hive_size, hive_obj=_hive_obj, hive_user=_user_sid, hive_mapping=_hive_mapping, hive_buffer=hive_buffer)

        return _hive

    def parse_value_obj(self, _key, value_obj, reg_handler, reg_item_obj=None) -> registry_provider.registry_value:

        try:
            value_name = value_obj.name()
        except Exception as msg:
            logger.error('value_obj.name() -> Exception: %s' % str(msg))
            value_name = '<value_name_error>'

        value_path = _key + "\\" + value_name
        value_name_unicode = bytes(value_name, "utf-16le")
        value_type = value_obj.value_type()
        value_type_str = value_obj.value_type_str()
        value_content = value_obj.value()
        value_content_str = str(value_content)
        value_content_unicode = value_obj.raw_data()
        value_size = len(value_obj.raw_data())
        value_raw_data = value_obj.raw_data()

        value_item = registry_provider.registry_value(_value_path=value_path, _value_name=value_name,
                                                      _value_name_unicode=value_name_unicode, _value_type=value_type,
                                                      _value_type_str=value_type_str, _value_content=value_content,
                                                      _value_content_str=value_content_str, _value_content_unicode=value_content_unicode,
                                                      _value_size=value_size, _value_raw_data=value_raw_data)

        if reg_handler:
            reg_handler.process_fields(registry_obj=value_item, reg_item_obj=reg_item_obj)

        return value_item

    def parse_key_obj(self, key_obj, reg_handler, reg_item_obj=None, parse_security_descriptor=True) -> registry_provider.registry_key:

        key_path = key_obj.path()
        key_item = None

        if key_path:
            # Strip the unnecessary root key
            if '\\' in key_path:
                _, __, key_path = key_path.partition('\\')


        key_path_unicode = bytes(key_path, "utf-16le")
        key_timestamp = key_obj.timestamp()
        key_subkey_count = len(key_obj.subkeys())
        key_value_count = len(key_obj.values())
        
        key_owner = ''
        key_group = ''
        key_permissions = ''
        key_sd_bytes = b''
        key_sd = None
        key_nk_record = None
        key_nk_record = registry_provider.nk_record(key_obj._nkrecord._buf[key_obj._nkrecord._offset:])
            
        if parse_security_descriptor:

            sk_record = key_obj._nkrecord.sk_record()

            if sk_record:
                key_sd, key_sd_bytes, key_owner, key_group, key_permissions = self.get_key_dacl(sk_record=sk_record)
                
                if key_sd_bytes == b'' or key_sd_bytes is None:
                    print('Debug -> Empty key_sd_bytes: ', key_path)

                key_item = registry_provider.registry_key(_key_path=key_path, _key_path_unicode=key_path_unicode,
                                                          _key_timestamp=key_timestamp,
                                                          _key_subkey_count=key_subkey_count,
                                                          _key_value_count=key_value_count, _key_owner=key_owner,
                                                          _key_group=key_group, _key_permissions=key_permissions,
                                                          _key_obj=key_obj, _key_sd_bytes=key_sd_bytes, _key_security_descriptor=key_sd, key_nk_record=key_nk_record)
            else:
                print('Debug -> Empty SK record: ', key_path)
        else:

            print('Debug -> Skip SD parsing: ', key_path)
            
            key_item = registry_provider.registry_key(_key_path=key_path, _key_path_unicode=key_path_unicode,
                                                      _key_timestamp=key_timestamp, _key_subkey_count=key_subkey_count,
                                                      _key_value_count=key_value_count, _key_obj=key_obj, _key_sd_bytes=key_sd_bytes, _key_security_descriptor=key_sd, key_nk_record=key_nk_record)

        if reg_handler:
            reg_handler.process_fields(registry_obj=key_item, reg_item_obj=reg_item_obj)

        return key_item

    def get_key_dacl(self, sk_record):

        key_owner = ''
        key_group = ''
        key_permissions = ''
        key_sd_bytes = b''

        if sk_record:
            
            # Determine SD size
            # - self.read_uint32(16)
                # def read_uint32(self, pos):
		        #    b = self.read_binary(pos, 4)  -> # b = buf[16:4]
		        #    return unpack('<L', b)[0]
            
            sd_size = sk_record._buf[sk_record._offset+16:sk_record._offset+16+4]
            sd_bytes_size = unpack('<L', sd_size)[0]
            
            # Get the SD bytes 
            # - self.read_binary(20, self.get_security_descriptor_size())
            """
                def read_binary(self, pos, length = None):
		                if length is None:
			                b = self.buf[pos : ]
			                return b

		                b = self.buf[pos : pos + length]
            """
            
            sd_bytes = sk_record._buf[sk_record._offset+20:sk_record._offset+20+sd_bytes_size]
            # Sometimes does work ...      
            # sd_bytes = sk_record._buf[sk_record._offset:sk_record._offset_next_sk]

            if sd_bytes:
                # According to get_security_descriptor() from https://github.com/msuhanov/yarp/blob/bcff19e5e1542e763c3ce2d86568d92b24af8d82/yarp/RegistryRecords.py
                # - self.read_binary(20, self.get_security_descriptor_size()) ... so it starts from 20

                # HeaderLength = 20
                # sd_bytes_len_bytes = sd_bytes[16:16+4]
                # sd_btes_len = int.from_bytes(sd_bytes_len_bytes, byteorder='little', signed=False) # struct.unpack('<L', sd_bytes_len_bytes)[0]
                # sd_bytes = sd_bytes[security_descriptor.HeaderLength:security_descriptor.HeaderLength + sd_btes_len]
                
                try:
                    # For some reason the HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" has no permission that way...
                    key_security_descriptor = windows_security_descriptor(sd_bytes)
                    key_owner = key_security_descriptor.owner_name
                    key_group = key_security_descriptor.group_name
                    key_permissions = key_security_descriptor.permissions
                except ValueError as msg:
                    logger.debug(msg)

        return key_security_descriptor, sd_bytes, key_owner, key_group, key_permissions

    def enum_root_subkeys(self, key_path, hive, reg_handler=None, key_name_pattern=None) -> list:

        subkeys = {}
        #  Check if both hive and key_path were given
        if hive:
            #  Case: key_path starts with *\
            logger.debug('ENUMERATE ROOT: %s, %s' % (hive.hive_file_path, key_path))

            try:
                key = hive.hive_obj.root()
                _subkey_names = []

                for _subkey in key.subkeys():
                    _subkey_name = _subkey.path()
                    _, __, _subkey_name = _subkey_name.rpartition('\\')

                    if key_name_pattern:
                        if re.search(key_name_pattern, _subkey_name, re.IGNORECASE):
                            _subkey_names.append(_subkey_name)
                    else:
                        _subkey_names.append(_subkey_name)

                subkeys['root'] = _subkey_names

            except Registry.RegistryKeyNotFoundException:
                logger.debug('KEY NOT FOUND: %s, %s' % (hive.hive_file_path, str(key_path)))
            except Exception as msg:
                logger.debug(
                    '%s: Key: %s\%s -> Unexpected error: %s' % (self.name, hive.hive_file_path, key_path, str(msg)))

            return subkeys

    def enum_key_subkeys(self, key_path, hive, reg_handler=None, key_name_pattern=None) -> list:

        subkeys = {}
        #  Check if both hive and key_path were given
        if key_path and hive:
            if not isinstance(key_path, list):
                key_path = [key_path]

            _keys = []

            for _key in key_path:
                _current_key = _key
                if _key[-1:] == '\\':
                    _key = _key[:-1]

                logger.debug('ENUMERATE: %s, %s' % (hive.hive_file_path, _key))

                try:
                    key = hive.hive_obj.open(_key)
                    _subkey_names = []

                    for _subkey in key.subkeys():
                        _subkey_name = _subkey.path()
                        _, __, _subkey_name = _subkey_name.rpartition('\\')

                        #  Return only the keys matching the regex pattern
                        if key_name_pattern:
                            if re.search(key_name_pattern, _subkey_name, re.IGNORECASE):
                                _subkey_names.append(_subkey_name)
                        else:
                            _subkey_names.append(_subkey_name)

                    subkeys[_current_key] = _subkey_names

                except Registry.RegistryKeyNotFoundException:
                    logger.debug('KEY NOT FOUND: %s, %s' % (hive.hive_file_path, _key))
                    continue
                except Exception as msg:
                    logger.debug(
                        '%s: Key: %s\%s -> Unexpected error: %s' % (self.name, hive.hive_file_path, _key, str(msg)))

            return subkeys

    def get_key_obj(self, hive, key_path):

        try:
            return hive.hive_obj.open(key_path)
        except Registry.RegistryKeyNotFoundException:
            logger.debug('KEY NOT FOUND: %s, %s' % (hive.hive_file_path, key_path))
            return None
        except Exception as msg:
            logger.debug(
                '%s: Key: %s\%s -> Unexpected error: %s' % (self.name, hive.hive_file_path, key_path, str(msg)))
            return None

    def query_key_recursive(self, hive, key_obj, reg_handler=None, depth=0, items=None, plugin_name='') -> list:

        if items is None: items = []

        if key_obj:

            _registry_key = None
            _registry_values = []

            key = key_obj
            key_path = key.path()

            #  Strip the root key
            _, __, key_path = key_path.partition('\\')

            logger.debug('QUERY: %s, %s' % (hive.hive_file_path, key_path))

            #  Parse registry key
            #  Create registry_item object
            _registry_item = registry_provider.registry_item()
            _registry_key = self.parse_key_obj(key_obj=key, reg_handler=reg_handler, reg_item_obj=_registry_item)

            #  The key has values
            if key.values():

                for value in key.values():

                    value_obj = self.parse_value_obj(_key=key_path, value_obj=value, reg_handler=reg_handler, reg_item_obj=_registry_item)
                    _registry_values.append(value_obj)

            _registry_item.add(_plugin_name=plugin_name, _registry_hive=hive, _registry_key=_registry_key,
                                                   _registry_values=_registry_values, _key_obj=key_obj)

            #  Extend the list with newly created registry_item
            if _registry_item:
                items.append(_registry_item)

            #  Follow the query actions for all subkeys (recursive mode)
            for subkey in key.subkeys():
                self.query_key_recursive(key_obj=subkey, hive=hive, reg_handler=reg_handler, depth=depth + 1, items=items
                                         ,plugin_name=plugin_name)
        else:
            logger.warning('KEY NOT FOUND')
            return []

        return items

    def query_key(self, key_path, hive, reg_handler=None, plugin_name='') -> list:

        _registry_key = None
        _registry_values = []

        #  Check if both hive and key_path were given
        if key_path and hive:
            if not isinstance(key_path, list):
                key_path = [key_path]

            _keys = []

            for _key in key_path:
                logger.debug('QUERY: %s, %s' % (hive.hive_file_path, _key))

                try:
                    key = hive.hive_obj.open(_key)
                except Registry.RegistryKeyNotFoundException:
                    logger.debug('KEY NOT FOUND: %s, %s' % (hive.hive_file_path, _key))
                    continue
                except Exception as msg:
                    logger.debug('%s: Key: %s\%s -> Unexpected error: %s' % (self.name, hive.hive_file_path, _key, str(msg)))
                    continue

                _registry_item = registry_provider.registry_item()
                _registry_key = self.parse_key_obj(key_obj=key, reg_handler=reg_handler, reg_item_obj=_registry_item)

                #  The key has values
                if key.values():

                    for value in key.values():

                        value_obj = self.parse_value_obj(_key=_key, value_obj=value, reg_handler=reg_handler, reg_item_obj=_registry_item)
                        _registry_values.append(value_obj)


                _registry_item.add(_plugin_name=plugin_name, _registry_hive=hive,
                                                             _registry_key=_registry_key, _registry_values=_registry_values, _key_obj=key)

                if _registry_item:
                    _keys.append(_registry_item)

                _registry_values = []
                _registry_key = None

            return _keys

        else:
            logger.error('The key_path to query was not specified or hive not initialized properly')
            return None

    def query_value_regex(self, key_path, value_name_pattern, hive, reg_handler=None, plugin_name=''):

        _registry_key = None
        _items = []
        _registry_values = []

        #  Check if both hive and key_path were given
        if key_path and hive:
            if not isinstance(key_path, list):
                value_path = [key_path]

            for _value_path in value_path:

                logger.debug('QUERY VALUE: %s, %s' % (hive.hive_file_path, _value_path))

                try:
                    if key_path is not None:
                        key = hive.hive_obj.open(key_path)
                    else:
                        key = hive.hive_obj.root()

                    #  Query all values and make filtering based on value_name_pattern
                    if key.values():
                        for value in key.values():

                            if re.search(value_name_pattern, value.name(), re.IGNORECASE):
                                _registry_values.append(self.parse_value_obj(_key=key_path, value_obj=value,
                                                                         reg_handler=reg_handler))

                except Registry.RegistryKeyNotFoundException:
                    logger.debug('KEY NOT FOUND: %s, %s' % (hive.hive_file_path, key_path))
                    continue
                except Registry.RegistryValueNotFoundException:
                    logger.debug('VALUE NOT FOUND: %s, %s' % (hive.hive_file_path, key_path + '\\' + value_name_pattern))
                    continue
                except Exception as msg:
                    logger.debug(
                        '%s: Value: %s\%s -> Unexpected error: %s' % (
                        self.name, hive.hive_file_path, key_path + '\\' + value_name_pattern, str(msg)))
                    continue

                if _registry_values:

                    _registry_item = registry_provider.registry_item()
                    _registry_key = self.parse_key_obj(key_obj=key, reg_handler=reg_handler, reg_item_obj=_registry_item)

                    _registry_item.add(_plugin_name=plugin_name, _registry_hive=hive,
                                                                  _registry_key=_registry_key,
                                                                  _registry_values=_registry_values, _key_obj=key)
                    if _registry_item:
                        _items.append(_registry_item)
                else:
                    return []

                _registry_values = []
                _registry_key = None
                value = None

            return _items

        else:
            logger.error('The value_path to query was not specified or hive not initialized properly')
            return None

    def query_value(self, value_path, hive, reg_handler=None, plugin_name='') -> list:

        _registry_key = None
        _items = []
        value = None

        #  Check if both hive and key_path were given
        if value_path and hive:
            if not isinstance(value_path, list):
                value_path = [value_path]

            for _value_path in value_path:

                #  IF there is no \\, the key shall be initialized with hive's root key
                if "\\" in _value_path:
                    _key_path, __, _value_name = _value_path.rpartition('\\')
                else:
                    _key_path = None
                    _value_name = _value_path

                try:
                    logger.debug('QUERY VALUE: %s, %s' % (hive.hive_file_path, _value_path))
                except:
                    test = ""

                try:

                    if _key_path is not None:
                        key = hive.hive_obj.open(_key_path)
                    else:
                        key = hive.hive_obj.root()

                    #  Query value
                    value = key.value(_value_name)

                except Registry.RegistryKeyNotFoundException:

                    logger.debug('KEY NOT FOUND: %s, %s' % (hive.hive_file_path, _key_path))
                    continue
                except Registry.RegistryValueNotFoundException:
                    logger.debug('VALUE NOT FOUND: %s, %s' % (hive.hive_file_path, _value_path))
                    continue
                except Exception as msg:
                    logger.debug(
                        '%s: Value: %s\%s -> Unexpected error: %s' % (self.name, hive.hive_file_path, _value_path, str(msg)))
                    continue

                _registry_item = registry_provider.registry_item()
                _registry_key = self.parse_key_obj(key_obj=key, reg_handler=reg_handler, reg_item_obj=_registry_item)
                value = self.parse_value_obj(_key=_key_path, value_obj=value, reg_handler=reg_handler, reg_item_obj=_registry_item)

                _registry_item.add(_plugin_name=plugin_name, _registry_hive=hive,
                                                             _registry_key=_registry_key,
                                                             _registry_values=[value],
                                                             _key_obj=key)
                if _registry_item:
                    _items.append(_registry_item)

                _registry_values = []
                _registry_key = None
                value = None

            return _items

        else:
            logger.error('The value_path to query was not specified or hive not initialized properly')
            return None

    def search_create_item(self, plugin_name, hive, key, values=None, reg_handler=None, parse_security_descriptor=True, custom_fields=None):

        #  Create key object (if necessary)
        if isinstance(key, Registry.RegistryKey):
            _registry_key = self.parse_key_obj(key_obj=key, reg_handler=reg_handler, parse_security_descriptor=parse_security_descriptor)
        else:
            _registry_key = key

        #  Create value object (if necessary)
        if values is None:
            registry_values = []
        else:
            registry_values = [self.parse_value_obj(_key=key.path(), value_obj=value, reg_handler=reg_handler) for value in values]

        _registry_item = registry_provider.registry_item()


        _registry_item.add(_plugin_name=plugin_name, _registry_hive=hive, _registry_key=_registry_key,
                           _registry_values=registry_values, custom_fields=custom_fields, _key_obj=key)

        return _registry_item

    def search_evaluate_pattern(self, hive, key, search_pattern, reg_handler=None, case_sensitive=False, plugin_name='search'):

        #  Create key and value object
        _registry_value = None
        _registry_key = None
        parse_security_descriptor = False

        key_path = key.path()
        key_values = key.values()
        key_owner = ''
        key_group = ''
        key_permissions = ''
        key_sd = None

        # First process key related pattern matching
        # Check all enabled key Patterns:

        # -ks
        if search_pattern.KEY_STRING_PATTERN:

            if search_pattern.eval(input_data=key_path, pattern_table=search_pattern.KEY_STRING_PATTERN,
                                   case_sensitive=case_sensitive):

                yield self.search_create_item(plugin_name=plugin_name, hive=hive, key=key, values=key_values,
                                              reg_handler=reg_handler, parse_security_descriptor=parse_security_descriptor)

                # Do not continue
                return None

        # -kr
        if search_pattern.KEY_REGEX_PATTERN:
            if search_pattern.eval(input_data=key_path, pattern_table=search_pattern.KEY_REGEX_PATTERN,
                                   case_sensitive=case_sensitive):

                yield self.search_create_item(plugin_name=plugin_name, hive=hive, key=key, values=key_values,
                                              reg_handler=reg_handler, parse_security_descriptor=parse_security_descriptor)

                # Do not continue
                return None

        # -kd
        if search_pattern.KEY_DATE_TIMESTAMP_PATTERN:
            if search_pattern.eval(input_data=key.timestamp(), pattern_table=search_pattern.KEY_DATE_TIMESTAMP_PATTERN,
                                   case_sensitive=case_sensitive):

                yield self.search_create_item(plugin_name=plugin_name, hive=hive, key=key, values=key_values,
                                              reg_handler=reg_handler, parse_security_descriptor=parse_security_descriptor)

                # Do not continue
                return None

        # -kb
        if search_pattern.KEY_BINARY_PATTERN:
            if search_pattern.eval(input_data=bytes(key_path, "utf-16le"),
                                           pattern_table=search_pattern.KEY_BINARY_PATTERN,
                                           case_sensitive=case_sensitive):

                yield self.search_create_item(plugin_name=plugin_name, hive=hive, key=key, values=key_values,
                                              reg_handler=reg_handler, parse_security_descriptor=parse_security_descriptor)

                # Do not continue
                return None

        # -kt
        if search_pattern.KEY_REGEX_TIMESTAMP_PATTERN:
            if search_pattern.eval(input_data=key.timestamp(),
                                           pattern_table=search_pattern.KEY_REGEX_TIMESTAMP_PATTERN,
                                           case_sensitive=case_sensitive):

                yield self.search_create_item(plugin_name=plugin_name, hive=hive, key=key, values=key_values,
                                              reg_handler=reg_handler, parse_security_descriptor=parse_security_descriptor)

                # Do not continue
                return None

        # -ko
        if search_pattern.KEY_REGEX_OWNER_PATTERN:
            key_sd, key_owner, key_group, key_permissions = self.get_key_dacl(sk_record=key._nkrecord.sk_record())
            if search_pattern.eval(input_data=key_owner, pattern_table=search_pattern.KEY_REGEX_OWNER_PATTERN,
                                           case_sensitive=case_sensitive):

                yield self.search_create_item(plugin_name=plugin_name, hive=hive, key=key, values=key_values,
                                              reg_handler=reg_handler, parse_security_descriptor=parse_security_descriptor)

                # Do not continue
                return None

        # -kp
        if search_pattern.KEY_REGEX_PERMISSIONS_PATTERN:
            key_sd, key_owner, key_group, key_permissions = self.get_key_dacl(sk_record=key._nkrecord.sk_record())
            if search_pattern.eval(input_data=key_permissions, pattern_table=search_pattern.KEY_REGEX_PERMISSIONS_PATTERN,
                                           case_sensitive=case_sensitive):

                yield self.search_create_item(plugin_name=plugin_name, hive=hive, key=key, values=key_values,
                                              reg_handler=reg_handler, parse_security_descriptor=parse_security_descriptor)

                # Do not continue
                return None

        # Next, process value related patterns
        if key_values:

            _registry_values = []

            for value in key_values:

                value_content_str = str(value.value())
                value_name = value.name()

                # -vs
                if search_pattern.VALUE_NAME_STRING_PATTERN:
                    if search_pattern.eval(input_data=value_name, pattern_table=search_pattern.VALUE_NAME_STRING_PATTERN, case_sensitive=case_sensitive):
                        _registry_values.append(value)

                        # Do not continue
                        break

                # -vr
                if search_pattern.VALUE_NAME_REGEX_PATTERN:
                    if search_pattern.eval(input_data=value_name, pattern_table=search_pattern.VALUE_NAME_REGEX_PATTERN, case_sensitive=case_sensitive):
                        _registry_values.append(value)

                        # Do not continue
                        break

                # -vb
                if search_pattern.VALUE_NAME_BINARY_PATTERN:
                    if search_pattern.eval(input_data=bytes(value_name, "utf-16le"), pattern_table=search_pattern.VALUE_NAME_BINARY_PATTERN, case_sensitive=case_sensitive):
                        _registry_values.append(value)

                        # Do not continue
                        break

                # -dl
                if search_pattern.VALUE_SIZE_PATTERN:
                    if search_pattern.eval(input_data=len(value.raw_data()), pattern_table=search_pattern.VALUE_SIZE_PATTERN, case_sensitive=case_sensitive):
                        _registry_values.append(value)

                        # Do not continue
                        break

                # -ds
                if search_pattern.VALUE_CONTENT_STRING_PATTERN:
                    if search_pattern.eval(input_data=value_content_str, pattern_table=search_pattern.VALUE_CONTENT_STRING_PATTERN, case_sensitive=case_sensitive):
                        _registry_values.append(value)

                        # Do not continue
                        break

                # -dr
                if search_pattern.VALUE_CONTENT_REGEX_PATTERN:
                    if search_pattern.eval(input_data=value_content_str, pattern_table=search_pattern.VALUE_CONTENT_REGEX_PATTERN, case_sensitive=case_sensitive):
                        _registry_values.append(value)

                        # Do not continue
                        break

                # -db
                if search_pattern.VALUE_CONTENT_BINARY_PATTERN:
                    if search_pattern.eval(input_data=value.raw_data(), pattern_table=search_pattern.VALUE_CONTENT_BINARY_PATTERN, case_sensitive=case_sensitive):
                        _registry_values.append(value)

                        # Do not continue
                        break


            if _registry_values:
                yield self.search_create_item(plugin_name=plugin_name, hive=hive, key=key, values=_registry_values,
                                                      reg_handler=reg_handler, parse_security_descriptor=parse_security_descriptor)

    def search(self, hive, key, search_pattern, reg_handler=None, case_sensitive=False, depth=0, items=None, plugin_name='search'):

        if items is None: items = []

        if depth == 0:
            try:
                items.extend(self.search_evaluate_pattern(hive=hive, key=key, search_pattern=search_pattern, reg_handler=reg_handler, case_sensitive=case_sensitive))
            except Exception as ex:
                print(f"Exception: Key {key.path()} -> Error: {str(ex)}")

        for subkey in key.subkeys():
            try:
                items.extend(self.search_evaluate_pattern(hive=hive, key=subkey, search_pattern=search_pattern, reg_handler=reg_handler, case_sensitive=case_sensitive))
            except Exception as ex:
                print(f"Exception: Key {key.path()} -> Error: {str(ex)}")

            # Recursive search
            self.search(hive=hive, key=subkey, search_pattern=search_pattern, reg_handler=reg_handler, case_sensitive=case_sensitive, depth=depth + 1, items=items)

        return items

    def Search(self, plugin_name, search_pattern, search_pattern_eval_func, hive, key, reg_handler=None,
               case_sensitive=False, depth=0, items=None):

        if items is None: items = []

        if depth == 0:
            try:
                items.extend(search_pattern_eval_func(hive=hive, key=key, search_pattern=search_pattern,
                                                   reg_handler=reg_handler, case_sensitive=case_sensitive,
                                                      plugin_name= plugin_name, search_create_item=self.search_create_item))
            except Exception as ex:
                print(f"Exception: Key {key.path()} -> Error: {str(ex)}")

        for subkey in key.subkeys():
            try:
                items.extend(search_pattern_eval_func(hive=hive, key=subkey, search_pattern=search_pattern,
                                                   reg_handler=reg_handler, case_sensitive=case_sensitive,
                                                      plugin_name=plugin_name, search_create_item=self.search_create_item))
            except Exception as ex:
                print(f"Exception: Key {key.path()} -> Error: {str(ex)}")

            # Recursive search
            self.Search(plugin_name=plugin_name, search_pattern_eval_func=search_pattern_eval_func,
                        search_pattern=search_pattern, hive=hive, key=subkey, reg_handler=reg_handler,
                        case_sensitive=case_sensitive, depth=depth + 1, items=items)

        return items