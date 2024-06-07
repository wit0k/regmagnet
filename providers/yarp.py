# pip3 install https://github.com/msuhanov/yarp/archive/1.0.25.tar.gz

"""
TO DO:
- Move some unnecessary functions like search_evaluate_pattern to registry_parser class (to simplify new provider integration)
  > The use of a reference dictionary resolving the right functions on objects depending on provider
-
"""
import logging
import re

from os.path import getsize, basename, isfile

from yarp import *
from providers.provider import registry_provider
from md.security_descriptor import security_descriptor, windows_security_descriptor
from md.errors import CYELLOW, CEND

logger = logging.getLogger('regmagnet')

class yarp(registry_provider):

    name = 'yarp'

    def __init__(self):
        pass

    def get_winreg_mapping(self, hive_type, hive_file=None):
        # Hives are stored in HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\hivelist
        # Hive names explained in: https://msdn.microsoft.com/en-us/library/windows/desktop/ms724877(v=vs.85).aspx

        if isinstance(hive_type, str):
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
                if 'UsrClass'.upper() in hive_file.upper():
                    return r"HKEY_CURRENT_USER\Software\Classes"

            return 'Unknown'

    def load_hive(self, hive_file_path, hive_transaction_logs=None, skip_transaction_log_discovery=False, load_hive_object=False) -> registry_provider.registry_hive:

        if hive_transaction_logs is None: hive_transaction_logs = []

        logger.debug('Loading hive: %s' % hive_file_path)

        if hive_transaction_logs and skip_transaction_log_discovery == False:

            logger.debug('Looking for specified transaction logs...')

            #  Make sure that the list of transaction logs has len of 3
            while len(hive_transaction_logs) < 3:
                hive_transaction_logs.append("")

            index = 0
            for tlog in hive_transaction_logs:

                # Assign transaction log path if it exist()
                if isfile(tlog):
                    hive_transaction_logs[index] = tlog
                else:
                    hive_transaction_logs[index] = None

                index += 1

            #  Get the transaction logs in expected format
            transaction_logs = RegistryHelpers.DiscoveredLogFiles(log_path=hive_transaction_logs[0], log1_path=hive_transaction_logs[1], log2_path=hive_transaction_logs[2])

        elif not hive_transaction_logs and skip_transaction_log_discovery == False:

            msg = 'Trying to discover transaction logs for: %s' % hive_file_path
            logger.debug(msg)

            print(CYELLOW + '[+] %s ...' % msg + CEND)

            # Discover transaction log files to be used to recover the primary file, if required.
            transaction_logs = RegistryHelpers.DiscoverLogFiles(hive_file_path)

        _hive_file_name = basename(hive_file_path)
        _hive_header = self.get_file_header(hive_file_path)

        try:
            logger.debug('Reading hive buffer: %s' % hive_file_path)
            hive_buffer = open(hive_file_path, 'rb')

            print(CYELLOW + '[+] %s ...' % "Creating hive object [Time consuming]" + CEND)

            _hive_obj = Registry.RegistryHive(hive_buffer)

            if any(True for log in [transaction_logs.log_path, transaction_logs.log1_path, transaction_logs.log2_path] if log is not None):

                print(CYELLOW + '[+] %s ...' % "Attempting to recover the hive..." + CEND)
                transaction_log_buffer = []

                for log in transaction_logs:
                    if log is not None and getsize(log) > 0:
                        transaction_log_buffer.append(open(log, 'rb'))
                    else:
                        transaction_log_buffer.append(None)

                try:
                    recovery_result = _hive_obj.recover_auto(transaction_log_buffer[0], transaction_log_buffer[1], transaction_log_buffer[2])

                    if recovery_result.recovered:
                        print(CYELLOW + '[+] %s ...' % "The hive has been recovered successfully" + CEND)

                        # Refresh hive_buffer
                        hive_file_path = '%s.recovered' % hive_file_path
                        _hive_obj.save_recovered_hive(hive_file_path)
                        hive_buffer = open(hive_file_path, 'rb').read()

                    else:
                        print(CYELLOW + '[+] %s ...' % "The hive recovery is not required, since it's not dirty" + CEND)

                except Registry.AutoRecoveryException as msg:
                    recovery_result = None
                    print(CYELLOW + '[+] %s ...' % str(msg) + CEND)

            else:
                if skip_transaction_log_discovery:
                    print(CYELLOW + '[+] %s ...' % "Hive recovery skipped" + CEND)
                else:
                    print(CYELLOW + '[+] %s ...' % "No transaction logs found" + CEND)

        except Exception:
            logger.warning('Unable to load hive: %s -> Header: %s' % (hive_file_path, _hive_header))
            return None

        logger.debug('Checking hive type...')
        _hive_type = Registry.GuessHiveRole(hive_buffer)

        if not _hive_type:
            if 'UsrClass'.upper() in _hive_file_name.upper():
                _hive_type = "USRCLASS"
            else:
                _hive_type = "UNKNOWN"


        if 'NTUSER/DEFAULT' in _hive_type:
            _hive_type = 'NTUSER'

        logger.debug('Getting hive mapping...')
        _hive_mapping = self.get_winreg_mapping(_hive_type)

        if _hive_type:
            _, __, _hive_type = str(_hive_type).rpartition('.')

        try:
            _hive_root = _hive_obj.root_key().path(show_root=True)
        except Exception:
            logger.error('Unable to get the root key, the hive might be corrupted')
            return None

        _hive_size = getsize(hive_file_path)

        _user_sid = ''
        if _hive_type == 'NTUSER':
            try:
                key = _hive_obj.find_key("Software\Microsoft\Protected Storage System Provider").subkeys()
                key = key.__next__()

                if key:
                    _user_sid = key.name()
                else:
                    _user_sid = ''
            except Exception:
                user_sid = ''

        hive_buffer = open(hive_file_path, 'rb').read()

        # Refersh hive
        # hive_header, hive_file_path, hive_file_name, hive_type, hive_root, hive_size, hive_obj=None, meta_data={}
        _hive = registry_provider.registry_hive(hive_header=_hive_header, hive_file_path=hive_file_path,
                                                hive_file_name=_hive_file_name, hive_type=_hive_type,
                                                hive_root=_hive_root,
                                                hive_size=_hive_size, hive_obj=_hive_obj, hive_user=_user_sid,
                                                hive_mapping=_hive_mapping, hive_buffer=hive_buffer)

        return _hive

    def parse_value_obj(self, _key, value_obj, reg_handler, reg_item_obj=None) -> registry_provider.registry_value:

        try:
            value_name = value_obj.name()

            if value_name == "\0" or value_name == "\x00":
                value_name = ""

        except Exception as msg:
            logger.error('value_obj.name() -> Exception: %s' % str(msg))
            value_name = '<value_name_error>'

        value_path = _key + "\\" + value_name
        value_name_unicode = bytes(value_name, "utf-16le")
        value_type = value_obj.type_raw()
        value_type_str = value_obj.type_str()
        value_content = value_obj.data()
        value_content_str = str(value_content)
        value_content_unicode = value_obj.data_raw()  #  I am not sure need to check it
        value_size = value_obj.data_size()
        value_raw_data = value_obj.data_raw()

        if value_type in [1, 2]:
            value_content = value_content.rstrip('\0')
            value_content = value_content.rstrip('\x00')


        value_item = registry_provider.registry_value(_value_path=value_path, _value_name=value_name,
                                                      _value_name_unicode=value_name_unicode, _value_type=value_type,
                                                      _value_type_str=value_type_str, _value_content=value_content,
                                                      _value_content_str=value_content_str, _value_content_unicode=value_content_unicode,
                                                      _value_size=value_size, _value_raw_data=value_raw_data)

        if reg_handler:
            reg_handler.process_fields(registry_obj=value_item, reg_item_obj=reg_item_obj)

        return value_item

    def parse_key_obj(self, key_obj, reg_handler, reg_item_obj, parse_security_descriptor=True) -> registry_provider.registry_key:

        key_path = key_obj.path()

        if key_path:
            # Strip the unnecessary root key
            if '\\' in key_path:
                _, __, key_path = key_path.partition('\\')

        key_path_unicode = bytes(key_path, "utf-16le")
        key_timestamp = str(key_obj.last_written_timestamp())
        key_subkey_count = str(key_obj.subkeys_count())
        key_value_count = str(key_obj.values_count())
        key_dacl = str(key_obj.security().descriptor())        
        key_owner = ''
        key_group = ''
        key_permissions = ''
        key_sd_bytes = b''
        key_sd = None
        key_nk_record = None

        key_nk_record = registry_provider.nk_record(key_obj.key_node.buf)

        if parse_security_descriptor:

            sd_bytes = key_obj.security().descriptor()

            # sc = security_descriptor(security_descriptor_bytes=_sec_descriptor)

            if sd_bytes:
                key_sd, key_sd_bytes, key_owner, key_group, key_permissions = self.get_key_dacl(sk_record=sd_bytes)

                key_item = registry_provider.registry_key(_key_path=key_path, _key_path_unicode=key_path_unicode,
                                                          _key_timestamp=key_timestamp,
                                                          _key_subkey_count=key_subkey_count,
                                                          _key_value_count=key_value_count, _key_owner=key_owner,
                                                          _key_group=key_group, _key_permissions=key_permissions,
                                                          _key_obj=key_obj, _key_sd_bytes=key_sd_bytes, _key_security_descriptor=key_sd, key_nk_record=key_nk_record)

        else:

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

        try:
            key_sd_bytes = sk_record
            key_security_descriptor = windows_security_descriptor(sk_record)
            key_owner = key_security_descriptor.owner_name
            key_group = key_security_descriptor.group_name
            key_permissions = key_security_descriptor.permissions
        except ValueError as msg:
            logger.debug(msg)

        return key_security_descriptor, key_sd_bytes, key_owner, key_group, key_permissions

    """ ------------------------------------------------------------------------------------------------------------ """
    """                        ~~~~  Registry Enum Functionality ~~~~                                              """
    """ ------------------------------------------------------------------------------------------------------------ """
    def enum_root_subkeys(self, key_path, hive, reg_handler=None, key_name_pattern=None) -> list:

        subkeys = {}
        #  Check if both hive and key_path were given
        if hive:
            #  Case: key_path starts with *\
            logger.debug('ENUMERATE ROOT: %s, %s' % (hive.hive_file_path, key_path))

            try:
                key = hive.hive_obj.root_key()

                if key is None:
                    logger.debug('KEY NOT FOUND: %s, %s' % (hive.hive_file_path, str(key_path)))
                    return subkeys

                _subkey_names = []

                for _subkey in key.subkeys():
                    _subkey_name = _subkey.path()
                    _, __, _subkey_name = _subkey_name.rpartition('\\')

                    if key_name_pattern:
                        if re.search(key_name_pattern, _subkey_name, re.IGNORECASE):
                            _subkey_names.append(_subkey_name)
                    else:
                        _subkey_names.append(_subkey_name)

                subkeys[key_path] = _subkey_names

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
                    key = hive.hive_obj.find_key(_key) if _key.lower() != hive.hive_root.lower() else hive.hive_obj.root_key()

                    if key is None:
                        logger.debug('KEY NOT FOUND: %s, %s' % (hive.hive_file_path, _key))
                        continue

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

                except Exception as msg:
                    logger.debug(
                        'EnumSubKeys: %s: Key: %s\%s -> Unexpected error: %s' % (self.name, hive.hive_file_path, _key, str(msg)))

            return subkeys

    def get_key_obj(self, hive, key_path):

        try:
            return hive.hive_obj.find_key(key_path)
        except Exception as msg:
            logger.error('GetKeyObj -> Exception: %s, %s -> %s' % (hive.hive_file_path, key_path, str(msg)))
            return None

    """ ------------------------------------------------------------------------------------------------------------ """
    """                        ~~~~  Registry Query Functionality ~~~~                                              """
    """ ------------------------------------------------------------------------------------------------------------ """
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
                    key = hive.hive_obj.find_key(_key)

                    if key:
                        _registry_item = registry_provider.registry_item()
                        _registry_key = self.parse_key_obj(key_obj=key, reg_handler=reg_handler,
                                                           reg_item_obj=_registry_item)

                        #  The key has values
                        if key.values_count():

                            loop = True
                            key_values = key.values()
                            while loop:
                                try:
                                    value = key_values.__next__()
                                    value_obj = self.parse_value_obj(_key=_key, value_obj=value,
                                                                     reg_handler=reg_handler,
                                                                     reg_item_obj=_registry_item)
                                    _registry_values.append(value_obj)

                                except StopIteration:
                                    loop = False

                        _registry_item.add(_plugin_name=plugin_name, _registry_hive=hive,
                                           _registry_key=_registry_key, _registry_values=_registry_values, _key_obj=key)

                        if _registry_item:
                            _keys.append(_registry_item)

                        _registry_values = []
                        _registry_key = None

                except Exception as msg:
                    logger.error('QueryKey -> Exception: %s, %s -> %s' % (hive.hive_file_path, _key, str(msg)))
                    continue

            return _keys

        else:
            logger.error('The key_path to query was not specified or hive not initialized properly')
            return []

    def query_value(self, value_path, hive, reg_handler=None, plugin_name='') -> list:

        _registry_key = None
        _items = []

        #  Check if both hive and value_path were given
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

                logger.debug('QUERY VALUE: %s, %s' % (hive.hive_file_path, _value_path))

                try:

                    if _key_path is not None:
                        key = hive.hive_obj.find_key(_key_path)

                    if key is None:
                        logger.debug('KEY NOT FOUND: %s, %s' % (hive.hive_file_path, _key_path))
                        continue

                    if _value_name == "(default)":
                        _value_name = ""

                    #  Query value
                    value = key.value(_value_name)

                    if value is None:
                        logger.debug('VALUE NOT FOUND: %s, %s' % (hive.hive_file_path, _value_path))
                        continue

                except Exception as msg:
                    logger.error('QueryValue -> Exception: %s, %s -> %s' % (hive.hive_file_path, _value_path, str(msg)))
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
            return []

    def query_value_regex(self, key_path, value_name_pattern, hive, reg_handler=None, plugin_name=''):

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
                    key = hive.hive_obj.find_key(_key)

                    if key:
                        _registry_item = registry_provider.registry_item()
                        _registry_key = self.parse_key_obj(key_obj=key, reg_handler=reg_handler,
                                                           reg_item_obj=_registry_item)

                        #  The key has values
                        if key.values_count():

                            loop = True
                            key_values = key.values()
                            while loop:
                                try:
                                    value = key_values.__next__()

                                    if re.search(value_name_pattern, value.name(), re.IGNORECASE):
                                        value_obj = self.parse_value_obj(_key=_key, value_obj=value,
                                                                         reg_handler=reg_handler,
                                                                         reg_item_obj=_registry_item)
                                        _registry_values.append(value_obj)

                                        _registry_item.add(_plugin_name=plugin_name, _registry_hive=hive,
                                                           _registry_key=_registry_key,
                                                           _registry_values=_registry_values, _key_obj=key)

                                except StopIteration:
                                    loop = False

                        if _registry_item:
                            _keys.append(_registry_item)

                        _registry_values = []
                        _registry_key = None

                except Exception as msg:
                    logger.error('QueryKey -> Exception: %s, %s -> %s' % (hive.hive_file_path, _key, str(msg)))
                    continue

            return _keys

        else:
            logger.error('The key_path to query was not specified or hive not initialized properly')
            return []

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
                                                   _registry_values=_registry_values, _key_obj=key)

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


    """ ------------------------------------------------------------------------------------------------------------ """
    """                        ~~~~  Registry Search Functionality ~~~~                                              """
    """ ------------------------------------------------------------------------------------------------------------ """

    def search_create_item(self, plugin_name, hive, key, values=None, reg_handler=None, parse_security_descriptor=True, custom_fields=None):

        #  Create key object (if necessary)
        if isinstance(key, Registry.RegistryKey):
            _registry_item = registry_provider.registry_item()
            _registry_key = self.parse_key_obj(key_obj=key, reg_handler=reg_handler, parse_security_descriptor=parse_security_descriptor, reg_item_obj=_registry_item)
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
        parse_security_descriptor = True

        key_path = key.path(show_root=True)
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
            if search_pattern.eval(input_data=key.last_written_timestamp(), pattern_table=search_pattern.KEY_DATE_TIMESTAMP_PATTERN,
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
            if search_pattern.eval(input_data=key.last_written_timestamp(),
                                           pattern_table=search_pattern.KEY_REGEX_TIMESTAMP_PATTERN,
                                           case_sensitive=case_sensitive):

                yield self.search_create_item(plugin_name=plugin_name, hive=hive, key=key, values=key_values,
                                              reg_handler=reg_handler, parse_security_descriptor=parse_security_descriptor)

                # Do not continue
                return None

        # -ko
        if search_pattern.KEY_REGEX_OWNER_PATTERN:
            key_sd, key_owner, key_group, key_permissions = self.get_key_dacl(sk_record=key.security().descriptor())
            if search_pattern.eval(input_data=key_owner, pattern_table=search_pattern.KEY_REGEX_OWNER_PATTERN,
                                           case_sensitive=case_sensitive):

                yield self.search_create_item(plugin_name=plugin_name, hive=hive, key=key, values=key_values,
                                              reg_handler=reg_handler, parse_security_descriptor=parse_security_descriptor)

                # Do not continue
                return None

        # -kp
        if search_pattern.KEY_REGEX_PERMISSIONS_PATTERN:
            key_sd, key_owner, key_group, key_permissions = self.get_key_dacl(sk_record=key.security().descriptor())
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

                value_content_str = str(value.data())
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
                    if search_pattern.eval(input_data=value.data_size(), pattern_table=search_pattern.VALUE_SIZE_PATTERN, case_sensitive=case_sensitive):
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
                    if search_pattern.eval(input_data=value.data_raw(), pattern_table=search_pattern.VALUE_CONTENT_BINARY_PATTERN, case_sensitive=case_sensitive):
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