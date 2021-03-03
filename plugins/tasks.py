"""
References:
https://github.com/gtworek/PSBits/blob/master/DFIR/GetDynamicTaskInfo.ps1
"""

import logging
import struct
from datetime import datetime
from datetime import timedelta
from io import BytesIO

from md.plugin import plugin
from md.args import build_registry_handler
from providers.provider import registry_provider

from datetime import datetime

logger = logging.getLogger('regmagnet')

QUERY_KEY_LIST = [
    r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\*"
]

QUERY_VALUE_LIST = [
    # r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\*\DynamicInfo"
]

class tasks(plugin):
    """ tasks - RegMagnet plugin  """

    """ Standard expected variables  """
    author = 'wit0k'
    name = 'tasks'
    description = 'Prints Scheduled Tasks info'
    config_file = ''  # IF it's empty/None, the config_data dictionary would not be auto-loaded

    """ Variables initialized by the plugin manager """
    args = None  # Holds plugin related arguments
    parser = None  # Represents the registry_parser object
    config_data = {}  # Contains the json data loaded from config_file (If any was specified and properly created)

    """ Plugin specific variables """
    supported_hive_types = ["SOFTWARE"]  # Hive type must be upper case

    def __init__(self, params=None, parser=None):

        self.parser = parser
        self.add_format_fields(field_names=['evaluation'])

    class custom_registry_handlers:

        class dynamic_info:

            decription = 'dynamic_info -> Parses Tasks DynamicInfo structure'

            def parse(input_data, return_values=False):
                return tasks.custom_registry_handlers.dynamic_info.dynamic_info(input_data, return_values)

            def dynamic_info(input_data, return_values=False):

                # https://gist.github.com/Mostafa-Hamdy-Elgiar/9714475f1b3bc224ea063af81566d873
                EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
                HUNDREDS_OF_NANOSECONDS = 10000000

                def getFileTime(FILETIME_BUFFER): #wit0k, previous function

                    _filetime = int.from_bytes(FILETIME_BUFFER, byteorder='little', signed=True)

                    try:

                        _datetime = datetime.utcfromtimestamp((_filetime - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS)
                        _datetime_str = _datetime.strftime('%Y-%m-%d %H:%M:%S.%f')
                        return _datetime_str
                    except Exception as msg:
                        return '%s - Error: %s' % (_filetime, str(msg))

                if input_data:
                    if isinstance(input_data, bytes):

                        bin_data = BytesIO(input_data)

                        try:
                            DIVersion = bin_data.read(4)[0]  # actually 4 bytes, but the rest is 0.
                            DICreationTime = getFileTime(bin_data.read(8))
                            DILastStartTime = getFileTime(bin_data.read(8))
                            DILastStopTime = getFileTime(bin_data.read(8))

                            if return_values is True:
                                return DICreationTime, DILastStartTime, DILastStopTime
                            else:
                                return 'Created: %s; Started: %s; Stopped: %s' % (DICreationTime, DILastStartTime, DILastStopTime)

                        except Exception as msg:

                            if return_values is True:
                                return None, None, None

                            return str(msg)

                return input_data

    def run(self, hive, registry_handler=None) -> list:
        """ Execute plugin specific actions on the hive file provided
                    - The return value should be the list of registry_provider.registry_item objects """

        if not hive:
            logger.warning('Unsupported hive file')
            return []

        #  Load required registry provider
        self.load_provider()

        logger.debug('Plugin: %s -> Run(%s)' % (self.name, hive.hive_file_path))

        if not self.is_hive_supported(hive=hive):
            logger.warning('Unsupported hive type: %s' % hive.hive_type)
            return []

        items = []

        """ 
        _plugin_reg_handler = build_registry_handler(registry_parser=self.parser,
                                                     registry_handlers="dynamic_info<field>value_content",
                                                     custom_handlers=tasks.custom_registry_handlers)
        """

        registry_handler = self.choose_registry_handler(main_reg_handler=registry_handler, plugin_reg_handler=None)

        _items = self.parser.query_key_wd(
            key_path=QUERY_KEY_LIST,
            hive=hive,
            plugin_name=self.name,
            reg_handler=registry_handler
        )

        # _items = self.parser.query_value_wd(value_path=QUERY_VALUE_LIST, hive=hive, plugin_name=self.name, reg_handler=registry_handler)

        for reg_item in _items:
            if reg_item.has_values:
                for reg_value in reg_item.values:
                    if reg_value.value_name == 'DynamicInfo':
                        DICreationTime, DILastStartTime, DILastStopTime = tasks.custom_registry_handlers.dynamic_info.parse(reg_value.value_raw_data, True)

                        new_values_content_mapping = {
                            'CreationTime': DICreationTime,
                            'LastStartTime': DILastStartTime,
                            'LastStopTime': DILastStopTime
                        }
                        new_reg_values = []

                        for value_name in ['CreationTime', 'LastStartTime', 'LastStopTime']:
                            new_reg_values.append(registry_provider.registry_value(
                                _value_path=reg_value.value_path.replace('DynamicInfo', value_name),
                                _value_name=value_name,
                                _value_name_unicode=bytes(value_name, "utf-16le"),
                                _value_type=1,
                                _value_type_str="REG_SZ",
                                _value_content=new_values_content_mapping[value_name],
                                _value_content_str=new_values_content_mapping[value_name],
                                _value_content_unicode=bytes(new_values_content_mapping[value_name], "utf-16le"),
                                _value_size=len(new_values_content_mapping[value_name]),
                                _value_raw_data=new_values_content_mapping[value_name].encode()
                            ))

                        reg_item.values.extend(new_reg_values)

        if _items:
            items.extend(_items)

        return items
