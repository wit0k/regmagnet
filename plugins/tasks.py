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
    r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*",
    r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\*",

]

QUERY_VALUE_LIST = [
    # r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*\SD"
]

class windows_task:

    ACTION_TYPE_EXECUTE_PROGRAM = b'\x66\x66'
    ACTION_TYPE_COM_HANDLER = b'\x77\x77'
    ACTION_TYPE_SEND_EMAIL = b'\x88\x88'
    ACTION_TYPE_MSG_BOX = b'\x99\x99'
    ACTION_TYPE_UNSUPPORTED = None
    
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
    supported_hive_types = ["SOFTWARE", "USRCLASS"]  # Hive type must be upper case
    # loaded_hives -> Is filled by PluginManager and contains list of all loaded plugins

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

        class actions:

            decription = 'actions -> Parses Tasks Actions structure'

            def actions(input_data, return_values=False, task_path=''):
                
                if isinstance(input_data, bytes):
                    buffer_stream = BytesIO(input_data)
                    buffer_stream.seek(0)

                    action_signature = buffer_stream.read(2)
                    run_as_account = buffer_stream.read(int.from_bytes(buffer_stream.read(4), 'little')).decode(encoding='utf16', errors='ignore')
                    not_sure_2 = buffer_stream.read(6)  # Unknown at time

                    action_type = not_sure_2[0:2]

                    if windows_task.ACTION_TYPE_COM_HANDLER in action_type:
                        # task_buffer = buffer_stream.read()
                        # print(task_buffer.hex())
                        # Read BSTR ID

                        if '\Microsoft\Windows\Chkdsk\ProactiveScan' in task_path:
                            debug = ""

                        action_bytes = buffer_stream.read()
                        bstr_terminator = action_bytes.find(b'\x00\x00\x00\x00')
                        action_clsid = action_bytes[0:bstr_terminator]
                        action_clsid_str = '{%s-%s-%s-%s-%s}' % (action_clsid[0:4][::-1].hex(),action_clsid[4:6][::-1].hex(),
                                                                 action_clsid[6:8][::-1].hex(),action_clsid[8:10].hex(),
                                                                 action_clsid[10:16].hex())
                        
                        
                        return {'ACTION_TYPE': windows_task.ACTION_TYPE_COM_HANDLER,'CLSID': action_clsid_str, 'CMD': ''}

                    elif windows_task.ACTION_TYPE_EXECUTE_PROGRAM in action_type:

                        program_path = buffer_stream.read(int.from_bytes(buffer_stream.read(4), 'little')).decode(encoding='utf16', errors='ignore')
                        program_parameters = buffer_stream.read(int.from_bytes(buffer_stream.read(4), 'little')).decode(encoding='utf16', errors='ignore')
                        working_dir = buffer_stream.read(2)
                        if b'\x00\x00' in working_dir or b'' in working_dir:
                            working_dir = None
                        else:
                            working_dir = buffer_stream.read(int.from_bytes(working_dir, 'little')).decode(encoding='utf16', errors='ignore')

                        if not working_dir is None:
                            return {'ACTION_TYPE': windows_task.ACTION_TYPE_EXECUTE_PROGRAM,'CMD': '[RunAs: %s, Working_Dir: %s] %s %s' % (run_as_account, working_dir, program_path, program_parameters)}
                        else:
                            return {'ACTION_TYPE': windows_task.ACTION_TYPE_EXECUTE_PROGRAM,'CMD': '[RunAs: %s] %s %s' % (run_as_account, program_path, program_parameters)}
                    else:
                        return {'ACTION_TYPE': windows_task.ACTION_TYPE_UNSUPPORTED,'CMD': ''}


    def run(self, hive, registry_handler=None, args=None) -> list:
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

        def create_registry_values(reg_base_value, new_reg_value_names:list, new_values_content_mapping:dict):

            new_reg_values = []

            # Create new registry entires based on reg_base_value
            for value_name in new_reg_value_names:
                if value_name in new_values_content_mapping.keys():
                    new_reg_values.append(registry_provider.registry_value(
                        _value_path=reg_base_value.value_path.replace(reg_base_value.value_name, value_name),
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

            return new_reg_values

        for reg_item in _items:
            task_path = ""
            if reg_item.has_values:
                for reg_value in reg_item.values:
                    new_reg_values = []
                    new_values_content_mapping = {}
                    
                    if reg_value.value_name == 'Path':
                        task_path = reg_value.value_content_str

                    if reg_value.value_name == 'Actions':
                        Command = tasks.custom_registry_handlers.actions.actions(reg_value.value_raw_data, True, task_path)

                        if isinstance(Command, dict):
                            # This is quick and dirty workaround, i need to improve it later
                            if Command.get('ACTION_TYPE', None) == windows_task.ACTION_TYPE_COM_HANDLER:
                                clsid_str = Command.get('CLSID', None)
                                if clsid_str:
                                    # Query values:
                                    # SOFTWARE -> 'Classes\CLSID\%s\(Default)' 
                                    # USRCLASS -> 'CLSID\%s\(Default)' 
                                    class_handlers = []
                                    for _hive in self.loaded_hives:
                                        class_handlers.extend(self.parser.query_value(value_path=[
                                            'Classes\CLSID\%s\InProcServer32\(default)' % clsid_str, 'CLSID\%s\InProcServer32\(default)' % clsid_str], 
                                            hive=_hive.get('hive'), plugin_name=self.name, reg_handler=None))
                                    
                                    if len(class_handlers) == 0:
                                        Command = '<COM_HANDLER_NOT_FOUND>'
                                    else:
                                        vals = []
                                        for item in class_handlers:
                                            ritems = item.items()
                                            if len(ritems) > 0:
                                                for ritem in ritems:
                                                    if ritem.get('value_content', None):
                                                        vals.append(ritem.get('value_content', None))
                                        
                                        if len(vals) > 0:
                                            Command = '\n'.join(vals)
                                            Command = '"%s -> %s"' % (clsid_str, Command)
                                        else:
                                            Command = '<COM_HANDLER_VALUES_NOT_FOUND>'
                                            Command = '"%s -> %s"' % (clsid_str, Command)
                                            
                                else:
                                    Command = '<UNABLE_TO_GET_CLSID>'
                                    Command = '"None -> %s"' % (clsid_str, Command)
                                
                            else:
                                Command = Command.get('CMD', '')

                        new_values_content_mapping.update({
                            'Actions_': Command,
                        }) #custom_registry_handlers

                        reg_item.values.extend(
                            create_registry_values(
                                reg_base_value=reg_value,
                                new_reg_value_names=['Actions_'],
                                new_values_content_mapping=new_values_content_mapping,
                            )
                        )

                    if reg_value.value_name == 'DynamicInfo':
                        DICreationTime, DILastStartTime, DILastStopTime = tasks.custom_registry_handlers.dynamic_info.parse(reg_value.value_raw_data, True)

                        new_values_content_mapping.update({
                            'CreationTime': DICreationTime,
                            'LastStartTime': DILastStartTime,
                            'LastStopTime': DILastStopTime
                        })

                        reg_item.values.extend(
                            create_registry_values(
                                reg_base_value=reg_value,
                                new_reg_value_names=['CreationTime', 'LastStartTime', 'LastStopTime'],
                                new_values_content_mapping=new_values_content_mapping,
                            )
                        )

                    # Add all newly created items back to general list
                    reg_item.values.extend(new_reg_values)

        if _items:
            items.extend(_items)

        return items
