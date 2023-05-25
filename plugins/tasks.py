__version__ = '0.6'

import logging
import struct
import argparse

from pathlib import Path 

from datetime import datetime, timedelta

from io import BytesIO

from md.plugin import plugin
from md.args import build_registry_handler
from providers.provider import registry_provider

from md.windows_scheduled_tasks import actions as task_actions
from md.windows_scheduled_tasks import dynamic_info as task_dynamic_info
from kaitaistruct import KaitaiStream
from os.path import join, abspath, dirname
import yara

logger = logging.getLogger('regmagnet')

QUERY_KEY_LIST = []

QUERY_VALUE_LIST = []

class buffer:

    class buffer_type:
        string = 1
        bytes = 2

    def convert_value(value, _type=buffer_type.bytes):

        if _type == buffer.buffer_type.string:
            
            if value is None:
                value = 'None'

            elif isinstance(value, int):
                value = str(value)
                
            elif isinstance(value, bytes):
                value = value.decode(errors='ignore')
                
            elif isinstance(value, list):
                value = str('|'.join(value))
        
        else:
            if value is None:
                value = 'None'.encode()

            elif isinstance(value, int):
                value = str(value).encode()
                
            elif isinstance(value, str):
                value = value.encode()

            elif isinstance(value, dict):
                value = str('ERROR: Dict_Not_Supported_Yet').encode()

            elif isinstance(value, list):
                value = str('|'.join(value)).encode()
            
            elif isinstance(value, bytes):
                return value

            else:
                value = 'Unsupported'.encode()
        
        return value

    def create(buffer_dict, _type=buffer_type.bytes):
        
        if _type == buffer.buffer_type.string:
            _buffer = ''
        else:
            _buffer = b''

        for key, value in buffer_dict.items():
        
            if isinstance(value, dict):
                for key, value in value.items():
                    _buffer += b'%s:%s|' % (key.encode(), buffer.convert_value(value))
            else:
                _buffer += b'%s:%s|' % (key.encode(), buffer.convert_value(value))
        
        return _buffer
            
class windows_task_parsed_data(object):

    actions = None
    dynamic_info = None
    job_schedule = None
    optional_settings = None
    triggers = None
    user_info = None
    sd = None

    def __init__(self):
        pass

    def json(self):
        
        return {
            'actions': self.actions,
            'dynamic_info': self.dynamic_info,
            'job_schedule': self.job_schedule,
            'optional_settings': self.optional_settings,
            'triggers': self.triggers,
            'user_info': self.user_info,
            'security_descriptor': self.sd,
        }

class windows_task_action_flat(object):

    version = None 
    context = None
    handler_type = None
    handler_type_str = None
    handler_payloads = None
    handler_payloads_count = None
    clsid = None
    data = None
    command = None
    arguments = None
    working_directory = None
    caption = None
    content = None
    to = None
    cc = None
    bcc = None
    reply_to = None
    server = None
    subject = None
    body = None
    num_attachment_filenames = None
    attachment_filenames = None
    num_headers = None
    headers = None
    blob = None
    size = None

    def __init__(self, field_names=None) -> None:
        pass
    
    def yara_blob(self):
        
        self.blob =  { 
            'variables': {
                '%s_headers_count' % windows_task.handler_type.name(windows_task.handler_type.SEND_EMAIL).lower(): self.num_headers,
                '%s_attachments_count' % windows_task.handler_type.name(windows_task.handler_type.SEND_EMAIL).lower(): self.num_attachment_filenames,
                '%s_payloads_count' % windows_task.handler_type.name(windows_task.handler_type.COM_HANDLER).lower(): self.handler_payloads_count,
                'handler_type': self.handler_type,
                'handler_type_str': self.handler_type_str,
                'action_size': self.size,
            },
            'buffer': buffer.create(self.json())
        }

        return self.blob

        
    def json(self, field_names=None) -> None:
        return {
            "handler_payloads_count": self.handler_payloads_count,
            "handler_payloads": self.handler_payloads,
            "handler_type": self.handler_type,
            "version": self.version,
            "context": self.context,
            "clsid": self.clsid,
            "data": self.data,
            "command": self.command,
            "arguments": self.arguments,
            "working_directory": self.working_directory,
            "caption": self.caption,
            "content": self.content,
            "to": self.to,
            "cc": self.cc,
            "bcc": self.bcc,
            "reply_to": self.reply_to,
            "server": self.server,
            "subject": self.subject,
            "body": self.body,
            "num_attachment_filenames": self.num_attachment_filenames,
            "attachment_filenames": self.attachment_filenames,
            "num_headers": self.num_headers,
            "headers": self.headers,
        }
    
    def __repr__(self) -> str:

        if self.handler_type == windows_task.handler_type.COM_HANDLER:
            return 'Action [Type: %s] -> Payload: %s -> data:"%s" -> Payloads: %s' % (self.handler_type_str, self.clsid, self.data, self.handler_payloads)

        if self.handler_type == windows_task.handler_type.EXECUTE_PROGRAM:
            return 'Action [Type: %s] -> Payload: %s %s [WD: %s]' % (self.handler_type_str, self.command, self.arguments, self.working_directory)
        
        if self.handler_type == windows_task.handler_type.SEND_EMAIL:
            return 'Action [Type: %s] -> Payload: ATTACHMENT_COUNT: %s TO:"%s" Content:"%s"' % (self.handler_type_str, self.num_attachment_filenames, self.to, self.content)
        
        if self.handler_type == windows_task.handler_type.MSG_BOX:
            return 'Action [Type: %s] -> Payload: %s %s' % (self.handler_type_str, self.caption, self.content)
    
    def payload(self) -> str:

        if self.handler_type == windows_task.handler_type.COM_HANDLER:
            # return '%s,%s" -> Payloads: %s' % (self.handler_type_str, self.clsid, self.data, self.handler_payloads)
            return '\n'.join(['%s' % payload for payload in self.handler_payloads])
           
        if self.handler_type == windows_task.handler_type.EXECUTE_PROGRAM:
            return '%s %s %s' % (self.command, self.arguments, self.working_directory)
        
        if self.handler_type == windows_task.handler_type.SEND_EMAIL:
            return 'ATTACHMENT_COUNT: "%s" TO:"%s" Content:"%s"' % (self.num_attachment_filenames, self.to, self.content)
        
        if self.handler_type == windows_task.handler_type.MSG_BOX:
            return 'CAPTION: "%s" CONTENT: "%s"' % (self.caption, self.content)
    
class windows_task_actions(object):
    
    version = None
    context = None
    obj = None
    actions = None
    count = None

    def __init__(self, buffer) -> None: 
        
        obj = task_actions.Actions(KaitaiStream(BytesIO(buffer)))
        
        if obj:
            
            self.obj = obj
            self.actions = []
            
            # Parse each action to windows_task_action_flat object 
            for _Action in self.obj.actions:
                
                _Action_obj = windows_task_action_flat()    
                _Action_obj.version = self.obj.version
                self.version = self.obj.version
                _Action_obj.context = self.obj.context.str
                self.context = self.obj.context.str

                if _Action.magic == windows_task.handler_type.COM_HANDLER:
                        
                    # clsid = _Action.properties.clsid.hex() is not correct, it must be reversed, hence:
                    _Action_obj.clsid = '{%s-%s-%s-%s-%s}' % (_Action.properties.clsid[0:4][::-1].hex(),_Action.properties.clsid[4:6][::-1].hex(),
                                                                 _Action.properties.clsid[6:8][::-1].hex(),_Action.properties.clsid[8:10].hex(),
                                                                 _Action.properties.clsid[10:16].hex())
                    _Action_obj.data = _Action.properties.data.str
                    _Action_obj.handler_type_str = windows_task.handler_type.name(windows_task.handler_type.COM_HANDLER)
                    _Action_obj.handler_type = windows_task.handler_type.COM_HANDLER

                if _Action.magic == windows_task.handler_type.EXECUTE_PROGRAM:

                    _Action_obj.command = _Action.properties.command.str
                    _Action_obj.arguments = _Action.properties.arguments.str
                    _Action_obj.working_directory = _Action.properties.working_directory.str
                    _Action_obj.handler_type_str = windows_task.handler_type.name(windows_task.handler_type.EXECUTE_PROGRAM)
                    _Action_obj.handler_type = windows_task.handler_type.EXECUTE_PROGRAM
                    
                if _Action.magic == windows_task.handler_type.MSG_BOX:

                    _Action_obj.caption = _Action.properties.caption.str
                    _Action_obj.content = _Action.properties.content.str
                    _Action_obj.handler_type = windows_task.handler_type.MSG_BOX
                    _Action_obj.handler_type_str = windows_task.handler_type.name(windows_task.handler_type.MSG_BOX)

                if _Action.magic == windows_task.handler_type.SEND_EMAIL:
                        
                    _Action_obj.to = _Action.properties.to.str
                    _Action_obj.cc = _Action.properties.cc.str
                    _Action_obj.bcc = _Action.properties.bcc.str
                    _Action_obj.reply_to = _Action.properties.reply_to.str
                    _Action_obj.server = _Action.properties.server.str
                    _Action_obj.subject =_Action.properties.subject.str
                    _Action_obj.body = _Action.properties.body.str
                    _Action_obj.num_attachment_filenames = _Action.properties.num_attachment_filenames
                    _Action_obj.attachment_filenames = _Action.properties.attachment_filenames
                    _Action_obj.num_headers = _Action.properties.num_headers
                    _Action_obj.headers = _Action.properties.headers
                    _Action_obj.handler_type = windows_task.handler_type.SEND_EMAIL
                    _Action_obj.handler_type_str = windows_task.handler_type.name(windows_task.handler_type.SEND_EMAIL)
                
                # Add parsed action
                _Action_obj.blob = _Action_obj.yara_blob()
                _Action_obj.size = len(_Action_obj.blob.get('buffer', b''))
                _Action_obj.blob['variables']['action_size'] = _Action_obj.size

                self.actions.append(_Action_obj)
            
            self.count = len(self.actions)

    def dynamic_parse(input_data):
        """ Old code - Do not use """

        if isinstance(input_data, bytes):
            buffer_stream = BytesIO(input_data)
            buffer_stream.seek(0)

            action_signature = buffer_stream.read(2)
            run_as_account = buffer_stream.read(int.from_bytes(buffer_stream.read(4), 'little')).decode(encoding='utf16', errors='ignore')
            not_sure_2 = buffer_stream.read(6)  # Unknown at time
            action_type = not_sure_2[0:2]

            if windows_task.handler_type.COM_HANDLER in action_type:

                action_bytes = buffer_stream.read()
                bstr_terminator = action_bytes.find(b'\x00\x00\x00\x00')
                action_clsid = action_bytes[0:bstr_terminator]
                action_clsid_str = '{%s-%s-%s-%s-%s}' % (action_clsid[0:4][::-1].hex(),action_clsid[4:6][::-1].hex(),
                                                         action_clsid[6:8][::-1].hex(),action_clsid[8:10].hex(),
                                                         action_clsid[10:16].hex())
                
                
                return {'ACTION_TYPE': windows_task.handler_type.COM_HANDLER,'CLSID': action_clsid_str, 'CMD': '[RunAs: %s]' % run_as_account}

            elif windows_task.handler_type.EXECUTE_PROGRAM in action_type:

                program_path = buffer_stream.read(int.from_bytes(buffer_stream.read(4), 'little')).decode(encoding='utf16', errors='ignore')
                program_parameters = buffer_stream.read(int.from_bytes(buffer_stream.read(4), 'little')).decode(encoding='utf16', errors='ignore')
                working_dir = buffer_stream.read(2)
                if b'\x00\x00' in working_dir or b'' in working_dir:
                    working_dir = None
                else:
                    working_dir = buffer_stream.read(int.from_bytes(working_dir, 'little')).decode(encoding='utf16', errors='ignore')

                if not working_dir is None:
                    return {'ACTION_TYPE': windows_task.handler_type.EXECUTE_PROGRAM,'CMD': '[RunAs: %s, Working_Dir: %s] %s %s' % (run_as_account, working_dir, program_path, program_parameters)}
                else:
                    return {'ACTION_TYPE': windows_task.handler_type.EXECUTE_PROGRAM,'CMD': '[RunAs: %s] %s %s' % (run_as_account, program_path, program_parameters)}
            else:
                return {'ACTION_TYPE': windows_task.handler_type.UNSUPPORTED,'CMD': ''}
                    
    def __repr__(self) -> str:
        return '\n'.join([a for a in self.actions])

class windows_task_dynamic_info(object):
    
    magic = None
    creation_time = None
    last_run_time = None
    task_state = None
    last_error_code = None
    last_successful_run_time = None

    def __init__(self, buffer) -> None: 
        
        obj = task_dynamic_info.DynamicInfo(KaitaiStream(BytesIO(buffer)))
        
        if obj:

            self.magic = str(obj.magic)
            self.creation_time = self.get_time(obj.creation_time)
            self.last_run_time = self.get_time(obj.last_run_time)
            self.task_state = obj.task_state
            self.last_error_code = obj.last_error_code
            self.last_successful_run_time = self.get_time(obj.last_successful_run_time)
    
    def get_time(self, FILETIME_BUFFER, format='%Y-%m-%d %H:%M:%S.%f'): #wit0k, previous function
                    
        # https://gist.github.com/Mostafa-Hamdy-Elgiar/9714475f1b3bc224ea063af81566d873
        EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
        HUNDREDS_OF_NANOSECONDS = 10000000

        if FILETIME_BUFFER: 
            # _filetime = int.from_bytes(FILETIME_BUFFER, byteorder='little', signed=True)
            _filetime = FILETIME_BUFFER
            try:

                _datetime = datetime.utcfromtimestamp((_filetime - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS)
                _datetime_str = _datetime.strftime(format)
                return _datetime_str
            except Exception as msg:
                return '%s - Error: %s' % (_filetime, str(msg))
        
        return None

class windows_task(object):

    class handler_type:

        EXECUTE_PROGRAM = 0x6666 # b'\x66\x66'
        COM_HANDLER = 0x7777 # b'\x77\x77'
        SEND_EMAIL = 0x8888 # b'\x88\x88'
        MSG_BOX = 0x9999 # b'\x99\x99'
        UNSUPPORTED = None

        # Holds mapping of handler types to str representation
        names = {
            EXECUTE_PROGRAM: 'EXECUTE_PROGRAM',
            COM_HANDLER: 'COM_HANDLER',
            SEND_EMAIL: 'SEND_EMAIL',
            MSG_BOX: 'MSG_BOX',
            UNSUPPORTED: 'UNSUPPORTED',
        }
            
        def name(handler_type_id, not_used=None):
            return windows_task.handler_type.names.get(handler_type_id, windows_task.handler_type.names[windows_task.handler_type.UNSUPPORTED])
        
    field_names = None
    data = None
    Path = None
    Uri = None
    SD = None
    Author = None
    Actions = None
    DynamicInfo = None
    blob = None
    detections = None

    def yara_blob(self):
        
        self.blob =  { 
            'variables': {
                'actions_count': self.data.actions.count,                                                           # Count of Actions 
                'actions_size': len(self.Actions),                                                                  # Total size of Actions buffer (in bytes)
                'actions_version': self.data.actions.version,                                                       # Actions Magic
                'actions_context': self.data.actions.context,                                                       # User context to execute the task/actions
                'actions_biggest_size': max([action.size for action in self.data.actions.actions]) ,                # The size of a biggest action
                'actions_smallest_size': min([action.size for action in self.data.actions.actions]),                # The size of a smallest action
                'dynamic_info_magic': self.data.dynamic_info.magic,                                                 # DynamicInfo Magic
                'dynamic_info_creation_time': self.data.dynamic_info.creation_time,                                 # DynamicInfo Task creation time
                'dynamic_info_last_run_time': self.data.dynamic_info.last_run_time,                                 # DynamicInfo Task Last Run time
                'dynamic_info_task_state': self.data.dynamic_info.task_state,                                       # DynamicInfo Task State
                'dynamic_info_last_error_code': self.data.dynamic_info.last_error_code,                             # DynamicInfo Last Error Code returned
                'dynamic_info_last_successful_run_time': self.data.dynamic_info.last_successful_run_time,           # DynamicInfo Last Successful run time
            }, 
            'actions': self.data.actions.actions,
            'buffer': buffer.create(self.json()),
        }
        return self.blob
    
    def json(self):

        ret  = {field_name: self.__getattribute__(field_name) for field_name in self.field_names}
        ret['data'] = self.data.json()
        return ret

    def __repr__(self) -> str:
        return 'Task: %s -> [Author: %s] -> Actions Count: %s' % (self.Path, self.Author, self.data.actions.count)
    
    def add_field(self, name, value):
        self.field_names.append(name)
        self.__setattr__(name, value)

    def __init__(self, field_names=None) -> None:
        
        if field_names is None: self.field_names = []
        self.data = windows_task_parsed_data()
    
    def process(self):
        """ Translate Raw Task Buffers/Values to corresponding objects
        """
        
        if self.Actions:
            self.data.actions = windows_task_actions(self.Actions)

        if self.DynamicInfo:
            self.data.dynamic_info = windows_task_dynamic_info(self.DynamicInfo)
        
        # I need to add parsing support later
        self.data.sd = self.SD
    
    def scan(self):
        
        # Refrences: 
        # - https://buildmedia.readthedocs.org/media/pdf/yara/latest/yara.pdf

        print('[+] SIG_SCAN Task: %s' % self.Path)
        external_variables = {}
        rule_paths = {}
        rule_matches = {}

        # Location of Yara rules 
        # rules_folder = join(dirname(abspath(__file__)).rstrip('\/plugins\/tasks.py'), 'signatures')  # it cuts t??????
        rules_folder = '/home/wit0k/repos/regmagnet/signatures'
        
        # Load all .yara files
        yara_rules = list(Path(rules_folder).rglob('*.yara'))

        # Initialize variable holding filepaths for Yara compile
        for yara_file in yara_rules:

            name_space = dirname(yara_file).split('/')[-1]
            name_suffix = 0
            org_name_space = name_space

            # Assure unique namespace name
            while name_space in rule_paths.keys():
                name_suffix += 1
                name_space = org_name_space + '_' + name_suffix

                if name_suffix > 1000:
                    raise Exception('Yara: Namespace duplication anomaly detected (Please contact Administrator)')

            rule_paths[name_space] = yara_file._str

        # Variable names which would be send to Yara engine
        task_variables = self.blob.get('variables', {})

        for action in self.blob.get('actions', []):
            
            scan_variables = None

            # Pull action specific variables 
            action_variables = action.blob.get('variables', {})

            # Copy Task and Action variables (Action variables may hold unique values per Action scan)
            scan_variables = task_variables.copy()
            scan_variables.update(action_variables.copy())
            
            # Format external variables
            for key, value in scan_variables.items():
                if value is None:
                    if '_count' in key:
                        scan_variables[key] = 0
                    else:
                        scan_variables[key] = 'None'

            # Compile all available Yara rules with task and action variables
            rules = yara.compile(filepaths=rule_paths, externals=scan_variables)

            matches = rules.match(data=self.blob.get('buffer', b''))

            for match in matches:
                rule_matches[match.rule] = {
                    'description': match.meta.get('description', ''),
                    'mitre_tid': match.meta.get('mitre_tid', ''),
                    'reference': match.meta.get('reference', ''),
                }

        if rule_matches:
            for detection_name, detection_data in rule_matches.items():
                logger.error(' [+] Suspicious Task: %s' % self.Path)
                logger.error('  [*] SIG_MATCH_FOUND: %s' % detection_name)
                logger.error('   [-] TID: %s -> Description: %s' % (detection_data.get('mitre_tid', 'None'), detection_data.get('description', 'None')) )
                logger.error('   [-] Action -> %s' % action)
            
            self.detections = list(rule_matches.keys())
                      
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
        """ Init function allowing plugin specific parameters """
        
        self.parser = parser
        self.add_format_fields(field_names=['tags'])
    
        argsparser = argparse.ArgumentParser(usage=argparse.SUPPRESS,
                                             description='Plugin: "%s" - %s' % (self.name, self.description))

        """ Argument groups """
        plugin_args = argsparser.add_argument_group('Plugin arguments', "\n")

        """ Script arguments """

        plugin_args.add_argument("-b", "--baseline", action='store_true', dest='baseline_enabled',
                                 required=False, default=False,
                                 help="Print or export items which are not part of baseline")
        
        plugin_args.add_argument("-s", "--sig-scan", action='store_true', dest='signature_scan_enabled',
                                 required=False, default=False,
                                 help="Scans parsed Scheduled Tasks against Yara rulesets (it fills Tags field on match)")
        
        plugin_args.add_argument("-r", "--raw", action='store_true', dest='raw_entries',
                                 required=False, default=False,
                                 help="...")


        plugin_args.add_argument("-rh", "--registry-handler", type=str, action='store', dest='registry_handlers',
                                 required=False,
                                 help="...")

        plugin_args.add_argument("-rhdp", "--registry-handler-decode-param", type=str, action='store',
                                 dest='rh_decode_param',
                                 required=False, default=None,
                                 help="...")

        self.parsed_args = argsparser.parse_args(args=params)
        argc = params.__len__()

        #  Convert required parameters to list
        self.format_parsed_args()

        #  Load Baseline file according to parameters specified
        self.load_baseline()
    
    def run(self, hive, registry_handler=None, args=None) -> list:
        """ Execute plugin specific actions on the hive file provided
                    - The return value should be the list of registry_provider.registry_item objects """

        _items = []

        # Proceed only with non-empty hives
        if not hive:
            logger.warning('Unsupported hive file')
            return []

        #  Load required registry provider
        self.load_provider()

        logger.debug('Plugin: %s -> Run(%s)' % (self.name, hive.hive_file_path))
        
        # Continue processing only for plugin supported registry hives
        if not self.is_hive_supported(hive=hive):
            logger.warning('Unsupported hive type: %s' % hive.hive_type)
            return []

        """ 
        _plugin_reg_handler = build_registry_handler(registry_parser=self.parser,
                                                     registry_handlers="dynamic_info<field>value_content",
                                                     custom_handlers=tasks.custom_registry_handlers)
        """

        # Build the registry handler specified in main regmagnet script (The one sent to all selected plugins)
        registry_handler = self.choose_registry_handler(main_reg_handler=registry_handler, plugin_reg_handler=None)

        # Query the key(s) specified
        # - Pull all Windows Scheduled Tasks from TaskCache"
        tasks = self.parser.query_key_wd(
            key_path=[r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\*"],
            hive=hive,
            plugin_name=self.name,
            reg_handler=registry_handler
        )

        # -----------------------------------------------------------------------------------------------------------.
        # Iterate over all tasks     
        for reg_item in tasks:
            
            # Query task tree/meta-data
            if reg_item.get_value('Path'):
                tree = self.parser.query_key_wd(
                        key_path=[r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree%s\*" % reg_item.get_value('Path')],
                        hive=hive,
                        plugin_name=self.name,
                        reg_handler=registry_handler)

                # Enrich Task's reg_item object with entries from Tree node
                for linked_reg_item in tree:
                    if linked_reg_item.has_values:
                        # for reg_value in linked_reg_item.values:
                        # Saves values from Tree\%task_path% to Tasks\%task_guid%
                        reg_item.add_values(linked_reg_item.values)
        # -----------------------------------------------------------------------------------------------------------.
        # - At this stage the reg_item contains values related to given task from Tree and Tasks node

        # Return all Tasks in raw format (not parsed)
        if self.parsed_args.raw_entries:
            return tasks

        # Iterate over all merged tasks     
        for reg_item in tasks:

            # Create empty task object
            task_obj = windows_task()

            if reg_item.has_values:
            
                # Update task object with task fields from registry
                for reg_value in reg_item.values:
                    task_obj.add_field(reg_value.value_name, reg_value.value_content)
                
                # Process Task fields
                task_obj.process()

                index = 0
                # Enrich Action data
                for _action in task_obj.data.actions.actions:
                    
                    index += 1
                    _action_prefix = 'Action.%s' % index

                    if _action.handler_payloads is None: _action.handler_payloads = []
                    if _action.handler_payloads_count is None: _action.handler_payloads_count = 0

                    if _action.handler_type == windows_task.handler_type.COM_HANDLER and _action.clsid is not None:
                        # Query values:
                        #  - SOFTWARE -> 'Classes\CLSID\%s\(Default)' -> Expected COM Handlers
                        #  - USRCLASS -> 'CLSID\%s\(Default)'  -> Unexpected/User Handlers
                        class_handlers = []
                        
                        # Time consuming task (Performed for each COM handler/action) - Query system and user class id
                        for _hive in self.loaded_hives:
                            class_handlers.extend(self.parser.query_value(value_path=[
                                'Classes\CLSID\%s\InProcServer32\(default)' % _action.clsid, 'CLSID\%s\InProcServer32\(default)' % _action.clsid], 
                                hive=_hive.get('hive'), plugin_name=self.name, reg_handler=None))
                        
                        # Update Handler payloads
                        for item in class_handlers:

                            # Saves values from associated COM clsss to Tasks\%task_guid%
                            reg_item.add_values(item.values)

                            for _val in item.values:
                                _action.handler_payloads.append('%s %s' % (_val.value_content, _action.data) if _action.data else '%s' % _val.value_content)
                    else:
                        # Update the handler payloads
                        _action.handler_payloads.append(_action.payload())

                    # Refresh/set any updated arguments before generating the blob
                    _action.handler_payloads_count = len(_action.handler_payloads)
                        
                    # Generate Action blob for further scanning
                    _action.blob = _action.yara_blob()
                    
                    # Saves Action variables as new values
                    reg_item.add_values(_action.blob.get('variables', {}), _action_prefix)

                    # Saves Action fields as new values
                    reg_item.add_values(_action.json(), _action_prefix)

                # Trigger a Yara scan on Task's blob
                if self.parsed_args.signature_scan_enabled:
                    
                    # Generate Task's blob for further Yara scanning
                    task_obj.yara_blob()

                    # Saves Task variables as new values
                    reg_item.add_values(task_obj.blob.get('variables', {}))
                    
                    # Scan Task
                    task_obj.scan()

                # Update Registry_item's tags
                setattr(reg_item, 'tags', '%s' % '\n'.join(task_obj.detections) if task_obj.detections else 'None')

                # Add item
                _items.append(reg_item)

            else:
                # Case: Empty Task
                # print(task_obj)
                pass
        
        if args:
            if 'tags' not in args.fields_to_print:
                args.fields_to_print.append('tags')

        # Return items not in baseline, if baseline is enabled
        return self.return_items(_items)
