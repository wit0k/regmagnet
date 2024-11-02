__version__ = '0.9'

#from dataclasses import dataclass
#from inspect import isclass
from doctest import debug
import logging
#from msilib.schema import File
from operator import index
from re import S
import struct
import argparse

from pathlib import Path 

from datetime import datetime, timedelta

from io import BytesIO
from typing import Type

from md.plugin import plugin
from md.args import build_registry_handler
from providers.provider import registry_provider
from md.windows_scheduled_tasks import actions as task_actions
from md.windows_scheduled_tasks import dynamic_info as task_dynamic_info
from md.windows_scheduled_tasks import job_schedule as task_job_schedule
from md.windows_scheduled_tasks import triggers as task_triggers

from kaitaistruct import KaitaiStream
from os.path import join, abspath, dirname, isdir
import yara
from md.time_class import days_ago
from md.security_descriptor import security_descriptor, windows_security_descriptor, SD_OBJECT_TYPE
from inspect import isfunction
from md.registry_parser import registry_action, registry_action_settings

import ctypes
import os

if os.name == 'nt':
    import ctypes.wintypes
    FILETIME = ctypes.wintypes.FILETIME
else: # fallback
    DWORD = ctypes.c_uint32
    class FILETIME(ctypes.Structure):
        _fields_ = [('dwLowDateTime', DWORD),
                    ('dwHighDateTime', DWORD)]

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
                value = str('(dict)Unsupported').encode()

            elif isinstance(value, list):
                value = str('|'.join(value)).encode()
            
            elif isinstance(value, bytes):
                return value
            
            elif isinstance(value, float):
                return ('%s' % str(value)).encode()

            else:
                value = b'Unsupported value type [%s] -> "%s"' % (type(value), value)
        
        return value

    def create(buffer_dict, _type=buffer_type.bytes):
        
        if _type == buffer.buffer_type.string:
            _buffer = ''
        else:
            _buffer = b''

        for root_key, root_value in buffer_dict.items():                          
            if isinstance(root_value, dict):
                
                for child_key, child_value in root_value.items():
                    
                    if isinstance(child_value, windows_task_triggers):
                        for trigger_key, trigger_obj in child_value.json().items():
                            _buffer += b'%s:%s|' % (trigger_key.encode(), buffer.convert_value(trigger_obj))
                    
                    elif isinstance(child_value, windows_task_actions):
                        for action_obj in child_value.actions:
                            if isinstance(action_obj, windows_task_action_flat):
                                for action_key, action_data in action_obj.json().items():
                                    _buffer += b'%s:%s|' % (action_key.encode(), buffer.convert_value(action_data))
                                    
                    elif isinstance(child_value, dict):
                        _nested_keys_ = child_value.get('_nested_keys_', [])
                        for string_key, a_value in child_value.items():
                            if string_key in _nested_keys_:
                                if isinstance(child_value[string_key], dict):
                                    for value_name, value_data in child_value[string_key].items():
                                        _buffer += b'%s:%s|' % (value_name.encode(), buffer.convert_value(value_data))
                                elif isinstance(child_value[string_key], list):
                                    for item in child_value[string_key]:
                                        for value_name, value_data in item.items():
                                            _buffer += b'%s:%s|' % (value_name.encode(), buffer.convert_value(value_data)) 
                                else:
                                    pass
                                    
                            else:
                                _buffer += b'%s:%s|' % (string_key.encode(), buffer.convert_value(a_value))
                    else:
                        _buffer += b'%s:%s|' % (child_key.encode(), buffer.convert_value(child_value))

            else:
                _buffer += b'%s:%s|' % (root_key.encode(), buffer.convert_value(root_value))
                
        return _buffer

class helpers(object):

    def ret_or_default(value, value_type):
        pass

    def from_filetime(FILETIME_BUFFER, format='%Y-%m-%d %H:%M:%S.%f') -> str:
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
        
        return ''
    
    def from_filetime_to_epoch(FILETIME_BUFFER, format='%Y-%m-%d %H:%M:%S.%f') -> int:
        # https://gist.github.com/Mostafa-Hamdy-Elgiar/9714475f1b3bc224ea063af81566d873
        EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
        HUNDREDS_OF_NANOSECONDS = 10000000

        if FILETIME_BUFFER: 
            # _filetime = int.from_bytes(FILETIME_BUFFER, byteorder='little', signed=True)
            _filetime = FILETIME_BUFFER
            try:
                _datetime = datetime.utcfromtimestamp((_filetime - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS)
                return _datetime.timestamp()
            
            except Exception as msg:
                # return '%s - Error: %s' % (_filetime, str(msg))
                return 0
        
        return 0
    
    def bytes_to_filetime(timestamp_bytes, format='%Y-%m-%d %H:%M:%S.%f'):
        try:
        
            t = FILETIME.from_buffer_copy(timestamp_bytes)
            quadword = (t.dwHighDateTime << 32) + t.dwLowDateTime
            us = quadword // 10 - 11644473600000000
            return (datetime(1970, 1, 1) + timedelta(microseconds=us)).strftime(format)
        except:
            return '%s' % us
    
    def filetime_to_stime(t, format='%Y-%m-%d %H:%M:%S.%f'):
        ts = 0
        try:
            if t.high_date_time != 0 or t.low_date_time != 0:
                quadword = (t.high_date_time << 32) + t.low_date_time
                ts = quadword // 10 - 11644473600000000
                # ts = (quadword / 10000000) - 11644473600000000

                if ts == 0 or ts >= 1833029933770955161:
                    return '%s' % 0 
                else:
                    return (datetime(1970, 1, 1) + timedelta(microseconds=ts)).strftime(format)
            else:
                return '%s' % 0 

        except:
            return '%s' % ts
    
    def int_to_bytes(int_variable, bytes_length, order='little', signed=False):
        # return (int_variable).to_bytes(bytes_length, byteorder='big'|'little').hex()
        return (int_variable).to_bytes(bytes_length, byteorder=order, signed=signed)
    
        def cast_uint(n): 
          return ctypes.c_uint(n)
      
        def cast_ulong(n): 
          return ctypes.c_ulong(n) 

class windows_task_registry_blobs(object):

    Actions = None
    Dynamic_Info = None
    Triggers = None
    User_Info = None
    Key_Tasks_SD = None
    Key_Tree_SD = None
    SD = None

    def __init__(self):
        pass

    def get_security_descriptor(self, key, obj_type=None, return_bytes=False, mapping_table=None):
        
        sk_record = None
        if mapping_table is None: mapping_table = {}
        
        if isinstance(key, bytes):
            sk_record = key
        elif getattr(key, 'key_security_descriptor', None):
            if return_bytes == False:
                return key.key_security_descriptor
            else:
                sk_record = key.key_sd_bytes
        elif getattr(key, 'key_sd_bytes', None):
            sk_record = key.key_sd_bytes
        elif getattr(key, 'key_obj', None): # Just in case (unfinished code...)
            if getattr(key.key_obj, '_nkrecord', None):
                sk_record = key.key_obj._nkrecord.sk_record()
            elif isfunction(key.key_obj, 'security'):
                sk_record = key.key_obj.security().descriptor()
        else:
            raise Exception('Unsupported Key type. Unable to get Security Descriptor!')

        if return_bytes:
            return  sk_record
        else:
            return windows_security_descriptor(sk_record, obj_type, mapping_table)
            
    def json(self, flat=True):
        
        return {
            'actions': self.Actions.json(flat=flat) if self.Actions else {},
            'dynamic_info': self.Dynamic_Info.json(flat=flat) if self.Dynamic_Info else {},
            'triggers': self.Triggers.json(flat=flat) if self.Triggers else {},
            # 'user_info': self.user_info,
        }

class windows_task_action_flat(object):

    index   = None 
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
    size = None

    def __init__(self, field_names=None) -> None:
        pass
    
    def variables(self, flat=False) -> dict:
        
        if flat == True:
            action_prefix = 'action.%s.' % self.index
        else:
            action_prefix = ''
            
        return { 
            '%s%s_headers_count' % (action_prefix, windows_task.handler_type.name(windows_task.handler_type.SEND_EMAIL).lower()): self.num_headers,
            '%s%s_attachments_count' % (action_prefix, windows_task.handler_type.name(windows_task.handler_type.SEND_EMAIL).lower()): self.num_attachment_filenames,
            '%s%s_payloads_count' % (action_prefix, windows_task.handler_type.name(windows_task.handler_type.COM_HANDLER).lower()): self.handler_payloads_count,
            '%shandler_type' % action_prefix: self.handler_type,
            '%shandler_type_str' % action_prefix: self.handler_type_str,
            '%saction_size' % action_prefix: self.size,
            '%shandler_payloads' % action_prefix: str(self.handler_payloads),
        }
    
    def buffer(self):
         return buffer.create(self.json())
        
    def json(self, flat=False) -> dict:
        
        if flat == True:
            action_prefix = 'action.%s.' % self.index
        else:
            action_prefix = ''
        
        return {
            "%sindex" % action_prefix: self.index,
            "%ssize" % action_prefix: self.size,
            "%shandler_payloads_count" % action_prefix: self.handler_payloads_count,
            "%shandler_payloads" % action_prefix: self.handler_payloads,
            "%shandler_type" % action_prefix: self.handler_type,
            "%sversion" % action_prefix: self.version,
            "%scontext" % action_prefix: self.context,
            "%sclsid" % action_prefix: self.clsid,
            "%sdata" % action_prefix: self.data,
            "%scommand" % action_prefix: self.command,
            "%sarguments" % action_prefix: self.arguments,
            "%sworking_directory" % action_prefix: self.working_directory,
            "%scaption" % action_prefix: self.caption,
            "%scontent" % action_prefix: self.content,
            "%sto" % action_prefix: self.to,
            "%scc" % action_prefix: self.cc,
            "%sbcc" % action_prefix: self.bcc,
            "%sreply_to" % action_prefix: self.reply_to,
            "%sserver" % action_prefix: self.server,
            "%ssubject" % action_prefix: self.subject,
            "%sbody" % action_prefix: self.body,
            "%snum_attachment_filenames" % action_prefix: self.num_attachment_filenames,
            "%sattachment_filenames" % action_prefix: self.attachment_filenames,
            "%snum_headers" % action_prefix: self.num_headers,
            "%sheaders" % action_prefix: self.headers,
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
            
            index = 1
            # Parse each action to windows_task_action_flat object 
            for _Action in self.obj.actions:
                
                _Action_obj = windows_task_action_flat()
                _Action_obj.index = index
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
                _Action_obj.size = len(_Action_obj.buffer())
                
                self.actions.append(_Action_obj)
                index += 1
                
            self.count = len(self.actions)
        else:
            self.actions = []
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
    
    def json(self, flat=True):
        
        actions_data = {}
        
        if flat == False:
            actions_data.update({
                '_nested_keys_': ['actions'],
                'actions': []
            })
        
        action_index = 1
        for action in self.actions:
            
            if flat == True: 
                for key, value in action.json().items():
                    actions_data['action.%s.%s' % (action_index,key)] = value
            else:
                json_data = {}
                for key, value in action.json().items():
                    json_data.update({'action_%s' % key: value})
                
                actions_data['actions'].append(json_data)
            action_index += 1
        
        return actions_data

class windows_task_dynamic_info(object):
    
    obj = None
    magic = None
    creation_time = None
    last_run_time = None
    task_state = None
    last_error_code = None
    last_successful_run_time = None

    def __init__(self, buffer) -> None: 
        
        self.obj = task_dynamic_info.DynamicInfo(KaitaiStream(BytesIO(buffer)))
        
        if self.obj:
            self.magic = str(self.obj.magic)
            self.creation_time = helpers.from_filetime(self.obj.creation_time)
            self.last_run_time = helpers.from_filetime(self.obj.last_run_time)
            self.creation_time_epoch = helpers.from_filetime_to_epoch(self.obj.creation_time)
            self.last_run_time_epoch = helpers.from_filetime_to_epoch(self.obj.last_run_time)
            self.task_state = self.obj.task_state
            self.last_error_code = self.obj.last_error_code
            self.last_successful_run_time = helpers.from_filetime(self.obj.last_successful_run_time)
            self.last_successful_run_time_epoch = helpers.from_filetime_to_epoch(self.obj.last_successful_run_time)
    
    def json(self, flat=True):
        if flat == False:
            return {
                '_nested_keys_': ['dynamic_info'],
                'dynamic_info': {
                    'magic': self.magic,
                    'creation_time': self.creation_time,
                    'last_run_time': self.last_run_time,
                    'creation_time_epoch': self.creation_time_epoch,
                    'last_run_time_epoch': self.last_run_time_epoch,
                    'task_state': self.task_state,
                    'last_error_code': self.last_error_code,
                    'last_successful_run_time': self.last_successful_run_time,
                    'last_successful_run_time_epoch': self.last_successful_run_time_epoch,
                }
            }
        else:
            return {
                'dynamic_info_magic': self.magic,
                'dynamic_info_creation_time': self.creation_time,
                'dynamic_info_last_run_time': self.last_run_time,
                'dynamic_creation_time_epoch': self.creation_time_epoch,
                'dynamic_last_run_time_epoch': self.last_run_time_epoch,
                'dynamic_info_task_state': self.task_state,
                'dynamic_info_last_error_code': self.last_error_code,
                'dynamic_info_last_successful_run_time': self.last_successful_run_time,
                'dynamic_last_successful_run_time_epoch': self.last_successful_run_time_epoch,
            }
    
class windows_task_triggers(object):
    
    obj = None
    triggers_count = None
    triggers_start_boundary = None
    triggers_end_boundary = None
    options = None
    privileges = None
    
    def json(self, flat=True):
        
        triggers_data = {}
        
        if flat == False:
            triggers_data.update({
                '_nested_keys_': ['triggers'],
                'triggers': []
            })
        
        # Parse Task Triggers 
        tr_index = 1
        for tr in self.obj.triggers:
            properties_obj = None
            trigger_type_str = None
            
            if tr.magic.value == 34952:
                trigger_type_str = 'RegistrationTrigger'
            elif tr.magic.value == 43690:
                trigger_type_str = 'LogonTrigger'
            elif tr.magic.value == 65535:
                trigger_type_str = 'BootTrigger'
            elif tr.magic.value == 30583:
                trigger_type_str = 'SessionChangeTrigger'
            elif tr.magic.value == 61166:
                trigger_type_str = 'IdleTrigger'
            elif tr.magic.value == 52428:
                trigger_type_str = 'EventTrigger'
            elif tr.magic.value == 56797:
                trigger_type_str = 'TimeTrigger'
            elif tr.magic.value == 26214:
                trigger_type_str = 'WnfStateChangeTrigger'
                
            if getattr(tr.properties, 'job_schedule', None):
                properties_obj = tr.properties.job_schedule
            elif getattr(tr.properties, 'generic_data', None):
                properties_obj = tr.properties.generic_data
            
            if flat == True:
                prefix = 'trigger.%s.' % tr_index
                
                if properties_obj:
                    triggers_data.update({
                        '%stype' % prefix: trigger_type_str, 
                        '%sstart_boundary' % prefix: helpers.filetime_to_stime(properties_obj.start_boundary.filetime),
                        '%send_boundary' % prefix: helpers.filetime_to_stime(properties_obj.end_boundary.filetime),
                        '%srepetition_interval_seconds' % prefix: properties_obj.repetition_interval_seconds,
                    })
            else:
                prefix = 'trigger_'
                
                if properties_obj:
                    triggers_data['triggers'].append({
                        'index': tr_index, 
                        '%stype' % prefix: trigger_type_str, 
                        '%sstart_boundary' % prefix: helpers.filetime_to_stime(properties_obj.start_boundary.filetime),
                        '%send_boundary' % prefix: helpers.filetime_to_stime(properties_obj.end_boundary.filetime),
                        '%srepetition_interval_seconds' % prefix: properties_obj.repetition_interval_seconds,
                    })                
            
            tr_index+=1
                
        triggers_data.update({
            'triggers_count': self.triggers_count,
            'triggers_start_boundary': self.triggers_start_boundary,
            'triggers_end_boundary': self.triggers_end_boundary,
        }) 
        
        return triggers_data
    
    def __init__(self, buffer) -> None: 
        
        self.obj = task_triggers.Triggers(KaitaiStream(BytesIO(buffer)))
        self.triggers_count = len(self.obj.triggers)
        self.triggers_start_boundary = helpers.filetime_to_stime(self.obj.header.start_boundary.filetime)
        self.triggers_end_boundary = helpers.filetime_to_stime(self.obj.header.end_boundary.filetime)
        self.options = self.obj.job_bucket.optional_settings
        if getattr(self.options, 'privileges', None) is not None:
            self.privileges = self.options.privileges

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
    registry_binary_blobs = None
    Path = None
    Uri = None
    SD = None
    Author = None
    Actions = None
    DynamicInfo = None
    blob = None
    detections = None
    reg_item = None
    reg_items = None

    def time_variables(self) -> dict:
        
        return {
            'ep_30d_ago': days_ago(30).timestamp(),
            'ep_14d_ago': days_ago(14).timestamp(),
            'ep_7d_ago': days_ago(7).timestamp(),
            'ep_3d_ago': days_ago(3).timestamp(),
            'ep_1d_ago': days_ago(1).timestamp(),
        }
    def variables(self) -> dict:
        
        variables =  {
            'actions_count': self.registry_binary_blobs.Actions.count,                                                           # Count of Actions 
            'actions_size': len(self.Actions),                                                                                   # Total size of Actions buffer (in bytes)
            'actions_version': self.registry_binary_blobs.Actions.version,                                                       # Actions Magic
            'actions_context': self.registry_binary_blobs.Actions.context,                                                       # User context to execute the task/actions
            'actions_biggest_size': max([action.size for action in self.registry_binary_blobs.Actions.actions]) ,                # The size of a biggest action
            'actions_smallest_size': min([action.size for action in self.registry_binary_blobs.Actions.actions]),                # The size of a smallest action
            'dynamic_info_magic': self.registry_binary_blobs.Dynamic_Info.magic,                                                 # DynamicInfo Magic
            'dynamic_info_creation_time': self.registry_binary_blobs.Dynamic_Info.creation_time,                                 # DynamicInfo Task creation time
            'dynamic_info_last_run_time': self.registry_binary_blobs.Dynamic_Info.last_run_time,                                 # DynamicInfo Task Last Run time
            'dynamic_info_task_state': self.registry_binary_blobs.Dynamic_Info.task_state,                                       # DynamicInfo Task State
            'dynamic_info_last_error_code': self.registry_binary_blobs.Dynamic_Info.last_error_code,                             # DynamicInfo Last Error Code returned
            'dynamic_info_last_successful_run_time': self.registry_binary_blobs.Dynamic_Info.last_successful_run_time,           # DynamicInfo Last Successful run time
            'dynamic_creation_time_epoch': self.registry_binary_blobs.Dynamic_Info.creation_time_epoch,                
		    'dynamic_last_run_time_epoch': self.registry_binary_blobs.Dynamic_Info.last_run_time_epoch,
            'dynamic_last_successful_run_time_epoch': self.registry_binary_blobs.Dynamic_Info.last_successful_run_time_epoch,
            'triggers_count': self.registry_binary_blobs.Triggers.triggers_count,
            'triggers_start_boundary': self.registry_binary_blobs.Triggers.triggers_count,
            'triggers_end_boundary': self.registry_binary_blobs.Triggers.triggers_end_boundary,
        }
        
        for sd_obj in [(self.registry_binary_blobs.SD, 'sd_'), (self.registry_binary_blobs.Key_Tasks_SD, 'sd_task_key_'), (self.registry_binary_blobs.Key_Tree_SD, 'sd_tree_key_')]:
            if sd_obj[0] is not None and not isinstance(sd_obj[0], bytes):
                sd_obj_json = sd_obj[0].json(flat=False, prefix='%s' % sd_obj[1])
                for key, value in sd_obj_json.items():
                    if not '_nested_keys_' in key:
                        variables.update({key:value})
            else:
                empty_sd = { 
                '%sowner_name' % sd_obj[1]: None,
                '%sgroup_name' % sd_obj[1]: None,
                '%sgroup_name' % sd_obj[1]: None,
                '%sgroup_sid' % sd_obj[1]: None,
                '%ssddl' % sd_obj[1]: None,
                '%spermissions' % sd_obj[1]: [],
                }
                variables.update(empty_sd)
         
        return variables           

    def buffer(self, flat=False):
        return buffer.create(self.json(flat=False))
    
    def json(self, flat=True):

        ret  = {field_name: self.__getattribute__(field_name) for field_name in self.field_names}
        ret['data'] = self.registry_binary_blobs.json(flat=flat)
        return ret

    def __repr__(self) -> str:
        return 'Task: %s -> [Author: %s] -> Actions Count: %s' % (self.Path, self.Author, self.registry_binary_blobs.Actions.count)
    
    def add_field(self, name, value):
        self.field_names.append(name)
        self.__setattr__(name, value)

    def __init__(self, reg_items, field_names=None, mapping_table=None) -> None:

        if mapping_table is None: mapping_table = {}
        if field_names is None: self.field_names = []

        self.mapping_table = mapping_table
        self.registry_binary_blobs = windows_task_registry_blobs()
        self.reg_items = [] if reg_items is None else reg_items
        self.reg_item = reg_items[0] if len(reg_items) > 0 else None # Should be Tasks\{...} key
        
    def process(self):
        """ Translate Raw Task Buffers/Values to corresponding objects """
        
        if getattr(self, 'Actions', None):
            self.registry_binary_blobs.Actions = windows_task_actions(self.Actions)

        if getattr(self, 'DynamicInfo', None):
            self.registry_binary_blobs.Dynamic_Info = windows_task_dynamic_info(self.DynamicInfo)
        
        if getattr(self, 'Triggers', None):
            self.registry_binary_blobs.Triggers = windows_task_triggers(self.Triggers)

        """
            Tasks Key -> Security Descriptor  
            Tree Key -> Security Descriptor  
            SD value content -> Security Descriptor  
        """
        if getattr(self, 'SD', None):
            for reg_item in self.reg_items:
                if r'Windows NT\CurrentVersion\Schedule\TaskCache\Tree' in reg_item.get_path():
                    self.registry_binary_blobs.SD = self.registry_binary_blobs.get_security_descriptor(self.SD, SD_OBJECT_TYPE.SE_FILE_OBJECT, False, self.mapping_table)

        for reg_item_ in self.reg_items:
                        
            if r'Windows NT\CurrentVersion\Schedule\TaskCache\Tasks' in reg_item_.get_path():
                # print('Start Tasks SD ------------')
                self.registry_binary_blobs.Key_Tasks_SD = self.registry_binary_blobs.get_security_descriptor(reg_item_.key, SD_OBJECT_TYPE.SE_REGISTRY_KEY, False, self.mapping_table)
                # print('End Tasks SD ------------')
            elif r'Windows NT\CurrentVersion\Schedule\TaskCache\Tree' in reg_item_.get_path():
                self.registry_binary_blobs.Key_Tree_SD = self.registry_binary_blobs.get_security_descriptor(reg_item_.key, SD_OBJECT_TYPE.SE_REGISTRY_KEY, False, self.mapping_table)

    def scan(self):
        
        # Refrences: 
        # - https://buildmedia.readthedocs.org/media/pdf/yara/latest/yara.pdf

        print('[+] SIG_SCAN Task: %s' % self.Path)
        external_variables = {}
        rule_paths = {}
        rule_matches = {}

        # Location of Yara rules 
        # rules_folder = join(dirname(abspath(__file__)).rstrip('\/plugins\/tasks.py'), 'signatures\default')  # it cuts t??????
        rules_folder = join(dirname(abspath(__file__)).strip('plugins'), r'signatures\default')

        
        if not isdir(rules_folder):
            logger.error(' [+] Error: %s' % 'Yara rules folder was not found! -> Location: %s' % rules_folder)
            raise Exception('Yara rules folder was not found! -> Location: %s' % rules_folder)

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
        task_variables = self.variables()
        
        # Update variables with time variables
        task_variables.update(self.time_variables()) 

        # Scan actions separately
        for action in self.registry_binary_blobs.Actions.actions:    
            scan_variables = None

            # Pull action specific variables 
            action_variables = action.variables()
            
            # Merge Task and Action variables (Action variables may hold unique values per Action scan)
            scan_variables = task_variables.copy()
            scan_variables.update(action_variables.copy())
            
            # Format external variables
            for key, value in scan_variables.items():
                if value is None:
                    if '_count' in key:
                        scan_variables[key] = 0
                    else:
                        scan_variables[key] = 'None'
                        
                if isinstance(value, list) or isinstance(value, dict):
                    scan_variables[key] = str(value)
                    
            # Compile all available Yara rules with task and action variables (Unique per scan)
            try:
                rules = yara.compile(filepaths=rule_paths, externals=scan_variables)
                
                # Look for a match
                matches = rules.match(data=action.buffer())
            
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

                    # logger.error(scan_variables)
                    # logger.error(action.buffer())
            
                self.detections = list(rule_matches.keys())
            except Exception as e:
                logger.error(' [-] ERROR: Scan Failed for Task: %s - Key: %s - Exception: %s' % (self.Path, self.reg_items[0].get_path(), str(e)))
            
            
                      
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
    # loaded_hives -> Is filled by PluginManager and contains list of all loaded hives

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
                                 help="Return non-parsed tasks")


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

        # Build SID mapping dict
        sid_mapping = {}
        profiles = []

        self.parser.query(
            items=profiles,
            action=registry_action.QUERY_VALUE,
            settings=registry_action_settings.DEFAULT_VALUE,
            path=["Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\*\\ProfileImagePath"],
            hive=hive,
            reg_handler=registry_handler,
            plugin_name=self.name,
        )

        for profile in profiles:
            ProfileImagePath = profile.get_value(value_name='ProfileImagePath', default=None)
            if ProfileImagePath:
                profile_name = ProfileImagePath.split('\\')[-1]
                sid = profile.get_path().split('\\')[-1]
                sid_mapping[sid] = profile_name

        """ 
        _plugin_reg_handler = build_registry_handler(registry_parser=self.parser,
                                                     registry_handlers="dynamic_info<field>value_content",
                                                     custom_handlers=tasks.custom_registry_handlers)
        """

        # Build the registry handler specified in main regmagnet script (The one sent to all selected plugins)
        registry_handler = self.choose_registry_handler(main_reg_handler=registry_handler, plugin_reg_handler=None)

        # Query the key(s) specified
        # - Pull all Windows Scheduled Tasks from TaskCache"
        tasks = []
        self.parser.query(
            items=tasks,
            action=registry_action.QUERY_KEY,
            settings=registry_action_settings.DEFAULT_KEY,
            path=[r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\*"],
            hive=hive,
            reg_handler=registry_handler,
            plugin_name=self.name,
        )

        # -----------------------------------------------------------------------------------------------------------.
        # Iterate over all tasks     
        for reg_item in tasks:
            
            # Add Tasks\{...} registry item
            reg_item.linked_items.append(reg_item)
            
            # Query task tree/meta-data
            if reg_item.get_value('Path'):
                tree = []
                self.parser.query(
                    items=tree,
                    action=registry_action.QUERY_KEY,
                    settings=registry_action_settings.DEFAULT_KEY,
                    path=[r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree%s" % reg_item.get_value('Path')],
                    hive=hive,
                    reg_handler=registry_handler,
                    plugin_name=self.name,
                )
                # Enrich Task's reg_item object with entries from Tree node
                for linked_reg_item in tree:
                    
                    # Add Tree\<Task_Root> registry item
                    reg_item.linked_items.append(linked_reg_item)
                    
                    if linked_reg_item.has_values:
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
            task_obj = windows_task(reg_items=reg_item.linked_items, mapping_table=sid_mapping)

            if reg_item.has_values:
            
                # Update task object with task fields from registry
                for reg_value in reg_item.values:
                    task_obj.add_field(reg_value.value_name, reg_value.value_content)
                
                # Process Task fields / True init function
                task_obj.process()

                index = 0
                # Enrich data
                for _action in task_obj.registry_binary_blobs.Actions.actions:
                    
                    index += 1
                    #_action_prefix = 'Action.%s' % index

                    if _action.handler_payloads is None: _action.handler_payloads = []
                    if _action.handler_payloads_count is None: _action.handler_payloads_count = 0

                    if _action.handler_type == windows_task.handler_type.COM_HANDLER and _action.clsid is not None:
                        # Query values:
                        #  - SOFTWARE -> 'Classes\CLSID\%s\InProcServer32\(Default)' -> Expected COM Handlers
                        #  - USRCLASS -> 'CLSID\%s\InProcServer32\(Default)'  -> Unexpected/User Handlers
                        # Ultimately these shall be supported:
                        # InprocServer/InprocServer32
                        # LocalServer/LocalServer32
                        # TreatAs
                        # ProgID

                        class_handlers = []
                        
                        # Time consuming task (Performed for each COM handler/action) - Query system and user class id
                        # TO DO: ...
                        for _hive in self.loaded_hives:
                            class_handlers.extend(self.parser.query_value(value_path=[
                                r'Classes\CLSID\%s\InProcServer32\(default)' % _action.clsid, r'CLSID\%s\InProcServer32\(default)' % _action.clsid],
                                hive=_hive.get('hive'), plugin_name=self.name, reg_handler=None))
                        
                        # Update Handler payloads
                        for item in class_handlers:

                            reg_item.linked_items.append(item)
    
                            # Saves values from associated COM clsss to Tasks\%task_guid%
                            reg_item.add_values(item.values)

                            for _val in item.values:
                                _action.handler_payloads.append('%s %s' % (_val.value_content, _action.data) if _action.data else '%s' % _val.value_content)
                    else:
                        # Update the handler payloads
                        _action.handler_payloads.append(_action.payload())

                    # Refresh/set any updated arguments (that might affect .variables())
                    _action.handler_payloads_count = len(_action.handler_payloads)
                                        
                    # Saves Action variables as new values
                    reg_item.add_values(_action.variables(flat=True))

                    # Saves Action fields as new values
                    reg_item.add_values(_action.json(flat=True))

                # Saves parsed task's variables as new values
                reg_item.add_values(task_obj.variables())
                    
                # Saves parsed triggers as new values
                reg_item.add_values(task_obj.registry_binary_blobs.Triggers.json(flat=True))
                    
                # Trigger a Yara scan on a Task
                if self.parsed_args.signature_scan_enabled:
                    task_obj.scan()

                # Update Registry_item's tags
                setattr(reg_item, 'tags', '%s' % '\n'.join(task_obj.detections) if task_obj.detections else 'None')

                # Debug
                # if '{419C821C-CF0E-423C-8033-206B1AE4EA3B}' in reg_item.get_path():
                #    logger.error('DEBUG: %s' % reg_item.get_path())
                #    logger.error(task_obj.buffer())
                #    # exit(0)
                
                # Escape specific values (CSV fix)
                values_to_escape = ['SecurityDescriptor', 'sd_permissions', 'sd_task_key_permissions', 'sd_tree_key_permissions']
                for _val_te in values_to_escape:
                    _current_content = reg_item.get_value(_val_te)
                    if _current_content:
                        reg_item.set_value(_val_te, '"%s"' % _current_content)
                
                # Add item
                _items.append(reg_item)

            else:
                # Case: Empty Task
                print('Error: Suspicious Empty Task: %s' % reg_item.get_path())
                pass
        
        if args:
            if 'tags' not in args.fields_to_print:
                args.fields_to_print.append('tags')

        # Return items not in baseline, if baseline is enabled
        return self.return_items(_items)