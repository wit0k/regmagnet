import logging

from md.registry_parser import registry_parser
from md.logger import Logger
_Logger = Logger()
logger = logging.getLogger('regmagnet')

logger.debug("Start the test script ...")
items = []  # Holds all registry items which either matched a search pattern or were queried

#parser = registry_parser(registry_provider_name='python-registry')
parser = registry_parser(registry_provider_name='yarp', verbose_mode=True)

#_hive_file = parser.load_hive(r'/repos/regparser/hives/case/sys/SOFTWARE-live')

#reg_handler = parser.reg.registry_reg_handler(recipes=['b64_encode<field>value_content,value_name'])
#reg_handler = parser.reg.registry_reg_handler(recipes=['sxor<param>XORkey<field>value_content', 'b64_encode'])
reg_handler = None

#  Add new format field
parser.add_format_field(field_name='comments')
_hive_file = parser.load_hive(hive_file_path='/mnt/hgfs/repos/_tmp/teamviewer/y')
if not _hive_file:
    exit(-1)

""" Enum key and hive info """
#print(*parser.hive_info(hive=_hive_file), sep='\n')
#print(*parser.key_info(key_path=r'Microsoft\Office\15.0\Common', hive=_hive_file), sep='\n')

""" Query registry values """
items.extend(parser.query_value_wd(value_path=r'Microsoft\Windows\CurrentVersion\Run\RTHDVCPL', hive=_hive_file, reg_handler=reg_handler))
items.extend(parser.query_value_wd(value_path=r'Microsoft\Windows\CurrentVersion\Run\*', hive=_hive_file))
items.extend(parser.query_value_wd('Microsoft\Windows\CurrentVersion\Run\*\\', _hive_file))
items.extend(parser.query_value_wd('*\Windows\CurrentVersion\Run\RTHDVCPL', _hive_file))
items.extend(parser.query_value_wd('regex(Microsoft)\Windows\CurrentVersion\Run\RTHDVCPL', _hive_file))
items.extend(parser.query_value_wd(r'Microsoft\regex(Windows)\regex(CurrentVersion)\Run\RTHDVCPL', _hive_file))
items.extend(parser.query_value_wd(r'Microsoft\regex(Windows)\regex(CurrentVersion)\Run\regex(v)', _hive_file))
items.extend(parser.query_value_wd(r'Microsoft\Office\*\*\Options\OPEN', _hive_file))
items.extend(parser.query_value(value_path=r'Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\DelegateFolders\{C2B136E2-D50E-405C-8784-363C582BF43E}\(default)', hive=_hive_file))
items.extend(parser.query_value_wd(value_path=r'Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\DelegateFolders\{C2B136E2-D50E-405C-8784-363C582BF43E}\*', hive=_hive_file))

""" Query registry keys """
items.extend(parser.query_key(r'Microsoft\Windows\CurrentVersion\Run', _hive_file))
items.extend(parser.query_key_wd(r'*\Windows\CurrentVersion\Run\*', _hive_file))
items.extend(parser.query_key_wd(r'Microsoft\Windows\CurrentVersion\Explorer\*\NameSpace\*\{C2B136E2-D50E-405C-8784-363C582BF43E}', _hive_file))
items.extend(parser.query_key_wd(r'Microsoft\Windows\regex(CurrentVersion)\regex(Run)', _hive_file))
items.extend(parser.query_key_wd(r'regex(Microsoft)\Windows\regex(CurrentVersion)\regex(RunOnc)', _hive_file))

items.extend(parser.exec_action(action_name='query_key', parameters=(parser, r'Microsoft\Windows\CurrentVersion\Run', _hive_file)))
items.extend(parser.exec_action(action_name='query_key', parameters=(parser, r'Microsoft\Windows\CurrentVersion\Run', _hive_file)))


""" Deduplicate items """
items = parser.dedup_items(items)
""" Print registry items and format fields """
#parser.print(items=items, format='tab', format_fields=['key_path', 'value_name', 'value_content'])
#parser.print(items=items, format='tab')
parser.print(items=items, format='csv')
#parser.print(items=items, format='winreg')
#parser.print_registry_handlers()
#parser.print_format_fields()

""" Export registry items """
parser.export(items=items, output_path='SOFTWARE.tab.txt', format='tab')
#parser.export(items=items, output_path='SOFTWARE.csv', format='csv', format_fields=['all'])
#parser.export(items=items, output_path='SOFTWARE.reg', format='winreg')
#parser.export(items=items, output_path='SOFTWARE.sqlite', format='sqlite')
