import logging
from providers.provider import registry_provider
from Registry import Registry

logger = logging.getLogger('regmagnet')

supported_registry_types = ['REG_BIN']
reg_format_header = u"\ufeffWindows Registry Editor Version 5.00\r\n\r\n"

def buffer_to_winreg(file, registry_type, dest_key_value_path, output_file):

    win_reg_items = []

    if registry_type not in supported_registry_types:
        logger.error('Unsupported registry value type specified')
        exit(-1)

    if not isinstance(dest_key_value_path, str):
        logger.error('Unsupported key-value path specified')
        exit(-1)

    if isinstance(file, str):
        if registry_type == 'REG_BIN':
            buffer = open(file, 'rb').read()
            value_type = Registry.RegBin
            value_type_str = "RegBin"

    # Get Registry Hive, Key, Value name
    hive_name, _, key_value_path = dest_key_value_path.partition('\\')
    key_path, _, value_name = key_value_path.rpartition('\\')

    #  Create a registry value
    value_path = key_value_path
    value_name_unicode = bytes(value_name, "utf-16le")
    value_content = buffer
    value_content_str = str(value_content)
    value_content_unicode = buffer
    value_size = len(buffer)
    value_raw_data = buffer

    reg_value = registry_provider.registry_value(
        _value_path=value_path, _value_name=value_name,
        _value_name_unicode=value_name_unicode,
        _value_type=value_type,                                          \
        _value_type_str=value_type_str,
        _value_content=value_content,
        _value_content_str=value_content_str,
        _value_content_unicode=value_content_unicode,
        _value_size=value_size,
        _value_raw_data=value_raw_data
    )

    win_reg_items.append(reg_format_header)

    wr = registry_provider.registry_export()
    item = wr.get_winreg_item(
        hive_mapping=hive_name,
        key_path=key_path,
        values=[reg_value.dict()]
    )

    win_reg_items.append(item)

    wr.save_winreg_data_to_file(file_path=output_file, winreg_data=win_reg_items)

