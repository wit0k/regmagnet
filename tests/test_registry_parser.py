from md.registry_parser import registry_parser
from md.registry_parser import registry_action

class test_obj(object):

    name = None
    hive = None
    test_output = None
    check_fn = None
    check_fn_params = None
    test_result = None

    def __init__(self, name, hive_obj, check_fn, check_fn_params=None):
        self.name = name
        self.hive = hive_obj
        self.check_fn = check_fn
        self.check_fn_params = check_fn_params

    def check(self, input):
        if self.check_fn_params is not None:
            args = [input, *self.check_fn_params]
            self.test_result = self.check_fn(*args)
        else:
            self.test_result = self.check_fn(*input)

        if self.test_result == True:
            return True
        else:
            return False


def check_list_length(input_list: list, expected_length: int):
    if len(input_list) == expected_length:
        return True
    else:
        return False
tests = []
tests.append(
    test_obj(
        name='<Root_Key>\*\<KeyName>',
        hive_obj=r'C:\Users\lawac\Downloads\htb\reg\UsrClass.dat.recovered',
        check_fn=check_list_length,
        check_fn_params=[16],
    )
)

parser = registry_parser(registry_provider_name='python_registry', verbose_mode=True)

for test in tests:
    for hive_info in parser.parse_input_files([test.hive]).values():
        print(hive_info['hive'].hive_md5, hive_info['hive'].hive_file_path)
        ## Pattern:  <Root_Key>\*\<KeyName>
        res = parser.query(action=registry_action.QUERY_KEY, path='CLSID\*\LocalServer32', hive=hive_info['hive'],
                                reg_handler=None)  # -> 16 items
        print('--------')
    if test.check(res) != True:
        print('Test Failure: "%s" !!!' % test.name)
        ## Pattern:  <Root_Key>\*\<KeyName>
        # return self.parser.query(action=registry_action.QUERY_KEY, path='CLSID\*\LocalServer32', hive=hive, reg_handler=registry_handler)  # -> 16 items
        # return self.parser.query(action=registry_action.QUERY_KEY, path='CLSID\*\*', hive=hive, reg_handler=registry_handler) # -> 150 items
        # return self.parser.query(action=registry_action.QUERY_KEY, path='*\\regex(.{1,})\\regex(.{2,})', hive=hive,reg_handler=registry_handler)  # -> 150 items
        # return self.parser.query(action=registry_action.QUERY_VALUE, path='.3fr\\OpenWithProgids\\AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h', hive=hive, reg_handler=registry_handler)
        # return self.parser.query(action=registry_action.QUERY_VALUE, path='*\\OpenWithProgids\\AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h', hive=hive, reg_handler=registry_handler)
        # return self.parser.query(action=registry_action.QUERY_VALUE, path='*\\OpenWithProgids\\regex(AppX[c-d][c-d]h38jxzbcberv50vxg2tg4k84kfnewn)', hive=hive, reg_handler=registry_handler)
        # return self.parser.query(action=registry_action.QUERY_VALUE, path='regex(.*)\\regex(.*)\\regex(AppX[c-d][c-d]h38jxzbcberv50vxg2tg4k84kfnewn)', hive=hive, reg_handler=registry_handler)
