from md.registry_parser import registry_parser
from md.registry_parser import registry_action, registry_action_settings

class test_obj(object):

    description = None
    query = None
    method = None
    verbose = None
    hive = None
    test_output = None
    check_fn = None
    check_fn_params = None
    test_result = None

    def __init__(self, method, query, hive_obj, check_fn, description, check_fn_params=None, verbose=None, query_settings=None):

        self.description = description
        self.method = method
        self.query = query
        self.query_settings = query_settings
        self.hive = hive_obj
        self.check_fn = check_fn
        self.check_fn_params = check_fn_params
        self.verbose = verbose

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
tests.extend(
    [
        test_obj(
            description=r'Regex Test - Last key has a pattern',
            verbose=False,
            method=registry_action.QUERY_KEY,
            query=r'regmagnet\c\e\regex(.*men.*)',
            hive_obj=r'hives\WINDEV2404EVAL\User\NTUSER.dat',
            check_fn=check_list_length,
            check_fn_params=[1],
        ),
        test_obj(
            description=r'Regex Test - Two last keys have a pattern',
            verbose=False,
            method=registry_action.QUERY_KEY,
            query=r'regmagnet\c\*\regex(.*men.*)',
            hive_obj=r'hives\WINDEV2404EVAL\User\NTUSER.dat',
            check_fn=check_list_length,
            check_fn_params=[3],
        ),
        test_obj(
            description=r'Recursion Test - Query all sub-keys from regmagnet',
            query_settings=registry_action_settings.DEFAULT_KEY | registry_action_settings.RECURSIVE,
            verbose=False,
            method=registry_action.QUERY_KEY,
            query=r'regmagnet',
            hive_obj=r'hives\WINDEV2404EVAL\User\NTUSER.dat',
            check_fn=check_list_length,
            check_fn_params=[13],
        ),
        test_obj(
            description=r'Recursion Test with Multi-Wildcard - Query all sub-keys of regmagnet +1 level down',
            verbose=False,
            method=registry_action.QUERY_KEY,
            query_settings=registry_action_settings.DEFAULT_KEY | registry_action_settings.RECURSIVE,
            query=r'regmagnet\*\*',
            hive_obj=r'hives\WINDEV2404EVAL\User\NTUSER.dat',
            check_fn=check_list_length,
            check_fn_params=[6],
        ),
        test_obj(
            description=r'Multi-Wildcard Test - Query all sub-keys of regmagnet and their 1 level down subkeys (not recursive)',
            verbose=False,
            method=registry_action.QUERY_KEY,
            query=r'regmagnet\*\*',
            hive_obj=r'hives\WINDEV2404EVAL\User\NTUSER.dat',
            check_fn=check_list_length,
            check_fn_params=[3],
        ),
        test_obj(
            description=r'Wildcard Test - Query all sub-keys of regmagnet key (not recursive)',
            verbose=False,
            method=registry_action.QUERY_KEY,
            query=r'regmagnet\*',
            hive_obj=r'hives\WINDEV2404EVAL\User\NTUSER.dat',
            check_fn=check_list_length,
            check_fn_params=[6],
        ),
        test_obj(
            description=r'Recursion Test - Query all sub-keys from regmagnet\c key (recursive mode), including c',
            verbose=False,
            method=registry_action.QUERY_KEY,
            query_settings=registry_action_settings.DEFAULT_KEY | registry_action_settings.RECURSIVE,
            query=r'regmagnet\c',
            hive_obj=r'hives\WINDEV2404EVAL\User\NTUSER.dat',
            check_fn=check_list_length,
            check_fn_params=[7],
        ),
    ]
)

parser = registry_parser(registry_provider_name='python_registry', verbose_mode=True)

for test in tests:
    for hive_info in parser.parse_input_files([test.hive]).values():
        # print(hive_info['hive'].hive_md5, hive_info['hive'].hive_file_path)
        res = parser.query(action=registry_action.QUERY_KEY, path=test.query, hive=hive_info['hive'], reg_handler=None, settings=test.query_settings)  # -> 16 items

        if test.verbose == True:
            for i in res:
                if i.values:
                    for v in i.values:
                        print('  [-]', i.key.key_path, v.value_name, v.value_content)
                else:
                    print('  [-]', i.key.key_path, '<No Values>', '')


        if test.check(res) != True:
            print(' [-] Query: "%s" -> Settings: "%s" -> Result: "Failure" -> Description: "%s"' % (test.query, test.query_settings, test.description))
            ## Pattern:  <Root_Key>\*\<KeyName>
            # return self.parser.query(action=registry_action.QUERY_KEY, path=r'CLSID\*\LocalServer32', hive=hive, reg_handler=registry_handler)  # -> 18 items
            # return self.parser.query(action=registry_action.QUERY_KEY, path='CLSID\*\*', hive=hive, reg_handler=registry_handler) # -> 150 items
            # return self.parser.query(action=registry_action.QUERY_KEY, path='*\\regex(.{1,})\\regex(.{2,})', hive=hive,reg_handler=registry_handler)  # -> 150 items
            # return self.parser.query(action=registry_action.QUERY_VALUE, path='.3fr\\OpenWithProgids\\AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h', hive=hive, reg_handler=registry_handler)
            # return self.parser.query(action=registry_action.QUERY_VALUE, path='*\\OpenWithProgids\\AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h', hive=hive, reg_handler=registry_handler)
            # return self.parser.query(action=registry_action.QUERY_VALUE, path='*\\OpenWithProgids\\regex(AppX[c-d][c-d]h38jxzbcberv50vxg2tg4k84kfnewn)', hive=hive, reg_handler=registry_handler)
            # return self.parser.query(action=registry_action.QUERY_VALUE, path='regex(.*)\\regex(.*)\\regex(AppX[c-d][c-d]h38jxzbcberv50vxg2tg4k84kfnewn)', hive=hive, reg_handler=registry_handler)
        else:
            print(' [-] Query: "%s" -> Settings: "%s" -> Result: "Success" -> Description: "%s"' % (test.query, test.query_settings, test.description))
