from md.registry_parser import registry_action, registry_action_settings
from md.registry_parser import registry_parser
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
            description=r'Regex Pattern Test - Query Value in keys with a double wildcard pattern and regex',
            verbose=False,
            method=registry_action.QUERY_VALUE,
            query=r'regmagnet\c\*\*\regex([a-b])',
            hive_obj=r'hives\WINDEV2404EVAL\User\NTUSER.dat',
            check_fn=check_list_length,
            check_fn_params=[6],
        ),
        test_obj(
            description=r'Regex Pattern Test - Root wildcard and double regex',
            verbose=False,
            method=registry_action.QUERY_KEY,
            query=r'*\regex(.{1,})\regex(.{2,})',
            hive_obj=r'hives\WINDEV2404EVAL\User\NTUSER.dat',
            check_fn=check_list_length,
            check_fn_params=[184],
        ),
        test_obj(
            description=r'Escape Test - Escaped Root, space in the path',
            verbose=False,
            method=registry_action.QUERY_VALUE,
            query=r'\\*\shellex\ContextMenuHandlers\ FileSyncEx\(default)',
            hive_obj=r'hives\ctf\UsrClass.dat',
            check_fn=check_list_length,
            check_fn_params=[1],
        ),
        test_obj(
            description=r'Regex Pattern Test - Root Regex and double regex',
            verbose=False,
            method=registry_action.QUERY_KEY,
            query=r'regex(.*)\regex(.{1,})\regex(.{2,})',
            hive_obj=r'hives\WINDEV2404EVAL\User\NTUSER.dat',
            check_fn=check_list_length,
            check_fn_params=[184],
        ),
        test_obj(
            description=r'Query Value - Direct path',
            verbose=False,
            method=registry_action.QUERY_VALUE,
            query=r'regmagnet\c\f\supermen\a',
            hive_obj=r'hives\WINDEV2404EVAL\User\NTUSER.dat',
            check_fn=check_list_length,
            check_fn_params=[1],
        ),
        test_obj(
            description=r'Query Value - Root Wildcard - Direct path',
            verbose=False,
            method=registry_action.QUERY_VALUE,
            query=r'*\c\f\supermen\a',
            hive_obj=r'hives\WINDEV2404EVAL\User\NTUSER.dat',
            check_fn=check_list_length,
            check_fn_params=[1],
        ),
        test_obj(
            description=r'Wildcard Pattern Test - Query Value in keys with a double wildcard pattern',
            verbose=False,
            method=registry_action.QUERY_VALUE,
            query=r'regmagnet\c\*\*\a',
            hive_obj=r'hives\WINDEV2404EVAL\User\NTUSER.dat',
            check_fn=check_list_length,
            check_fn_params=[3],
        ),
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
            description=r'Regex Pattern Test - Two last keys have a pattern',
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

def run(parser_name):

    parser = registry_parser(registry_provider_name=parser_name, verbose_mode=True)
    parser.hives = {} # A trick, don't ask why

    for test in tests:
        for hive_info in parser.parse_input_files([test.hive], skip_print=True, skip_hive_cache=False).values():
            res = parser.query(action=test.method, path=test.query, hive=hive_info['hive'], reg_handler=None,
                               settings=test.query_settings)

            if test.verbose == True:
                for i in res:
                    if i.values:
                        for v in i.values:
                            print('  [-]', i.key.key_path, v.value_name, v.value_content)
                    else:
                        print('  [-]', i.key.key_path, '<No Values>', '')

            if test.check(res) != True:
                print('%s\t%s\t"%s"\t%s\t"%s"' % (
                'FAILED', parser.reg.name, test.query, test.query_settings, test.description))
            else:
                print('%s\t%s\t"%s"\t%s\t"%s"' % (
                'OK', parser.reg.name, test.query, test.query_settings, test.description))

for parser_name in ['yarp', 'python_registry']:
    run(parser_name=parser_name)


