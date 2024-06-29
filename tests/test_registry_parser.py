from md.registry_parser import registry_parser
from md.registry_parser import registry_action

class test_main(object):
    parser = None

    test_hive_mapping = {
        'wildcard_test': {
            'hives': [r'C:\Users\lawac\Downloads\htb\reg\UsrClass.dat.recovered'],
        }
    }

    def __init__(self):
        self.parser = registry_parser(registry_provider_name='python_registry', verbose_mode=True)

class wildcard_test(test_main):
    def run(self, registry_handler=None):

        for hive_info in self.parser.parse_input_files(self.test_hive_mapping['wildcard_test']['hives']).values():

            print(hive_info['hive'].hive_md5, hive_info['hive'].hive_file_path)
            ## Pattern:  <Root_Key>\*\<KeyName>
            res = self.parser.query(action=registry_action.QUERY_KEY, path='CLSID\*\LocalServer32', hive=hive_info['hive'], reg_handler=registry_handler)  # -> 16 items
            print('--------')

        ## Pattern:  <Root_Key>\*\<KeyName>
        # return self.parser.query(action=registry_action.QUERY_KEY, path='CLSID\*\LocalServer32', hive=hive, reg_handler=registry_handler)  # -> 16 items
        # return self.parser.query(action=registry_action.QUERY_KEY, path='CLSID\*\*', hive=hive, reg_handler=registry_handler) # -> 150 items
        # return self.parser.query(action=registry_action.QUERY_KEY, path='*\\regex(.{1,})\\regex(.{2,})', hive=hive,reg_handler=registry_handler)  # -> 150 items
        # return self.parser.query(action=registry_action.QUERY_VALUE, path='.3fr\\OpenWithProgids\\AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h', hive=hive, reg_handler=registry_handler)
        # return self.parser.query(action=registry_action.QUERY_VALUE, path='*\\OpenWithProgids\\AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h', hive=hive, reg_handler=registry_handler)
        # return self.parser.query(action=registry_action.QUERY_VALUE, path='*\\OpenWithProgids\\regex(AppX[c-d][c-d]h38jxzbcberv50vxg2tg4k84kfnewn)', hive=hive, reg_handler=registry_handler)
        # return self.parser.query(action=registry_action.QUERY_VALUE, path='regex(.*)\\regex(.*)\\regex(AppX[c-d][c-d]h38jxzbcberv50vxg2tg4k84kfnewn)', hive=hive, reg_handler=registry_handler)

# Run tests...
wd_test = wildcard_test()
wd_test.run()