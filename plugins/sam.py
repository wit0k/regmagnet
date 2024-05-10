import logging
import argparse
import struct
from md.plugin import plugin


from providers.provider import registry_provider
from datetime import datetime

logger = logging.getLogger('regmagnet')
class sam(plugin):
    """ sam - RegMagnet plugin  """

    """ Standard expected variables  """
    author = 'wit0k'
    name = 'sam'
    description = 'Parses SAM registry hive'
    config_file = ''  # IF it's empty/None, the config_data dictionary would not be auto-loaded
    baseline_file = 'baseline/sam.bl'

    """ Variables initialized by the plugin manager """
    args = None  # Holds plugin related arguments
    parser = None  # Represents the registry_parser object
    config_data = {}  # Contains the json data loaded from config_file (If any was specified and properly created)

    """ Plugin specific variables """
    supported_hive_types = ['SAM']  # Hive type must be upper case

    """ Constants """
    # ACB Flags which tell us if the account is disabled/etc
    acb_flags = {0x0001: "Account Disabled",
                 0x0002: "Home directory required",
                 0x0004: "Password not required",
                 0x0008: "Temporary duplicate account",
                 0x0010: "Normal user account",
                 0x0020: "MNS logon user account",
                 0x0040: "Interdomain trust account",
                 0x0080: "Workstation trust account",
                 0x0100: "Server trust account",
                 0x0200: "Password does not expire",
                 0x0400: "Account auto locked"}

    # Account Types
    types = {0xbc: "Default Admin User",
             0xd4: "Custom Limited Acct",
             0xb0: "Default Guest Acct"}

    """ Pieces of code borrowed from https://raw.githubusercontent.com/yampelo/samparser/master/samparser.py """
    def sam_parse_users(self, items, hive, registry_handler):
        # SAM\Domains\Account\Users\regex(.*)\regex(ResetData|UserPasswordHint)
        # SAM\Domains\Account\Users

        reg_item: registry_provider.registry_item = None
        # _registry_item.add(_plugin_name=self.name, _registry_hive=hive, _registry_key=reg_item.key, _registry_values=_values, _key_obj=reg_item.key_obj)

        # Enumerate Names subkeys and derive AccountCreatedOn and AccountName fpr each user
        for reg_item in self.parser.query_key_wd(key_path=r'SAM\Domains\Account\Users\Names\*', hive=hive, plugin_name=self.name,
                                                 reg_handler=registry_handler):

            if 'Names\\' in reg_item.get_path(): # Process sub keys only (not the root)
                _values = {
                    'AccountCreatedOn': reg_item.get_str_timestamp(),
                    'AccountName': reg_item.get_key_name(),
                }
                reg_item.add_values(new_values=_values)
                items.append(reg_item)

        f_values = {}  # Used to temp store F Data before we get V Value data

        i = 0
        # Enumerate Users subkeys (excluding Names) and parse F
        for reg_item in self.parser.query_key_wd(key_path=r'SAM\Domains\Account\Users\*', hive=hive,
                                                         plugin_name=self.name, reg_handler=registry_handler):

            if 'Names\\' not in reg_item.get_path():  # Do not process Names subkey

                copy_of_values = reg_item.values.copy()

                for value in copy_of_values:
                    if 'F' == value.value_name:

                        i += 1
                        with open('F_%s_%s' % (reg_item.get_key_name(), i), 'wb') as ofile:
                            ofile.write(value.value_content)

                        b = struct.unpack('<xxxxxxxxLLxxxxxxxxLLxxxxxxxxLLLxxxxHxxxxxxHHxxxxxxxxxxxx', value.value_content)
                        f_values[b[6]] = []  # Create a List and sort by RID
                        f_values[b[6]].append(self.getTime(b[0], b[1]))  # Last Login Date
                        f_values[b[6]].append((self.getTime(b[2], b[3])))  # This is password reset date
                        f_values[b[6]].append((self.getTime(b[4], b[5])))  # PWD Fail Date maybe?

                        flags = []
                        for flag in self.acb_flags:  # Compare the two hex values and check if one is contained in the other, if so save it
                            if bool(flag & b[7]):
                                flags.append(self.acb_flags[flag])
                        f_values[b[6]].append(flags)
                        f_values[b[6]].append(b[8])  # Failed Login Count
                        f_values[b[6]].append(b[9])  # Login Count

                    if 'V' == value.value_name:
                        data = value.value_content

                        # Unpacking The values, refrence here http://www.beginningtoseethelight.org/ntsecurity/index.htm
                        # Get the account type, username, fullname, comment, driveletter, logon script, profile path, workstation's allowed, and LM and NT password hashes
                        account_type = struct.unpack("<L", data[4:8])[0]
                        username_ofst = struct.unpack("<L", data[12:16])[0]
                        username_lngth = struct.unpack("<L", data[16:20])[0]
                        fullname_ofst = struct.unpack("<L", data[24:28])[0]
                        fullname_lngth = struct.unpack("<L", data[28:32])[0]
                        comment_ofst = struct.unpack("<L", data[36:40])[0]
                        comment_lngth = struct.unpack("<L", data[40:44])[0]
                        driveletter_ofst = struct.unpack("<L", data[84:88])[0]
                        driveletter_lngth = struct.unpack("<L", data[88:92])[0]
                        logonscript_ofst = struct.unpack("<L", data[96:100])[0]
                        logonscript_lngth = struct.unpack("<L", data[100:104])[0]
                        profilepath_ofst = struct.unpack("<L", data[108:112])[0]
                        profilepath_lngth = struct.unpack("<L", data[112:116])[0]
                        workstations_ofst = struct.unpack("<L", data[120:124])[0]
                        workstations_lngth = struct.unpack("<L", data[124:128])[0]
                        lmpwhash_ofset = struct.unpack("<L", data[156:160])[0]
                        lmpwhash_lngth = struct.unpack("<L", data[160:164])[0]
                        ntpwhash_ofset = struct.unpack("<L", data[168:172])[0]
                        ntpwhash_lngth = struct.unpack("<L", data[172:176])[0]

                        _values = {}
                        def get_user_account_type(account_type):
                            for acctype in self.types:
                                if account_type == int(acctype):
                                    return self.types[acctype]
                            return 'Unknown [%s]' % str(account_type)

                        _values = {
                            'UserName': data[(username_ofst + 0xCC):(username_ofst + 0xCC + username_lngth)].replace(b'\x00',b''),
                            'FullName': data[(fullname_ofst + 0xCC):(fullname_ofst + 0xCC + fullname_lngth)],
                            'UserComment': data[(comment_ofst + 0xCC):(comment_ofst + 0xCC + comment_lngth)].decode('utf16', errors='ignore'),
                            'UserAccountType': get_user_account_type(account_type),
                            'RID': str(int(reg_item.get_key_name().strip("0000"), 16)),
                            'DriveLetter': data[(driveletter_ofst + 0xCC):(driveletter_ofst + 0xCC + driveletter_lngth)],
                            'ProfilePath': data[(profilepath_ofst + 0xCC):(profilepath_ofst + 0xCC + profilepath_lngth)],
                            'LogonScript': data[(logonscript_ofst + 0xCC):(logonscript_ofst + 0xCC + logonscript_lngth)],
                            'Workstations': data[(workstations_ofst + 0xCC):(workstations_ofst + 0xCC + workstations_lngth)],
                            'LM_PWD_Hash': data[(lmpwhash_ofset+0xCC):(lmpwhash_ofset+0xCC + lmpwhash_lngth)].hex(),
                            'NT_PWD_Hash': data[(ntpwhash_ofset+0xCC):(ntpwhash_ofset+0xCC + ntpwhash_lngth)].hex(),
                            'LastLoginDate': f_values[list(f_values.keys())[0]][0],
                            'PasswordResetDate': f_values[list(f_values.keys())[0]][1],
                            'PasswordFailDate': f_values[list(f_values.keys())[0]][2],
                            'AccountFlags': ' | '.join(f_values[list(f_values.keys())[0]][3]),
                            'FailedLoginCount': f_values[list(f_values.keys())[0]][4],
                            'LoginCount': f_values[list(f_values.keys())[0]][4],
                        }

                        reg_item.add_values(new_values=_values)
                        items.append(reg_item)

                    if 'UserPasswordHint' == value.value_name:
                        value.value_content = value.value_content.decode('utf16', errors='ignore')

                    if 'ResetData' == value.value_name:
                        value.value_content = value.value_content.decode('utf16', errors='ignore')

                    if 'SupplementalCredentials' == value.value_name:
                        value.value_content = '--- ENCRYPTED(SupplementalCredentials) ---'

        return items

    def binary_to_sid(binary_data):
        if len(binary_data) < 12:
            return ''
        elif len(binary_data) == 12:
            rev = struct.unpack("<B", binary_data[0:1])[0]
            # dash = struct.unpack("<B", binary_data[1:1])[0]
            authid = str(binary_data[2:8].encode("hex")).replace("00000000000", '')
            sub = struct.unpack("<L", binary_data[8:12])[0]
            return "S-" + str(rev) + "-" + str(authid) + "-" + str(sub)
        elif len(binary_data) > 12:
            rev = struct.unpack("<B", binary_data[0:1])[0]
            authid = str(binary_data[2:8].encode("hex")).replace("00000000000", '')
            sub = struct.unpack("<LLLL", binary_data[8:24])
            sub = map(str, sub)
            rid = struct.unpack("<L", binary_data[24:30])[0]
            return "S-" + str(rev) + "-" + str(authid) + "-" + '-'.join(sub) + "-" + str(rid)

    def sid_to_username(sid, software):
        try:
            key = software.open("Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\" + sid)
        except:
            return None
        return key.value("ProfileImagePath").value().split("\\")[-1]

    # Converts windows FILETIME (2 DWORDS) to datetime object formatted by strftime
    def getTime(self, low, high):
        low = float(low)
        high = float(high)
        if (high == 0) and (low == 0):
            return "Never"
        else:
            low -= 0xd53e8000
            high -= 0x019db1de
            a = int(high * 429.4967296 + low / 1e7)
        if a < 0:
            return "Never"
        return datetime.utcfromtimestamp(a).strftime('%d %B %Y - %H:%M:%S')

    # parses the hive and returns it as a dictionary.
    def samparse(samhive):

        results = OrderedDict()
        results['users'] = OrderedDict()

        # Ok this one is a bit more diffuclt. the data in here is in Binary data which means we need to unpack all of it.
        # The SAM file is structed like this
        # 0000123F
        # F - Contains binary data
        # V - Contains binary data
        # 0000234F
        # F - Contains binary data
        # V - Contains binary data

        # The subkeys that start with 0000  Correlate with each user on the computer while the F and V contain different data.
        # The 0000 can be striped off then you get a hex value which can be decoded to the user's RID
        # F contains type of account, and various account settings
        # V contains username, fullname, comment, password hashes and more
        # We have to individually parse both the F and V for every user.
        f_values = {}  # Used to temp store F Data before we get V Value data



        sam = Registry.Registry(samhive)  # open the hive using python-registry

        usersRoot = sam.open("SAM\\Domains\\Account\\Users")
        for x in usersRoot.subkeys():
            # We Use this to get the account name and timestamp
            if x.name() == "Names":
                for a in x.subkeys():
                    results['users'][a.name()]['Account Created Date'] = a.timestamp().strftime('%d %B %Y - %H:%M:%S')
            else:
                for a in x.values():
                    # F comes before V, and since we're using usernames, F will store in a temporary dict
                    # F Comes in binary data aswell
                    # For unpacking this is the formatting
                    # x = padded null bytes (\00x)
                    # L = Unsigned long (32bit) in little-endian
                    # H = Unsigned short (16bit) in little-endian
                    if a.name() == "F":
                        b = struct.unpack('<xxxxxxxxLLxxxxxxxxLLxxxxxxxxLLLxxxxHxxxxxxHHxxxxxxxxxxxx', a.value())
                        f_values[b[6]] = []  # Create a List and sort by RID
                        f_values[b[6]].append(getTime(b[0], b[1]))  # Last Login Date
                        f_values[b[6]].append(getTime(b[2], b[3]))  # This is password reset date
                        f_values[b[6]].append(getTime(b[4], b[5]))  # PWD Fail Date maybe?
                        flags = []
                        for flag in acb_flags:  # Compare the two hex values and check if one is contained in the other, if so save it
                            if bool(flag & b[7]):
                                flags.append(acb_flags[flag])
                        f_values[b[6]].append(flags)
                        f_values[b[6]].append(b[8])  # Failed Login Count
                        f_values[b[6]].append(b[9])  # Login Count

                    # Parsing the "V" Value
                    # the first 4 bytes of each entry refer to the location of the entry relative to offset
                    # the second 4 bytes refer to the entry length, rounded up to the nearest multiple of 4
                    # for example the 4 bytes from 0x0c -> 0x10 contains the offset+0xcc(4) where the username is
                    if a.name() == "V":
                        data = a.value()

                        # Unpacking The values, refrence here http://www.beginningtoseethelight.org/ntsecurity/index.htm
                        # Get the account type, username, fullname, comment, driveletter, logon script, profile path, workstation's allowed, and LM and NT password hashes
                        account_type = struct.unpack("<L", data[4:8])[0]
                        username_ofst = struct.unpack("<L", data[12:16])[0]
                        username_lngth = struct.unpack("<L", data[16:20])[0]
                        fullname_ofst = struct.unpack("<L", data[24:28])[0]
                        fullname_lngth = struct.unpack("<L", data[28:32])[0]
                        comment_ofst = struct.unpack("<L", data[36:40])[0]
                        comment_lngth = struct.unpack("<L", data[40:44])[0]
                        driveletter_ofst = struct.unpack("<L", data[84:88])[0]
                        driveletter_lngth = struct.unpack("<L", data[88:92])[0]
                        logonscript_ofst = struct.unpack("<L", data[96:100])[0]
                        logonscript_lngth = struct.unpack("<L", data[100:104])[0]
                        profilepath_ofst = struct.unpack("<L", data[108:112])[0]
                        profilepath_lngth = struct.unpack("<L", data[112:116])[0]
                        workstations_ofst = struct.unpack("<L", data[120:124])[0]
                        workstations_lngth = struct.unpack("<L", data[124:128])[0]
                        # lmpwhash_ofset = struct.unpack("<L", data[156:160])[0]	Can enable this, contains the NT and LM hashes
                        # lmpwhash_lngth = struct.unpack("<L", data[160:164])[0]
                        # ntpwhash_ofset = struct.unpack("<L", data[168:172])[0]
                        # ntpwhash_lngth = struct.unpack("<L", data[172:176])[0]

                        username = data[(username_ofst + 0xCC):(username_ofst + 0xCC + username_lngth)].replace('\x00',
                                                                                                                '')

                        results['users'][username] = OrderedDict()

                        results['users'][username]['Full Name'] = data[(fullname_ofst + 0xCC):(
                                    fullname_ofst + 0xCC + fullname_lngth)]
                        results['users'][username]['Comment'] = data[(comment_ofst + 0xCC):(
                                    comment_ofst + 0xCC + comment_lngth)]
                        for acctype in types:
                            if account_type == int(acctype):
                                results['users'][username]['Account Type'] = types[acctype]
                        results['users'][username]['RID'] = str(int(x.name().strip("0000"), 16))  # Since im converting hex to int, you need to tell python it's in base 16
                        results['users'][username]['Drive Letter'] = data[(driveletter_ofst + 0xCC):(
                                    driveletter_ofst + 0xCC + driveletter_lngth)]
                        results['users'][username]['Profile Path'] = data[(profilepath_ofst + 0xCC):(
                                    profilepath_ofst + 0xCC + profilepath_lngth)]
                        results['users'][username]['Logon Script'] = data[(logonscript_ofst + 0xCC):(
                                    logonscript_ofst + 0xCC + logonscript_lngth)]
                        results['users'][username]['Workstations'] = data[(workstations_ofst + 0xCC):(
                                    workstations_ofst + 0xCC + workstations_lngth)]
                        # results['users'][username]['LM Password Hash'] = data[(lmpwhash_ofset+0xCC):(lmpwhash_ofset+0xCC + lmpwhash_lngth)]
                        # results['users'][username]['NT Password Hash'] = data[(ntpwhash_ofset+0xCC):(ntpwhash_ofset+0xCC + ntpwhash_lngth)]

                        continue
        # Now we combine the two!
        for RID in f_values:
            for user in results['users']:
                if results['users'][user]['RID'] == str(RID):
                    results['users'][user]['Last Login Date'] = f_values[RID][0]
                    results['users'][user]['Password Reset Date'] = f_values[RID][1]
                    results['users'][user]['Password Fail Date'] = f_values[RID][2]
                    results['users'][user]['Account Flags'] = ""
            for user in results:
                if results[user]['RID'] == str(RID):
                    results['users'][user]['Last Login Date'] = f_values[RID][0]
                    results['users'][user]['Password Reset Date'] = f_values[RID][1]
                    results['users'][user]['Password Fail Date'] = f_values[RID][2]
                    results['users'][user]['Account Flags'] = ""
                    for flag in f_values[RID][3]:
                        results['users'][user]['Account Flags'] += (flag + " | ")
                    results['users'][user]['Failed Login Count'] = f_values[RID][4]
                    results['users'][user]['Login Count'] = f_values[RID][5]
                    break

        results['groups'] = OrderedDict()
        # Now to parse the groups!
        groupsRoot = sam.open("SAM\\Domains\\Builtin\\Aliases")
        for x in groupsRoot.subkeys():
            if x.name()[
               :5] == "00000":  # We dont actually need the Names/Members keys here beacuse everything is in the "C" value
                # this is going to be the same as the V value, we have to unpack offsets/points to get the data we need
                # In the C key all offsets are started from 0x34 (this means we do offset+0x34)
                data = x.value("C").value()
                name_offst = struct.unpack("<L", data[16:20])[0]
                name_length = struct.unpack("<L", data[20:24])[0]
                comment_offst = struct.unpack("<L", data[28:32])[0]
                comment_lngth = struct.unpack("<L", data[32:36])[0]
                users_offset = struct.unpack("<L", data[40:44])[0]

                user_count = struct.unpack("<L", data[48:52])[0]

                groupname = data[(name_offst + 52):(name_offst + 52 + name_length)]
                results['groups'][groupname] = OrderedDict()
                results['groups'][groupname]['Group Description'] = data[(comment_offst + 52):(
                            comment_offst + 52 + comment_lngth)]
                results['groups'][groupname]['Last Write'] = x.timestamp()
                results['groups'][groupname]['User Count'] = user_count
                results['groups'][groupname]['Members'] = ''

                try:
                    newOffset = 0
                    for i in range(11, 0, -1):
                        offset = int(users_offset + 52 + newOffset)
                        tmp = struct.unpack("<L", data[offset:offset + 4])[0]
                        if tmp == 257:
                            if struct.unpack("<B", data[offset:offset + 1])[0] == 0:
                                offset = offset + 1
                            results['groups'][groupname]['Members'] += binary_to_sid(data[offset:offset + 12])
                            # username = sid_to_username(binary_to_sid(data[offset:offset+12]))
                            username = None
                            if username != None:
                                results['groups'][groupname]['Members'] += " -> " + username + "</br>"
                            else:
                                results['groups'][groupname]['Members'] += "\t\n"
                            newOffset += 12
                        elif tmp == 1281:
                            results['groups'][groupname]['Members'] += binary_to_sid(data[offset:offset + 28])
                            # username = sid_to_username(binary_to_sid(data[offset:offset+28]))
                            username = None
                            if username != None:
                                results['groups'][groupname]['Members'] += " -> " + username + "</br>"
                            else:
                                results['groups'][groupname]['Members'] += "\n"
                            newOffset += 28


                except:
                    if len(results['groups'][groupname]['Members']) == 0:
                        results['groups'][groupname]['Members'] = 'No users in this group'
                    else:
                        continue

        return results
    def run(self, hive, registry_handler=None, args=None) -> list:
        """ Execute plugin specific actions on the hive
                    - The return value should be the list of registry_provider.registry_item objects """

        if not hive:
            logger.warning('Unsupported hive file')
            return []

        if not self.is_hive_supported(hive=hive):
            logger.warning('Unsupported hive type: %s' % hive.hive_type)
            return []

        #  Load required registry provider
        self.load_provider()

        logger.debug('Plugin: %s -> Run(%s)' % (self.name, hive.hive_file_path))

        items = []

        registry_handler = self.choose_registry_handler(main_reg_handler=registry_handler, plugin_reg_handler=self.parsed_args.registry_handlers)

        items.extend(self.sam_parse_users(items, hive, registry_handler))

        return self.return_items(items)
