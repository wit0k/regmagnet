import logging
import argparse
from md.plugin import plugin

logger = logging.getLogger('regmagnet')

QUERY_VALUE_LIST = [
    r"Software\Microsoft\Windows NT\CurrentVersion\Windows\Load",
    r"Microsoft\Windows NT\CurrentVersion\Windows\Load",
    r"Software\Microsoft\Windows NT\CurrentVersion\Windows\Run",
    r"Microsoft\Windows NT\CurrentVersion\Windows\Run",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\*",
    r"Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\*",
    r"Software\Microsoft\Windows\CurrentVersion\Run\COM+",
    r"Microsoft\Windows\CurrentVersion\Run\COM+",
    r"ControlSet001\Control\SafeBoot\AlternateShell",
    r"ControlSet002\Control\SafeBoot\AlternateShell",
    r"ControlSet003\Control\SafeBoot\AlternateShell",
    r"Microsoft\Windows NT\CurrentVersion\Winlogon\System",  # https://attack.mitre.org/techniques/T1547/004/, # Manual_CS.txt (#ContiLeaks)
    r"Microsoft\Windows NT\CurrentVersion\Winlogon\TaskMan",
    r"Microsoft\Windows NT\CurrentVersion\Winlogon\VMApplet",
    r"Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
    r"Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
    r"Microsoft\Windows NT\CurrentVersion\Winlogon\UIHost",
    r"Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\Lock",
    r"Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\Logoff",
    r"Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\Logon",
    r"Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\Shutdown",
    r"Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\StartScreenSaver",
    r"Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\StartShell",
    r"Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\Startup",
    r"Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\StopScreenSaver",
    r"Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\Unlock",
    r"Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\*\DLLName",
    r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\System",
    r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\TaskMan",
    r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\VMApplet",
    r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
    r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
    r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\UIHost",
    r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\Lock",
    r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\Logoff",
    r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\Logon",
    r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\Shutdown",
    r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\StartScreenSaver",
    r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\StartShell",
    r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\Startup",
    r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\StopScreenSaver",
    r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\Unlock",
    r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\*\DLLName",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\System",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\TaskMan",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\VMApplet",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\UIHost",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\Lock",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\Logoff",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\Logon",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\Shutdown",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\StartScreenSaver",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\StartShell",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\Startup",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\StopScreenSaver",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\Unlock",
    r"Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\*\DLLName",
    r"Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",  # Need to check if value or a key
    r"Wow6432Node\Microsoft\Active Setup\Installed Components\*\StubPath",
    r"Microsoft\Active Setup\Installed Components\*\StubPath",
    r"Microsoft\Office\*\*\Options\OPEN",  # https://twitter.com/william_knows/status/909788804696944642/photo/1
    r"Software\Microsoft\Office\*\Common\AdditionalActionsDLL",
    r"Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs",
    r"ControlSet001\Control\Lsa\Authentication Packages",
    r"ControlSet002\Control\Lsa\Authentication Packages",
    r"ControlSet003\Control\Lsa\Authentication Packages",
    r"ControlSet001\Control\Lsa\Security Packages",
    r"ControlSet002\Control\Lsa\Security Packages",
    r"ControlSet003\Control\Lsa\Security Packages",
    r"ControlSet001\Control\Lsa\OSConfig\Security Packages",
    r"ControlSet002\Control\Lsa\OSConfig\Security Packages",
    r"ControlSet003\Control\Lsa\OSConfig\Security Packages",
    r"ControlSet001\Control\Print\Monitors\*\Driver",
    r"ControlSet002\Control\Print\Monitors\*\Driver",
    r"ControlSet003\Control\Print\Monitors\*\Driver",
    r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*\VerifierDlls", # http://cybellum.com/doubleagentzero-day-code-injection-and-persistence-technique/
    r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*\VerifierDlls",
    r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*\Debugger", # https://blog.malwarebytes.com/101/2015/12/an-introduction-to-image-file-execution-options/
    r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*\Debugger",
    r"Microsoft\Windows\CurrentVersion\App Paths\*\(default)",
    r"Microsoft\Windows\CurrentVersion\App Paths\wmplayer.exe\Path",
    # http://www.hexacorn.com/blog/2018/03/15/beyond-good-ol-run-key-part-73/
    r"Environment\UserInitMprLogonScript",  # http://www.hexacorn.com/blog/2014/11/14/beyond-good-ol-run-key-part-18/
    r"Environment\UserInitLogonServer",
    r"Environment\UserInitLogonScript",
    r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*\GlobalFlag",
    # https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/
    r"Microsoft\Windows NT\CurrentVersion\SilentProcessExit\*\MonitorProcess",
    # https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/
    r"Software\Microsoft\HtmlHelp Author\location",
    # http://www.hexacorn.com/blog/2018/04/22/beyond-good-ol-run-key-part-76/
    r"Microsoft\PushRouter\Test\TestDllPath2",  # http://www.hexacorn.com/blog/2018/10/10/beyond-good-ol-run-key-part-91/
    r"Microsoft\Windows NT\CurrentVersion\ICM\Calibration\DisplayCalibrator",  # https://twitter.com/James_inthe_box/status/1084982201496657921?s=03
    r"ControlSet001\services\TermService\Parameters\ServiceDll",  # https://twitter.com/SBousseaden/status/1090411586139885568?s=03
    r"ControlSet002\services\TermService\Parameters\ServiceDll",
    r"ControlSet003\services\TermService\Parameters\ServiceDll",
    r"ControlSet001\Control\ContentIndex\Language\English_UK\DLLOverridePat",
    r"ControlSet002\Control\ContentIndex\Language\English_US\DLLOverridePat",
    r"ControlSet003\Control\ContentIndex\Language\Neutral\DLLOverridePath",
    r"System\*\*\ImagePath",  # https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/,
    r'Microsoft\Windows\Windows Error Reporting\Hangs\Debugger',  # http://www.hexacorn.com/blog/2019/09/20/beyond-good-ol-run-key-part-116/
    r"Microsoft\Windows NT\CurrentVersion\AeDebugProtected\ProtectedDebugger",  # http://www.hexacorn.com/blog/2019/10/11/beyond-good-ol-run-key-part-119/
    r"Microsoft\Windows NT\CurrentVersion\Ports",  # https://windows-internals.com/printdemon-cve-2020-1048/
    r"regex(ControlSet00[0-4])\Services\regex(.*)\NetworkProvider\ProviderPath",  # https://github.com/gtworek/PSBits/tree/master/PasswordStealing/NPPSpy"
    r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options\regex(.*)\VerifierDlls", # https://cybellum.com/doubleagentzero-day-code-injection-and-persistence-technique/
    r"regex(ControlSet00[0-4])\Control\LsaExtensionConfig\LsaSrv\Extensions", # https://twitter.com/0gtweet/status/1476286368385019906?t=hfWwMUjghwgeIFr9JuGtWQ&s=03
    r"Software\Microsoft\Office test\Special\Perf", # https://attack.mitre.org/techniques/T1137/002/, # Manual_CS.txt (#ContiLeaks)
    r"Microsoft\Office test\Special\Perf", # https://attack.mitre.org/techniques/T1137/002/, # Manual_CS.txt (#ContiLeaks)
    r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs", # https://attack.mitre.org/techniques/T1546/010/, # Manual_CS.txt (#ContiLeaks)
    r"Microsoft\Windows NT\CurrentVersion\SilentProcessExit\*\MonitorProcess", # https://attack.mitre.org/techniques/T1546/012/, # Manual_CS.txt (#ContiLeaks) .. This must be enabled to make it work reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\*" /v ReportingMode /t REG_DWORD /d 1
]

QUERY_KEY_LIST = [
    r"Select",
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Microsoft\Windows\CurrentVersion\Run",
    r"Wow6432Node\Microsoft\Windows\CurrentVersion\Run",  # Might not exist
    r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows NT\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\Run\*",  # http://www.silentrunners.org/launchpoints.html
    r"Microsoft\Windows\CurrentVersion\Run\*",
    r"Wow6432Node\Microsoft\Windows\CurrentVersion\Run\*",
    r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run\*",
    r"Software\Microsoft\Windows NT\CurrentVersion\Run\*",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Microsoft\Windows\CurrentVersion\RunOnce",
    r"Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Microsoft\Windows\CurrentVersion\RunOnceEx",
    r"Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx",
    r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce\*",  # http://www.silentrunners.org/launchpoints.html
    r"Microsoft\Windows\CurrentVersion\RunOnce\*",
    r"Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce\*",
    r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce\*",
    r"Microsoft\Windows\CurrentVersion\RunOnceEx\*",
    r"Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx\*",
    r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx\*",
    # https://oddvar.moe/2018/03/21/persistence-using-runonceex-hidden-from-autoruns-exe/
    r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx\*",
    r"Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\RunServices",
    r"Microsoft\Windows\CurrentVersion\RunServices",
    r"Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices",
    r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices",
    r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run",
    r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run",
    r"Microsoft\Windows NT\CurrentVersion\WOW\boot",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
    r"Microsoft\Windows\CurrentVersion\Policies\System",
    r"ControlSet001\Control\Session Manager\AppCertDlls",
    r"ControlSet002\Control\Session Manager\AppCertDlls",
    r"ControlSet003\Control\Session Manager\AppCertDlls",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\Common Startup",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\Common Startup",
    r"Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\Common Startup",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\Startup",
    r"Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\Startup",
    r"Microsoft\Windows\CurrentVersion\explorer\ShellExecuteHooks",
    r"Control Panel\Desktop\Scrnsave.exe",
    r"Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB",
    r"Microsoft\NetSh",  # https://attack.mitre.org/wiki/Technique/T1128
    r"Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\*",
    r"Software\Microsoft\Office test\Special\Perf\*",
    r"Software\Microsoft\Windows\Windows Error Reporting\RuntimeExceptionHelperModules",
    # https://msdn.microsoft.com/en-us/library/windows/desktop/dd408167(v=vs.85).aspx
    r"Microsoft\Windows\Windows Error Reporting\RuntimeExceptionHelperModules",
    # https://msdn.microsoft.com/en-us/library/windows/desktop/dd408167(v=vs.85).aspx
    r"Software\Microsoft\Office Test\Special\Perf",
    # http://www.hexacorn.com/blog/2014/04/16/beyond-good-ol-run-key-part-10/
    r"ControlSet001\Control\Lsa\Notification Packages",
    r"ControlSet002\Control\Lsa\Notification Packages",
    r"ControlSet003\Control\Lsa\Notification Packages", # https://attack.mitre.org/wiki/Technique/T1174
    r'Microsoft\Windows NT\CurrentVersion\WirelessDocking\DockingProviderDLLs',
    r"Software\Classes\ActivatableClasses\Package\*\DebugInformation\*",  # https://oddvar.moe/2018/09/06/persistence-using-universal-windows-platform-apps-appx/
    r"Software\Microsoft\Windows\CurrentVersion\PackagedAppXDebug\*",
    r'Microsoft\Windows\CurrentVersion\Installer\RunOnceEntries',
    r'Wow6432Node\Microsoft\Windows\CurrentVersion\Installer\RunOnceEntries',
    r'Software\Microsoft\Run' #  https://brica.de/alerts/alert/public/1250345/evading-av-with-javascript-obfuscation/,
    r'Software\Microsoft\Microsoft SQL Server\*\Tools\Shell\Addins',
    r'Microsoft\Microsoft SQL Server\*\Tools\Shell\Addins',
    r"Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList", # https://attack.mitre.org/techniques/T1564/002/, # Manual_CS.txt (#ContiLeaks) /v attacker /t REG_DWORD /d 0
    r"Microsoft\NetSh", # https://attack.mitre.org/techniques/T1546/007/, # Manual_CS.txt (#ContiLeaks)
]


class autoruns(plugin):
    """ autoruns - RegMagnet plugin  """

    """ Standard expected variables  """
    author = 'wit0k'
    name = 'autoruns'
    description = 'Enumerates common ASEPs / Loadpoints'
    config_file = ''  # IF it's empty/None, the config_data dictionary would not be auto-loaded
    baseline_file = 'baseline/autoruns.bl'

    """ Variables initialized by the plugin manager """
    args = None  # Holds plugin related arguments
    parser = None  # Represents the registry_parser object
    config_data = {}  # Contains the json data loaded from config_file (If any was specified and properly created)

    def run(self, hive, registry_handler=None, args=None) -> list:
        """ Execute plugin specific actions on the hive
                    - The return value should be the list of registry_provider.registry_item objects """

        if not hive:
            logger.warning('Unsupported hive file')
            return []

        #  Load required registry provider
        self.load_provider()

        logger.debug('Plugin: %s -> Run(%s)' % (self.name, hive.hive_file_path))

        items = []

        registry_handler = self.choose_registry_handler(main_reg_handler=registry_handler, plugin_reg_handler=self.parsed_args.registry_handlers)

        items.extend(self.parser.query_key_wd(key_path=QUERY_KEY_LIST, hive=hive, plugin_name=self.name, reg_handler=registry_handler))
        items.extend(self.parser.query_value_wd(value_path=QUERY_VALUE_LIST, hive=hive, plugin_name=self.name, reg_handler=registry_handler))

        return self.return_items(items)
