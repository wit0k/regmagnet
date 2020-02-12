# RegMagnet 0.0.0.3 [BETA]

#### Description:

RegMagnet (rm) is a python wrapper script for offline registry framework like:
* python-registry (@williballenthin) [Default registry provider]
* yarp (@msuhanov) [Support for registry permissions related searches]

This command-line utility is designed to slightly extend and facilitate framework’s capabilities. I wrote it once to improve my older regparser script.
In general it is used to parse any offline windows registry hives during malware hunting or forensic investigations.

**--> The right documentation yet to come (When time allows) <--**

It comes with following major features: 

* Search for a registry key, value name or value data patterns described by a comma separated: strings, regex strings or utf8 hex binary strings
* Search for value data by its size, specified by operators like range, equality or inequality
* Search for registry modified keys at given date and time, specified by regex string pattern or range, or inequality operators 
* Query the registry keys or values (including partial wildcard support)
* Enumerate and display hidden keys and values
* Supports searching by registry permissions (Key owner etc.) [Experimental - Not finished yet]
* Hash registry value content
* Detect hive type
* Export results to .REG format (Simplifies malware analysis/infection reproduction based on file-less registry load points)
* Export results to SQLite (Used by regmagnet for plugin’s baseline)
* Export results to CSV or stout
* Export results to JSON (str(dict))
* Customize output data (21+ different format fields)
* Easy plugin implementation and support with built in plugins like "autoruns", "services", "apt", "macro", "search", "parser", ...
* Improved Plugins baseline support 

Note: More details in **README.pdf**

#### Minimum Requirements:

* Python 3.7 Framework
* Dependencies from requirements.txt
* Operating system:  Windows, Linux, MacOS, Cygwin

***Install***:
<pre>
mkdir /tools  # Adjust the path as required 
mkdir /venvs  # Adjust the path as required 
cd /venvs
pip install virtualenv # More info here: https://docs.python-guide.org/dev/virtualenvs/
virtualenv -p /usr/bin/python3.X regmagnet  # Adjust python version. (3.7+ required)
cd /tools
git clone https://github.com/wit0k/regmagnet.git
cd regmagnet
source /venvs/regmagnet/bin/activate
pip install -U pip
pip install -U setuptools
pip install -r requirements.txt 
</pre>

In proxy enabled environment: 
<pre>
pip --proxy http://PROXY_IP:PORT install -U pip
pip --proxy http://PROXY_IP:PORT install -U -r requirements.txt
</pre>
<pre>
REMARK: Regarding git configuration: 

To add proxy support: 
    git config --global http.proxy http://proxyUsername:proxyPassword@proxy.server.com:port
    git config --global http.proxy http://proxy.server.com:port

To remove proxy support: 
    git config --global --unset http.proxy
</pre>

***Update***:
<pre>
cd /tools/regmagnet
git pull
</pre>

***Usage***:

Following code example covers the usage of <b>regmagnet</b> parameters.

####Get Hive information
Print information about given hive and its direct sub-keys:
<pre>
-s "examples/poweliks.dat" -p "parser -hi"
</pre>
Result:
<pre>
Mapping: HKEY_CURRENT_USER
Root Key: $$$PROTO.HIV
Hive: examples/poweliks.dat
Hive type: NTUSER
Subkeys: 
     [*] $$$PROTO.HIV:
     [+] AppEvents
     [+] Console
     [+] Control Panel
     [+] Environment
     [+] Identities
     [+] Keyboard Layout
     [+] Network
     [+] Printers
     [+] Software
     [+] UNICODE Program Groups
</pre>

####Query keys
Query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
* Both queries produce the same result, since -f csv is enabled by default
<pre>
-s "examples/poweliks.dat" -p "parser -qk Software\Microsoft\Windows\CurrentVersion\Run"
-s "examples/poweliks.dat" -f csv -p "parser -qk Software\Microsoft\Windows\CurrentVersion\Run"
</pre>
Result:
* [...] means that i have removed the value content manually to improve readability [The content was very long]
<pre>
[+] Loading Registry Provider: python_registry
[+] Parsing script arguments
[+] Loading Plugin Manager
[+] Searching for input files
[+] Parsing input hives
[+] Loading Plugin: parser
[+] Executing plugins ...
[+] Printing CSV formatted data
parser,HKEY_CURRENT_USER,2014-09-04 13:12:25.703125,1,4,S-1-5-21-606747145-117609710-1801674531-500,Software\Microsoft\Windows\CurrentVersion\Run,fbdfabbccabsacfsfdsf,"C:\Documents and Settings\All Users\Application Data\fbdfabbccabsacfsfdsf.exe"
parser,HKEY_CURRENT_USER,2014-09-04 13:12:25.703125,1,4,S-1-5-21-606747145-117609710-1801674531-500,Software\Microsoft\Windows\CurrentVersion\Run, a,rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write("\74script language=jscript.encode>" [...]
parser,HKEY_CURRENT_USER,2014-09-04 13:12:25.703125,1,4,S-1-5-21-606747145-117609710-1801674531-500,Software\Microsoft\Windows\CurrentVersion\Run,(default),#@~^ZXgAAA==W!x^DkKx [...] snAA==^#~@
parser,HKEY_CURRENT_USER,2014-09-04 13:12:25.703125,1,4,S-1-5-21-606747145-117609710-1801674531-500,Software\Microsoft\Windows\CurrentVersion\Run,ctfmon.exe,C:\WINDOWS\system32\ctfmon.exe
</pre>
*Registry Handlers:*

Print all registry handlers:
<pre>
Option:  "-prh", "--print-registry-handlers"
</pre>
Example output:
<pre>
Registry Handlers:
 [+] decrypt_teamviewer - aes_cbc() -> Decrypt data with aes-cbc ... beta
 [+] dump_to_file - dump_to_file() -> Saves the input data buffer to a file specified by a parameter
 [+] decompress_gzip - decompress_gzip() -> Attempts to un-gzip the input data
 [+] decrypt_rc4 - decrypt_rc4(Key) -> Decrypts the input data with a string key specified
 [+] sxor - sxor(Key) -> XOR the input data with a string key specified
 [+] str - str() -> Converts the input data to String
 [+] shexdump - str2hex(input_data) -> Converts the input data to HexDump string format
 [+] unescape_url - unescape_url -> Unescapes the input data string/url
 [+] cit_dump - cit_dump() -> Dumps the unicode string and converts it to human readable format (Used for strings originating from cit plugin)
 [+] utf8_dump - utf8_dump() -> Dumps the unicode string and converts it to human readable format
 [+] rslice - slice(start) -> Slice the input data [Range: start:]
 [+] slice - slice(0, stop) -> Slice the input data [Range: 0:stop]
 [+] b64_dump - Dump and decode base64 strings from the input data
 [+] b64_decode - Decode the input data as base64 string
 [+] b64_encode - Encode the input data to base64 string
 [+] decode_vbe - Attempts to VBE decrypt the input data
 [+] nothing - Do nothing, reserved for plugin developers...(Mainly used when only custom handler is required)
 [+] entropy - entropy() -> Calculates the entropy of the input data
</pre>

Create a registry handler, which would base64 encode fields: value_name and value_content:

<pre>-rh "b64_encode&lt;field&gt;value_name;value_content"</pre>

*Executing Plugins:*

<pre>
Option:  -p, --plugins
</pre>

Following command would execute all specified plugins against all loaded hives:
<pre>
-p "autoruns,office"
</pre>

Following code example covers the usage of "parser" plugin.

Get information about loaded registry hives:

<pre>
Option:  --hive-info, -hi
</pre>

Get information about a registry key:

<pre>
Option:  --key-info, -ki
Param:   --key-info "key_string"

Example: 
         --key-info "Microsoft\Windows\CurrentVersion"
</pre>

Query registry key(s): 

<pre>
Option:  --query-key, -qk
Param:   --query-key "key_string"
         --query-key "key_string1","key_string2","key_stringN"

Example: 
         --query-key "Microsoft\Windows\CurrentVersion\Run","Software\Microsoft\Windows\CurrentVersion\Run"
</pre>

Query registry value(s): 

<pre>
Option:  --query-value, -qv
Param:   --query-value "key_string"
         --query-value "value_path_string1","value_path_string2","..."

Example: 
         --query-key "Microsoft\Windows\CurrentVersion\Run\ValueName","Software\Microsoft\Windows\CurrentVersion\Run\ValueName2"
</pre>

**Baseline:**

It's still in beta version (a feature from regparser, with low attention rate, but i still think that it's usefull)

* Create a baseline file (Whitelisted entries) on vanilla-clean machine: 
  <pre>-s "/hives/baseline/clean" -o baseline/autoruns.bl -f sqlite -p "autoruns"</pre>

* Only the items NOT present in the autoruns.bl will be printed 
  <pre>
  -s "/hives/offline_reg_file" -p "autoruns -b"
  Note: -b force the plugin to load a baseline file (default: baseline/%name_of_plugin.bl%)
  </pre>

***Plugins***:

**Functions usage:**

RegMagnet functions can be called via **exec_action** which accepts a function name and parameters:
<pre>
items = []
items = parser.exec_action(action_name='query_key', parameters=(parser, r'Microsoft\Windows\CurrentVersion\Run', _hive_file))
</pre>

Similarly all functions can be triggered directly by the registry_parser object (in traditional way):
<pre>
items = []
items = items = parser.query_key(r'Microsoft\Windows\CurrentVersion\Run', _hive_file)
</pre>

Currently following functions are exposed by a string:

<pre>actions = {
        'python-registry': {
            'query_key_wd': query_key_wd,
            'query_key': query_key,
            'query_key_recursive': query_key_recursive,
            'query_value': query_value,
            'query_value_wd': query_value_wd,
            'hive_info': hive_info,
            'key_info': key_info,
            'export': export,
            'print': print
        }
    }
</pre>

**Format fields:**

Plugins can dynamically add new format fields(upon startup) to following objects: registry_hive, registry_key and registry_value respectively, by calling following parser function:

*Note*: IF you specify the same field_name for all obj_names, only the field for obj_name="value" would be taken into account upon creation of registry_item object. 

<pre>
parser.add_format_field(obj_name='hive', field_name='hive_hostname')
parser.add_format_field(obj_name='key', field_name='key_hidden')
parser.add_format_field(obj_name='value', field_name='comments')
</pre>

List of all format fields:  -s "/hives/offline_reg_file" -pff
<pre>
 [+] plugin_name
 [+] hive
 [+] key
 [+] values
 [+] hive_header
 [+] hive_file_path
 [+] hive_file_name
 [+] hive_obj
 [+] hive_root
 [+] hive_type
 [+] hive_size
 [+] hive_md5
 [+] hive_user
 [+] hive_mapping
 [+] key_path
 [+] key_path_unicode
 [+] key_timestamp
 [+] key_subkey_count
 [+] key_value_count
 [+] key_owner
 [+] key_group
 [+] key_permissions
 [+] key_sddl
 [+] value_path
 [+] value_name
 [+] value_name_unicode
 [+] value_type
 [+] value_type_str
 [+] value_content
 [+] value_content_str
 [+] value_content_unicode
 [+] value_size
 [+] value_raw_data
</pre>

**Registry Handlers:**

<pre>
Convert registry value name and value content to base64:

    reg_handler = parser.reg.registry_reg_handler(recipes=['b64_encode&lt;field&gt;value_content,value_name'])
    items.extend(parser.query_value(value_path=r'Microsoft\Windows\CurrentVersion\Run\RTHDVCPL', hive=_hive_file, reg_handler=reg_handler))

Encrypt registry value content with a XOR key and encode it to base64:

    reg_handler = parser.reg.registry_reg_handler(recipes=['sxor&lt;param&gt;XORkey&lt;field&gt;value_content', 'b64_encode'])
    items.extend(parser.query_value(value_path=r'Microsoft\Windows\CurrentVersion\Run\RTHDVCPL', hive=_hive_file, reg_handler=reg_handler))   
</pre>

**Command-line parameters:**
 
 <pre>
* Print script params: -h
* Print plugin specific params:
     -s "/hives/offline_reg_file" -p "parser -h"
     -s "/hives/offline_reg_file" -p "search -h"
     etc.
 </pre>
 
 Script parameters:
 <pre>
RegMagnet - Working with Microsoft Offline Registry Hives

optional arguments:
  -h, --help            show this help message and exit

Script arguments:

  -rp DEFAULT_REGISTRY_PROVIDER, --registry-provider DEFAULT_REGISTRY_PROVIDER
                        Specify the default registry provider to load
                        (Default: -rp "python_registry")
  -v, --verbose         Enables verbose logging
  -s INPUT_HIVES, --hives INPUT_HIVES
                        Registry hive fie or folder containing registry hives
  -r, --recursive       Recursively scan the input folder
  --disable-unzip       Skip supported archives
  -o OUTPUT_FILE, --output OUTPUT_FILE
                        Output file path
  -f OUTPUT_FORMAT, --output-format OUTPUT_FORMAT
                        Output format: "cs" | "tab" | "winreg" | "sqlite"
  -ff FIELDS_TO_PRINT, --output-fields FIELDS_TO_PRINT
                        Comma separated list of output format fields like: -ff
                        "value_path,value_content_str"
  -ffa EXTRA_FIELDS_TO_PRINT, --output-field-append EXTRA_FIELDS_TO_PRINT
                        Append a format field to output format fields list
  -eek, --output-empty-keys
                        Exclude keys without values from the output
  -rh REGISTRY_HANDLERS, --registry-handler REGISTRY_HANDLERS
                        Registry handler string: "handler_name&lt;field&gt;input_fie
                        ld&lt;param&gt;param_n&lt;rfield&gt;result_field" like -rh
                        "b64_encode&lt;field&gt;value_name;value_content" [Note:
                        Input fields and params must be ; separated]
  -rhdp RH_DECODE_PARAM, --registry-handler-decode-param RH_DECODE_PARAM
                        Allow to specify the handler parameters in any of
                        supported encodings: "base64"
  -p PLUGINS_TO_EXECUTE [PLUGINS_TO_EXECUTE ...], --plugins PLUGINS_TO_EXECUTE [PLUGINS_TO_EXECUTE ...]
                        The list of comma separated plugins to execute with
                        thier params like: -p "autoruns,macro,plugin_name"
  -pff, --print-format-fields
                        Print available output format fields
  -prh, --print-registry-handlers
                        Print available registry handlers
 </pre>
 
#### TO DO:
* Continue working on security_descriptor, to obtain the key_sddl field 
* Make sure that regex, cannot be used in conjunction with *
* Use the list of registry_item objects to create winreg data and sqlite data (instead of a list of dicts, coming from registry_item.items())
* Add json output format
