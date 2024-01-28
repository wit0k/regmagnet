import io
import logging
from operator import iand
import bitstring
import struct
import re
import enum
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from winacl.dtyp.ace import FILE_ACCESS_MASK, REGISTRY_ACCESS_MASK

logger = logging.getLogger('regmagnet')

""" 
TO DO:
- Finish key_sddl function
- Simplify the code
- Review: https://medium.com/@cryps1s/detecting-windows-endpoint-compromise-with-sacls-cd748e10950

References:

Windows registry file format specification
https://github.com/msuhanov/regf

https://referencesource.microsoft.com/#mscorlib/system/security/accesscontrol/securitydescriptor.cs,85a0744218296e54,references
https://referencesource.microsoft.com/#mscorlib/system/security/accesscontrol/registrysecurity.cs
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428

"""

# New code:
# https://github.com/skelsec/winacl/blob/main/winacl/functions/constants.py#L5
class SD_OBJECT_TYPE(enum.Enum):
	SE_UNKNOWN_OBJECT_TYPE = 0 #Unknown object type.
	SE_FILE_OBJECT = 1 #Indicates a file or directory.
	SE_SERVICE = 2 #Indicates a Windows service
	SE_PRINTER = 3 #Indicates a printer.
	SE_REGISTRY_KEY = 4 #Indicates a registry key.
	SE_LMSHARE = 5 #Indicates a network share.
	SE_KERNEL_OBJECT = 6 #Indicates a local 
	SE_WINDOW_OBJECT = 7 #Indicates a window station or desktop object on the local computer
	SE_DS_OBJECT = 8 #Indicates a directory service object or a property set or property of a directory service object. 
	SE_DS_OBJECT_ALL = 9 #Indicates a directory service object and all of its property sets and properties.
	SE_PROVIDER_DEFINED_OBJECT = 10 #Indicates a provider-defined object.
	SE_WMIGUID_OBJECT = 11 #Indicates a WMI object.
	SE_REGISTRY_WOW64_32KEY = 12 #Indicates an object for a registry entry under WOW64.
	SE_REGISTRY_WOW64_64KEY = 13 #Indicates an object for a registry entry under WOW64.
        

class windows_security_descriptor(object): # https://github.com/xBlackSwan/winacl/blob/master/winacl/dtyp/security_descriptor.py

    obj_type = None
    
    def __init__(self, sd_bytes: bytes, obj_type=None):
                
        if obj_type is None:
            self.obj_type=SD_OBJECT_TYPE.SE_REGISTRY_KEY.value
        else:
            self.obj_type=obj_type.value

        self.sd_bytes = io.BytesIO(sd_bytes)
        self.sd = SECURITY_DESCRIPTOR.from_buffer(self.sd_bytes)
        self.sddl = '"%s"' % self.sd.to_sddl()
        self.owner_name = self.get_owner_name()
        self.owner_sid = self.get_owner_sid()
        self.group_name = self.get_group_name()
        self.group_sid = self.get_group_sid()
        self.permissions = []
        
        for ace in self.sd.Dacl.aces:
            ace_permissions = self.get_ace_mask_permissions(ace=ace, sd_obj_type=self.obj_type)
            self.permissions.append(ace_permissions)
    
    
    def json(self, flat=True, prefix=''):
        
        sd_data = {
            '%spermissions' % prefix: []
        }
        
        if flat == False:
            sd_data.update({
                '%sowner_name' % prefix: self.owner_name,
                '%sgroup_name' % prefix: self.group_name,
                '%sgroup_name' % prefix: self.group_name,
                '%sgroup_sid' % prefix: self.group_sid,
                '%ssddl' % prefix: self.sddl,
                '_nested_keys_': ['permissions'],
                '%spermissions' % prefix: []
            })
        
        ace_index = 1
        for ace in self.permissions:
            
            if flat == True: 
                for key, value in ace.items():
                    sd_data['ace.%s.%s' % (ace_index,key)] = value
            else:
                json_data = {}
                for key, value in ace.items():
                    json_data.update({'ace_%s' % key: value})
                
                sd_data['%spermissions' % prefix].append(json_data)
            ace_index += 1
        
        return sd_data

    def get_owner_sid(self):
        return (self.sd.Owner.to_sddl())

    def get_owner_name(self):
        return (self.sd.Owner.wellknown_sid_lookup(self.sd.Owner.to_sddl()))
    
    def get_group_sid(self):
        return (self.sd.Group.to_sddl())

    def get_group_name(self) -> str:
        return (self.sd.Group.wellknown_sid_lookup(self.sd.Group.to_sddl()))
        
    def get_ace_mask_permissions(self, ace, sd_obj_type) -> dict:
        
        # print(ace.to_bytes())
        
        ace_mask = ace.Mask
        ace_type = self.get_ace_type_str(ace.AceType)
        user = self.sd.Owner.wellknown_sid_lookup(ace.Sid.to_sddl())
        
        access_rights = {}

        if sd_obj_type == SD_OBJECT_TYPE.SE_FILE_OBJECT.value:
            access_rights = {
                'user_sid': ace.Sid.to_sddl(),
                'user_name': user,
                'ace_type': ace_type,
                'permissions':'([User:%s] - [File-%s] - %s)' % (user, ace_type, FILE_ACCESS_MASK(ace_mask).name),
                'sd_type': 'SE_FILE_OBJECT',
            }
        elif sd_obj_type == SD_OBJECT_TYPE.SE_REGISTRY_KEY.value:
            access_rights = {
                'user_sid': ace.Sid.to_sddl(),
                'user_name': user,
                'ace_type': ace_type,
                'permissions': '([User:%s] - [Registry-%s] - %s)' % (user, ace_type, REGISTRY_ACCESS_MASK(ace_mask).name),
                'sd_type': 'SE_REGISTRY_KEY',
            }
        else:
            pass
            
        return access_rights
    
    def get_ace_type_str(self, ace_type):
        
        type_str = '%s' % ace_type
        
        if len(type_str) > 1:
            type_str = type_str.replace('ACEType.', '')
            type_str = type_str.replace('_ACE_TYPE', '')
        else:
            type_str = 'ACE_Unknown'
        
        return type_str
    


# Old code:
class security_descriptor(object):

    """ The class exposes data used by following format fields:  key_owner, key_group, key_permissions, key_sddl

    MS Documentation:

    SECURITY_DESCRIPTOR
    https://msdn.microsoft.com/en-us/library/cc230366.aspx

    Security descriptors appear in one of two forms, absolute or self-relative.

    - A security descriptor is said to be in absolute format if it stores all of its security information via pointer fields, as specified in the RPC representation in section 2.4.6.1.
    - A security descriptor is said to be in self-relative format if it stores all of its security information in a contiguous block of memory and expresses all of its pointer fields as offsets from its beginning.
        The order of appearance of pointer target fields is not required to be in any particular order; the location of  the OwnerSid, GroupSid, Sacl, and/or Dacl is only based on OffsetOwner, OffsetGroup, OffsetSacl, and/or OffsetDacl pointers found in the fixed portion of the relative security descriptor.


    typedef struct _SECURITY_DESCRIPTOR {
        BYTE                        Revision;  --> Revision (1 byte): An unsigned 8-bit value that specifies the revision of the SECURITY_DESCRIPTOR structure. This field MUST be set to one.
        BYTE                        Sbz1;      --> Sbz1 (1 byte): An unsigned 8-bit value with no meaning unless the Control RM bit is set to 0x1. If the RM bit is set to 0x1, Sbz1 is interpreted as the resource manager control bits that contain specific information<72> for the specific resource manager that is accessing the structure. The permissible values and meanings of these bits are determined by the implementation of the resource manager.
        SECURITY_DESCRIPTOR_CONTROL Control;   --> Control (2 bytes): An unsigned 16-bit field that specifies control access bit flags. The Self Relative (SR) bit MUST be set when the security descriptor is in self-relative format.
        PSID                        Owner;     --> OffsetOwner (4 bytes): An unsigned 32-bit integer that specifies the offset to the SID. This SID specifies the owner of the object to which the security descriptor is associated. This must be a valid offset if the OD flag is not set. If this field is set to zero, the OwnerSid field MUST not be present.
        PSID                        Group;     --> OffsetGroup (4 bytes): An unsigned 32-bit integer that specifies the offset to the SID. This SID specifies the group of the object to which the security descriptor is associated. This must be a valid offset if the GD flag is not set. If this field is set to zero, the GroupSid field MUST not be present.
        PACL                        Sacl;      --> OffsetSacl (4 bytes): An unsigned 32-bit integer that specifies the offset to the ACL that contains system ACEs. Typically, the system ACL contains auditing ACEs (such as SYSTEM_AUDIT_ACE, SYSTEM_AUDIT_CALLBACK_ACE, or SYSTEM_AUDIT_CALLBACK_OBJECT_ACE), and at most one Label ACE (as specified in section 2.4.4.13). This must be a valid offset if the SP flag is set; if the SP flag is not set, this field MUST be set to zero. If this field is set to zero, the Sacl field MUST not be present.
        PACL                        Dacl;      --> OffsetDacl (4 bytes): An unsigned 32-bit integer that specifies the offset to the ACL that contains ACEs that control access. Typically, the DACL contains ACEs that grant or deny access to principals or groups. This must be a valid offset if the DP flag is set; if the DP flag is not set, this field MUST be set to zero. If this field is set to zero, the Dacl field MUST not be present.

    } SECURITY_DESCRIPTOR, *PISECURITY_DESCRIPTOR;

    Remark:

    - OwnerSid (variable): The SID of the owner of the object. The length of the SID MUST be a multiple of 4. This field MUST be present if the OffsetOwner field is not zero.
    - GroupSid (variable): The SID of the group of the object. The length of the SID MUST be a multiple of 4. This field MUST be present if the GroupOwner field is not zero.<73>
    - Sacl (variable): The SACL of the object. The length of the SID MUST be a multiple of 4. This field MUST be present if the SP flag is set.
    - Dacl (variable): The DACL of the object. The length of the SID MUST be a multiple of 4. This field MUST be present if the DP flag is set.

        Revision = 0x00	        # Size: 1
        Padding = 0x01	        # Size: 1
        Control_Flags = 0x02    # Size: 2
        OffsetOwner = 0x04	    # Size: 4
        OffsetGroup = 0x08      # Size: 4
        OffsetSacl = 0x0C       # Size: 4
        OffsetDacl = 0x10       # Size: 4
        OwnerSid = None         # Size: Variable
        GroupSid = None         # Size: Variable
        Sacl = None             # Size: Variable
        Dacl = None             # Size: Variable

    SID--Packet Representation:

    - Revision (1 byte): An 8-bit unsigned integer that specifies the revision level of the SID. This value MUST be set to 0x01.
    - SubAuthorityCount (1 byte): An 8-bit unsigned integer that specifies the number of elements in the SubAuthority array. The maximum number of elements allowed is 15.
    - IdentifierAuthority (6 bytes): A SID_IDENTIFIER_AUTHORITY structure that indicates the authority under which the SID was created. It describes the entity that created the SID. The Identifier Authority value {0,0,0,0,0,5} denotes SIDs created by the NT SID authority.
    - SubAuthority (variable): A variable length array of unsigned 32-bit integers that uniquely identifies a principal relative to the IdentifierAuthority. Its length is determined by SubAuthorityCount.

    ACL -> ACEs:

    ACE_HEADER:

    AceType = None  # AceType (1 byte): An unsigned 8-bit integer that specifies the ACE types. This field MUST be one of the following values.
    AceFlags = None # AceFlags (1 byte): An unsigned 8-bit integer that specifies a set of ACE type-specific control flags. This field can be a combination of the following values.
    AceSize = None  # (2 bytes): An unsigned 16-bit integer that specifies the size, in bytes, of the ACE. The AceSize field can be greater than the sum of the individual fields, but MUST be a multiple of 4 to ensure alignment on a DWORD boundary. In cases where the AceSize field encompasses additional data for the callback ACEs types, that data is implementation-specific. Otherwise, this additional data is not interpreted and MUST be ignored.

    Other references:
    - https://github.com/An0ther0ne/SSDL_Utils/blob/master/readsddl.py
    - https://github.com/qtc-de/wconv/blob/master/wconv/sddl.py
    
    """
    def __repr__(self):
        resp = '%s | %s | %s | %s' % (self.Control, self.Owner, self.Group, self.Dacl)

        resp = {
            'Control': self.Control.__str__(),
            'Owner': self.Owner,
            'Group': self.Group,
            'Dacl': [_ace.__str__() for _ace in self.Dacl]
        }
        return str(resp)

    def json(self):

        resp = {
            'Control': self.Control,
            'Owner': self.Owner,
            'Group': self.Group,
            'Dacl':  self.Dacl,
            'Sacl': self.Sacl
        }
        return resp

    # Reversing of https://docs.microsoft.com/en-us/windows/desktop/api/sddl/nf-sddl-convertstringsecuritydescriptortosecuritydescriptorw might be required
    def _key_sddl(self):
        """ Not ready yet """

        sddl = []
        _sddl = ''
        _sddl += 'O:' + self.Owner.name() + '  ' + 'G:' + self.Group.name()

        # Case:  Dacl present
        if self.Sacl:
            _sddl += ' S:'  # Sacl SDDL prefix

        if self.Dacl:
            _sddl += ' D:'  # Dacl SDDL prefix

            for _sid in self.Dacl:
                pass

        return _sddl

    def key_group(self):
        """ Returns resolved SID, or just SID if resolution is not possible """
        if self.Group:
            return self.Group.name()
        else:
            return ""

    def key_owner(self):
        """ Returns resolved SID, or just SID if resolution is not possible """
        if self.Owner:
            return self.Owner.name()
        else:
            return ""

    def key_permissions(self):
        """ Shall return AccessToString like output similar to Get-Acl"""
        key_permissions = []

        if self.Dacl:

            for _ace in self.Dacl:
                key_permissions.append(_ace.permissions())

        if key_permissions:
            return ' | '.join(key_permissions)
        else:
            return ''

    HeaderLength = 20

    format_self_relative = None
    format_absolute = None
    Revision = None
    Sbz1 = None
    Control = None
    Owner = None
    Group = None
    Sacl = None
    Dacl = None

    class structures:

        # Ref: https://docs.microsoft.com/pl-pl/windows/desktop/SecAuthZ/security-descriptor-control
        # https://github.com/ldaptools/ldaptools/blob/master/src/LdapTools/Security/SecurityDescriptor.php
        SECURITY_DESCRIPTOR_CONTROL = {
            "SE_DACL_AUTO_INHERIT_REQ": b'\x01\x00',  # '0x0100'
            "SE_DACL_AUTO_INHERITED": b'\x04\x00',  # '0x0400'
            "SE_DACL_DEFAULTED": b'\x00\x08',  # '0x0008'
            "SE_DACL_PRESENT": b'\x00\x04',  # '0x0004'
            "SE_DACL_PROTECTED": b'\x10\x00',  # '0x1000'
            "SE_GROUP_DEFAULTED": b'\x00\x02',  # '0x0002'
            "SE_OWNER_DEFAULTED": b'\x00\x01',  # '0x0001'
            "SE_RM_CONTROL_VALID": b'\x40\x00',  # '0x4000'
            "SE_SACL_AUTO_INHERIT_REQ": b'\x02\x00',  # '0x0200'
            "SE_SACL_AUTO_INHERITED": b'\x08\x00',  # '0x0800'
            "SE_SACL_DEFAULTED": b'\x00\x20',  # '0x0008'
            "SE_SACL_PRESENT": b'\x00\x10',  # '0x0010'
            "SE_SACL_PROTECTED": b'\x20\x00',  # '0x2000'
            "SE_SELF_RELATIVE": b'\x80\x00'  # '0x8000'
        }

        # Ref: https://msdn.microsoft.com/en-us/library/cc230366.aspx
        SECURITY_DESCRIPTOR_CONTROL_BITS_MAPPING = {
            'SR': 'Self-Relative - Set when the security descriptor is in self-relative format. Cleared when the security descriptor is in absolute format.',
            'RM': 'RM Control Valid - Set to 0x1 when the Sbz1 field is to be interpreted as resource manager control bits.',
            'PS': 'SACL Protected - Set when the SACL will be protected from inherit operations.',
            'PD': 'DACL Protected - Set when the DACL will be protected from inherit operations.',
            'SI': 'SACL Auto-Inherited - Set when the SACL was created through inheritance.',
            'DI': 'DACL Auto-Inherited - Set when the DACL was created through inheritance.',
            'SC': 'SACL Computed Inheritance Required - Set when the SACL is to be computed through inheritance. When both SC and SI are set, the resulting security descriptor sets SI; the SC setting is not preserved.',
            'DC': 'DACL Computed Inheritance Required - Set when the DACL is to be computed through inheritance. When both DC and DI are set, the resulting security descriptor sets DI; the DC setting is not preserved.',
            'SS': 'Server Security - Set when the caller wants the system to create a Server ACL based on the input ACL, regardless of its source (explicit or defaulting).',
            'DT': 'DACL Trusted - Set when the ACL that is pointed to by the DACL field was provided by a trusted source and does not require any editing of compound ACEs.',
            'SD': 'SACL Defaulted - Set when the SACL was established by default means.',
            'SP': 'SACL Present - Set when the SACL is present on the object.',
            'DD': 'DACL Defaulted - Set when the DACL was established by default means.',
            'DP': 'DACL Present - Set when the DACL is present on the object.',
            'GD': 'Group Defaulted - Set when the group was established by default means.',
            'OD': 'Owner Defaulted - Set when the owner was established by default means.'
        }

        ACL_REVISION = {
            'ACL_REVISION': 0x02,  # When set to 0x02, only AceTypes 0x00, 0x01, 0x02, 0x03, 0x11, 0x12, and 0x13 can be present in the ACL. An AceType of 0x11 is used for SACLs but not for DACLs. For more information about ACE types, see section 2.4.4.1.
            'ACL_REVISION_DS': 0x04  # When set to 0x04, AceTypes 0x05, 0x06, 0x07, 0x08, and 0x11 are allowed. ACLs of revision 0x04 are applicable only to directory service objects. An AceType of 0x11 is used for SACLs but not for DACLs.
        }

        ACE_TYPE = {
            'ACCESS_ALLOWED_ACE_TYPE': 0x00, # Access-allowed ACE that uses the ACCESS_ALLOWED_ACE (section 2.4.4.2) structure.
            'ACCESS_DENIED_ACE_TYPE': 0x01,  # Access-denied ACE that uses the ACCESS_DENIED_ACE (section 2.4.4.4) structure.
            'SYSTEM_AUDIT_ACE_TYPE': 0x02,  # System-audit ACE that uses the SYSTEM_AUDIT_ACE (section 2.4.4.10) structure.
            'SYSTEM_ALARM_ACE_TYPE': 0x03,  # Reserved for future use.
            'ACCESS_ALLOWED_COMPOUND_ACE_TYPE': 0x04,  # Reserved for future use.
            'ACCESS_ALLOWED_OBJECT_ACE_TYPE': 0x05,  # Object-specific access-allowed ACE that uses the ACCESS_ALLOWED_OBJECT_ACE (section 2.4.4.3) structure.<44>
            'ACCESS_DENIED_OBJECT_ACE_TYPE': 0x06, # Object-specific access-denied ACE that uses the ACCESS_DENIED_OBJECT_ACE (section 2.4.4.5) structure.<45>
            'SYSTEM_AUDIT_OBJECT_ACE_TYPE': 0x07,  # Object-specific system-audit ACE that uses the SYSTEM_AUDIT_OBJECT_ACE (section 2.4.4.11) structure.<46>
            'SYSTEM_ALARM_OBJECT_ACE_TYPE': 0x08,  # Reserved for future use.
            'ACCESS_ALLOWED_CALLBACK_ACE_TYPE': 0x09,  # Access-allowed callback ACE that uses the ACCESS_ALLOWED_CALLBACK_ACE (section 2.4.4.6) structure.<47>
            'ACCESS_DENIED_CALLBACK_ACE_TYPE': 0x0A,  # Access-denied callback ACE that uses the ACCESS_DENIED_CALLBACK_ACE (section 2.4.4.7) structure.<48>
            'ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE': 0x0B,  # Object-specific access-allowed callback ACE that uses the ACCESS_ALLOWED_CALLBACK_OBJECT_ACE (section 2.4.4.8) structure.<49>
            'ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE': 0x0C,  # Object-specific access-denied callback ACE that uses the ACCESS_DENIED_CALLBACK_OBJECT_ACE (section 2.4.4.9) structure.<50>
            'SYSTEM_AUDIT_CALLBACK_ACE_TYPE': 0x0D,  # System-audit callback ACE that uses the SYSTEM_AUDIT_CALLBACK_ACE (section 2.4.4.12) structure.<51>
            'SYSTEM_ALARM_CALLBACK_ACE_TYPE': 0x0E,  # Reserved for future use.
            'SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE': 0x0F,  # Object-specific system-audit callback ACE that uses the SYSTEM_AUDIT_CALLBACK_OBJECT_ACE (section 2.4.4.14) structure.
            'SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE': 0x10,  # Reserved for future use.
            'SYSTEM_MANDATORY_LABEL_ACE_TYPE': 0x11,  # Mandatory label ACE that uses the SYSTEM_MANDATORY_LABEL_ACE (section 2.4.4.13) structure.
            'SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE': 0x12,  # Resource attribute ACE that uses the SYSTEM_RESOURCE_ATTRIBUTE_ACE (section 2.4.4.15)
            'SYSTEM_SCOPED_POLICY_ID_ACE_TYPE': 0x13  # A central policy ID ACE that uses the SYSTEM_SCOPED_POLICY_ID_ACE (section 2.4.4.16)'
        }

        ACE_TYPE_SHORT_MAPPING = {
            'ACCESS_ALLOWED_ACE_TYPE': 'A',
            'ACCESS_DENIED_ACE_TYPE': 'D',
            'ACCESS_ALLOWED_OBJECT_ACE_TYPE': 'OA',
            'ACCESS_DENIED_OBJECT_ACE_TYPE': 'OD',
            'SYSTEM_AUDIT_ACE_TYPE' : 'AU',
            'SYSTEM_ALARM_ACE_TYPE': 'AL',
            'SYSTEM_AUDIT_OBJECT_ACE_TYPE': 'OU',
            'SYSTEM_ALARM_OBJECT_ACE_TYPE': 'AL'
        }

        ACE_FLAGS = {
            'CONTAINER_INHERIT_ACE': 0x02,  # Child objects that are containers, such as directories, inherit the ACE as an effective ACE. The inherited ACE is inheritable unless the NO_PROPAGATE_INHERIT_ACE bit flag is also set.
            'FAILED_ACCESS_ACE_FLAG': 0x80,  # Used with system-audit ACEs in a system access control list (SACL) to generate audit messages for failed access attempts.
            'INHERIT_ONLY_ACE': 0x08,  # Indicates an inherit-only ACE, which does not control access to the object to which it is attached. If this flag is not set, the ACE is an effective ACE that controls access to the object to which it is attached. Both effective and inherit-only ACEs can be inherited depending on the state of the other inheritance flags.
            'INHERITED_ACE': 0x10,  # Indicates that the ACE was inherited. The system sets this bit when it propagates an inherited ACE to a child object.<53>
            'NO_PROPAGATE_INHERIT_ACE': 0x04,  # If the ACE is inherited by a child object, the system clears the OBJECT_INHERIT_ACE and CONTAINER_INHERIT_ACE flags in the inherited ACE. This prevents the ACE from being inherited by subsequent generations of objects.
            'OBJECT_INHERIT_ACE': 0x01,  # Noncontainer child objects inherit the ACE as an effective ACE. For child objects that are containers, the ACE is inherited as an inherit-only ACE unless the NO_PROPAGATE_INHERIT_ACE bit flag is also set.
            'SUCCESSFUL_ACCESS_ACE_FLAG': 0x40  # Used with system-audit ACEs in a SACL to generate audit messages for successful access attempts.
        }

        ACE_FLAGS_SHORT_MAPPING = {
            'CONTAINER_INHERIT_ACE': 'CI',
            'OBJECT_INHERIT_ACE': 'OI',
            'NO_PROPAGATE_INHERIT_ACE': 'NP',
            'INHERIT_ONLY_ACE': 'IO',
            'INHERITED_ACE': 'ID',
            'SUCCESSFUL_ACCESS_ACE_FLAG': 'SA',
            'FAILED_ACCESS_ACE_FLAG': 'FA'
        }

        # Ref: https://docs.microsoft.com/en-us/windows/desktop/sysinfo/registry-key-security-and-access-rights
        ACCESS_MASK = {
            """
            'GENERIC_READ': 0x80000000,  # When used in an Access Request operation: When read access to an object is requested, this bit is translated to a combination of bits. These are most often set in the lower 16 bits of the ACCESS_MASK. (Individual protocol specifications MAY specify a different configuration.) The bits that are set are implementation dependent. During this translation, the GR bit is cleared. The resulting ACCESS_MASK bits are the actual permissions that are checked against the ACE structures in the security descriptor that attached to the object. When used to set the Security Descriptor on an object: When the GR bit is set in an ACE that is to be attached to an object, it is translated into a combination of bits, which are usually set in the lower 16 bits of the ACCESS_MASK. (Individual protocol specifications MAY specify a different configuration.) The bits that are set are implementation dependent. During this translation, the GR bit is cleared. The resulting ACCESS_MASK bits are the actual permissions that are granted by this ACE.
            'GENERIC_WRITE': 0x40000000,  # When used in an Access Request operation: When write access to an object is requested, this bit is translated to a combination of bits, which are usually set in the lower 16 bits of the ACCESS_MASK. (Individual protocol specifications MAY specify a different configuration.) The bits that are set are implementation dependent. During this translation, the GW bit is cleared. The resulting ACCESS_MASK bits are the actual permissions that are checked against the ACE structures in the security descriptor that attached to the object. When used to set the Security Descriptor on an object: When the GW bit is set in an ACE that is to be attached to an object, it is translated into a combination of bits, which are usually set in the lower 16 bits of the ACCESS_MASK. (Individual protocol specifications MAY specify a different configuration.) The bits that are set are implementation dependent. During this translation, the GW bit is cleared. The resulting ACCESS_MASK bits are the actual permissions that are granted by this ACE.
            'GENERIC_EXECUTE': 0x20000000,  # When used in an Access Request operation: When execute access to an object is requested, this bit is translated to a combination of bits, which are usually set in the lower 16 bits of the ACCESS_MASK. (Individual protocol specifications MAY specify a different configuration.) The bits that are set are implementation dependent. During this translation, the GX bit is cleared. The resulting ACCESS_MASK bits are the actual permissions that are checked against the ACE structures in the security descriptor that attached to the object. When used to set the Security Descriptor on an object: When the GX bit is set in an ACE that is to be attached to an object, it is translated into a combination of bits, which are usually set in the lower 16 bits of the ACCESS_MASK. (Individual protocol specifications MAY specify a different configuration.) The bits that are set are implementation dependent. During this translation, the GX bit is cleared. The resulting ACCESS_MASK bits are the actual permissions that are granted by this ACE.
            'GENERIC_ALL': 0x10000000,  # When used in an Access Request operation: When all access permissions to an object are requested, this bit is translated to a combination of bits, which are usually set in the lower 16 bits of the ACCESS_MASK. (Individual protocol specifications MAY specify a different configuration.) Objects are free to include bits from the upper 16 bits in that translation as required by the objects semantics. The bits that are set are implementation dependent. During this translation, the GA bit is cleared. The resulting ACCESS_MASK bits are the actual permissions that are checked against the ACE structures in the security descriptor that attached to the object. When used to set the Security Descriptor on an object: When the GA bit is set in an ACE that is to be attached to an object, it is translated into a combination of bits, which are usually set in the lower 16 bits of the ACCESS_MASK. (Individual protocol specifications MAY specify a different configuration.) Objects are free to include bits from the upper 16 bits in that translation, if required by the objects semantics. The bits that are set are implementation dependent. During this translation, the GA bit is cleared. The resulting ACCESS_MASK bits are the actual permissions that are granted by this ACE.
            'MAXIMUM_ALLOWED': 0x02000000,  # When used in an Access Request operation: When requested, this bit grants the requestor the maximum permissions allowed to the object through the Access Check Algorithm. This bit can only be requested; it cannot be set in an ACE. When used to set the Security Descriptor on an object: Specifying the Maximum Allowed bit in the SECURITY_DESCRIPTOR has no meaning. The MA bit SHOULD NOT be set and SHOULD be ignored when part of a SECURITY_DESCRIPTOR structure.
            'ACCESS_SYSTEM_SECURITY': 0x01000000,  # When used in an Access Request operation: When requested, this bit grants the requestor the right to change the SACL of an object. This bit MUST NOT be set in an ACE that is part of a DACL. When set in an ACE that is part of a SACL, this bit controls auditing of accesses to the SACL itself.
            'SYNCHRONIZE': 0x00100000,  # Specifies access to the object sufficient to synchronize or wait on the object.
            'WRITE_OWNER': 0x00080000,  # Specifies access to change the owner of the object as listed in the security descriptor.
            'WRITE_DACL': 0x00040000,  # Specifies access to change the discretionary access control list of the security descriptor of an object.
            'READ_CONTROL': 0x00020000,  # Specifies access to read the security descriptor of an object.
            'DELETE': 0x10000,  # Specifies access to delete an object.
            """
            'KEY_ALL_ACCESS': 0x000F003F,  # 'FullControl' -> Combines the STANDARD_RIGHTS_REQUIRED, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_CREATE_SUB_KEY, KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY, and KEY_CREATE_LINK 'access rights.
            'KEY_CREATE_LINK': 0x00000020,  # Reserved for system use.
            'KEY_CREATE_SUB_KEY': 0x00000004,  # Required to create a subkey of a registry key.
            'KEY_ENUMERATE_SUB_KEYS': 0x00000008,  # Required to enumerate the subkeys of a registry key.
            'KEY_EXECUTE': 0x00020019,  # ReadKey - Equivalent to KEY_READ.
            'KEY_NOTIFY': 0x00000010,  # Required to request change notifications for a registry key or for subkeys of a registry key.
            'KEY_QUERY_VALUE': 0x00000001,  # Required to query the values of a registry key.
            'KEY_READ': 0x00020019,  # Combines the STANDARD_RIGHTS_READ, KEY_QUERY_VALUE, KEY_ENUMERATE_SUB_KEYS, and KEY_NOTIFY values.
            'KEY_SET_VALUE': 0x00000002,  # Required to create, delete, or set a registry value.
            'KEY_WOW64_32KEY': 0x00000200,  # Indicates that an application on 64-bit Windows should operate on the 32-bit registry view. This flag is ignored by 32-bit Windows. For more 'information, see Accessing an Alternate Registry View. This flag must be combined using the OR operator with the other flags in this table that either query or access 'registry values. Windows 2000: This flag is not supported.
            'KEY_WOW64_64KEY': 0x00000100,  # Indicates that an application on 64-bit Windows should operate on the 64-bit registry view. This flag is ignored by 32-bit Windows. For more 'information, see Accessing an Alternate Registry View. This flag must be combined using the OR operator with the other flags in this table that either query or access 'registry values. Windows 2000: This flag is not supported.
            'KEY_WRITE': 0x00020006,  # Combines the STANDARD_RIGHTS_WRITE, KEY_SET_VALUE, and KEY_CREATE_SUB_KEY access rights.
        }

        # Ref: https://msdn.microsoft.com/en-us/library/cc230294.aspx
        # https://itconnect.uw.edu/wares/msinf/other-help/understanding-sddl-syntax/
        ACCESS_MASK_SHORT_MAPPING = {
            'GENERIC_READ': 'GR',
            'GENERIC_WRITE': 'GW',
            'GENERIC_EXECUTE': 'GX',
            'GENERIC_ALL': 'GA',
            'MAXIMUM_ALLOWED': 'MA',
            'ACCESS_SYSTEM_SECURITY': 'AS',
            'SYNCHRONIZE': 'SY',
            'WRITE_OWNER': 'WO',
            'WRITE_DACL': 'WD',
            'READ_CONTROL': 'RC',
            'DELETE': 'DE',
            'KEY_ALL_ACCESS': 'KA',
            'KEY_READ': 'KR',
            'KEY_WRITE': 'KW',
            'KEY_EXECUTE': 'KE'
        }

        # Ref: https://msdn.microsoft.com/en-us/library/cc980032.aspx  (I didn't check if they are all there)
        SID_WELL_KNOWN_USER_MAPPING = {
            'S-1-0-0': 'NULL',
            'S-1-1': 'WORLD_AUTHORITY',
            'S-1-1-0': 'EVERYONE',
            'S-1-2': 'LOCAL_AUTHORITY',
            'S-1-2-0': 'LOCAL',
            'S-1-2-1': 'CONSOLE_LOGON',
            'S-1-3': 'CREATOR_AUTHORITY',
            'S-1-3-0': 'CREATOR_OWNER',
            'S-1-3-1': 'CREATOR_GROUP',
            'S-1-3-2': 'CREATOR_OWNER_SERVER',
            'S-1-3-3': 'CREATOR_GROUP_SERVER',
            'S-1-3-4': 'CREATOR_OWNER_RIGHTS',
            'S-1-5-80-0': 'ALL_SERVICES',
            'S-1-5-84-0-0-0-0-0': 'USER_MODE_DRIVERS',
            'S-1-4': 'NON_UNIQUE_AUTHORITY',
            'S-1-5': 'NT_AUTHORITY',
            'S-1-5-1': 'DIALUP',
            'S-1-5-2': 'NETWORK',
            'S-1-5-3': 'BATCH',
            'S-1-5-4': 'INTERACTIVE',
            'S-1-5-6': 'SERVICE',
            'S-1-5-7': 'ANONYMOUS',
            'S-1-5-8': 'PROXY',
            'S-1-5-9': 'ENTERPRISE_DOMAIN_CONTROLLERS',
            'S-1-5-10': 'PRINCIPAL_SELF',
            'S-1-5-11': 'AUTHENTICATED_USERS',
            'S-1-5-12': 'RESTRICTED_CODE',
            'S-1-5-33': 'WRITE_RESTRICTED_CODE',
            'S-1-5-13': 'TERMINAL_SERVER_USERS',
            'S-1-5-14': 'INTERACTIVE_LOGON',
            'S-1-5-15': 'ORGANIZATION',
            'S-1-5-17': 'ORGANIZATION_IIS',
            'S-1-5-18': 'LOCAL_SYSTEM',
            'S-1-5-19': 'NT_AUTHORITY_LOCAL',
            'S-1-5-20': 'NT_AUTHORITY_NETWORK',
            'S-1-5-32-544': 'ADMINISTRATORS',
            'S-1-5-32-545': 'USERS',
            'S-1-5-32-546': 'GUESTS',
            'S-1-5-32-547': 'POWER_USERS',
            'S-1-5-32-548': 'ACCOUNT_OPERATORS',
            'S-1-5-32-549': 'SERVER_OPERATORS',
            'S-1-5-32-550': 'PRINT_OPERATORS',
            'S-1-5-32-551': 'BACKUP_OPERATORS',
            'S-1-5-32-552': 'REPLICATORS',
            'S-1-5-64-10': 'NTLM_AUTHENTICATION',
            'S-1-5-64-14': 'SCHANNEL_AUTHENTICATION',
            'S-1-5-64-21': 'DIGEST_AUTHENTICATION',
            'S-1-5-80': 'NT_SERVICE',
            'S-1-5-80-0': 'NT_SERVICE_ALL',
            'S-1-5-83-0': 'NT_VM',
            'S-1-15-2-1': 'ALL_APP_PACKAGES',
            'S-1-16-0': 'UNTRUSTED_MANDATORY_LEVEL',
            'S-1-16-4096': 'LOW_MANDATORY_LEVEL',
            'S-1-16-8192': 'MEDIUM_MANDATORY_LEVEL',
            'S-1-16-8448': 'MEDIUM_PLUS_MANDATORY_LEVEL',
            'S-1-16-12288': 'HIGH_MANDATORY_LEVEL',
            'S-1-16-16384': 'SYSTEM_MANDATORY_LEVEL',
            'S-1-16-20480': 'PROTECTED_PROCESS_MANDATORY_LEVEL',
            'S-1-16-28672': 'SECURE_PROCESS_MANDATORY_LEVEL',
            'S-1-5-32-554': 'BI_PRE2K_COMPATIBLE',
            'S-1-5-32-555': 'BI_RDS_USERS',
            'S-1-5-32-556': 'BI_NET_CFG_OPERATORS',
            'S-1-5-32-557': 'BI_INC_FT_BUILDERS',
            'S-1-5-32-558': 'BI_PERF_MON_USERS',
            'S-1-5-32-559': 'BI_PERF_LOG_USERS',
            'S-1-5-32-560': 'BI_WIN_AUTH_AG',
            'S-1-5-32-561': 'BI_TS_LIC_SERVERS',
            ' S-1-5-32-562': 'BI_DIST_COM_USERS',
            'S-1-5-32-574': 'BI_CERT_DCOM_USERS',
            'S-1-5-32-568': 'BI_IIS_USERS',
            'S-1-5-32-569': 'BI_CRYPTO_OPERATORS',
            'S-1-5-32-573': 'BI_EVENT_LOG_READERS',
            ' S-1-5-32-575': 'BI_RDS_REMOTE_ACCESS_SERVERS',
            'S-1-5-32-576': 'BI_RDS_ENPOINT_SERVERS',
            'S-1-5-32-577': 'BI_RDS_MGMT_SERVERS',
            'S-1-5-32-578': 'BI_HYPERV_ADMINS',
            'S-1-5-32-579': 'BI_ACCESS_CONTROL_ASSISTANCE_OPS',
            'S-1-5-32-580': 'BI_REMOTE_MANAGEMENT_USERS',
        }

        # Ref: https://msdn.microsoft.com/en-us/library/cc980032.aspx
        # zhttps://github.com/ldaptools/ldaptools/blob/b7a4f6df96ef83e82c7ed6238e4d0346c0f666f7/src/LdapTools/Security/SID.php
        SID_SPECIAL_GROUPS = {
            # <domain sid>
            '-517': 'CERT_PUBLISHERS',  # 'CA'
            '-522': 'CLONEABLE_CONTROLLERS',  # 'CN'
            '-512': 'DOMAIN_ADMINS',  # 'DA'
            '-515': 'DOMAIN_COMPUTERS',  # 'DC'
            '-516': 'DOMAIN_DOMAIN_CONTROLLERS',  # 'DD'
            '-514': 'DOMAIN_GUESTS',  # 'DG'
            '-513': 'DOMAIN_USERS',  # 'DU'
            '-500': 'ADMINISTRATOR',  # 'LA'
            '-501': 'GUEST',  # 'LG'
            '-520': 'GROUP_POLICY_CREATOR_OWNERS',  # 'PA'
            '-553': 'RAS_SERVERS',  # 'RS'
            # <root-domain sid>
            '-519': 'ENTERPRISE_ADMINS',  # 'EA'
            '-498': 'ENTERPRISE_READONLY_DOMAIN_CONTROLLERS',  # 'RO'
            '-518': 'SCHEMA_ADMINISTRATORS'  # 'SA'
        }

        class control_flags:
            flags = None
            flagsSDDL = None
            flags_info = None
            id = None

            def __str__(self):
                resp = '%s; [%s]' % (";".join(self.flags), ";".join(self.flagsSDDL))
                return resp

        class acl_header:

            AclRevision = None  # AclRevision (1 byte): An unsigned 8-bit value that specifies the revision of the ACL. The only two legitimate forms of ACLs supported for on-the-wire management or manipulation are type 2 and type 4. No other form is valid for manipulation on the wire. Therefore this field MUST be set to one of the following values.
            Sbz1 = None
            AclSize = None
            AceCount = None
            Sbz2 = None

        class ace_header:

            AceID = None
            AceType = None
            AceTypeSDDL = None
            AceFlags = None
            AceFlagsSDDL = None
            AceSize = None
            AceAccessMask = None
            AceAccessMaskSDDL = None
            SID = None

            def __str__(self):

                if self.AceFlags:
                    resp = '%s | %s | %s | %s | %s | %s' % (
                    self.AceID, self.AceType, ";".join(self.AceFlags.keys()), self.AceFlagsSDDL, ";".join(self.AceAccessMaskSDDL), self.SID)
                else:
                    resp = '%s | %s | %s | %s | %s | %s' % (
                        self.AceID, self.AceType, "None", "None", ";".join(self.AceAccessMaskSDDL),
                        self.SID)
                return resp

            def permissions(self):

                AccessPriviledges = list(self.AceAccessMask.keys())
                AceType = self.AceType

                if 'ACCESS_ALLOWED_ACE_TYPE' in AceType:
                    AceType = 'Allow'
                elif 'ACCESS_DENIED_ACE_TYPE' in AceType:
                    AceType = 'Deny'
                else:
                    AceType = self.AceType


                if 'KEY_ALL_ACCESS' in AccessPriviledges:
                    AccessPriviledges = 'FullControl'

                elif all(_flag in ['READ_CONTROL', 'KEY_SET_VALUE', 'KEY_CREATE_SUB_KEY'] for _flag in AccessPriviledges):
                    AccessPriviledges = 'WriteKey'

                elif any(_flag in ['KEY_EXECUTE'] for _flag in AccessPriviledges):
                    AccessPriviledges = 'ReadKey'

                elif all(_flag in ['READ_CONTROL', 'KEY_QUERY_VALUE', 'KEY_ENUMERATE_SUB_KEYS',
                                       'KEY_NOTIFY'] for _flag in AccessPriviledges):
                    AccessPriviledges = 'ReadKey'
                else:
                    AccessPriviledges = ';'.join(AccessPriviledges)

                return '%s %s %s' % (self.SID.name(), AceType, AccessPriviledges)

        class sid:

            Revision = None
            SubAuthorityCount = None
            IdentifierAuthority = None
            SubAuthorities = None
            SID = None

            def __str__(self):
                return self.SID

            def name(self):

                _SID = security_descriptor.structures.SID_WELL_KNOWN_USER_MAPPING.get(self.SID, None)

                if _SID:
                    return _SID

                elif not _SID:
                    #  Get the RID
                    _RID = re.findall(r'(-[0-9]+)$', self.SID, re.IGNORECASE)

                    if _RID:
                        if _RID[0] in security_descriptor.structures.SID_SPECIAL_GROUPS:
                            return security_descriptor.structures.SID_SPECIAL_GROUPS.get(_RID[0])

                return self.SID


    def __init__(self, security_descriptor_bytes):

        sd_bits_array = bitstring.BitArray(security_descriptor_bytes)
        sd_bytes = bitstring.BitStream(sd_bits_array)

        # Unpack the values according to _SECURITY_DESCRIPTOR struct,  but i prefer different way, somehow more clear to me
        # B - uint size 1, ushort size 2, L - ulong size 4
        # Revision, Sbz1, ControlBytes, OffsetOwner, OffsetGroup, OffsetSacl, OffsetDacl = unpack('<BBHLLLL', security_descriptor_bytes[: 20])

        try:
            self.Revision = int.from_bytes(sd_bytes.read('bytes:1'), byteorder='little', signed=False)
            self.Sbz1 = sd_bytes.read('bytes:1')

            ###########################################################################
            #  Control Flags                                                          #
            self.Control = self.parse_control_flags(buffer_bytes=sd_bytes.read('bytes:2'))
            self.set_security_descriptor_format(self.Control.flags)

            ###########################################################################
            #  Owner                                                                  #
            OffsetOwner = int.from_bytes(sd_bytes.read('bytes:4'), byteorder='little', signed=False)
            self.Owner = self.get_SID(security_descriptor_bytes[OffsetOwner:]) # Since SubAuthority is variable in len, i need to pass complete buffer from OwnerOffset location

            ###########################################################################
            #  Group                                                                  #
            OffsetGroup = int.from_bytes(sd_bytes.read('bytes:4'), byteorder='little', signed=False)
            self.Group = self.get_SID(security_descriptor_bytes[OffsetGroup:])

            ###########################################################################
            #  SACL                                                                   #
            OffsetSacl = int.from_bytes(sd_bytes.read('bytes:4'), byteorder='little', signed=False)

            if OffsetSacl == 0 and 'SP' in self.Control.flagsSDDL:
                raise ValueError('SACL Present but SACL offset is Null ... Something went wrong')
            elif OffsetSacl != 0 and 'SP' in self.Control.flagsSDDL:
                # Follow the stuff
                # logger.error('SACL --> Witold, please have a look and finish this function ')
                pass

            ###########################################################################
            #  DACL                                                                   #
            OffsetDacl = int.from_bytes(sd_bytes.read('bytes:4'), byteorder='little', signed=False)  # Offset to an ACL containing ACEs

            if OffsetDacl == 0 and 'DP' in self.Control.flagsSDDL:
                raise ValueError('DACL Present but DACL offset is Null ... Something went wrong')
            elif OffsetDacl != 0 and 'DP' in self.Control.flagsSDDL:
                self.Dacl = self.parse_acl(security_descriptor_bytes[OffsetDacl:])

            self.remaining_bytes = sd_bytes.read('bytes:%s' % str(int((sd_bytes.len/8) - sd_bytes.pos/8)))
            
            # print(self.remaining_bytes.hex("-"))
            
        except Exception as msg:
            logger.debug('ERROR: Unable to parse SD. Message: %s' % msg)


    """ Security Descriptor Functions """
    # Ref:https://msdn.microsoft.com/en-us/library/cc230297.aspx
    # https://msdn.microsoft.com/en-us/library/cc230296.aspx
    def get_AceType(self, AceTypeValue):

        flag_name = 'None'
        for flag_name, flag_value in self.structures.ACE_TYPE.items():

            if AceTypeValue == flag_value:
                return flag_name

        return None

    # Ref: https://msdn.microsoft.com/en-us/library/cc230294.aspx
    def get_ace_mask(self, access_mask_bytes, convert_to_le=True):

        access_rights = {}
        _bytes = bitstring.Bits(bytes=access_mask_bytes)

        try:
            if convert_to_le:
                bit_mask = self.convert_to_le(_bytes, bits_length=32)
            else:
                bit_mask = _bytes

            for flag_name, flag in self.structures.ACCESS_MASK.items():

                bit_flag = bitstring.Bits(uint=flag, length=32)

                if (bit_mask & bit_flag) == bit_flag:
                    access_rights[flag_name] = '0x%s' % bit_flag.hex

        except Exception:
            test = ""

        return access_rights

    def get_ace_flags_sddl(self, AceFlags):
        AceFLagsSDDL = []

        if AceFlags:
            for _flag in AceFlags.keys():
                _sddl_flag = self.structures.ACE_FLAGS_SHORT_MAPPING.get(_flag, None)

                if _sddl_flag:
                    AceFLagsSDDL.append(_sddl_flag)

        return AceFLagsSDDL

    def get_ace_flags(self, ace_flags_int, convert_to_le=True):

        control_flags = {}

        for flag_name, flag in self.structures.ACE_FLAGS.items():

            if (ace_flags_int & flag) == flag:
                control_flags[flag_name] = '0x%s' % str(flag)

        if control_flags == {}:
            return None

        return control_flags

    def get_ace_mask_sddl(self, AceAccessMaskDict):

        mask_short = []
        for flag in AceAccessMaskDict.keys():

            short_flag = self.structures.ACCESS_MASK_SHORT_MAPPING.get(flag, None)

            if short_flag:
                mask_short.append(short_flag)

        return mask_short

    def get_ace_type_sddl(self, AceType):

        SDDLFlags = []

        if AceType:
            _sddl_flag = self.structures.ACE_TYPE_SHORT_MAPPING.get(AceType, None)

            if _sddl_flag:
                SDDLFlags.append(_sddl_flag)

        return SDDLFlags

    # Ref: https://msdn.microsoft.com/en-us/library/hh877835.aspx
    def parse_acl(self, buffer_bytes):
        
        ace_entries = []
        _acl_header = security_descriptor.structures.acl_header()

        _buffer_bytes = bitstring.Bits(bytes=buffer_bytes)
        bit_buffer = bitstring.BitStream(bitstring.BitArray(_buffer_bytes))

        # Get the ACL info
        _acl_header.AclRevision = int.from_bytes(bit_buffer.read('bytes:1'), byteorder='little', signed=False)

        if _acl_header.AclRevision not in self.structures.ACL_REVISION.values():
            logger.error('Incorrect ACL Revision: %d' % _acl_header.AclRevision)
            return None

        _acl_header.Sbz1 = int.from_bytes(bit_buffer.read('bytes:1'), byteorder='little', signed=False)

        if _acl_header.Sbz1 != 0:
            logger.error('Incorrect Sbz1: %d' % _acl_header.Sbz1)
            return None

        _acl_header.AclSize = int.from_bytes(bit_buffer.read('bytes:2'), byteorder='little', signed=False)
        _acl_header.AceCount = int.from_bytes(bit_buffer.read('bytes:2'), byteorder='little', signed=False)
        _acl_header.Sbz2 = bit_buffer.read('bytes:2')

        # Get all ACEs
        AceCount = _acl_header.AceCount

        AceID = 0
        while AceCount > 0:
            _ace_start = bit_buffer.bytepos
            _ace_header = security_descriptor.structures.ace_header()

            _ace_header.AceID = AceID
            AceTypeID = int.from_bytes(bit_buffer.read('bytes:1'), byteorder='little', signed=False)
            _ace_header.AceType = self.get_AceType(AceTypeValue=AceTypeID)
            _ace_header.AceTypeSDDL = self.get_ace_type_sddl(AceType=_ace_header.AceType)
            _ace_header.AceFlags = self.get_ace_flags(int.from_bytes(bit_buffer.read('bytes:1'), byteorder='little', signed=False))
            _ace_header.AceFlagsSDDL = self.get_ace_flags_sddl(AceFlags=_ace_header.AceFlags)
            _ace_header.AceSize = int.from_bytes(bit_buffer.read('bytes:2'), byteorder='little', signed=False)
            _ace_end = _ace_start + _ace_header.AceSize
            _ace_header.AceAccessMask = self.get_ace_mask(bit_buffer.read('bytes:4'))
            _ace_header.AceAccessMaskSDDL = self.get_ace_mask_sddl(AceAccessMaskDict=_ace_header.AceAccessMask)
            _ace_header.SID = self.get_SID(bit_buffer.read('bytes:%s' % str(_ace_end - bit_buffer.bytepos)))
            ace_entries.append(_ace_header)

            AceCount -= 1
            AceID += 1

        return ace_entries

    # Ref: https://docs.python.org/3/library/struct.html ... could use struct pack instead
    def convert_to_le(self, buffer, bits_length=None) -> bitstring.Bits:

        if bits_length == 32:
            new_bytes_order = struct.pack('<I', buffer.int)
        else:
            dec = buffer.int
            new_bytes_order = dec.to_bytes((dec.bit_length() + 7) // 8, 'little', signed=False) or b'\0'


        if bits_length:
            buffer_le = bitstring.Bits(bytes=new_bytes_order, length=bits_length)
        buffer_le = bitstring.Bits(bytes=new_bytes_order)

        return buffer_le

    # Ref: https://msdn.microsoft.com/en-us/library/gg465313.aspx
    def get_SID(self, buffer_bytes, convert_to_le=True):

        sid = security_descriptor.structures.sid()
        OwnerSID = ''

        if len(buffer_bytes) < 8:
            raise ValueError('SID buffer is too short')

        _buffer_bytes = bitstring.Bits(bytes=buffer_bytes)
        bit_buffer = bitstring.BitStream(bitstring.BitArray(_buffer_bytes))

        sid.Revision = int.from_bytes(bit_buffer.read('bytes:1'), byteorder='little', signed=False)
        sid.SubAuthorityCount = int.from_bytes(bit_buffer.read('bytes:1'), byteorder='little', signed=False)
        sid.IdentifierAuthority = int.from_bytes(bit_buffer.read('bytes:6'), byteorder='big', signed = False)  # SID_IDENTIFIER_AUTHORITY structure
        SubAuthority = None

        # Look for all SubAuthority'ies
        sid.SubAuthorities = []
        if sid.SubAuthorityCount > 0:
            index = sid.SubAuthorityCount
            while index > 0:
                try:
                    SubAuthority = int.from_bytes(bit_buffer.read('bytes:4'), byteorder='little', signed=False)
                    sid.SubAuthorities.append(str(SubAuthority))
                    index -= 1
                except Exception:
                    logger.error('Corrupted SubAuthority. Data: %s' % bit_buffer)
                    index = 0

        if sid.SubAuthorities:
            # OwnerSID = f'S-{sid.Revision}-{sid.IdentifierAuthority}-' + "-".join(sid.SubAuthorities)
            OwnerSID = 'S-%s-%s-%s' % (sid.Revision, sid.IdentifierAuthority, '-'.join(sid.SubAuthorities))
        else:
            # OwnerSID = f'S-{sid.Revision}-{sid.IdentifierAuthority}'
            OwnerSID = 'S-%s-%s' % (sid.Revision, sid.IdentifierAuthority)

        sid.SID = OwnerSID

        return sid

    def get_control_flags_sddl(self, buffer_bytes):

        buffer_bits = bitstring.Bits(bytes=buffer_bytes)
        buffer_bits = self.convert_to_le(buffer_bits)

        flags = []
        for bit, flag_short in zip(buffer_bits.bin, self.structures.SECURITY_DESCRIPTOR_CONTROL_BITS_MAPPING):

            if int(bit) != 0:
                flags.append(flag_short)

        return flags

    def get_short_flag_description(self, short_flags):

        info = []

        if short_flags:
            for flag in short_flags:
                _info = self.structures.SECURITY_DESCRIPTOR_CONTROL_BITS_MAPPING.get(flag, '')

                if _info:
                    info.append('%s - %s' % (flag, _info))

        return info

    def get_control_flags(self, buffer_bytes, convert_to_le=True):

        control_flags = {}
        _bytes = bitstring.Bits(bytes=buffer_bytes)

        if convert_to_le:
            bit_mask = self.convert_to_le(_bytes)
        else:
            bit_mask = _bytes

        for flag_name, flag in self.structures.SECURITY_DESCRIPTOR_CONTROL.items():

            bit_flag = bitstring.Bits(flag)

            if (bit_mask & bit_flag) == bit_flag:
                control_flags[flag_name] = '0x%s' % bit_flag.hex

        return control_flags


        """ 
        bool(mask & 0x00000001), "\tReadData\n",
        bool(mask & 0x00000002), "\tWriteData\n",
        bool(mask & 0x00000004), "\tAppendData\n",
        bool(mask & 0x00000008), "\tReadEa\n",
        bool(mask & 0x00000010), "\tWriteEa\n",
        bool(mask & 0x00000020), "\tExecute\n",
        bool(mask & 0x00000040), "\tDeleteChildn\n",
        bool(mask & 0x00000080), "\tReadAttributes\n",
        bool(mask & 0x00000100), "\tWriteAttributes\n",
        bool(mask & 0x00010000), "\tDelete\n",
        bool(mask & 0x00020000), "\tReadControl\n",
        bool(mask & 0x00040000), "\tWriteDac\n",
        bool(mask & 0x00080000), "\tWriteOwner\n",
        bool(mask & 0x00100000), "\tSynchronize\n")
        """

    def parse_control_flags(self, buffer_bytes):

        control_flags = security_descriptor.structures.control_flags()
        control_flags.id = int.from_bytes(buffer_bytes, byteorder='little', signed=False)
        control_flags.flags = self.get_control_flags(buffer_bytes=buffer_bytes, convert_to_le=True)
        control_flags.flagsSDDL = self.get_control_flags_sddl(buffer_bytes=buffer_bytes)
        control_flags.flags_info = self.get_short_flag_description(short_flags=control_flags.flagsSDDL)

        return control_flags

    def set_security_descriptor_format(self, control_flags):

        absolute = False
        self_relative = control_flags.get('SE_SELF_RELATIVE', False)

        if not self_relative:
            absolute = True
        else:
            self_relative = True

        self.format_self_relative = self_relative
        self.format_absolute = absolute
