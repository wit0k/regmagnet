rule COM_Hijack_multi_payloads {
    meta:
        author = "wit0k"
        date = "2023-05-04"
        description = "COM-Hijack - Windows Scheduled Task with COM-enabled handler having multiple payloads."
        reference = "https://attack.mitre.org/techniques/T1546/015/"
        mitre_tid = "['T1546.015']"

    condition:
        handler_type_str iequals "COM_HANDLER" and com_handler_payloads_count > 1
}

rule Suspicious_Task_multi_actions {
    meta:
        author = "wit0k"
        date = "2023-05-04"
        description = "Suspicious Task - Multiple Actions"
        reference = "None"
        mitre_tid = "['None']"

    condition:
        actions_count > 1
}

rule Hidden_Task_security_descriptor_abuse {
    meta:
        author = "wit0k"
        date = "2023-05-04"
        description = "Suspicious Task - Missing or Empty Security Descriptor (SD)"
        reference = "https://github.com/wit0k/tarrask"
        mitre_tid = "['None']"

    strings:
        $SD_IS_EMPTY = "security_descriptor:|" nocase
        $SD_IS_MISSING = "security_descriptor:None" nocase

    condition:
        $SD_IS_EMPTY or $SD_IS_MISSING
}