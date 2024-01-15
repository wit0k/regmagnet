rule Suspicious_Task_path {
    meta:
        author = "wit0k"
        date = "2023-05-26"
        description = "Triggers when a windows scheduled task path is located within suspicious folders"
        reference = ""
        mitre_tid = "['None']"
    
    strings:
        $p1 = /handler_payloads\:.*\\Temp\\.*/ nocase
        $p2 = /handler_payloads\:.*Malware.*/ nocase
        $p3 = /handler_payloads\:.*Windows\\Tasks.*/ nocase

    condition:
        //for all of ($p*) : (handler_payloads icontains "$")
        //for all of ($p*) : (handler_payloads icontains $) //  syntax error, unexpected string identifier
        //for any of ($p*) : (handler_payloads icontains $)
        any of ($p*)
}

rule COM_Hijack_multi_payloads {
    meta:
        author = "wit0k"
        date = "2023-05-04"
        description = "Triggers when a windows scheduled task with COM-enabled handler has multiple COM payloads"
        reference = "https://attack.mitre.org/techniques/T1546/015/"
        mitre_tid = "['T1546.015']"

    condition:
        handler_type_str iequals "COM_HANDLER" and com_handler_payloads_count > 1
}

rule Suspicious_Task_multi_actions {
    meta:
        author = "wit0k"
        date = "2023-05-04"
        description = "Triggers when a Scheduled Task has more than 1 action under Actions"
        reference = "None"
        mitre_tid = "['None']"

    condition:
        actions_count > 1
}

rule Hidden_Task_security_descriptor_abuse {
    meta:
        author = "wit0k"
        date = "2023-05-04"
        description = "Triggers when an SD value holding a Security Descriptor bytes for a scheduled task is missing or empty"
        reference = "https://github.com/wit0k/tarrask"
        mitre_tid = "['None']"

    strings:
        $SD_IS_EMPTY = "security_descriptor:|" nocase
        $SD_IS_MISSING = "security_descriptor:None" nocase

    condition:
        $SD_IS_EMPTY or $SD_IS_MISSING
}

rule Info_Recent_Manual_Trigger {
    meta:
        author = "wit0k"
        date = "2023-12-14"
        description = "Triggers for Scheduled Tasks, executed without any Triggers within last 3 days"
        reference = "..."
        mitre_tid = "['None']"

    condition:
        triggers_count == 0 and dynamic_last_run_time_epoch >= ep_3d_ago
}

rule Key_Permissions_Abuse {
    meta:
        author = "wit0k"
        date = "2024-01-05"
        description = "Triggers when a task key has abused permissions like a user SID is present in Tasks's Tasks or Tree key permissions..."
        reference = "..."
        mitre_tid = "['None']"

    condition:
        sd_task_key_permissions contains "S-1-5-21-" or sd_tree_key_permissions contains "S-1-5-21-"
}