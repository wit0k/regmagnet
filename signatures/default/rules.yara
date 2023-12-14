rule Suspicious_task_path {
    meta:
        author = "wit0k"
        date = "2023-05-26"
        description = "Triggers when a windows scheduled task path is located within suspicious folders"
        reference = ""
        mitre_tid = "['None']"
    
    strings:
        $p1 = /handler_payloads\:.*Temp.*/ nocase
        $p2 = /handler_payloads\:.*Malware.*/ nocase

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

rule Triggers_Test_Rules {
    meta:
        author = "wit0k"
        date = "2023-12-10"
        description = "Triggers when a task has more than 1 Trigger"
        reference = "..."
        mitre_tid = "['None']"

    strings:
        $trigger_start_boundary = /start_boundary\:2023\-12\-09.*/ nocase

    condition:
        triggers_count > 2 and $trigger_start_boundary
}

rule Manual_Task {
    meta:
        author = "wit0k"
        date = "2023-12-14"
        description = "Triggers when a task was most likely executed manually and without automatic Triggers"
        reference = "..."
        mitre_tid = "['None']"

    condition:
        triggers_count == 0 and (dynamic_info_last_run_time != "" or dynamic_info_last_run_time != "None") and triggers_count == 0
}

