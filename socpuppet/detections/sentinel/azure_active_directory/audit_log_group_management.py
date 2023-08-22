

def aad_group_modification(x: str):
    logic_json = {
        "query": f"""
        let MonitoredGroups = dynamic(['UUI_or_DisplayName']);
        AuditLogs
        | where TimeGenerated >= ago({x})
        | where Category == "GroupManagement" and OperationName == "Add member to group"
        | where TargetResources has_any(MonitoredGroups)
        """,
        "title": "User Added to Monitored AAD Group",
        "attackId": "",
        "dataSource": "Group_Management",
        "platform": "Azure_Active_Directory",
        "deployGroup": "AAD_All",
        "author": "Detection_Engineering",
        "detectCon": "3",
        "type": "simple_pattern_match",
        "openSource": ["https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/azure_group_user_addition_ca_modification.yml",
                       "https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/azure_group_user_removal_ca_modification.yml"],
        "emulation": [],
        "intelReference": [],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json