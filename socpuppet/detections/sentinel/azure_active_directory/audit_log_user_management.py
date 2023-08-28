def aad_guest_invite(x: str):
    logic_json = {
        "query": f"""
        AuditLogs
        | where TimeGenerated >= ago({x})
        | where OperationName in~ ('Invite external user', 'Bulk invite users - started (bulk)',
            'Invite external user with reset invitation status')
        """,
        "title": "Guest User Invited to Azure Directory",
        "attackId": "",
        "dataSource": "User_Management",
        "platform": "Azure_Active_Directory",
        "deployGroup": "AAD_All",
        "author": "Detection_Engineering",
        "detectCon": "4",
        "type": "simple_pattern_match",
        "openSource": ["https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/azure_guest_invite_failure.yml",
                       "https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/azure_ad_guest_users_invited_to_tenant_by_non_approved_inviters.yml"
                       ],
        "emulation": [],
        "intelReference": [],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json


def aad_guest_promote_member(x: str):
    logic_json = {
        "query": f"""
        AuditLogs
        | where TimeGenerated >= ago({x})
        | where Category =~ 'UserManagement' and OperationName =~ 'Update user'
        | where TargetResources has_all('Guest', 'Member')
        """,
        "title": "Guest User Promoted to Member in Azure Directory",
        "attackId": "",
        "dataSource": "User_Management",
        "platform": "Azure_Active_Directory",
        "deployGroup": "AAD_All",
        "author": "Detection_Engineering",
        "detectCon": "4",
        "type": "simple_pattern_match",
        "openSource": ["https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/azure_guest_to_member.yml"],
        "emulation": [],
        "intelReference": [],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json
