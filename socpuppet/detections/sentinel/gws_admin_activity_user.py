

def gws_user_admin_modification(x: str):
    logic_json = {
        "query": f"""
        GWorkspace_ReportsAPI_admin_CL
        | where TimeGenerated >= ago({x})
        | where event_type_s =~ 'USER_SETTINGS'
        | where event_name_s in~ ('GRANT_ADMIN_PRIVILEGE' , 'REVOKE_ADMIN_PRIVILEGE' , 'GRANT_DELEGATED_ADMIN_PRIVILEGES')
        """,
        "title": "Google Workspace User Admin Privileges Modification",
        "attackId": "",
        "dataSource": "Admin_Activity",
        "platform": "Google_Workspace",
        "deployGroup": "GWS_All",
        "author": "Detection_Engineering",
        "detectCon": "3",
        "type": "simple_pattern_match",
        "openSource": ["https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/GoogleWorkspaceReports/Analytic%20Rules/GWorkspaceAdminPermissionsGranted.yaml",
                       "hhttps://github.com/SigmaHQ/sigma/blob/master/rules/cloud/gworkspace/gworkspace_role_modified_or_deleted.yml"
                       "https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/gworkspace/gworkspace_role_privilege_deleted.yml"
                       "https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/gworkspace/gworkspace_user_granted_admin_privileges.yml"
                       ],
        "emulation": [],
        "intelReference": [],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json


def gws_user_mfa_disable(x: str):
    logic_json = {
        "query": f"""
        GWorkspace_ReportsAPI_admin_CL
        | where TimeGenerated >= ago({x})
        | where event_type_s =~ 'USER_SETTINGS'
        | where event_name_s =~ 'TURN_OFF_2_STEP_VERIFICATION'
        """,
        "title": "Google Workspace User Admin Privileges Modification",
        "attackId": "",
        "dataSource": "Admin_Activity",
        "platform": "Google_Workspace",
        "deployGroup": "GWS_All",
        "author": "Detection_Engineering",
        "detectCon": "3",
        "type": "simple_pattern_match",
        "openSource": ["https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/GoogleWorkspaceReports/Analytic%20Rules/GWorkspaceTwoStepAuthenticationDisabledForUser.yaml",
                       "https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/gworkspace/gworkspace_mfa_disabled.yml"
                       ],
        "emulation": [],
        "intelReference": [],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json
