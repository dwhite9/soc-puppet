

def gws_api_auth_modification(x: str):
    logic_json = {
        "query": f"""
        GWorkspace_ReportsAPI_admin_CL
        | where TimeGenerated >= ago({x})
        | where event_type_s =~ 'DOMAIN_SETTINGS'
        | where event_name_s in~ ('AUTHORIZE_API_CLIENT_ACCESS' , 'REMOVE_API_CLIENT_ACCESS')
        """,
        "title": "Google Workspace API Client Access Modification",
        "attackId": "",
        "dataSource": "Admin_Activity",
        "platform": "Google_Workspace",
        "deployGroup": "GWS_All",
        "author": "Detection_Engineering",
        "detectCon": "3",
        "type": "simple_pattern_match",
        "openSource": ["https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/GoogleWorkspaceReports/Analytic%20Rules/GWorkspaceApiAccessToNewClient.yaml",
                       "https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/gworkspace/gworkspace_granted_domain_api_access.yml"],
        "emulation": [],
        "intelReference": [],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json


def gws_domain_trust(x: str):
    logic_json = {
        "query": f"""
        GWorkspace_ReportsAPI_admin_CL
        | where TimeGenerated >= ago({x})
        | where event_type_s =~ 'DOMAIN_SETTINGS'
        | where event_name_s in~ ('ADD_TRUSTED_DOMAINS' , 'REMOVE_TRUSTED_DOMAINS')
        """,
        "title": "Google Workspace Domain Trust Modified",
        "attackId": "",
        "dataSource": "Admin_Activity",
        "platform": "Google_Workspace",
        "deployGroup": "GWS_All",
        "author": "Detection_Engineering",
        "detectCon": "2",
        "type": "simple_pattern_match",
        "openSource": [],
        "emulation": [],
        "intelReference": [],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json


def gws_domain_admin_email(x: str):
    logic_json = {
        "query": f"""
        GWorkspace_ReportsAPI_admin_CL
        | where TimeGenerated >= ago({x})
        | where event_type_s =~ 'DOMAIN_SETTINGS'
        | where event_name_s =~ 'UPDATE_DOMAIN_PRIMARY_ADMIN_EMAIL'
        """,
        "title": "Google Workspace Update Primary Admin Email",
        "attackId": "",
        "dataSource": "Admin_Activity",
        "platform": "Google_Workspace",
        "deployGroup": "GWS_All",
        "author": "Detection_Engineering",
        "detectCon": "2",
        "type": "simple_pattern_match",
        "openSource": [],
        "emulation": [],
        "intelReference": [],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json
