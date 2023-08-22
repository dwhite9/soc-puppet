

def gws_seed_admin(x: str):
    logic_json = {
        "query": f"""
        GWorkspace_ReportsAPI_admin_CL
        | where TimeGenerated >= ago({x})
        | where event_type_s =~ 'DELEGATED_ADMIN_SETTINGS'
        | where ROLE_NAME_s contains 'SEED_ADMIN' or PRIVILEGE_NAME_s contains 'SUPER_ADMIN'
        """,
        "title": "User Assigned SEED ADMIN Role in Google Workspace",
        "attackId": "",
        "dataSource": "Admin_Activity",
        "platform": "Google_Workspace",
        "deployGroup": "GWS_All",
        "author": "Detection_Engineering",
        "detectCon": "3",
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


def gws_role_modification(x: str):
    logic_json = {
        "query": f"""
        GWorkspace_ReportsAPI_admin_CL
        | where TimeGenerated >= ago({x})
        | where event_type_s =~ 'DELEGATED_ADMIN_SETTINGS'
        | where event_name_s in~ ('CREATE_ROLE' , 'DELETE_ROLE' , 'RENAME_ROLE' ,'UPDATE_ROLE' , 'ADD_PRIVILEGE' , 'REMOVE_PRIVILEGE')
        """,
        "title": "Google Workspace Role Settings Modified",
        "attackId": "",
        "dataSource": "Admin_Activity",
        "platform": "Google_Workspace",
        "deployGroup": "GWS_All",
        "author": "Detection_Engineering",
        "detectCon": "3",
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


def gws_any_role_assigned(x: str):
    logic_json = {
        "query": f"""
        GWorkspace_ReportsAPI_admin_CL
        | where TimeGenerated >= ago({x})
        | where event_type_s =~ 'DELEGATED_ADMIN_SETTINGS' and event_name_s =~ 'ASSIGN_ROLE'
        """,
        "title": "Google Workspace User Added to Role",
        "attackId": "",
        "dataSource": "Admin_Activity",
        "platform": "Google_Workspace",
        "deployGroup": "GWS_All",
        "author": "Detection_Engineering",
        "detectCon": "5",
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


def gws_privileged_role_assigned(x: str):
    logic_json = {
        "query": f"""
        GWorkspace_ReportsAPI_admin_CL
        | where TimeGenerated >= ago({x})
        | where event_type_s =~ 'DELEGATED_ADMIN_SETTINGS'
        | where event_name_s =~ 'ASSIGN_ROLE'
        | where ROLE_NAME_s in~ ( '_DIRECTORY_SYNC_ADMIN_ROLE' , '_DOMAINLESS_SUPER_ADMIN_ROLE' ,'_DRIVE_TEAM_ADMIN_ROLE' ,
            '_GROUPS_ADMIN_ROLE' , '_SEED_ADMIN_ROLE' , '_USER_MANAGEMENT_ADMIN_ROLE')
        """,
        "title": "Google Workspace User Added to Privileged Role",
        "attackId": "",
        "dataSource": "Admin_Activity",
        "platform": "Google_Workspace",
        "deployGroup": "GWS_All",
        "author": "Detection_Engineering",
        "detectCon": "3",
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