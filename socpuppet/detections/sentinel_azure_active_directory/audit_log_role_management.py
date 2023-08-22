

def aad_role_global_admin(x: str):
    logic_json = {
        "query": f"""
        AuditLogs
        | where TimeGenerated >= ago({x})
        | where Category =~ 'RoleManagement'
        | where TargetResources contains '62e90394-69f5-4237-9190-012177145e10'
        | extend PimLog= case(Identity == 'MS-PIM' , 'PIM' , 
            LoggedByService == 'PIM' , 'PIM' , 
            ' ')
        """,
        "title": "Global Admin Role Add, Remove or Modify Activity",
        "attackId": "T1098.003",
        "dataSource": "Role_Management",
        "platform": "Azure_Active_Directory",
        "deployGroup": "AAD_All",
        "author": "Detection_Engineering",
        "detectCon": "4",
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


def aad_role_privileged_role_admin(x: str):
    logic_json = {
        "query": f"""
        AuditLogs
        | where TimeGenerated >= ago({x})
        | where Category =~ 'RoleManagement'
        | where TargetResources contains 'e8611ab8-c189-46e8-94e1-60213ab1f814'
        | extend PimLog= case(Identity == 'MS-PIM' , 'PIM' , 
            LoggedByService == 'PIM' , 'PIM' , 
            ' ')
        """,
        "title": "Privileged Role Admin Add, Remove or Modify Activity",
        "attackId": "T1098.003",
        "dataSource": "Role_Management",
        "platform": "Azure_Active_Directory",
        "deployGroup": "AAD_All",
        "author": "Detection_Engineering",
        "detectCon": "4",
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


def aad_role_billing_admin(x: str):
    logic_json = {
        "query": f"""
        AuditLogs
        | where TimeGenerated >= ago({x})
        | where Category =~ 'RoleManagement'
        | where TargetResources contains 'b0f54661-2d74-4c50-afa3-1ec803f12efe'
        | extend PimLog= case(Identity == 'MS-PIM' , 'PIM' , 
            LoggedByService == 'PIM' , 'PIM' , 
            ' ')
        """,
        "title": "Billing Admin Add, Remove or Modify Activity",
        "attackId": "T1098.003",
        "dataSource": "Role_Management",
        "platform": "Azure_Active_Directory",
        "deployGroup": "AAD_All",
        "author": "Detection_Engineering",
        "detectCon": "4",
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


def aad_role_domain_name_admin(x: str):
    logic_json = {
        "query": f"""
        AuditLogs
        | where TimeGenerated >= ago({x})
        | where Category =~ 'RoleManagement'
        | where TargetResources contains '8329153b-31d0-4727-b945-745eb3bc5f31'
        | extend PimLog= case(Identity == 'MS-PIM' , 'PIM' , 
            LoggedByService == 'PIM' , 'PIM' , 
            ' ')
        """,
        "title": "Domain Name Admin Add, Remove or Modify Activity",
        "attackId": "T1098.003",
        "dataSource": "Role_Management",
        "platform": "Azure_Active_Directory",
        "deployGroup": "AAD_All",
        "author": "Detection_Engineering",
        "detectCon": "4",
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


def aad_role_directory_writer(x: str):
    logic_json = {
        "query": f"""
        AuditLogs
        | where TimeGenerated >= ago({x})
        | where Category =~ 'RoleManagement'
        | where TargetResources contains '9360feb5-f418-4baa-8175-e2a00bac4301'
        | extend PimLog= case(Identity == 'MS-PIM' , 'PIM' , 
            LoggedByService == 'PIM' , 'PIM' , 
            ' ')
        """,
        "title": "Directory Writers Add, Remove or Modify Activity",
        "attackId": "T1098.003",
        "dataSource": "Role_Management",
        "platform": "Azure_Active_Directory",
        "deployGroup": "AAD_All",
        "author": "Detection_Engineering",
        "detectCon": "4",
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


def add_role_privileged_auth_admin(x: str):
    logic_json = {
        "query": f"""
        AuditLogs
        | where TimeGenerated >= ago({x})
        | where Category =~ 'RoleManagement'
        | where TargetResources contains '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'
        | extend PimLog= case(Identity == 'MS-PIM' , 'PIM' , 
            LoggedByService == 'PIM' , 'PIM' , 
            ' ')
        """,
        "title": "Privileged Authentication Administrator Add, Remove or Modify Activity",
        "attackId": "T1098.003",
        "dataSource": "Role_Management",
        "platform": "Azure_Active_Directory",
        "deployGroup": "AAD_All",
        "author": "Detection_Engineering",
        "detectCon": "4",
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


def add_role_groups_admin(x: str):
    logic_json = {
        "query": f"""
        AuditLogs
        | where TimeGenerated >= ago({x})
        | where Category =~ 'RoleManagement'
        | where TargetResources contains 'fdd7a751-b60b-444a-984c-02652fe8fa1c'
        | extend PimLog= case(Identity == 'MS-PIM' , 'PIM' , 
            LoggedByService == 'PIM' , 'PIM' , 
            ' ')
        """,
        "title": "Groups Administrator Add, Remove or Modify Activity",
        "attackId": "T1098.003",
        "dataSource": "Role_Management",
        "platform": "Azure_Active_Directory",
        "deployGroup": "AAD_All",
        "author": "Detection_Engineering",
        "detectCon": "4",
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


def aad_role_user_admin(x: str):
    logic_json = {
        "query": f"""
        AuditLogs
        | where TimeGenerated >= ago({x})
        | where Category =~ 'RoleManagement'
        | where TargetResources contains 'fe930be7-5e62-47db-91af-98c3a49a38b1'
        | extend PimLog= case(Identity == 'MS-PIM' , 'PIM' , 
            LoggedByService == 'PIM' , 'PIM' , 
            ' ')
        """,
        "title": "Groups Administrator Add, Remove or Modify Activity",
        "attackId": "T1098.003",
        "dataSource": "Role_Management",
        "platform": "Azure_Active_Directory",
        "deployGroup": "AAD_All",
        "author": "Detection_Engineering",
        "detectCon": "4",
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


def aad_role_app_admin(x: str):
    logic_json = {
        "query": f"""
        AuditLogs
        | where TimeGenerated >= ago({x})
        | where Category =~ 'RoleManagement'
        | where TargetResources contains '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'
        | extend PimLog= case(Identity == 'MS-PIM' , 'PIM' , 
            LoggedByService == 'PIM' , 'PIM' , 
            ' ')
        """,
        "title": "Application Administrator Add, Remove or Modify Activity",
        "attackId": "T1098.003",
        "dataSource": "Role_Management",
        "platform": "Azure_Active_Directory",
        "deployGroup": "AAD_All",
        "author": "Detection_Engineering",
        "detectCon": "4",
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


def aad_role_auth_admin(x: str):
    logic_json = {
        "query": f"""
        AuditLogs
        | where TimeGenerated >= ago({x})
        | where Category =~ 'RoleManagement'
        | where TargetResources contains 'c4e39bd9-1100-46d3-8c65-fb160da0071f'
        | extend PimLog= case(Identity == 'MS-PIM' , 'PIM' , 
            LoggedByService == 'PIM' , 'PIM' , 
            ' ')
        """,
        "title": "Authentication Administrator Add, Remove or Modify Activity",
        "attackId": "T1098.003",
        "dataSource": "Role_Management",
        "platform": "Azure_Active_Directory",
        "deployGroup": "AAD_All",
        "author": "Detection_Engineering",
        "detectCon": "4",
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


def aad_role_auth_policy_admin(x: str):
    logic_json = {
        "query": f"""
        AuditLogs
        | where TimeGenerated >= ago({x})
        | where Category =~ 'RoleManagement'
        | where TargetResources contains '0526716b-113d-4c15-b2c8-68e3c22b9f80'
        | extend PimLog= case(Identity == 'MS-PIM' , 'PIM' , 
            LoggedByService == 'PIM' , 'PIM' , 
            ' ')
        """,
        "title": "Authentication Policy Administrator Add, Remove or Modify Activity",
        "attackId": "T1098.003",
        "dataSource": "Role_Management",
        "platform": "Azure_Active_Directory",
        "deployGroup": "AAD_All",
        "author": "Detection_Engineering",
        "detectCon": "4",
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


def aad_role_cloud_app_admin(x: str):
    logic_json = {
        "query": f"""
        AuditLogs
        | where TimeGenerated >= ago({x})
        | where Category =~ 'RoleManagement'
        | where TargetResources contains '158c047a-c907-4556-b7ef-446551a6b5f7'
        | extend PimLog= case(Identity == 'MS-PIM' , 'PIM' , 
            LoggedByService == 'PIM' , 'PIM' , 
            ' ')
        """,
        "title": "Cloud Application Administrator Add, Remove or Modify Activity",
        "attackId": "T1098.003",
        "dataSource": "Role_Management",
        "platform": "Azure_Active_Directory",
        "deployGroup": "AAD_All",
        "author": "Detection_Engineering",
        "detectCon": "4",
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
