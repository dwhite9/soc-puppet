

def aad_app_privileged_perms(x: str):
    logic_json = {
        "query": f"""
        AuditLogs
        | where TimeGenerated >= ago({x})
        | where Category =~ 'ApplicationManagement'
        | where OperationName in~ ('Add delegated permission grant', 'Add app role assignment to service principal')
        | where TargetResources has_any ('AdministrativeUnit.ReadWrite.All' , 
            'Directory.ReadWrite.All' ,
            'Directory.Write.Restricted' , 
            'Application.ReadWrite.All' , 
            'AppRoleAssignment.ReadWrite.All' ,
            'Domain.ReadWrite.All' , 
            'Group.ReadWrite.All' , 
            'GroupMember.ReadWrite.All' ,
            'RoleManagement.ReadWrite.Directory' , 
            'RoleManagementPolicy.ReadWrite.Directory' ,
            'PrivilegedAccess.ReadWrite' ,
            'PrivligedAccess.Read' , 
            'ReportSettings' ,
            'DelegatedPermissionGrant.ReadWrite.All')
        """,
        "title": "Specific API Perms Added To Service Principal",
        "attackId": "",
        "dataSource": "Application_Management",
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


def aad_app_mail_read_write(x: str):
    logic_json = {
        "query": f"""
        AuditLogs
        | where TimeGenerated >= ago({x})
        | where Category =~ "ApplicationManagement"
        | where OperationName has_any ("Add delegated permission grant", "Add app role assignment to service principal")
        | where Result =~ "success"
        | where TargetResources has_any ('mail.read', 'mail.readwrite', 'MailboxSettings', 'Mail.Send' , 'Mail')
        """,
        "title": "Mail Or Mailbox Read/Write Added To Service Principal",
        "attackId": "",
        "dataSource": "Application_Management",
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


def aad_app_admin_consent(x: str):
    logic_json = {
        "query": f"""
        AuditLogs
        | where TimeGenerated >= ago({x})
        | where Category =~ "ApplicationManagement"
        | where OperationName =~ "Consent to application"
        | where Result =~ 'success'
        """,
        "title": "Admin Consent Added To Service Principal",
        "attackId": "",
        "dataSource": "Application_Management",
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