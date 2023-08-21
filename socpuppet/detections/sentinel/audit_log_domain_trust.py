

def domain_trust(x: str):
    logic_json = {
        "query": f"""
        AuditLogs
        | where TimeGenerated >= ago({x})
        | where LoggedByService =~ 'B2C'
        | where OperationName =~ 'Set federation settings on domain' 
            or OperationName =~ 'Set domain authentication'
        """,
        "title": "AAD Directory Domain Trust Settings Modified ",
        "attackId": "T1482",
        "dataSource": "Audit_Log_B2C",
        "platform": "Azure_Active_Directory",
        "deployGroup": "AAD_All",
        "author": "Detection_Engineering",
        "detectCon": "3",
        "type": "simple_pattern_match",
        "openSource": ["https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Azure%20Active%20Directory/Analytic%20Rules/ADFSDomainTrustMods.yaml",
                       "https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Azure%20Active%20Directory/Analytic%20Rules/NRT_ADFSDomainTrustMods.yaml ",
                       "https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/azure/azure_federation_modified.yml"
                       ],
        "emulation": [],
        "intelReference": [],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json

