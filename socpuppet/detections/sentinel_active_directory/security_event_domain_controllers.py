

def ad_4625_threshold_match(x: str, y: int):
    logic_json = {
        "query": f"""
        SecurityEvent
        | where TimeGenerated >= ago({x})
        | where EventID == 4625 
            and AccountType == 'User' 
            and SubStatus == '0x0000064'
        | summarize AccountSet=make_set(TargetUserName) by IpAddress, SubStatus, EventID, 
            TargetDomainName, bin(TimeGenerated, 1h)
        | extend TargetUserNameCount = array_length(AccountSet)
        | where TargetUserNameCount >= {y} 
        """,
        "title": "4625(F) User Logon with Bad Account Name from Same IP ",
        "attackId": "T110.003",
        "dataSource": "Security_Event_Log",
        "platform": "Active_Directory",
        "deployGroup": "Domain_Controllers_All",
        "author": "Detection_Engineering",
        "detectCon": "3",
        "type": "aggregate_threshold_match",
        "openSource": [],
        "emulation": [],
        "intelReference": [],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json


def ad_4768_threshold_match(x: str, y: int):
    logic_json = {
        "query": f"""
        SecurityEvent
        | where TimeGenerated >= ago({x})
        | where EventID == 4768
        | where TargetUserName !endswith '$' //Remove Machine Accounts
        | extend IpExtract = extract(@'([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})' , 0 , IpAddress) 
        | where Status in~ ('0x6')
        | summarize AccountSet=make_set(TargetUserName) by IpExtract, ServiceName, Status, EventID, bin(TimeGenerated, 1h)
        | extend AccountTotal = array_length(AccountSet)
        | where AccountTotal >= {y} 
        """,
        "title": "4768(S,F) Auth With Bad User Names From Single IP",
        "attackId": "T110.003",
        "dataSource": "Security_Event_Log",
        "platform": "Active_Directory",
        "deployGroup": "Domain_Controllers_All",
        "author": "Detection_Engineering",
        "detectCon": "3",
        "type": "aggregate_threshold_match",
        "openSource": [],
        "emulation": [],
        "intelReference": [],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json


def ad_4771_threshold_match(x: str, y: int):
    logic_json = {
        "query": f"""
        SecurityEvent
        | where TimeGenerated >= ago({x})
        | where EventID == 4771
        | where TargetUserName !endswith '$' //Remove Machine Accounts
        | extend IpExtract = extract(@'([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})' , 0 , IpAddress) 
        | where Status in~ ('0x18') 
        | summarize AccountSet=make_set(TargetUserName) by IpExtract, ServiceName, Status, EventID, bin(TimeGenerated, 1h)
        | extend AccountTotal = array_length(AccountSet)
        | where AccountTotal >= {y}
        """,
        "title": "4771(F) Wrong Password From Single IP",
        "attackId": "T110.003",
        "dataSource": "Security_Event_Log",
        "platform": "Active_Directory",
        "deployGroup": "Domain_Controllers_All",
        "author": "Detection_Engineering",
        "detectCon": "3",
        "type": "aggregate_threshold_match",
        "openSource": [],
        "emulation": [],
        "intelReference": [],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json


def ad_4771_threshold_match(x: str, y: int):
    logic_json = {
        "query": f"""
        SecurityEvent
        | where TimeGenerated >= ago({x})
        | where EventID == 4771
        | where TargetUserName !endswith '$' //Remove Machine Accounts
        | extend IpExtract = extract(@'([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})' , 0 , IpAddress) 
        | where Status in~ ('0x18') 
        | summarize AccountSet=make_set(TargetUserName) by IpExtract, ServiceName, Status, EventID, bin(TimeGenerated, 1h)
        | extend AccountTotal = array_length(AccountSet)
        | where AccountTotal >= {y}
        """,
        "title": "4771(F) Wrong Password From Single IP",
        "attackId": "T110.003",
        "dataSource": "Security_Event_Log",
        "platform": "Active_Directory",
        "deployGroup": "Domain_Controllers_All",
        "author": "Detection_Engineering",
        "detectCon": "3",
        "type": "aggregate_threshold_match",
        "openSource": [],
        "emulation": [],
        "intelReference": [],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json


def ad_4738_uac_modification(x: str):
    logic_json = {
        "query": f"""
        SecurityEvent
        | where TimeGenerated >= ago({x})
        | where EventID == "4738" 
            and AccountType == "User" 
            and SubjectAccount !endswith '$'
            and SubjectAccount !endswith 'ANONYMOUS LOGON'
            and UserAccountControl != '-'
        | extend SubAccount = extract(@'\\(.+)', 1, SubjectAccount)
        | extend TarAccount = extract(@'\\(.+)', 1, TargetAccount)
        | extend UacOldToNew = strcat(OldUacValue,'<>',NewUacValue)
        | summarize UacChange=make_set(UacOldToNew) by SubAccount, TarAccount, bin(TimeGenerated, 6h), EventID, 
            TargetDomainName
        | extend Trigger = case(UacChange has '0x10<>0x210' , 'TRUE' ,
            UacChange has '0x11<>0x210' , 'TRUE' ,
            UacChange has '0x15<>0x210' , 'TRUE' ,
            'FALSE')
        | where Trigger == 'TRUE'
        """,
        "title": "4738 UAC Changes in a Set Time Period",
        "attackId": "",
        "dataSource": "Security_Event_Log",
        "platform": "Active_Directory",
        "deployGroup": "Domain_Controllers_All",
        "author": "Detection_Engineering",
        "detectCon": "3",
        "type": "aggregate_pattern_match",
        "openSource": [],
        "emulation": [],
        "intelReference": [],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json

