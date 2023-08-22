

def function():
    logic_json = {
        "query": """
        SecurityEvent
        | where EventID == 4625 
            and AccountType == 'User' 
            and SubStatus == '0x0000064'
        | summarize AccountSet=make_set(TargetUserName) by IpAddress, SubStatus, EventID, 
            TargetDomainName, bin(TimeGenerated, 1h)
        | extend TargetUserNameCount = array_length(AccountSet)
        | where TargetUserNameCount >= 5 
        """,
        "title": "4625(F) User Logon with Bad Account Name from Same IP ",
        "attackId": "T110.003",
        "dataSource": "Security_Event_Log",
        "platform": "Active_Directory",
        "deployGroup": "Domain_Controllers_All",
        "author": "Detection_Engineering",
        "detectCon": "2",
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



