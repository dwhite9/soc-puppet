

def builtin_t1003_alerts(x: str):
    logic_json = {
        "query": f"""
        let AlertName = dynamic(['Process memory dump', 'Suspicious access to LSASS service', 
            'Endpoint attack notifications: Credential theft activity', 'Sensitive credential memory read', 
            'Malicious credential theft tool execution detected', 'Possible attempt to steal credentials']);
        let AlertKeyWord = dynamic(['DumpLsass', 'LsassDump', 'RundllLolBin', 'pypykatz', 'minidump', 'wincred', 
            'mimikatz', 'MiniDump', 'PowerSploit', 'Lazagne']);
        AlertEvidence
        | where Timestamp >= ago({x})
        | extend Trigger = case(Title in~ (AlertName), 'Title Trigger',
            Title has_any (AlertKeyWord), 'Title Keyword Trigger' ,
            ThreatFamily has_any (AlertKeyWord), 'Threat Family Keyword' ,
            '')
        | where isnotempty(Trigger)
            or AttackTechniques contains 'T1003'
        | where DetectionSource !~ 'Custom detection'
        """,
        "title": "MDE EDR and Antivirus Built In Alert Filter for T1003: Os Cred Dumping Alerts",
        "attackId": "T1003",
        "dataSource": "Process_Creation",
        "platform": "MSFT_Defender_Endpoint",
        "deployGroup": "Windows_Os_All_Endpoints",
        "author": "Detection Engineering",
        "detectCon": "1",
        "type": "alert_filter",
        "openSource": [],
        "emulation": [],
        "intelReference": [],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json


def builtin_folina_alerts(x: str):
    logic_json = {
        "query": f"""
        let AlertName = dynamic(['Suspicious msdt.exe behavior', 'Suspicious behavior by an Office application', 
            'Suspicious behavior by Msdt.exe', 'Possible exploitation attempt of CVE-2022-30190', 
            'Trojan:Win32/Mesdetty.A', 'Trojan:Win32/Mesdetty.B', 'Behavior:Win32/MesdettyLaunch.A!blk', 
            'Trojan:Win32/MesdettyScript.A', 'Trojan:Win32/MesdettyScript.B', 'Behavior:Win32/MesdettyPayload.B', 
            'Behavior:Win32/MesdettyLaunch.D']);
        let AlertKeyWord = dynamic([]);
        AlertEvidence
        | where Timestamp >= ago({x})
        | extend Trigger = case(Title in~ (AlertName), 'Title Trigger',
            Title has_any (AlertKeyWord), 'Title Keyword Trigger' ,
            ThreatFamily has_any (AlertKeyWord), 'Threat Family Keyword' ,
            '')
        | where isnotempty(Trigger)
            or AttackTechniques contains 'T1003'
        | where DetectionSource !~ 'Custom detection'
        """,
        "title": "MDE EDR and Antivirus Built In Alert Filter for T1003: Os Cred Dumping Alerts",
        "attackId": "T1003",
        "dataSource": "Process_Creation",
        "platform": "MSFT_Defender_Endpoint",
        "deployGroup": "Windows_Os_All_Endpoints",
        "author": "Detection Engineering",
        "detectCon": "2",
        "type": "alert_filter",
        "openSource": [],
        "emulation": [],
        "intelReference": [],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json


