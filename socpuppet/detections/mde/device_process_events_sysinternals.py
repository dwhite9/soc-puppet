

def procdump_used():
    logic_json = {
        "query": """
        DeviceProcessEvents
        | where FileName has_any('procdump', 'procdump64')
            or InitiatingProcessFileName has_any('procdump', 'procdump64')
        """,
        "title": "Procdump Usage",
        "attackId": "",
        "dataSource": "Process_Creation",
        "platform": "MSFT_Defender_Endpoint",
        "deployGroup": "Windows_Os_All_Endpoints",
        "author": "Detection Engineering",
        "detectCon": "4",
        "type": "simple_pattern_match",
        "openSource": ["https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_sysinternals_procdump.yml"],
        "emulation": [],
        "intelReference": [],
        "generalReference": ["https://learn.microsoft.com/en-us/sysinternals/downloads/procdump"],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }
    return logic_json


def procdump_renamed():
    logic_json = {
        "query": """
        DeviceProcessEvents
        | where FileName =~ 'dump64.exe'
            or InitiatingProcessFileName has_any ('procdump' , 'procdump64')
        | where ProcessCommandLine has_any ('accepteula' , '-ma' , '-mm')
        | where FileName !contains 'procdump'
        """,
        "title": "Procdump Renamed",
        "attackId": "",
        "dataSource": "Process_Creation",
        "platform": "MSFT_Defender_Endpoint",
        "deployGroup": "Windows_Os_All_Endpoints",
        "author": "Detection Engineering",
        "detectCon": "4",
        "type": "simple_pattern_match",
        "openSource": ["https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_lolbin_dump64.yml",
                       "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_renamed_sysinternals_procdump.yml"
                       ],
        "emulation": [],
        "intelReference": ["https://twitter.com/mrd0x/status/1460597833917251595"],
        "generalReference": ["https://learn.microsoft.com/en-us/sysinternals/downloads/procdump"],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }
    return logic_json

