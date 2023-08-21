

def hklm_lsa_dump(x: str):
    logic_json = {
        "query": f"""
        DeviceProcessEvents
        | where Timestamp >= ago({x})
        | where ProcessCommandLine has 'reg'
        | where ProcessCommandLine has_all('save' , 'security' , 'hklm')
        """,
        "title": "LSA Secrets Dump",
        "attackId": "T1003.002",
        "dataSource": "Process_Creation",
        "platform": "MSFT_Defender_Endpoint",
        "deployGroup": "Windows_Os_All_Endpoints",
        "author": "Detection Engineering",
        "detectCon": "1",
        "type": "simple_pattern_match",
        "openSource": [],
        "emulation": ["https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.004/T1003.004.md#atomic-test-1---dumping-lsa-secrets"],
        "intelReference": [],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json