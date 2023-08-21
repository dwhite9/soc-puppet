

def lolbin_comsvcs_write_file(x: str):
    logic_json = {
        "query": f"""
        DeviceFileEvents
        | where Timestamp >= ago({x})
        | where ActionType =~ 'FileCreated'
        | where InitiatingProcessCommandLine has_all ('rundll32' , 'comsvcs')
        """,
        "title": "Comsvcs Writing Files",
        "attackId": "T1003.001",
        "dataSource": "File_Creation",
        "platform": "MSFT_Defender_Endpoint",
        "deployGroup": "Windows_Os_All_Endpoints",
        "author": "Detection Engineering",
        "detectCon": "1",
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


