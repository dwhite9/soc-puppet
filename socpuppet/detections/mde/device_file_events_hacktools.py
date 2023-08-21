

def hacktool_dumpert_file(x: str):
    logic_json = {
        "query": f"""
        DeviceFileEvents
        | where Timestamp >= ago({x})
        | where ActionType =~ 'FileCreated'
        | where FileName has_any ('dumpert' , 'nanodump')
            or FileName =~ 'dumpert.exe'
        """,
        "title": "Dumpert File Created",
        "attackId": "T1003.001",
        "dataSource": "File_Creation",
        "platform": "MSFT_Defender_Endpoint",
        "deployGroup": "Windows_Os_All_Endpoints",
        "author": "Detection Engineering",
        "detectCon": "1",
        "type": "simple_pattern_match",
        "openSource": ["https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_hktl_dumpert.yml"],
        "emulation": ["https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md"],
        "intelReference": ["https://github.com/outflanknl/Dumpert",
                           "https://unit42.paloaltonetworks.com/actors-still-exploiting-sharepoint-vulnerability/"
                           ],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json