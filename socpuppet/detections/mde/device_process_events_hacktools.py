


def hacktool_adplus(x: str):
    logic_json = {
        "query": f"""
        DeviceProcessEvents
        | where Timestamp >= ago({x})
        | where FileName has 'adplus'
            or ProcessCommandLine has 'adplus'
        | where ProcessCommandLine has_any('-c' ,'-pn' ,'pmn' ,'-p' ,'po' ,'-hang' ,'-sc' , 'lsass.exe' )
        """,
        "title": "Adplus Usage",
        "attackId": "T1003.001",
        "dataSource": "Process_Creation",
        "platform": "MSFT_Defender_Endpoint",
        "deployGroup": "Windows_Os_All_Endpoints",
        "author": "Detection Engineering",
        "detectCon": "1",
        "type": "simple_pattern_match",
        "openSource": ["https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_adplus_memory_dump.yml"],
        "emulation": [""],
        "intelReference": ["https://lolbas-project.github.io/lolbas/OtherMSBinaries/Adplus/",
                           "https://mrd0x.com/adplus-debugging-tool-lsass-dump/"
                           ],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json


def hacktool_dumpert(x: str):
    logic_json = {
        "query": f"""
        DeviceProcessEvents
        | where Timestamp >= ago({x})
        | where ProcessCommandLine has_all ('dumpert' , 'dmp')
        """,
        "title": "Dumpert DLL Hacktool Used to Dump LSASS",
        "attackId": "T1003.001",
        "dataSource": "Process_Creation",
        "platform": "MSFT_Defender_Endpoint",
        "deployGroup": "Windows_Os_All_Endpoints",
        "author": "Detect Engineering",
        "detectCon": "1",
        "type": "simple_pattern_match",
        "openSource": ["https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_dumpert.yml"],
        "emulation": ["https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md#atomic-test-3---dump-lsassexe-memory-using-direct-system-calls-and-api-unhooking"],
        "intelReference": ["https://unit42.paloaltonetworks.com/actors-still-exploiting-sharepoint-vulnerability/",
                           "https://github.com/outflanknl/Dumpert",
                           "https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/"
                           ],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json


def hacktool_mimikatz_commands(x: str):
    logic_json = {
        "query": f"""
        DeviceProcessEvents
        | where Timestamp >= ago({x})
        | where ProcessCommandLine has_any('sekurlsa::', 'dpapi::', 'rpc::', 'token::', 'crypto::', 
            'kerberos::' ,'lsadump::', 'privilege::', 'process::', 'vault::')    
        """,
        "title": "Mimikatz Command Line Args",
        "attackId": "T1003.001",
        "dataSource": "Process_Creation",
        "platform": "MSFT_Defender_Endpoint",
        "deployGroup": "Windows_Os_All_Endpoints",
        "author": "Detection Engineering",
        "detectCon": "1",
        "type": "simple_pattern_match",
        "openSource": ["https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_mimikatz_command_line.yml"],
        "emulation": ["https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md#atomic-test-6---offline-credential-theft-with-mimikatz",
                      "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md#atomic-test-10---powershell-mimikatz"
                      ],
        "intelReference": [],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json


def hacktool_mimikatz(x: str):
    logic_json = {
        "query": f"""
        DeviceProcessEvents
        | where Timestamp >= ago({x})
        | where ProcessCommandLine has_any('dumpcreds' , 'mimikatz') 
            or FileName has 'mimikatz'  
        """,
        "title": "Mimikatz Hacktool",
        "attackId": "T1003.001",
        "dataSource": "Process_Creation",
        "platform": "MSFT_Defender_Endpoint",
        "deployGroup": "Windows_Os_All_Endpoints",
        "author": "Detection Engineering",
        "detectCon": "1",
        "type": "simple_pattern_match",
        "openSource": ["https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_mimikatz_command_line.yml"],
        "emulation": ["https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md#atomic-test-6---offline-credential-theft-with-mimikatz"],
        "intelReference": ["ttps://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using-invoke-reflectivedllinjection-ps1/",
                           "https://tools.thehacker.recipes/mimikatz/modules",
                           "https://github.com/gentilkiwi/mimikatz"
                           ],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json


def hacktool_nanodump(x: str):
    logic_json = {
        "query": f"""
        DeviceProcessEvents
        | where Timestamp >= ago({x})
        | where ProcessCommandLine has_all ('nanodump' , '.dmp')
        """,
        "title": "Nanodump Hacktool Usage",
        "attackId": "T1003.001",
        "dataSource": "Process_Creation",
        "platform": "MSFT_Defender_Endpoint",
        "deployGroup": "Windows_Os_All_Endpoints",
        "author": "Detect Engineering",
        "detectCon": "1",
        "type": "simple_pattern_match",
        "openSource": [],
        "emulation": ["https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md"],
        "intelReference": ["https://github.com/helpsystems/nanodump"],
        "generalReferences": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json


def hacktool_procdump_lsass(x: str):
    logic_json = {
        "query": f"""
        DeviceProcessEvents
        | where Timestamp >= ago({x})
        | where ProcessCommandLine has_all ('lsass' , 'accepteula')
            and ProcessCommandLine has_any ('-ma' , '-mm')
        """,
        "title": "Procdump Used to Dump LSASS",
        "attackId": "T1003.001",
        "dataSource": "Process_Creation",
        "platform": "MSFT_Defender_Endpoint",
        "deployGroup": "Windows_Os_All_Endpoints",
        "author": "Detection Engineering",
        "detectCon": "1",
        "type": "simple_pattern_match",
        "openSource": ["https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_sysinternals_procdump_lsass.yml"],
        "emulation": ["https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md#atomic-test-1---dump-lsassexe-memory-using-procdump",
                      "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md#atomic-test-9---create-mini-dump-of-lsassexe-using-procdump"
                      ],
        "intelReference": ["https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz",
                           "https://attack.mitre.org/techniques/T1003/001/",
                           "https://research.splunk.com/endpoint/e102e297-dbe6-4a19-b319-5c08f4c19a06/",
                           "https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/"
                           ],
        "generalReference": ["https://learn.microsoft.com/en-us/sysinternals/downloads/procdump"],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }
    return logic_json


def hacktool_pypykatz(x: str):
    logic_json = {
        "query": f"""
        DeviceProcessEvents
        | where Timestamp >= ago({x})
        | where FileName has 'pypykatz'
            or ProcessCommandLine has 'pypykatz'
            or ProcessCommandLine has_all ('cmd' , 'live' , 'lsa')
            or ProcessCommandLine has_all ('python' , 'live' , 'lsa')
            or ProcessCommandLine has_all ('live' , 'registry')
        """,
        "title": "Pypykatz Hacktool Activity",
        "attackId": "T1003.001",
        "dataSource": "Process_Creation",
        "platform": "MSFT_Defender_Endpoint",
        "deployGroup": "Windows_Os_All_Endpoints",
        "author": "Detection Engineering",
        "detectCon": "1",
        "type": "simple_pattern_match",
        "openSource": ["https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_pypykatz.yml"],
        "emulation": ["https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md"],
        "intelReference": ["https://github.com/skelsec/pypykatz",
                           "https://andreafortuna.org/2020/03/20/pypykatz-a-mimikatz-python-implementation/",
                           "https://kalilinuxtutorials.com/pypykatz/"
                           ],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json


