

def lolbin_comsvcs_minidump(x: str):
    logic_json = {
        "query": f"""
        DeviceProcessEvents
        | where Timestamp >= ago({x})
        | where ProcessCommandLine has_all ('rundll32' , 'minidump' , 'comsvcs')
            or ProcessCommandLine has_all('minidump' , 'comsvcs')
        """,
        "title": "Rundll32 Spawning Comsvcs to Create Minidump of LSASS",
        "attackId": "T1003.001",
        "dataSource": "Process_Creation",
        "platform": "MSFT_Defender_Endpoint",
        "deployGroup": "Windows_Os_All_Endpoints",
        "author": "Detection Engineering",
        "detectCon": "1",
        "type": "simple_pattern_match",
        "openSource": ["https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_rundll32_process_dump_via_comsvcs.yml"],
        "emulation": ["https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md#atomic-test-2---dump-lsassexe-memory-using-comsvcsdll"],
        "intelReference": ["https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/",
                           "https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz",
                           "https://book.hacktricks.xyz/windows-hardening/stealing-credentials",
                           "https://lolbas-project.github.io/lolbas/Libraries/comsvcs/",
                           "https://twitter.com/Wietze/status/1542107456507203586"
                           ],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json


def lolbin_cmstp_inf(x: str):
    logic_json = {
        "query": f"""
        DeviceProcessEvents
        | where Timestamp >= ago({x})
        | where ProcessCommandLine has_all('cmstp' , '/s' , '.inf')
        """,
        "title": "CMSTP Executing .inf File",
        "attackId": "T1218.003",
        "dataSource": "Process_Creation",
        "platform": "MSFT_Defender_Endpoint",
        "deployGroup": "Windows_Os_All_Endpoints",
        "author": "Detection Engineering",
        "detectCon": "3",
        "type": "simple_pattern_match",
        "openSource": [],
        "emulation": ["https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.003/T1218.003.md#atomic-test-1---cmstp-executing-remote-scriptlet",
                      "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.003/T1218.003.md#atomic-test-2---cmstp-executing-uac-bypass"
                      ],
        "intelReference": ["https://lolbas-project.github.io/lolbas/Binaries/Cmstp/"],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json


def lolbin_control_cpl(x: str):
    logic_json = {
        "query": f"""
        DeviceProcessEvents
        | where Timestamp >= ago({x})
        | where ProcessCommandLine has_all ('cmd' , 'control.exe' , '/c')
        """,
        "title": "Control Executing .cpl File",
        "attackId": "T1218.002",
        "dataSource": "Process_Creation",
        "platform": "MSFT_Defender_Endpoint",
        "deployGroup": "Windows_Os_All_Endpoints",
        "author": "Detection Engineering",
        "detectCon": "3",
        "type": "simple_pattern_match",
        "openSource": [],
        "emulation": ["https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.002/T1218.002.md#atomic-test-1---control-panel-items"],
        "intelReference": ["https://lolbas-project.github.io/lolbas/Binaries/Control/"],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json


def lolbin_esentutl_copy_file(x: str):
    logic_json = {
        "query": f"""
        DeviceProcessEvents
        | where Timestamp >= ago({x})
        | where ProcessCommandLine has 'esentutl'
        | where ProcessCommandLine has_any ('/y' , '/vss')
        """,
        "title": "Esentutil.exe Copied a File",
        "attackId": "T1003.002",
        "dataSource": "Process_Creation",
        "platform": "MSFT_Defender_Endpoint",
        "deployGroup": "Windows_Os_All_Endpoints",
        "author": "Detection Engineering",
        "detectCon": "1",
        "type": "simple_pattern_match",
        "openSource": ["https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_esentutl_sensitive_file_copy.yml"],
        "emulation": ["https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.002/T1003.002.md#atomic-test-3---esentutlexe-sam-copy"],
        "intelReference": ["https://dfironthemountain.wordpress.com/2018/12/06/locked-file-access-using-esentutl-exe/",
                           "https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment",
                           "https://room362.com/post/2013/2013-06-10-volume-shadow-copy-ntdsdit-domain-hashes-remotely-part-1/"
                           ],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json


def lolbin_hh_chm(x: str):
    logic_json = {
        "query": f"""
        DeviceProcessEvents
        | where Timestamp >= ago({x})
        | where ProcessCommandLine has_all ('hh.exe' , 'chm')
        """,
        "title": "HH.exe Executing Compiled HTML Help File",
        "attackId": "T1218.001",
        "dataSource": "Process_Creation",
        "platform": "MSFT_Defender_Endpoint",
        "deployGroup": "Windows_Os_All_Endpoints",
        "author": "Detection Engineering",
        "detectCon": "3",
        "type": "simple_pattern_match",
        "openSource": [],
        "emulation": ["https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.001/T1218.001.md#atomic-test-1---compiled-html-help-local-payload",
                      "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.001/T1218.001.md#atomic-test-2---compiled-html-help-remote-payload"],
        "intelReference": ["https://lolbas-project.github.io/lolbas/Binaries/Hh/"],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json


def lolbin_infdefaultinstall_inf(x: str):
    logic_json = {
        "query": f"""
        DeviceProcessEvents
        | where Timestamp >= ago({x})
        | where ProcessCommandLine has_all('infdefaultinstall' , '.inf')
        """,
        "title": "InfDefaultInstall.exe Executing .inf File",
        "attackId": "T1218",
        "dataSource": "Process_Creation",
        "platform": "MSFT_Defender_Endpoint",
        "deployGroup": "Windows_Os_All_Endpoints",
        "author": "Detection Engineering",
        "detectCon": "3",
        "type": "simple_pattern_match",
        "openSource": [],
        "emulation": ["https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md#atomic-test-3---infdefaultinstallexe-inf-execution"],
        "intelReference": ["https://lolbas-project.github.io/lolbas/Binaries/Infdefaultinstall/"],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json


def lolbin_keymgr_dump(x: str):
    logic_json = {
        "query": f"""
        DeviceProcessEvents
        | where Timestamp >= ago({x})
        | where InitiatingProccessCommandLine has_all('rundll32' , 'keymgr' , 'krshowkeymgr')
        """,
        "title": "Rundll32 Calling Keymgr.dll to Dump Creds",
        "attackId": "T1003",
        "dataSource": "Process_Creation",
        "platform": "MSFT_Defender_Endpoint",
        "deployGroup": "Windows_Os_All_Endpoints",
        "author": "Detection Engineering",
        "detectCon": "1",
        "type": "simple_pattern_match",
        "openSource": ["https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_rundll32_keymgr.yml"],
        "emulation": [],
        "intelReference": [],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json


def lolbin_mavinject(x: str):
    logic_json = {
        "query": f"""
        DeviceProcessEvents
        | where Timestamp >= ago({x})
        | where ProcessCommandLine has_all ('INJECTRUNNING', 'dll')
        """,
        "title": "InfDefaultInstall.exe Executing .inf File",
        "attackId": "T1218.013",
        "dataSource": "Process_Creation",
        "platform": "MSFT_Defender_Endpoint",
        "deployGroup": "Windows_Os_All_Endpoints",
        "author": "Detection Engineering",
        "detectCon": "3",
        "type": "simple_pattern_match",
        "openSource": [],
        "emulation": [],
        "intelReference": ["https://lolbas-project.github.io/lolbas/Binaries/Mavinject/"],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json


def lolbin_msdt_folina(x: str):
    logic_json = {
        "query": f"""
        DeviceProcessEvents
        | where Timestamp >= ago({x})
        | where ProcessCommandLine has_all ('msdt', 'PCWDiagnostic', 'IT_BrowseForFile=')
            and ProcessCommandLine contains '../../'
        """,
        "title": "MSDT Folina Match",
        "attackId": "T1218",
        "dataSource": "Process_Creation",
        "platform": "MSFT_Defender_Endpoint",
        "deployGroup": "Windows_Os_All_Endpoints",
        "author": "Detection Engineering",
        "detectCon": "3",
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


def lolbin_msdt_pcwrun(x: str):
    logic_json = {
        "query": f"""
        DeviceProcessEvents
        | where Timestamp >= ago({x})
        | where ProcessCommandLine has_all ('msdt', 'PCWDiagnostic', '-af')
            and InitiatingProcessFileName != 'pcwrun.exe'
        """,
        "title": "MSDT Simulating Pcwrun",
        "attackId": "T1218",
        "dataSource": "Process_Creation",
        "platform": "MSFT_Defender_Endpoint",
        "deployGroup": "Windows_Os_All_Endpoints",
        "author": "Detection Engineering",
        "detectCon": "3",
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


def lolbin_msdt_rare_spawn(x: str):
    logic_json = {
        "query": f"""
        DeviceProcessEvents
        | where Timestamp >= ago({x})
        | where FileName =~ 'msdt.exe'
        | where InitiatingProcessFileName in~ ('cscript.exe' , 'mshta.exe' , 'powershell.exe' ,
            'pwsh.exe' , 'wmic.exe' , 'wscript.exe' , 'schtasks.exe' 'cmd.exe')
        """,
        "title": "MSDT Spawned by Rare Parent",
        "attackId": "T1218",
        "dataSource": "Process_Creation",
        "platform": "MSFT_Defender_Endpoint",
        "deployGroup": "Windows_Os_All_Endpoints",
        "author": "Detection Engineering",
        "detectCon": "3",
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


def lolbin_mshta_hta(x: str):
    logic_json = {
        "query": f"""
        DeviceProcessEvents
        | where Timestamp >= ago({x})
        | where ProcessCommandLine has_all('mshta' , '.hta')
        """,
        "title": "MSHTA Executing hta File",
        "attackId": "T1218.005",
        "dataSource": "Process_Creation",
        "platform": "MSFT_Defender_Endpoint",
        "deployGroup": "Windows_Os_All_Endpoints",
        "author": "Detection Engineering",
        "detectCon": "3",
        "type": "simple_pattern_match",
        "openSource": [],
        "emulation": ["https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.005/T1218.005.md#atomic-test-3---mshta-executes-remote-html-application-hta"],
        "intelReference": ["https://lolbas-project.github.io/lolbas/Binaries/Mshta/"],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json


def lolbin_mshta_vbs(x: str):
    logic_json = {
        "query": f"""
        DeviceProcessEvents
        | where Timestamp >= ago({x})
        | where ProcessCommandLine has_all('mshta' , 'vbscript' , 'execute')
        """,
        "title": "MSHTA Executing VB Script",
        "attackId": "T1218.005",
        "dataSource": "Process_Creation",
        "platform": "MSFT_Defender_Endpoint",
        "deployGroup": "Windows_Os_All_Endpoints",
        "author": "Detection Engineering",
        "detectCon": "3",
        "type": "simple_pattern_match",
        "openSource": [],
        "emulation": ["https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.005/T1218.005.md#atomic-test-2---mshta-executes-vbscript-to-execute-malicious-command"],
        "intelReference": ["https://lolbas-project.github.io/lolbas/Binaries/Mshta/"],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json


def lolbin_werfault_lsass(x: str):
    logic_json = {
        "query": f"""
        DeviceProcessEvents
        | where Timestamp >= ago({x})
        | where InitiatingProcessFileName =~ 'werfault.exe'
            or FileName =~ 'werfault.exe'
        | where ProcessCommandLine has_all ('-u' , '-p' ,'-ip' ,'-s')
        """,
        "title": "Werfault Dumping LSASS",
        "attackId": "T1003.001",
        "dataSource": "Process_Creation",
        "platform": "MSFT_Defender_Endpoint",
        "deployGroup": "Windows_Os_All_Endpoints",
        "author": "Detection Engineering",
        "detectCon": "1",
        "type": "simple_pattern_match",
        "openSource": ["https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_werfault_lsass_shtinkering.yml"],
        "emulation": [],
        "intelReference": ["https://github.com/deepinstinct/Lsass-Shtinkering",
                           "https://media.defcon.org/DEF%20CON%2030/DEF%20CON%2030%20presentations/Asaf%20Gilboa%20-%20LSASS%20Shtinkering%20Abusing%20Windows%20Error%20Reporting%20to%20Dump%20LSASS.pdf"
                           ],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json


def lolbin_wuauclt(x: str):
    logic_json = {
        "query": f"""
        DeviceProcessEvents
        | where Timestamp >= ago({x})
        | where ProcessCommandLine has_all('/UpdateDeploymentProvider' , 
            '/RunHandlerComServer' , '.dll')
        | where not (ProcessCommandLine has_any('UpdateDeploymentProvider.dll' ,
            'UpdateDeploy.dll' , 'wuaueng.dll'))
        """,
        "title": "Wuauclt Proxy Execution",
        "attackId": "T1218",
        "dataSource": "Process_Creation",
        "platform": "MSFT_Defender_Endpoint",
        "deployGroup": "Windows_Os_All_Endpoints",
        "author": "Detection Engineering",
        "detectCon": "3",
        "type": "simple_pattern_match",
        "openSource": ["https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_lolbin_wuauclt.yml"],
        "emulation": ["https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md#atomic-test-9---load-arbitrary-dll-via-wuauclt-windows-update-client"],
        "intelReference": ["https://lolbas-project.github.io/lolbas/Binaries/Wuauclt/"],
        "generalReference": [],
        "tags": [],
        "responsePlaybook": [],
        "detectUseCases": [],
    }

    return logic_json





