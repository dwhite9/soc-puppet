import requests
import pandas as pd


def azure_monitor_query_run(token: str, workspace_id: str, query_data: object):
    api_call_url = f"https://api.loganalytics.azure.com/v1/workspaces/{workspace_id}/query"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    api_call_response = requests.request("POST", api_call_url, headers=headers, json=query_data).json()

    return api_call_response


def azure_monitor_query_run_df(token: str, workspace_id: str, query_data: object):
    data = azure_monitor_query_run(token, workspace_id, query_data)

    df_col_names = []

    column_name_list = data['tables'][0]['columns']
    row_list = data['tables'][0]['rows']

    for item in column_name_list:
        df_col_names.append(item['name'])

    df_output = pd.DataFrame(row_list, columns=df_col_names)

    return df_output

