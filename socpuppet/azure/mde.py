import requests
import pandas as pd
import json
from datetime import datetime


def mde_list_logic(token: str):
    api_call_url = 'https://api.security.microsoft.com/api/CustomDetections'
    req_headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': 'Bearer ' + token
            }

    api_call_response = requests.request('GET', api_call_url, headers=req_headers).json()
    return json.dumps(api_call_response)


def mde_list_logic_flat_df(token: str):
    data = mde_list_logic(token)
    mde_df = pd.read_json(data)
    mde_df = pd.concat([mde_df, mde_df['value'].apply(pd.Series)], axis=1)
    mde_df = mde_df.drop('value', axis=1)

    mde_df['dumpDateUtc'] = datetime.utcnow()

    col_a = mde_df.pop('lastUpdatedTime')
    col_b = mde_df.pop('dumpDateUtc')
    col_c = mde_df.pop('ruleName')

    mde_df.insert(0, col_a.name, col_a)
    mde_df.insert(1, col_b.name, col_b)
    mde_df.insert(2, col_c.name, col_c)

    return mde_df


def mde_graph_hunt_query_run(token: str, query_data: object):
    api_call_url = f"https://graph.microsoft.com/v1.0/security/runHuntingQuery"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    api_call_response = requests.request('POST', api_call_url, headers=headers, json=query_data).json()

    return api_call_response


def mde_graph_hunt_query_run_df(token: str, query_data: json):
    output = mde_graph_hunt_query_run(token, query_data)
    mde_df = pd.DataFrame.from_dict(output['results'])

    return mde_df


