import requests
import pandas as pd
import json
from datetime import datetime


def sentinel_list_logic(bearer_token: str, subscriptionId: str, resourceGroupName: str, workspaceName: str):
    # API is latest stable release
    apiVersion = '2023-02-01'
    api_call_url = f'https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/alertRules?api-version={apiVersion}'
    req_headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + bearer_token
    }

    api_call_response = requests.request('GET', api_call_url, headers=req_headers).json()
    json_object = json.dumps(api_call_response)
    return json_object


def sentinel_list_logic_flat_df(bearer_token: str, subscriptionId: str, resourceGroupName: str, workspaceName: str):
    jsonobj = sentinel_list_logic(bearer_token, subscriptionId, resourceGroupName, workspaceName)
    raw_df = pd.read_json(jsonobj, orient='columns')

    raw_df = pd.concat([raw_df, raw_df['value'].apply(pd.Series)], axis=1)
    raw_df = raw_df.drop('value', axis=1)
    raw_df = pd.concat([raw_df, raw_df['properties'].apply(pd.Series)], axis=1)
    raw_df = raw_df.drop('properties', axis=1)
    raw_df = pd.concat([raw_df, raw_df['eventGroupingSettings'].apply(pd.Series)], axis=1)
    raw_df = raw_df.drop('eventGroupingSettings', axis=1)
    raw_df = pd.concat([raw_df, raw_df['incidentConfiguration'].apply(pd.Series)], axis=1)
    raw_df = raw_df.drop('incidentConfiguration', axis=1)
    raw_df = pd.concat([raw_df, raw_df['groupingConfiguration'].apply(pd.Series)], axis=1)
    raw_df = raw_df.drop('groupingConfiguration', axis=1)

    meta_df = raw_df

    meta_df['dumpDateUtc'] = datetime.utcnow()
    col_a = meta_df.pop('lastModifiedUtc')
    col_b = meta_df.pop('dumpDateUtc')
    col_c = meta_df.pop('displayName')

    meta_df.insert(0, col_a.name, col_a)
    meta_df.insert(1, col_b.name, col_b)
    meta_df.insert(2, col_c.name, col_c)

    return meta_df.sort_values(by=['lastModifiedUtc'] , ascending=False)

