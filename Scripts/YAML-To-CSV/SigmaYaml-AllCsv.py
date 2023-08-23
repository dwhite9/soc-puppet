import pandas as pd
import os
import yaml


rule_df = pd.DataFrame()
rule_list = []
rule_location = input('Enter Rule Path: ')

for root, dirs, files in os.walk(rule_location):
    for filename in files:
        filepath = os.path.join(root, filename)
        if filepath.endswith('yaml') or filepath.endswith('yml'):
            rule_list.append(filepath)


# print(rule_list)

for item in rule_list:
    file = open(item)
    data = yaml.safe_load(file)
    sigma_series = pd.Series(data)
    x = sigma_series.to_frame(name=item)
    rule_df = pd.concat([rule_df, x], axis=1)


final_df = rule_df.transpose()


final_df.to_csv('dumps/sigma-all.csv')