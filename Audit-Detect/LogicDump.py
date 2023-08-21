import socpuppet.azure as az
from dotenv import load_dotenv
import os
from datetime import date


# Set Variables
# Load your environment variables this methods uses Dotenv python package
load_dotenv()
tid = os.getenv('aad_tid')
cid = os.getenv('aad_cid')
sid = os.getenv('aad_sid')
sub = os.getenv('sen_sub')
rgn = os.getenv('sen_rgn')
wks = os.getenv('sen_wks')


# Sentinel Logic Data Dump
sent_bt = az.auth_resp_bearer_token(az.auth_resp_arm_sentinel(tid, cid, sid))
sent_data = az.sentinel_list_logic_flat_df(sent_bt, sub, rgn, wks)

sent_data.to_csv('datalib/sentinel/' + str(date.today()) + '-SentinelLogicDf.csv', index_label='index')

# MDE Logic Data Dump
mde_bt = az.auth_resp_bearer_token(az.auth_resp_m365d_mtp(tid, cid, sid))
mde_data = az.mde_list_logic_flat_df(mde_bt)

mde_data.to_csv('datalib/mdecustom/' + str(date.today()) + '-MdeCustomLogicDf.csv', index_label='index')
