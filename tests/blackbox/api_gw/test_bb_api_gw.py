#!/usr/bin/env python3
'''Test api_gw mode'''
# ------------------------------------------------------------------------------
# Imports
# ------------------------------------------------------------------------------
import subprocess
import os
import json
import sys
import time
import re
import requests
import pytest
import base64
# ------------------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------------------
G_TEST_HOST = 'http://127.0.0.1:12345'
# ------------------------------------------------------------------------------
# run_command
# ------------------------------------------------------------------------------
def run_command(command):
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    return (p.returncode, stdout, stderr)
# ------------------------------------------------------------------------------
# setup waflz server in api_gw mode
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_waflz_server_api_gw_mode():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_cwd = os.getcwd()
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_waflz_server_path = os.path.abspath(os.path.join(l_file_path, '../../../build/util/waflz_server/waflz_server'))
    l_api_gw_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/api_gw/0050-nif70s89.api_gw.json'))
    l_conf_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/'))
    l_subproc = subprocess.Popen([l_waflz_server_path,
                                  '-P', l_api_gw_path,
                                  '-d', l_conf_dir])
    time.sleep(1)
    print('cmd: \n{}\n'.format(' '.join([l_waflz_server_path,
                                  '-P', l_api_gw_path,
                                  '-d', l_conf_dir])))
    # ------------------------------------------------------
    # yield...
    # ------------------------------------------------------
    yield setup_waflz_server_api_gw_mode
    # ------------------------------------------------------
    # tear down
    # ------------------------------------------------------
    l_code, l_out, l_err = run_command('kill -9 %d'%(l_subproc.pid))
    time.sleep(0.5)
# ----------------------------------------------------------
# test rqst in api_gw config
# ----------------------------------------------------------
def test_api_gw(setup_waflz_server_api_gw_mode):
    # ------------------------------------------------------
    # type error
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'myapigw.com',
                 'Content-Type': 'application/json'}
    l_data = {'name': 1}
    l_r = requests.get(l_uri, headers=l_headers, json=l_data)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json["rule_msg"] == "Request JSON Schema Validation Error"
    assert l_r_json["sub_event"][0]["rule_msg"] == "type"
    assert l_r_json["sub_event"][0]["rule_id"] == 900118
    assert l_r_json["api_gw_config_id"] == "nif70s89"
    assert l_r_json["schema_config_id"] == "W9057Zkg"
    assert l_r_json["sub_event"][0]["schema_error_location"] == "#/properties/name"
    assert l_r_json["sub_event"][0]["body_schema_error_location"] == "#/name"
    # ------------------------------------------------------
    # pass
    # ------------------------------------------------------
    l_data = {'name': 'Bob Bobberson', 'Employee_ID':2374}
    l_r = requests.get(l_uri, headers=l_headers, json=l_data)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json["status"] == "ok"
    # ------------------------------------------------------
    # key val exceeds max
    # ------------------------------------------------------
    l_data = {'name': 'Bob Bobberson', 'Employee_ID':264346}
    l_r = requests.get(l_uri, headers=l_headers, json=l_data)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json["rule_msg"] == "Request JSON Schema Validation Error"
    assert l_r_json["sub_event"][0]["rule_msg"] == "maximum"
    assert l_r_json["sub_event"][0]["rule_id"] == 900102
    assert l_r_json["api_gw_config_id"] == "nif70s89"
    assert l_r_json["schema_config_id"] == "W9057Zkg"
    assert l_r_json["sub_event"][0]["schema_error_location"] == "#/properties/Employee_ID"
    assert l_r_json["sub_event"][0]["body_schema_error_location"] == "#/Employee_ID"
    # ------------------------------------------------------
    # Parse error
    # ------------------------------------------------------
    l_data = "{\"name\": \"Bob Bobberson\", \"Employee_ID\":23"
    l_r = requests.get(l_uri, headers=l_headers, data=l_data)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json["rule_msg"] == "Request JSON Schema Parsing Error"
    assert l_r_json["sub_event"][0]["rule_id"] == 90006
    assert l_r_json["api_gw_config_id"] == "nif70s89"
    assert l_r_json["schema_config_id"] == "W9057Zkg"
    # ------------------------------------------------------
    # Parse error (Key Error)
    # ------------------------------------------------------
    l_data = "{\"name\": \"Bob Bobberson, \"Employee_ID\":23"
    l_r = requests.get(l_uri, headers=l_headers, data=l_data)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json["rule_msg"] == "Request JSON Schema Parsing Error"
    assert l_r_json["sub_event"][0]["rule_id"] == 90001
    assert l_r_json["api_gw_config_id"] == "nif70s89"
    assert l_r_json["schema_config_id"] == "W9057Zkg"
    # ------------------------------------------------------
    # Pass
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/bananas.html'
    l_data = "{\"message\": \"success\",\"iss_position\": {\"longitude\": \"-128.7452\",\"latitude\": \"37.0598\"},\"timestamp\": 1666214982}"
    l_r = requests.get(l_uri, headers=l_headers, data=l_data)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json["status"] == "ok"
    # ------------------------------------------------------
    # Missing required field
    # ------------------------------------------------------
    l_data = "{\"message\": \"success\"}"
    l_r = requests.get(l_uri, headers=l_headers, data=l_data)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json["rule_msg"] == "Request JSON Schema Validation Error"
    assert l_r_json["sub_event"][0]["rule_msg"] == "required"
    assert l_r_json["sub_event"][0]["rule_id"] == 900115
    assert l_r_json["api_gw_config_id"] == "nif70s89"
    assert l_r_json["schema_config_id"] == "D58gMFTz"
    assert l_r_json["sub_event"][0]["schema_error_location"] == "#"
    assert l_r_json["sub_event"][0]["body_schema_error_location"] == "#"
    # ------------------------------------------------------
    # key val exceeds max
    # ------------------------------------------------------
    l_data = {'name': 'Bob Bobberson', 'Employee_ID':23274}
    l_uri = G_TEST_HOST+'/monkey/bananas.html'
    l_r = requests.get(l_uri, headers=l_headers, json=l_data)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json["rule_msg"] == "Request JSON Schema Validation Error"
    assert l_r_json["sub_event"][0]["rule_msg"] == "maximum"
    assert l_r_json["sub_event"][0]["rule_id"] == 900102
    assert l_r_json["api_gw_config_id"] == "nif70s89"
    assert l_r_json["schema_config_id"] == "W9057Zkg"
    assert l_r_json["sub_event"][0]["schema_error_location"] == "#/properties/Employee_ID"
    assert l_r_json["sub_event"][0]["body_schema_error_location"] == "#/Employee_ID"
    # ------------------------------------------------------
    # Doesn't match any, so should pass
    # ------------------------------------------------------
    l_data = {'name': 'Bob Bobberson', 'Employee_ID':23274}
    l_uri = G_TEST_HOST+'/cool.html'
    l_r = requests.get(l_uri, headers=l_headers, json=l_data)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json["status"] == "ok"

# ----------------------------------------------------------
# test rqst in api_gw config
# ----------------------------------------------------------
def test_api_gw_response(setup_waflz_server_api_gw_mode):
    # ------------------------------------------------------
    # type error
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'myapigw.com',
                 'Content-Type': 'application/json'}
    l_data = {'name': 1}
    l_r = requests.get(l_uri, headers=l_headers, json=l_data)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json["rule_msg"] == "Request JSON Schema Validation Error"
    assert l_r_json["sub_event"][0]["rule_msg"] == "type"
    assert l_r_json["sub_event"][0]["rule_id"] == 900118
    assert l_r_json["api_gw_config_id"] == "nif70s89"
    assert l_r_json["schema_config_id"] == "W9057Zkg"
    assert l_r_json["sub_event"][0]["schema_error_location"] == "#/properties/name"
    assert l_r_json["sub_event"][0]["body_schema_error_location"] == "#/name"
    # ------------------------------------------------------
    # pass
    # ------------------------------------------------------
    l_data = {'name': 'Bob Bobberson', 'Employee_ID':2374}
    l_r = requests.get(l_uri, headers=l_headers, json=l_data)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json["status"] == "ok"
    # ------------------------------------------------------
    # key val exceeds max
    # ------------------------------------------------------
    l_data = {'name': 'Bob Bobberson', 'Employee_ID':264346}
    l_r = requests.get(l_uri, headers=l_headers, json=l_data)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json["rule_msg"] == "Request JSON Schema Validation Error"
    assert l_r_json["sub_event"][0]["rule_msg"] == "maximum"
    assert l_r_json["sub_event"][0]["rule_id"] == 900102
    assert l_r_json["api_gw_config_id"] == "nif70s89"
    assert l_r_json["schema_config_id"] == "W9057Zkg"
    assert l_r_json["sub_event"][0]["schema_error_location"] == "#/properties/Employee_ID"
    assert l_r_json["sub_event"][0]["body_schema_error_location"] == "#/Employee_ID"
    # ------------------------------------------------------
    # Parse error
    # ------------------------------------------------------
    l_data = "{\"name\": \"Bob Bobberson\", \"Employee_ID\":23"
    l_r = requests.get(l_uri, headers=l_headers, data=l_data)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json["rule_msg"] == "Request JSON Schema Parsing Error"
    assert l_r_json["sub_event"][0]["rule_id"] == 90006
    assert l_r_json["api_gw_config_id"] == "nif70s89"
    assert l_r_json["schema_config_id"] == "W9057Zkg"
    # ------------------------------------------------------
    # Parse error (Key Error)
    # ------------------------------------------------------
    l_data = "{\"name\": \"Bob Bobberson, \"Employee_ID\":23"
    l_r = requests.get(l_uri, headers=l_headers, data=l_data)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json["rule_msg"] == "Request JSON Schema Parsing Error"
    l_r_json["sub_event"][0]["rule_id"] == 90001
    assert l_r_json["api_gw_config_id"] == "nif70s89"
    assert l_r_json["schema_config_id"] == "W9057Zkg"
    # ------------------------------------------------------
    # Pass
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/bananas.html'
    l_data = "{\"message\": \"success\",\"iss_position\": {\"longitude\": \"-128.7452\",\"latitude\": \"37.0598\"},\"timestamp\": 1666214982}"
    l_r = requests.get(l_uri, headers=l_headers, data=l_data)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json["status"] == "ok"
    # ------------------------------------------------------
    # Missing required field
    # ------------------------------------------------------
    l_data = "{\"message\": \"success\"}"
    l_r = requests.get(l_uri, headers=l_headers, data=l_data)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json["rule_msg"] == "Request JSON Schema Validation Error"
    assert l_r_json["sub_event"][0]["rule_msg"] == "required"
    assert l_r_json["sub_event"][0]["rule_id"] == 900115
    assert l_r_json["api_gw_config_id"] == "nif70s89"
    assert l_r_json["schema_config_id"] == "D58gMFTz"
    assert l_r_json["sub_event"][0]["schema_error_location"] == "#"
    # ------------------------------------------------------
    # key val exceeds max
    # ------------------------------------------------------
    l_data = {'name': 'Bob Bobberson', 'Employee_ID':23274}
    l_uri = G_TEST_HOST+'/monkey/bananas.html'
    l_r = requests.get(l_uri, headers=l_headers, json=l_data)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json["rule_msg"] == "Request JSON Schema Validation Error"
    assert l_r_json["sub_event"][0]["rule_msg"] == "maximum"
    assert l_r_json["sub_event"][0]["rule_id"] == 900102
    assert l_r_json["api_gw_config_id"] == "nif70s89"
    assert l_r_json["schema_config_id"] == "W9057Zkg"
    assert l_r_json["sub_event"][0]["schema_error_location"] == "#/properties/Employee_ID"
    assert l_r_json["sub_event"][0]["body_schema_error_location"] == "#/Employee_ID"
    # ------------------------------------------------------
    # Doesn't match any, so should pass
    # ------------------------------------------------------
    l_data = {'name': 'Bob Bobberson', 'Employee_ID':23274}
    l_uri = G_TEST_HOST+'/cool.html'
    l_r = requests.get(l_uri, headers=l_headers, json=l_data)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json["status"] == "ok"

def test_bb_jwt_expired_token(setup_waflz_server_api_gw_mode):
    # ------------------------------------------------------
    #  test with expired token
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/jwt-test.html'
    l_headers = {'host': 'myapigw.com',
                 'Content-Type': 'application/json',
                 'Authorization': 'Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjE3NEVGQ0EzOTIzQjI1MTYzRjU4MUEwQ0I3MUNBRDk3QjAzNkUwQjgiLCJ0eXAiOiJKV1QiLCJ4NXQiOiJGMDc4bzVJN0pSWV9XQm9NdHh5dGw3QTI0TGcifQ.eyJuYmYiOjE2OTQ2MzU3MTAsImV4cCI6MTY5NDcyMjExMCwiaXNzIjoiaHR0cHM6Ly9pZC52ZG1zLmlvIiwiYXVkIjpbIldBRiIsImVjLndhZi5jYXMiLCJodHRwczovL2lkLnZkbXMuaW8vcmVzb3VyY2VzIl0sImNsaWVudF9pZCI6IjM0MmU0YzNmLTFkNzYtNGQzOC1hZWZlLWE1MTFlODM3ZWU3MyIsImNsaWVudF90ZW5hbnRfaWQiOiI4MWVjMTdmNC0wNjIyLTQzYmItODRkMy1iZGM4NWM2OGM2OWUiLCJqdGkiOiI0RDc0RTY3MTcxNzJCRTA4MDNFQkQ5REEwNEQ2REQ4QiIsImlhdCI6MTY5NDYzNTcxMCwic2NvcGUiOlsiZWMud2FmIl19.BK7k2lc_eRLdYG4C1HI8h-6tAObZvCnlhLZftB_SwJDygo7_W9ja3lQMo7F8JE6XLduVGrgDzoOWMIHTSdd-_HP0N1j1DZnwZGpJZJPRfWhcN1BkTHYTVOjKajgd6P93FWCUwWzvzUiCFL8TvU4VOC9UaLSDtBXw4MU1fU80U0koRjLczf84UxzX8yW1ziEflK2uwNb7Lhb317F4vVdEtpt4cPjbPtVytxBZO0ehUZUTI6hkLE91D40mwlmtoFrWwQAj5LOO31CdmGW9qMAz0B-r0bIMdO8mEeTbT2sEQKibNum3d5b1j8uaBPWlC4DWc_4u_nn8ZR563u7Wj8e62Q'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json["rule_msg"] == "JWT validation error"
    assert l_r_json["jwt_error_reason"] == "token expired"
    assert l_r_json["jwt_failed_kid"] == "174EFCA3923B25163F581A0CB71CAD97B036E0B8"
    assert l_r_json["api_gw_rule_name"] == "JWT config"

def test_bb_jwt_missing_token(setup_waflz_server_api_gw_mode):
    # ------------------------------------------------------
    # send request without token
    # ------------------------------------------------------
    l_r = requests.get(
        f"{G_TEST_HOST}/jwt-test.html",
        headers={
            'host': 'myapigw.com',
            'Content-Type': 'application/json'
        }
    )
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # assert we were blocked because we dont allow missing
    # tokens.
    # ------------------------------------------------------
    l_r_json = l_r.json()
    assert l_r_json["rule_msg"] == "JWT validation error"
    assert l_r_json["jwt_error_reason"] == "Authorization header missing"
    assert l_r_json["api_gw_rule_name"] == "JWT config"

def test_bb_jwt_missing_bearer(setup_waflz_server_api_gw_mode):
    # ------------------------------------------------------
    # send request without token
    # ------------------------------------------------------
    l_r = requests.get(
        f"{G_TEST_HOST}/jwt-test.html",
        headers={
            'host': 'myapigw.com',
            'Content-Type': 'application/json',
            'Authorization': 'blah blah blah'
        }
    )
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # assert we were blocked because we are missing the
    # 'bearer' scheme
    # ------------------------------------------------------
    l_r_json = l_r.json()
    assert l_r_json["rule_msg"] == "JWT validation error"
    assert l_r_json["jwt_error_reason"] == "Authorization header doesn't have Bearer scheme"
    assert l_r_json["api_gw_rule_name"] == "JWT config"

def test_bb_jwt_bogus_token(setup_waflz_server_api_gw_mode):
    # ------------------------------------------------------
    # test with bogus token..changed characters in the token
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/jwt-test.html'
    l_headers = {'host': 'myapigw.com',
                 'Content-Type': 'application/json',
                 'Authorization': 'Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjE3NEVGQ0EzOTIzQjI1MTYzRjU4MUEwQ0I3MUNBRDk3QjAzNkUwQjgiLCJ0eXAiOiJKV1QiLCJ4NXQiOiJGMDc4bzVJN0pSWV9XQm9NdHh5dGw3QTI0TGcifQ.eyJuYmYiOjE2OTU0MDczNjYsImV4cCI6MTY5NTQ5Mzc2NiwiaXNzIjoiaHR0cHM6Ly9pZC52ZG1zLmlvIiwiYXVkIjpbIldBRiIsImVjLndhZi5jYXMiLCJodHRwczovL2lkLnZkbXMuaW8vcmVzb3VyY2VzIl0sImNsaWVudF9pZCI6IjM0MmU0YzNmLTFkNzYtNGQzOC1hZWZlLWE1MTFlODM3ZWU3MyIsImNsaWVudF90ZW5hbnRfaWQiOiI4MWVjMTdmNC0wNjIyLTQzYmItODRkMy1iZGM4NWM2OGM2OWUiLCJqdGkiOiI2NjA3MjdBQjU2M0NBRTkwQjdDRjAxQTZFNjJFMDIyNiIsImlhdCI6MTY5NTQwNzM2Niwic2NvcGUiOlsiZWMud2FmIl19.O6jt801rys0e53RopmV1l04ZtkLrv0B0sCCY6rWju_5Ss1HkoPYp3ZODHHg2j7Yau29UwicS0dnsprJ4FR5u7reoCnhTPJvo7YmChItIv-CpYWN2hQtqrOoMaBxd4mmNYzwtG2THho9f4NlvT2hg8X7RmLPD5sF-xrkIuwwthplY6pnlUVrFHUD80yknznfR3d0qLCJTNF7w4J1f4Zbmgj4IyWHyXntNxB9zN9RLxB5YmFPQi3OI7e3tz4T8TRf43E8oXZ-Bfhq8g8N33C3HOL-IcSp0vkbbJzgRVMBF9uS93ni'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json["rule_msg"] == "JWT validation error"
    assert l_r_json["jwt_error_reason"] == "failed to verify signature: VerifyFinal failed"
    assert l_r_json["jwt_failed_kid"] == "174EFCA3923B25163F581A0CB71CAD97B036E0B8"
    assert l_r_json["api_gw_rule_name"] == "JWT config"

