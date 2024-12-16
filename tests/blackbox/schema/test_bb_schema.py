#!/usr/bin/env python3
'''Test schema mode'''
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
# setup waflz server in schema mode
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_waflz_server_schema_mode():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_cwd = os.getcwd()
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_waflz_server_path = os.path.abspath(os.path.join(l_file_path, '../../../build/util/waflz_server/waflz_server'))
    l_schema_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/api_schema/0050-W9057Zkg.api_schema.json'))
    l_subproc = subprocess.Popen([l_waflz_server_path,
                                  '-S', l_schema_path])
    time.sleep(1)
    print('cmd: \n{}\n'.format(' '.join([l_waflz_server_path,
                                  '-S', l_schema_path])))
    # ------------------------------------------------------
    # yield...
    # ------------------------------------------------------
    yield setup_waflz_server_schema_mode
    # ------------------------------------------------------
    # tear down
    # ------------------------------------------------------
    l_code, l_out, l_err = run_command('kill -9 %d'%(l_subproc.pid))
    time.sleep(0.5)
# ----------------------------------------------------------
# test rqst against api schema config
# ----------------------------------------------------------
def test_api_schema(setup_waflz_server_schema_mode):
    # ------------------------------------------------------
    # type error
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'myapigw.com',
                 'Content-Type': 'application/json'}
    l_data = "{\"favorite_numbers\": [1,2,\"bananas\"]}"
    l_r = requests.get(l_uri, headers=l_headers, data=l_data)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json["rule_msg"] == "JSON Schema Validation Error"
    assert l_r_json["sub_event"][0]["rule_msg"] == "type"
    assert l_r_json["sub_event"][0]["rule_id"] == 900118
    assert l_r_json["sub_event"][0]["schema_error_location"] == \
        "#/properties/favorite_numbers/items"
    assert l_r_json["sub_event"][0]["body_schema_error_location"] == \
        "#/favorite_numbers/2"
    # ------------------------------------------------------
    # pass
    # ------------------------------------------------------
    l_data = "{\"favorite_numbers\":[]}"
    l_r = requests.get(l_uri, headers=l_headers, data=l_data)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json["rule_msg"] == "JSON Schema Validation Error"
    assert l_r_json["sub_event"][0]["rule_msg"] == "minItems"
    assert l_r_json["sub_event"][0]["rule_id"] == 900110
    assert l_r_json["sub_event"][0]["schema_error_location"] == \
        "#/properties/favorite_numbers"
    assert l_r_json["sub_event"][0]["body_schema_error_location"] == \
        "#/favorite_numbers"
    # ------------------------------------------------------
    # key val exceeds max
    # ------------------------------------------------------
    l_data = {'favorite_numbers':[1,1]}
    l_r = requests.get(l_uri, headers=l_headers, json=l_data)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json["rule_msg"] == "JSON Schema Validation Error"
    assert l_r_json["sub_event"][0]["rule_msg"] == "uniqueItems"
    assert l_r_json["sub_event"][0]["rule_id"] == 900111
    assert l_r_json["sub_event"][0]["schema_error_location"] == \
        "#/properties/favorite_numbers"
    assert l_r_json["sub_event"][0]["body_schema_error_location"] == \
        "#/favorite_numbers/1"
    # ------------------------------------------------------
    # Parse error
    # ------------------------------------------------------
    l_data = "{\"name\": \"Bob Bobberson\", \"Employee_ID\": }"
    l_r = requests.get(l_uri, headers=l_headers, data=l_data)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json["rule_msg"] == "JSON Schema Parsing Error"
    assert l_r_json["sub_event"][0]["rule_id"] == 90001
    # ------------------------------------------------------
    # key val exceeds max
    # ------------------------------------------------------
    l_data = {'name': 'Bob Bobberson', 'Employee_ID':-1}
    l_uri = G_TEST_HOST+'/monkey/bananas.html'
    l_r = requests.get(l_uri, headers=l_headers, json=l_data)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json["rule_msg"] == "JSON Schema Validation Error"
    assert l_r_json["sub_event"][0]["rule_msg"] == "minimum"
    assert l_r_json["sub_event"][0]["rule_id"] == 900104
    assert l_r_json["sub_event"][0]["schema_error_location"] == \
        "#/properties/Employee_ID"
    assert l_r_json["sub_event"][0]["body_schema_error_location"] == \
        "#/Employee_ID"

