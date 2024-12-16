#!/usr/bin/env python3
'''Test WAF Access settings'''
#TODO: make so waflz_server only runs once and then can post to it
# ------------------------------------------------------------------------------
# Imports
# ------------------------------------------------------------------------------
import pytest
import subprocess
import os
import sys
import json
import time
import requests
import base64
# ------------------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------------------
G_TEST_HOST = 'http://127.0.0.1:12345/'
# ------------------------------------------------------------------------------
# globals
# ------------------------------------------------------------------------------
g_server_pid = -1
# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
def run_command(command):
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    return (p.returncode, stdout, stderr)
# ------------------------------------------------------------------------------
# fixture
# ------------------------------------------------------------------------------
@pytest.fixture(scope='module')
def setup_waflz_server():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_cwd = os.getcwd()
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_ruleset_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/ruleset'))
    l_geoip2city_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-City.mmdb'))
    l_geoip2ISP_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-ASN.mmdb'))
    l_profile_path = os.path.realpath(os.path.join(l_file_path, 'test_bb_custom_score.waf.prof.json'))
    l_waflz_server_path = os.path.abspath(os.path.join(l_file_path, '../../../build/util/waflz_server/waflz_server'))
    l_subproc = subprocess.Popen([l_waflz_server_path,
                                  '-f', l_profile_path,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path])
    time.sleep(1)
    # ------------------------------------------------------
    # yield...
    # ------------------------------------------------------
    yield setup_waflz_server
    # ------------------------------------------------------
    # tear down
    # ------------------------------------------------------
    l_code, l_out, l_err = run_command('kill -9 %d'%(l_subproc.pid))
    time.sleep(0.5)
# ------------------------------------------------------------------------------
# test_bb_rtu_request_body
# ------------------------------------------------------------------------------
def test_bb_custom_score_request_body(setup_waflz_server):
    # ------------------------------------------------------
    # make suspicious request
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'myhost.com',
                 'Content-Type': 'application/x-www-form-urlencoded',
                 'User-Agent': 'Mozilla'}
    l_body = 'java.io.BufferedInputStream'
    l_r = requests.post(l_uri,
                        headers=l_headers,
                        data=l_body)
    # ------------------------------------------------------
    # assert request worked
    # ------------------------------------------------------
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # assert event fired
    # ------------------------------------------------------
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    # ------------------------------------------------------
    # assert that action was take, and custom score was 
    # applied
    # ------------------------------------------------------
    assert l_r_json['rule_intercept_status'] == 403
    assert 'Suspicious Java class detected' in l_r_json['sub_event'][0]['rule_msg']
    assert l_r_json['sub_event'][0]['total_anomaly_score'] == 100
# ------------------------------------------------------------------------------
# test_bb_rtu_request_body
# ------------------------------------------------------------------------------
def test_bb_multi_custom_score_request_body(setup_waflz_server):
    # ------------------------------------------------------
    # make suspicious request
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'myhost.com',
                 'Content-Type': 'application/x-www-form-urlencoded',
                 'User-Agent': 'Mozilla'}
    l_body = 'runtime:clonetransformer'
    l_r = requests.post(l_uri,
                        headers=l_headers,
                        data=l_body)
    # ------------------------------------------------------
    # assert request worked
    # ------------------------------------------------------
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # assert action was taken
    # ------------------------------------------------------
    l_r_json = l_r.json()
    assert l_r_json['rule_intercept_status'] == 403
    # ------------------------------------------------------
    # assert events fired
    # ------------------------------------------------------
    assert len(l_r_json['sub_event']) == 2
    # ------------------------------------------------------
    # assert rule 944120 fired with custom score of 3
    # ------------------------------------------------------
    assert 944120 == l_r_json['sub_event'][0]['rule_id']
    assert l_r_json['sub_event'][0]['total_anomaly_score'] == 3
    assert 'Remote Command Execution: Java serialization (CVE-2015-4852)' in l_r_json['sub_event'][0]['rule_msg']
    # ------------------------------------------------------
    # assert rule 944240 fired with custom score of 3
    # ------------------------------------------------------
    assert 944240 == l_r_json['sub_event'][1]['rule_id']
    assert l_r_json['sub_event'][0]['total_anomaly_score'] == 3
    assert 'Remote Command Execution: Java serialization (CVE-2015-4852)' in l_r_json['sub_event'][1]['rule_msg']
    # ------------------------------------------------------
    # assert total score is 6
    # ------------------------------------------------------
    assert l_r_json['total_anomaly_score'] == 6
