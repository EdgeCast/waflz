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
# ------------------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------------------
G_TEST_HOST = 'http://127.0.0.1:12345/'
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
@pytest.fixture
def setup_waflz_server():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_cwd = os.getcwd()
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_ruleset_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/ruleset'))
    l_geoip2city_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-City.mmdb'))
    l_geoip2ISP_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-ASN.mmdb'))
    l_profile_path = os.path.realpath(os.path.join(l_file_path, 'test_bb_rules.waf.prof.json'))
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
# fixture
# ------------------------------------------------------------------------------
@pytest.fixture
def setup_waflz_server_rules():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_cwd = os.getcwd()
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_rules_path = os.path.realpath(os.path.join(l_file_path, 'test_bb_ua.rules.json'))
    l_geoip2city_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-City.mmdb'))
    l_geoip2ISP_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-ASN.mmdb'))
    l_waflz_server_path = os.path.abspath(os.path.join(l_file_path, '../../../build/util/waflz_server/waflz_server'))
    l_subproc = subprocess.Popen([l_waflz_server_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path,
                                  '-e', l_rules_path])
    time.sleep(1)
    # ------------------------------------------------------
    # yield...
    # ------------------------------------------------------
    yield setup_waflz_server_rules
    # ------------------------------------------------------
    # tear down
    # ------------------------------------------------------
    l_code, l_out, l_err = run_command('kill -9 %d'%(l_subproc.pid))
    time.sleep(0.5)
# ------------------------------------------------------------------------------
# test_bb_without_rule_target_update_fail
# ------------------------------------------------------------------------------
def test_bb_without_rule_target_update_fail(setup_waflz_server):
    l_uri = G_TEST_HOST + '?' + 'origin=Mal%C3%A9&destination=Southeast+Asia&marketcode=MLESEA&countrycode=MV'
    l_headers = {'host': 'myhost.com'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    # print json.dumps(l_r_json,indent=4)
    assert l_r_json['rule_intercept_status'] == 403
    assert 'UTF8 Encoding Abuse Attack Attempt' in l_r_json['sub_event'][0]['rule_msg']
    l_conf = {}
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_conf_path = os.path.realpath(os.path.join(l_file_path, 'test_bb_rules.waf.prof.json'))
    try:
        with open(l_conf_path) as l_f:
            l_conf = json.load(l_f)
    except Exception as l_e:
        print('error opening config file: %s.  Reason: %s error: %s, doc: %s' % (
            l_conf_path, type(l_e), l_e, l_e.__doc__))
        assert False
    #-------------------------------------------------------
    # Add a rule target update
    # ------------------------------------------------------
    l_conf['rule_target_updates'] = [
        {
            'replace_target': '',
            'rule_id': '920250',
            'is_regex': False,
            'is_negated': True,
            'target_match': 'origin',
            'target': 'ARGS'
        }]
    # ------------------------------------------------------
    # post conf
    # ------------------------------------------------------
    l_url = '%supdate_profile' % (G_TEST_HOST)
    # ------------------------------------------------------
    # urlopen (POST)
    # ------------------------------------------------------
    l_headers = {'Content-Type': 'application/json'}
    l_r = requests.post(l_url,
                        headers=l_headers,
                        data=json.dumps(l_conf))
    assert l_r.status_code == 200
    #-------------------------------------------------------
    # GET the same uri which returned a 403 before RTU
    # ------------------------------------------------------
    l_headers = {'host': 'myhost.com'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    #-------------------------------------------------------
    # check no event is returned
    # ------------------------------------------------------
    assert 'status' in l_r_json
    assert l_r_json['status'] == 'ok'
# ------------------------------------------------------------------------------
# test_bb_without_rule_target_update_fail
# ------------------------------------------------------------------------------
def test_bb_rule_target_update_xml_var(setup_waflz_server):
    l_uri = G_TEST_HOST
    l_headers = {'host': 'myhost.com',
                 'Content-Type': 'text/xml'}
    l_body = '<abc>s-guide-for-e2-refrigeration-bx-hvac-cx-convenience-store-controllers-en-5375988.pdf</abc>'
    l_r = requests.post(l_uri,
                        headers=l_headers,
                        data=l_body)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    #print(json.dumps(l_r_json,indent=4))
    assert l_r_json['rule_intercept_status'] == 403
    assert 'Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (12)' in l_r_json['sub_event'][0]['rule_msg']
    assert l_r_json['sub_event'][0]['matched_var']['name'] == 'WE1MOi8q'
    l_conf = {}
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_conf_path = os.path.realpath(os.path.join(l_file_path, 'test_bb_rules.waf.prof.json'))
    try:
        with open(l_conf_path) as l_f:
            l_conf = json.load(l_f)
    except Exception as l_e:
        print('error opening config file: %s.  Reason: %s error: %s, doc: %s' % (
            l_conf_path, type(l_e), l_e, l_e.__doc__))
        assert False
    #-------------------------------------------------------
    # Add a rule target update
    # ------------------------------------------------------
    l_conf['rule_target_updates'] = [
        {
            'replace_target': '',
            'rule_id': '942430',
            'is_regex': False,
            'is_negated': True,
            'target_match': '/*',
            'target': 'XML'
        }]
    # ------------------------------------------------------
    # post conf
    # ------------------------------------------------------
    l_url = '%supdate_profile'%(G_TEST_HOST)
    # ------------------------------------------------------
    # urlopen (POST)
    # ------------------------------------------------------
    l_headers = {'Content-Type': 'application/json'}
    l_r = requests.post(l_url,
                        headers=l_headers,
                        data=json.dumps(l_conf))
    assert l_r.status_code == 200
    #-------------------------------------------------------
    # GET the same uri which returned a 403 before RTU
    # ------------------------------------------------------
    l_headers = {'host': 'myhost.com',
                 'Content-Type' : 'text/xml'}
    l_body = '<abc>s-guide-for-e2-refrigeration-bx-hvac-cx-convenience-store-controllers-en-5375988.pdf</abc>'
    l_r = requests.post(l_uri,
                        headers=l_headers,
                        data=l_body)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    #-------------------------------------------------------
    # check no event is returned
    # ------------------------------------------------------
    assert 'status' in l_r_json
    assert l_r_json['status'] == 'ok'
# ------------------------------------------------------------------------------
# test_bb_without_rule_target_update_fail
# ------------------------------------------------------------------------------
def test_bb_custom_rule_sd_iso(setup_waflz_server_rules):
    l_uri = G_TEST_HOST
    l_headers = {
        'Host': 'example.com',
        'x-waflz-ip': '188.31.121.90'
    }
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    #print(json.dumps(l_r_json,indent=4))
    assert l_r_json['rule_intercept_status'] == 403
    assert 'Request SD_ISO Comes from GB' in l_r_json['rule_msg']
    assert '2020-10-06T18:18:09.329793Z' in l_r_json['config_last_modified']
# ------------------------------------------------------------------------------
# test_bb_without_rule_target_update_fail
# ------------------------------------------------------------------------------
def test_bb_rule_ua(setup_waflz_server_rules):
    l_uri = G_TEST_HOST
    l_headers = {
        'Host': 'example.com',
        'User-Agent': 'bananas'
    }
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    # print(json.dumps(l_r_json,indent=4))
    assert l_r_json['rule_intercept_status'] == 403
    assert 'Request User-Agent is bananas' in l_r_json['rule_msg']
    assert '2020-10-06T18:18:09.329793Z' in l_r_json['config_last_modified']
# ------------------------------------------------------------------------------
# test_bb_rule_ja3
#
# NOTE: This rule will fire for any request because waflz_server
# returns a static ja3. i make it fire last by putting it in phase 2
# ------------------------------------------------------------------------------
def test_bb_rule_ja3(setup_waflz_server_rules):
    l_uri = G_TEST_HOST
    l_headers = {
        'Host': 'example.com',
    }
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    # print(json.dumps(l_r_json,indent=4))
    assert l_r_json['rule_intercept_status'] == 403
    assert 'ja3 is fishy' in l_r_json['rule_msg']
    assert '2020-10-06T18:18:09.329793Z' in l_r_json['config_last_modified']
# ------------------------------------------------------------------------------
# test_bb_rule_ja4
# ------------------------------------------------------------------------------
def test_bb_rule_ja4(setup_waflz_server_rules):
    l_uri = G_TEST_HOST
    l_headers = {
        'Host': 'example.com',
        'x-waflz-ja3': 'wangwangja4',
        'x-waflz-ja4': 't12i1314h2_f57a46bbacb6_3939823b2ae2'
    }
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    # print(json.dumps(l_r_json,indent=4))
    assert l_r_json['rule_intercept_status'] == 403
    assert 'ja4 is fishy' in l_r_json['rule_msg']
    assert '2020-10-06T18:18:09.329793Z' in l_r_json['config_last_modified']
# ------------------------------------------------------------------------------
# test_bb_rule_ja4
# ------------------------------------------------------------------------------
def test_bb_rule_ja4_a(setup_waflz_server_rules):
    l_uri = G_TEST_HOST
    l_headers = {
        'Host': 'example.com',
        'x-waflz-ja3': 'wangwangja4',
        'x-waflz-ja4_a': 't12i1314h2'
    }
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    # print(json.dumps(l_r_json,indent=4))
    assert l_r_json['rule_intercept_status'] == 403
    assert 'ja4_a is fishy' in l_r_json['rule_msg']
    assert '2020-10-06T18:18:09.329793Z' in l_r_json['config_last_modified']
# ------------------------------------------------------------------------------
# test_bb_rule_ja4_b
# ------------------------------------------------------------------------------
def test_bb_rule_ja4_b(setup_waflz_server_rules):
    l_uri = G_TEST_HOST
    l_headers = {
        'Host': 'example.com',
        'x-waflz-ja3': 'wangwangja4',
        'x-waflz-ja4_b': 'f57a46bbacb6'
    }
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    # print(json.dumps(l_r_json,indent=4))
    assert l_r_json['rule_intercept_status'] == 403
    assert 'ja4_b is fishy' in l_r_json['rule_msg']
    assert '2020-10-06T18:18:09.329793Z' in l_r_json['config_last_modified']
# ------------------------------------------------------------------------------
# test_bb_rule_ja4_c
# ------------------------------------------------------------------------------
def test_bb_rule_ja4_c(setup_waflz_server_rules):
    l_uri = G_TEST_HOST
    l_headers = {
        'Host': 'example.com',
        'x-waflz-ja3': 'wangwangja4',
        'x-waflz-ja4_c': '3939823b2ae2'
    }
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    # print(json.dumps(l_r_json,indent=4))
    assert l_r_json['rule_intercept_status'] == 403
    assert 'ja4_c is fishy' in l_r_json['rule_msg']
    assert '2020-10-06T18:18:09.329793Z' in l_r_json['config_last_modified']
# ------------------------------------------------------------------------------
# test_bb_rule_streq_values
# ------------------------------------------------------------------------------
def test_bb_rule_streq_values(setup_waflz_server_rules):
    l_uri = G_TEST_HOST
    l_headers = {
        'Host': 'example.com',
        'User-Agent': 'test3'
    }
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json['rule_intercept_status'] == 403
    assert len(l_r_json['sub_event']) > 0
    assert l_r_json['sub_event'][0]['rule_id'] == 231548
    assert 'Request user-agent found in values' in l_r_json['rule_msg']
# ------------------------------------------------------------------------------
# test_bb_rule_streq_values
# ------------------------------------------------------------------------------
def test_bb_rule_multipart_bodies(setup_waflz_server_rules):
    l_uri = G_TEST_HOST
    l_headers = {
        'Host': 'example.com',
        'User-Agent': 'dev',
        'x-waflz-ja3' : 'wangwangja3',
        'Content-Type': 'multipart/form-data; ------WebKitFormBoundary5WJ61X4PRwyYKlip'
        }

    l_body = """
            {{randstr(4097,4097)}}
            test upload.action
    """
    l_r = requests.post(l_uri, headers=l_headers, data=l_body)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json['rule_intercept_status'] == 403
    assert len(l_r_json['sub_event']) > 0
    assert l_r_json['sub_event'][0]['rule_id'] == 66000201
    assert 'Apache Struts unsafe file upload request (CVE-2023-50164)' in l_r_json['rule_msg']