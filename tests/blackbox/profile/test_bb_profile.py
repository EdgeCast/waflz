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
    print(command)
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
    l_profile_path = os.path.realpath(os.path.join(l_file_path, 'test_bb_profile.waf.prof.json'))
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
# test_bb_profile_01_no_log_matched_data
# ------------------------------------------------------------------------------
def test_bb_profile_01_no_log_matched_data(setup_waflz_server):
    l_uri = G_TEST_HOST + '/?a=%27select%20*%20from%20testing%27'
    l_headers = {'Host': 'myhost.com'}
    l_r = requests.get(url=l_uri,
                        headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    l_matched_var_name = 'ARGS:a'
    l_matched_var_value = '\'select * from testing\''
    assert l_matched_var_name == base64.b64decode(l_r_json['sub_event'][0]['matched_var']['name']).decode("utf-8")
    assert l_matched_var_value == base64.b64decode(l_r_json['sub_event'][0]['matched_var']['value']).decode("utf-8")
    #-------------------------------------------------------
    # create config
    # ------------------------------------------------------
    l_conf = {}
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_conf_path = os.path.realpath(os.path.join(l_file_path, 'test_bb_profile.waf.prof.json'))
    try:
        with open(l_conf_path) as l_f:
            l_conf = json.load(l_f)
    except Exception as l_e:
        print('error opening config file: %s.  Reason: %s error: %s, doc: %s' % (
            l_conf_path, type(l_e), l_e, l_e.__doc__))
        assert False
    #-------------------------------------------------------
    # Update profile to not log matched data value
    # ------------------------------------------------------
    l_conf['general_settings']['no_log_matched'] = True
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
    # ------------------------------------------------------
    # test again verify that matched data value is scrubbed
    # ------------------------------------------------------
    l_headers = {'Host': 'myhost.com'}
    l_r = requests.get(url=l_uri,
                        headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    assert l_matched_var_name == base64.b64decode(l_r_json['sub_event'][0]['matched_var']['name']).decode("utf-8")
    assert '**SANITIZED**' == base64.b64decode(l_r_json['sub_event'][0]['matched_var']['value']).decode("utf-8")
    assert '2022-05-7T19:48:25.142172Z' == l_r_json['config_last_modified']
    #-------------------------------------------------------
    # reset config back to before test state
    # ------------------------------------------------------
    l_conf['general_settings']['no_log_matched'] = False
    l_headers = {'Content-Type': 'application/json'}
    l_r = requests.post(l_url,
                        headers=l_headers,
                        data=json.dumps(l_conf))
    assert l_r.status_code == 200
# ------------------------------------------------------------------------------
# test if recaptcha cookie is not firing an alert
# ------------------------------------------------------------------------------
def test_bb_profile_02_ec_recaptcha_cookie(setup_waflz_server):
    l_uri = G_TEST_HOST + '/test.html'
    l_g_token = "03AEkXODAXXQZDIorggQl9PptE2p6VNVgbGNvidcfLA25RFZZ5i1f1XKYFPANznmNQoRpDbEyNxUs3LbPMFEViRkZ0NVyfHwC5Cwyt7CjbAbGicc3tubCo0kVLXRg4JpQVxdnLl4L3tO_VrKCrFhG1y9pp8qPQX5X26FrZlriiNnNvJe8l_hHpgY5iynyw1R6LoNf2K_pE33Zk5V_WjBRkqveH3yJZPdHmmDWfasGB4DlmjB5qYdqp9BHW_L_rdWO4KBR1iQXjBDtmNIaZDrb-lh6ETmTuiS3wM32i61TE6Gk50S5e2z-gdyag8SaAv7Q3aC_BCmljPqaYDQlNVpPWLXhMpFv1OHPuQbenAxc8_Vc4OUzaF9QT7pFkhd--vubqScrEAGL9NiRni6q5XXkzf5qddSbrJA3B2os-tal91h2FuiFZFuwnKUDuc3j7Xh24KWP--DEwyz7HKtieYLXsJRH-Nsoyl_h7qbrdSeyrAh7_dtrtNhAOKNfdVTVB25PHLR3kzqm9zEgdLw41mrAbJUjDeUKR5F2YcxLtT0ZQwkuKwUWLNSHiL44"
    l_site_cookie = "__ecreha__="+l_g_token
    l_headers = {'Host': 'myhost.com',
                 'Cookie': l_site_cookie}
    l_r = requests.get(url=l_uri,
                        headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json['status'] == 'ok'
# ------------------------------------------------------------------------------
# test_bb_profile_with_redacted_vars
# ------------------------------------------------------------------------------
def test_bb_profile_with_redacted_vars(setup_waflz_server):
    #-------------------------------------------------------
    # test normal state
    # ------------------------------------------------------
    l_uri = G_TEST_HOST + '/?a=%27select%20*%20from%20testing%27'
    l_headers = {'Host': 'myhost.com'}
    l_r = requests.get(url=l_uri,
                        headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    l_matched_var_name = 'ARGS:a'
    l_matched_var_value = '\'select * from testing\''
    assert l_matched_var_name == base64.b64decode(l_r_json['sub_event'][0]['matched_var']['name']).decode("utf-8")
    assert l_matched_var_value == base64.b64decode(l_r_json['sub_event'][0]['matched_var']['value']).decode("utf-8")
    #-------------------------------------------------------
    # create config
    # ------------------------------------------------------
    l_conf = {}
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_conf_path = os.path.realpath(os.path.join(l_file_path, 'test_bb_profile.waf.prof.json'))
    try:
        with open(l_conf_path) as l_f:
            l_conf = json.load(l_f)
    except Exception as l_e:
        print('error opening config file: %s.  Reason: %s error: %s, doc: %s' % (
            l_conf_path, type(l_e), l_e, l_e.__doc__))
        assert False
    #-------------------------------------------------------
    # Update profile redact any variable that comes from
    # args and starts with a
    # ------------------------------------------------------
    l_conf['redacted_variables'] = [
        {
            "match_on": "ARGS:a.*",
            "replacement_value": "<REPLACED!>"
        },
        {
            "match_on": ".*blank.*",
            "replacement_name": "<NAME_REPLACED>",
            "replacement_value": ""
        },
        {
            "match_on": "MATCHED_VAR:MATCHED_VAR",
            "replacement_value": "<CHAIN_IS_BROKEN!>"
        },

    ]
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
    # ------------------------------------------------------
    # test again verify that matched data value is scrubbed
    # ------------------------------------------------------
    l_headers = {'Host': 'myhost.com'}
    l_r = requests.get(url=l_uri,
                        headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    assert l_matched_var_name == base64.b64decode(l_r_json['sub_event'][0]['matched_var']['name']).decode("utf-8")
    assert '<REPLACED!>' == base64.b64decode(l_r_json['sub_event'][0]['matched_var']['value']).decode("utf-8")
    # ------------------------------------------------------
    # test again with a args that should not match the regex
    # ------------------------------------------------------
    l_matched_var_name = 'ARGS:b'
    l_matched_var_value = '\'select * from testing\''
    l_uri = G_TEST_HOST + '/?b=%27select%20*%20from%20testing%27'
    l_r = requests.get(url=l_uri,
                        headers=l_headers)
    l_r_json = l_r.json()
    assert l_matched_var_name == base64.b64decode(l_r_json['sub_event'][0]['matched_var']['name']).decode("utf-8")
    assert l_matched_var_value == base64.b64decode(l_r_json['sub_event'][0]['matched_var']['value']).decode("utf-8")
    # ------------------------------------------------------
    # test again with a args that should match the regex
    # ------------------------------------------------------
    l_matched_var_name = 'ARGS:abdwiajdo'
    l_matched_var_value = '<REPLACED!>'
    l_uri = G_TEST_HOST + '/?abdwiajdo=%27select%20*%20from%20testing%27'
    l_r = requests.get(url=l_uri,
                        headers=l_headers)
    l_r_json = l_r.json()
    assert l_matched_var_name == base64.b64decode(l_r_json['sub_event'][0]['matched_var']['name']).decode("utf-8")
    assert l_matched_var_value == base64.b64decode(l_r_json['sub_event'][0]['matched_var']['value']).decode("utf-8")
    # ------------------------------------------------------
    # test again with a empty replace value
    # ------------------------------------------------------
    l_matched_var_name = '<NAME_REPLACED>'
    l_matched_var_value = ''
    l_uri = G_TEST_HOST + '/?should_be_blank=%27select%20*%20from%20testing%27'
    l_r = requests.get(url=l_uri,
                        headers=l_headers)
    l_r_json = l_r.json()
    assert l_matched_var_name == base64.b64decode(l_r_json['sub_event'][0]['matched_var']['name']).decode("utf-8")
    assert l_matched_var_value == base64.b64decode(l_r_json['sub_event'][0]['matched_var']['value']).decode("utf-8")
    # ------------------------------------------------------
    # test again with chain rule
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'myhost.com',
                 'Cookie': 'mycookie=true|c|-1|easyweb|-|1607356144310|554290487_890|https://mysite.com/waw/brk/wb/wbr/static/main/index.html|webbroker - order status|1607356081298|/page/trading/order-status?accountid=uass7j-9elpoiabja6eykgubinbzfbh1b2hw2zbetqs=',
                 'User-Agent': 'Mozilla'}
    l_r = requests.get(l_uri,
                        headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    assert l_r_json['rule_intercept_status'] == 403
    assert base64.b64decode(l_r_json['sub_event'][0]['matched_var']['name']).decode("utf-8") == 'MATCHED_VAR:MATCHED_VAR'
    assert base64.b64decode(l_r_json['sub_event'][0]['matched_var']['value']).decode("utf-8") == '<CHAIN_IS_BROKEN!>'
    #-------------------------------------------------------
    # reset config back to before test state
    # ------------------------------------------------------
    del l_conf['redacted_variables']
    l_headers = {'Content-Type': 'application/json'}
    l_r = requests.post(l_url,
                        headers=l_headers,
                        data=json.dumps(l_conf))
    assert l_r.status_code == 200
