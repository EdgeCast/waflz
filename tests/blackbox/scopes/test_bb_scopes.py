#!/usr/bin/env python3
'''Test scopes with custom rules'''
# ------------------------------------------------------------------------------
# imports
# ------------------------------------------------------------------------------
import pytest
import subprocess
import os
import sys
import json
import time
import requests
import datetime
import base64
import time
# ------------------------------------------------------------------------------
# constants
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
# setup scopez server with scopes dir
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_waflz_server():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_cwd = os.getcwd()
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_scopez_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/scopes'))
    l_conf_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf'))
    l_ruleset_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/ruleset'))
    l_geoip2city_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-City.mmdb'))
    l_geoip2ISP_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-ASN.mmdb'))
    l_bot_info_file = os.path.realpath(os.path.join(l_file_path, '../../data/bot/known_bot_info.json'))
    l_waflz_server_path = os.path.abspath(os.path.join(l_file_path, '../../../build/util/waflz_server/waflz_server'))
    l_subproc = subprocess.Popen([l_waflz_server_path,
                                  '-d', l_conf_dir,
                                  '-b', l_scopez_dir,
                                  '-r', l_ruleset_path,
                                  '-Q', l_bot_info_file,
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
# setup scopez server with single scope for an 0050
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_waflz_server_single():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_cwd = os.getcwd()
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_geoip2city_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-City.mmdb'))
    l_geoip2ISP_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-ASN.mmdb'))
    l_conf_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf'))
    l_ruleset_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/ruleset'))
    l_scopez_file = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/scopes/0050.scopes.json'))
    l_waflz_server_path = os.path.abspath(os.path.join(l_file_path, '../../../build/util/waflz_server/waflz_server'))
    l_subproc = subprocess.Popen([l_waflz_server_path,
                                  '-d', l_conf_dir,
                                  '-b', l_scopez_file,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path])
    print('cmd: {}'.format(' '.join([l_waflz_server_path,
                                  '-d', l_conf_dir,
                                  '-b', l_scopez_file,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path])))
    time.sleep(1)
    # ------------------------------------------------------
    # yield...
    # ------------------------------------------------------
    yield setup_waflz_server_single
    # ------------------------------------------------------
    # tear down
    # ------------------------------------------------------
    l_code, l_out, l_err = run_command('kill -9 %d'%(l_subproc.pid))
    time.sleep(0.5)
# ------------------------------------------------------------------------------
# setup scopez server in action mode
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_waflz_server_action():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_cwd = os.getcwd()
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_geoip2city_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-City.mmdb'))
    l_geoip2ISP_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-ASN.mmdb'))
    l_conf_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf'))
    l_ruleset_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/ruleset'))
    l_scopez_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/scopes'))
    l_waflz_server_path = os.path.abspath(os.path.join(l_file_path, '../../../build/util/waflz_server/waflz_server'))
    l_subproc = subprocess.Popen([l_waflz_server_path,
                                  '-d', l_conf_dir,
                                  '-b', l_scopez_dir,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path,
                                  '-j'])
    print('cmd: {}'.format(' '.join([l_waflz_server_path,
                                  '-d', l_conf_dir,
                                  '-b', l_scopez_dir,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path,
                                  '-j'])))
    time.sleep(1)
    # ------------------------------------------------------
    # yield...
    # ------------------------------------------------------
    yield setup_waflz_server_action
    # ------------------------------------------------------
    # tear down
    # ------------------------------------------------------
    l_code, l_out, l_err = run_command('kill -9 %d'%(l_subproc.pid))
    time.sleep(0.5)
# ------------------------------------------------------------------------------
# update profile
# ------------------------------------------------------------------------------
def update_profile(profile):
    # ------------------------------------------------------
    # update profile
    # ------------------------------------------------------
    profile['last_modified_date'] = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
    l_url = f'{G_TEST_HOST}/update_profile'
    l_headers = {'Content-Type': 'application/json',
                 'waf-scopes-id': '0050'}
    l_r = requests.post(l_url,
                        headers=l_headers,
                        data=json.dumps(profile))
    # ------------------------------------------------------
    # assert update worked
    # ------------------------------------------------------
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # sleep so next update will work
    # ------------------------------------------------------
    time.sleep(1)
# ------------------------------------------------------------------------------
# an 0050
# ------------------------------------------------------------------------------
def test_scopes_dir_for_an_0050(setup_waflz_server):
    # ------------------------------------------------------
    # test without UA for AN 0050
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'monkeez.com',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile'] == None
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile'] == None
    # ------------------------------------------------------
    # test with UA for AN 0050
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'monkeez.com',
                 'user-agent': 'monkeez',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile'] == None
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'Request User-Agent is monkeez'
    assert 'account_type' in l_r_json['prod_profile']
    assert l_r_json['prod_profile']['account_type'] == 'P'
    assert l_r_json['prod_profile']['bot_tier'] == 'A'
    assert 'partner_id' in l_r_json['prod_profile']
    assert l_r_json['prod_profile']['partner_id'] == 'this_is_the_partner_id'
# ------------------------------------------------------------------------------
# an 0051
# ------------------------------------------------------------------------------
def test_scopes_dir_for_an_0051(setup_waflz_server):
    # ------------------------------------------------------
    # test with wrong path for AN 0051
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/index.html'
    l_headers = {'host': 'bananas.com',
                 'waf-scopes-id': '0051'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile'] == None
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile'] == None
    # ------------------------------------------------------
    # test with wrong host for AN 0051
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'wronghost.com',
                 'waf-scopes-id': '0051'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile'] == None
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile'] == None
    # ------------------------------------------------------
    # test with correct host and path and without UA for AN 0051
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'bananas.com',
                 'waf-scopes-id': '0051'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile'] == None
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile'] == None
    # ------------------------------------------------------
    # test with correct host and path and with UA for AN 0051
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'bananas.com',
                 'user-agent': 'bananas',
                 'waf-scopes-id': '0051'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile'] == None
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'Request User-Agent is bananas'
# ------------------------------------------------------------------------------
# single scope
# ------------------------------------------------------------------------------
def test_single_scope(setup_waflz_server_single):
    # ------------------------------------------------------
    # test single scope for AN 0050
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'monkeez.com',
                 'user-agent': 'monkeez',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile'] == None
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'Request User-Agent is monkeez'
    # ------------------------------------------------------
    # test acl
    # ------------------------------------------------------
    l_headers['user-agent'] = 'gizoogle'
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile'] == None
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'Blacklist User-Agent match'
    # ------------------------------------------------------
    # test acl
    # ------------------------------------------------------
    l_headers['user-agent'] = 'curl'
    l_uri = G_TEST_HOST + '/?a=%27select%20*%20from%20testing%27'
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile'] == None
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'SQL Injection Attack Detected via libinjection'
# ------------------------------------------------------------------------------
# test audit and prod alert for an 0050
# ------------------------------------------------------------------------------
def test_audit_and_prod_for_scope(setup_waflz_server_single):
    # ------------------------------------------------------
    # test audit and prod acl
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'test.com',
                 'user-agent': 'gizoogle',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile'] ['sub_event'][0]['rule_msg'] == 'Blacklist User-Agent match'
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'Blacklist User-Agent match'
    assert 'account_type' in l_r_json['audit_profile']
    assert l_r_json['audit_profile']['account_type'] == 'P'
    assert 'account_type' in l_r_json['prod_profile']
    assert l_r_json['prod_profile']['account_type'] == 'P'
    assert 'partner_id' in l_r_json['audit_profile']
    assert l_r_json['audit_profile']['partner_id'] == 'this_is_the_partner_id'
    assert 'partner_id' in l_r_json['prod_profile']
    assert l_r_json['prod_profile']['partner_id'] == 'this_is_the_partner_id'
    # ------------------------------------------------------
    # test audit acl only
    # ------------------------------------------------------
    l_uri = G_TEST_HOST + '/audit.html'
    l_headers = {'host': 'test.com',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile'] ['sub_event'][0]['rule_msg'] == 'Blacklist URL match'
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile'] == None
    assert 'account_type' in l_r_json['audit_profile']
    assert l_r_json['audit_profile']['account_type'] == 'P'
    assert 'partner_id' in l_r_json['audit_profile']
    assert l_r_json['audit_profile']['partner_id'] == 'this_is_the_partner_id'
    # ------------------------------------------------------
    # test prod acl only
    # ------------------------------------------------------
    l_uri = G_TEST_HOST + '/prod.html'
    l_headers = {'host': 'test.com',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile'] == None
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'Blacklist URL match'
    assert 'account_type' in l_r_json['prod_profile']
    assert l_r_json['prod_profile']['account_type'] == 'P'
    assert 'partner_id' in l_r_json['prod_profile']
    assert l_r_json['prod_profile']['partner_id'] == 'this_is_the_partner_id'
    # ------------------------------------------------------
    # test audit and prod profile
    # ------------------------------------------------------
    l_uri = G_TEST_HOST + '/?a=%27select%20*%20from%20testing%27'
    l_headers = { 'host': 'test.com',
                  'waf-scopes-id': '0050',
                  'x-waflz-ip': '2606:2800:400c:2::7c',
                  'user-agent': 'curl'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'SQL Injection Attack Detected via libinjection'
    assert l_r_json['prod_profile']['geoip_country_name'] == 'United States'
    assert l_r_json['prod_profile']['geoip_country_code2'] == 'US'
    assert l_r_json['prod_profile']['geoip_city_name'] == 'Los Angeles'
    assert l_r_json['prod_profile']['geoip_latitude'] == 34.0544
    assert l_r_json['prod_profile']['geoip_longitude'] == -118.244
    assert l_r_json['prod_profile']['geoip_sd1_iso'] == 'CA'
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'SQL Injection Attack Detected via libinjection'
    assert 'account_type' in l_r_json['audit_profile']
    assert l_r_json['audit_profile']['account_type'] == 'P'
    assert 'account_type' in l_r_json['prod_profile']
    assert l_r_json['prod_profile']['account_type'] == 'P'
    assert 'partner_id' in l_r_json['audit_profile']
    assert l_r_json['audit_profile']['partner_id'] == 'this_is_the_partner_id'
    assert 'partner_id' in l_r_json['prod_profile']
    assert l_r_json['prod_profile']['partner_id'] == 'this_is_the_partner_id'
    # ------------------------------------------------------
    # test prod rule
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'test.com',
                 'waf-scopes-id': '0050',
                 'user-agent': 'monkeez'
                }
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile'] == None
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'Request User-Agent is monkeez'
    assert 'account_type' in l_r_json['prod_profile']
    assert l_r_json['prod_profile']['account_type'] == 'P'
    assert 'partner_id' in l_r_json['prod_profile']
    assert l_r_json['prod_profile']['partner_id'] == 'this_is_the_partner_id'
    # ------------------------------------------------------
    # test audit rule
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'test.com',
                 'waf-scopes-id': '0050',
                 'user-agent': 'bananas'
                }
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile']['sub_event'][0]['rule_msg'] == 'Request User-Agent is bananas'
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile'] == None
    assert 'account_type' in l_r_json['audit_profile']
    assert l_r_json['audit_profile']['account_type'] == 'P'
    assert 'partner_id' in l_r_json['audit_profile']
    assert l_r_json['audit_profile']['partner_id'] == 'this_is_the_partner_id'
# ------------------------------------------------------------------------------
# test acl, rules and profile alert ordering for an 0050
# ------------------------------------------------------------------------------
def test_alert_order(setup_waflz_server_single):
    # ------------------------------------------------------
    # acl alert should kick in for prod (URL blacklist) 
    # acl alert should kick in for audit(User-Agent blacklist)
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/prod.html?a=%27select%20*%20from%20testing%27'
    l_headers = { 'host': 'test.com',
                  'user-agent': 'gizoogle',
                  'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json['audit_profile']['sub_event'][0]['rule_msg'] == 'Blacklist User-Agent match' 
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'Blacklist URL match'
    # ------------------------------------------------------
    # acl alert should kick in for prod(URL blacklist)
    # custom rule alert should kick in audit (User-agent match)
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/prod.html?a=%27select%20*%20from%20testing%27'
    l_headers = { 'host': 'test.com',
                  'user-agent': 'bananas',
                  'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json['audit_profile']['sub_event'][0]['rule_msg'] == 'Request User-Agent is bananas' 
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'Blacklist URL match'
    # ------------------------------------------------------
    # acl alert should kick in for prod(URL blacklist)
    # waf profile alert should kick in for audit (SQL injection)
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/prod.html?a=%27select%20*%20from%20testing%27'
    l_headers = { 'host': 'test.com',
                  'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json['audit_profile']['sub_event'][0]['rule_msg'] == 'SQL Injection Attack Detected via libinjection' 
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'Blacklist URL match'
    # ------------------------------------------------------
    # acl alert should kick in for audit(URL blacklist)
    # waf profile alert should kick in for prod (SQL injection)
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/audit.html?a=%27select%20*%20from%20testing%27'
    l_headers = { 'host': 'test.com',
                  'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json['audit_profile']['sub_event'][0]['rule_msg'] == 'Blacklist URL match'
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] =='SQL Injection Attack Detected via libinjection'
    # ------------------------------------------------------
    # acl alert should kick in for audit(URL blacklist)
    # custom rule alert should kick in for prod (SQL injection)
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/audit.html?a=%27select%20*%20from%20testing%27'
    l_headers = { 'host': 'test.com',
                  'user-agent': 'monkeez',
                  'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json['audit_profile']['sub_event'][0]['rule_msg'] == 'Blacklist URL match'
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] =='Request User-Agent is monkeez'
# ------------------------------------------------------------------------------
# test limit and waf with scopes
# ------------------------------------------------------------------------------
def test_limit_and_waf_with_scopes(setup_waflz_server_action):
    # ------------------------------------------------------
    # shoot 3 request in 5 sec
    # 3rd request should get rate limited
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'limit.com',
                 'waf-scopes-id': '0050'}
    for x in range(2):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is ddos custom response\n'
    # ------------------------------------------------------
    # shoot SQL injection request during enforcement window.
    # Should still get a ddos custom response
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html?a=%27select%20*%20from%20testing%27'
    l_headers = { 'host': 'limit.com',
                  'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is ddos custom response\n'
    # ------------------------------------------------------
    # shoot acl request during enforcement period.
    # should see acl action
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/audit.html'
    l_headers = {'host': 'limit.com',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is acl custom response\n'
    # ------------------------------------------------------
    # sleep for 1 seconds enforcement period.
    # Shoot SQL injection request again.
    # should see waf action
    # ------------------------------------------------------
    time.sleep(2)
    l_uri = G_TEST_HOST+'/test.html?a=%27select%20*%20from%20testing%27'
    l_headers = { 'host': 'limit.com',
                  'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is profile custom response\n'
    # ------------------------------------------------------
    # limit should fire after passing api_gw
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/prod.html'
    l_headers = { 'host': 'test_api_gw.com',
                  'Content-Type': 'application/json',
                  'waf-scopes-id': '0050'}
    l_data = "{\"name\": \"Bob Bobberson\", \"Employee_ID\":1234}"
    for x in range(2):
        l_r = requests.get(l_uri, headers=l_headers, data=l_data)
        assert l_r.status_code == 200
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is ddos custom response\n'
# ------------------------------------------------------------------------------
# test scopes operator
# ------------------------------------------------------------------------------
def test_scopes_operators(setup_waflz_server_action):
    # ------------------------------------------------------
    # test for EM
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'bananas.com',
                 'user-agent': 'bananas',
                 'waf-scopes-id': '0051'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == "This is from EM scope\n"
    # ------------------------------------------------------
    # test for RX
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test/path.html'
    l_headers = {'host': 'test.regexhost.com',
                 'user-agent': 'bananas',
                 'waf-scopes-id': '0051'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == "This is from RX scope\n"
    # ------------------------------------------------------
    # test for GLOB - random hostname and path
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/somepath.html'
    l_headers = {'host': 'somedomain.com',
                 'user-agent': 'bananas',
                 'waf-scopes-id': '0051'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == "This is from GLOB scope\n"
# ------------------------------------------------------------------------------
# test acl whitelist
# ------------------------------------------------------------------------------
def test_acl_whitelist(setup_waflz_server_action):
    # ------------------------------------------------------
    # Request with more than number of args configured in
    # profile. waf should alert
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html?arg1&arg2&arg3&arg4'
    l_headers = {'host': 'monkeez.com',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == "This is profile custom response\n"
    # ------------------------------------------------------
    # Request with lot of args in whitelisted url
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/robots.txt?arg1&arg2&arg3&arg4'
    l_headers = {'host': 'monkeez.com',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
# ------------------------------------------------------------------------------
# test mutiple scopes for ratelimiting
# ------------------------------------------------------------------------------
def test_multiple_scopes_for_limit(setup_waflz_server_action):
    # ------------------------------------------------------
    # Make 3 request in 5 sec.
    # 3rd request should get rate limited
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'limit.com',
                 'waf-scopes-id': '0050'}
    for x in range(2):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is ddos custom response\n'
    # ------------------------------------------------------
    # Make another request for different scope during enf
    # window of first request. should get 200 and followed
    # by enforcement for that scope
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'test.limit.com',
                 'waf-scopes-id': '0050'}
    for x in range(2):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == "custom response for limits from limit_id_2\n"
# ------------------------------------------------------------------------------
# custom rules in scopes
# ------------------------------------------------------------------------------
def test_custom_rules_in_scopes(setup_waflz_server_action):
    # ------------------------------------------------------
    # create request
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'rulestest.com',
                 'user-agent': 'RULESTEST',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'basic custom rule triggered\n'
# ------------------------------------------------------------------------------
# chained custom rules in scopes
# ------------------------------------------------------------------------------   
def test_chained_custom_rules_in_scopes(setup_waflz_server_action):
    # ------------------------------------------------------
    # create request
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'chainedrulestest.com',
                 'waf-scopes-id': '0052',
                 'Pragma': 'NO-CACHE'
                 }
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'response from chained custom rules\n'
# ------------------------------------------------------------------------------
# custom rules test json body parsing
# ------------------------------------------------------------------------------
def test_custom_rules_body_parsing_in_scopes(setup_waflz_server_action):
    # ------------------------------------------------------
    # create request
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'bodytest.com',
                 'user-agent': 'monkey',
                 'Content-Type': 'application/json',
                 'waf-scopes-id': '0052'}
    l_body = {
        'email' : 'ps.switch.delivery@gmail.com',
        'origin' : 'mobile',
        'password' : 'ps654321'
    }
    l_r = requests.post(l_uri,
                        headers=l_headers,
                        data=json.dumps(l_body))
    assert l_r.status_code == 403
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    l_event = l_r_json['prod_profile']
    #-------------------------------------------------------
    # check we have an event
    # ------------------------------------------------------
    assert l_event['rule_intercept_status'] == 403
    assert l_event['rule_msg'] == 'testing request bodies in custom rules'
    assert l_event['sub_event'][0]['rule_op_param'] == 'ps654321'
    #-------------------------------------------------------
    # test an xml
    # ------------------------------------------------------
    l_body = """<?xml version="1.0" encoding="UTF-8"?>
    <body>
        <email>ps.switch.delivery@gmail.com</email>
        <origin>mobile</origin>
        <password>ps654321</password>
    </body>
    """
    l_headers = {'host': 'bodytest.com',
                 'user-agent': 'monkey',
                 'Content-Type': 'text/xml',
                 'waf-scopes-id': '0052'}
    l_r = requests.post(l_uri,
                        headers=l_headers,
                        data=l_body)
    assert l_r.status_code == 403
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    assert l_event['rule_msg'] == 'testing request bodies in custom rules'
    assert l_event['sub_event'][0]['rule_op_param'] == 'ps654321'
# ------------------------------------------------------------------------------
# test spoof header works
# ------------------------------------------------------------------------------
def test_spoof_header(setup_waflz_server_single):
    # ------------------------------------------------------
    # create request
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'host': 'test.com',
        'x-waflz-ip': '2.2.2.2'
    }
    # ------------------------------------------------------
    # send request that should be blocked by ip
    # ------------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers)
    # ------------------------------------------------------
    # assert blocked by ip
    # ------------------------------------------------------
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json['audit_profile']['rule_msg'] == 'Blacklist IP match'
    assert l_r_json['audit_profile']['geoip_asn'] == 3215
    # ------------------------------------------------------
    # add spoof ip header that still gets blocked
    # ------------------------------------------------------
    l_headers['spoof_header'] = '101.191.255.255'
    # ------------------------------------------------------
    # send request with spoofed ip
    # ------------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers)
    # ------------------------------------------------------
    # assert that ip was spoofed was blocked
    # ------------------------------------------------------
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json['audit_profile']['rule_msg'] == 'Blacklist Subdivision match'
    # ------------------------------------------------------
    # add spoof ip header 
    # ------------------------------------------------------
    l_headers['spoof_header'] = '1.1.1.1'
    # ------------------------------------------------------
    # send request with spoofed ip
    # ------------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers)
    # ------------------------------------------------------
    # assert that ip was spoofed and not blocked
    # ------------------------------------------------------
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert not l_r_json['audit_profile']
# ------------------------------------------------------------------------------
# test bot_manager event has req data + customer id
# ------------------------------------------------------------------------------
def test_bot_manager_event_has_rqst_info(setup_waflz_server):
    # ------------------------------------------------------
    # create request
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'host': 'botmanagertest.com',
        'User-Agent': 'Googlebot',
        'waf-scopes-id': '0052',
        'x-waflz-ip': '1.179.71.247'
    }
    # ------------------------------------------------------
    # send request that should be blocked by ip
    # ------------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers)
    # ------------------------------------------------------
    # assert blocked by ip
    # ------------------------------------------------------
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'sub_event' in l_r_json['bot_event']
    assert l_r_json['bot_event']['sub_event'][0]['rule_id'] == 70000
    # ------------------------------------------------------
    # assert rqst info present
    # ------------------------------------------------------
    assert l_r_json['bot_event']['geoip_latitude'] == -33.494
    assert l_r_json['bot_event']['is_anonymous_proxy'] == False
    assert l_r_json['bot_event']['geoip_country_name'] == 'Australia'
    # ------------------------------------------------------
    # assert cust_id is present
    # ------------------------------------------------------
    assert 'req_info' in l_r_json['bot_event']
    assert 'customer_id' in l_r_json['bot_event']['req_info']
    # ------------------------------------------------------
    # assert cust_id is value of the callback
    # ------------------------------------------------------
    assert l_r_json['bot_event']['req_info']['customer_id'] == 108221
# ------------------------------------------------------------------------------
# test parser behavior
# ------------------------------------------------------------------------------
def test_scopes_parser_behavior(setup_waflz_server_single):
    # ------------------------------------------------------
    # create request
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'Host': 'test.com',
        'user-agent': 'monkey',
        'Content-Type': 'application/json',
        'waf-scopes-id': '0050'
    }
    # ------------------------------------------------------
    # scenario 1: All profiles have all parser turned on
    # ------------------------------------------------------
    # ------------------------------------------------------
    # Test custom rules: Both audit and prod custom rules
    # should fire
    # ------------------------------------------------------
    l_body = {
        'email' : 'ps.switch.delivery@gmail.com',
        'origin' : 'mobile',
        'password' : 'ps654321'
    }
    l_r = requests.post(l_uri,
                        headers=l_headers,
                        data=json.dumps(l_body))
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    assert 'audit_profile' in l_r_json
    l_audit_event = l_r_json['audit_profile']
    l_prod_event = l_r_json['prod_profile']
    assert l_audit_event['rule_intercept_status'] == 403
    assert l_audit_event['rule_msg'] == 'testing request bodies in custom rules'
    assert l_prod_event['rule_intercept_status'] == 403
    assert l_prod_event['rule_msg'] == 'testing request bodies in custom rules'
    # ------------------------------------------------------
    # both audit and prod profiles should fire as well
    # ------------------------------------------------------
    l_body = { 'PARAMETER1': 'PARAMETER',
                'PARAMETER': 'PARAMETER:\'4\' UNION SELECT 31337,name COLLATE Arabic_CI_AS FROM master..sysdatabases--'
             }
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'Host': 'test.com',
        'user-agent': 'monkey',
        'Content-Type': 'application/json',
        'waf-scopes-id': '0050'
    }
    l_r = requests.post(l_uri,
                        headers=l_headers,
                        data=json.dumps(l_body))
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    assert 'audit_profile' in l_r_json
    l_audit_event = l_r_json['audit_profile']
    l_prod_event = l_r_json['prod_profile']
    assert l_audit_event['rule_intercept_status'] == 403
    assert l_audit_event['rule_msg'] == 'Inbound Anomaly Score Exceeded (Total Score: 5): Last Matched Message: '
    assert l_prod_event['rule_intercept_status'] == 403
    assert l_prod_event['rule_msg'] == 'Inbound Anomaly Score Exceeded (Total Score: 5): Last Matched Message: '
    # ------------------------------------------------------
    # scenario 2: Audit profile parser off
    # ------------------------------------------------------
    l_audit_profile_path = os.path.realpath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        '../../data/waf/conf/profile/0050-YrLf3KkQ.wafprof.json'
    ))
    l_audit_profile = None
    with open(l_audit_profile_path, 'r') as file_handler:
        l_audit_profile = json.loads(file_handler.read());
    l_audit_profile['general_settings']['json_parser'] = False
    update_profile(l_audit_profile)
    # ------------------------------------------------------
    # Test custom rules: Both audit and prod custom rules
    # should fire, Audit should not fire, prod should fire
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'Host': 'test.com',
        'user-agent': 'monkey',
        'Content-Type': 'application/json',
        'waf-scopes-id': '0050'
    }
    l_body = {
        'email' : 'ps.switch.delivery@gmail.com',
        'origin' : 'mobile',
        'password' : 'ps654321'
    }
    l_r = requests.post(l_uri,
                        headers=l_headers,
                        data=json.dumps(l_body))
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    assert 'audit_profile' in l_r_json
    l_audit_event = l_r_json['audit_profile']
    l_prod_event = l_r_json['prod_profile']
    assert l_audit_event['rule_intercept_status'] == 403
    assert l_audit_event['rule_msg'] == 'testing request bodies in custom rules'
    assert l_prod_event['rule_intercept_status'] == 403
    assert l_prod_event['rule_msg'] == 'testing request bodies in custom rules'
    # ------------------------------------------------------
    # test managed profiles. Audit should not fire, prod should
    # ------------------------------------------------------
    l_body = { 'PARAMETER1': 'PARAMETER',
                'PARAMETER': 'PARAMETER:\'4\' UNION SELECT 31337,name COLLATE Arabic_CI_AS FROM master..sysdatabases--'
             }
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'Host': 'test.com',
        'user-agent': 'monkey',
        'Content-Type': 'application/json',
        'waf-scopes-id': '0050'
    }
    l_r = requests.post(l_uri,
                        headers=l_headers,
                        data=json.dumps(l_body))
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    assert 'audit_profile' in l_r_json
    l_audit_event = l_r_json['audit_profile']
    l_prod_event = l_r_json['prod_profile']
    assert l_audit_event is None
    assert l_prod_event['rule_intercept_status'] == 403
    assert l_prod_event['rule_msg'] == 'Inbound Anomaly Score Exceeded (Total Score: 5): Last Matched Message: '
    # ------------------------------------------------------
    # scenario 3: both profile parser turned off
    # ------------------------------------------------------
    l_prod_profile_path = os.path.realpath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        '../../data/waf/conf/profile/0050-Ab98JXk.wafprof.json'
    ))
    l_prod_profile = None
    with open(l_prod_profile_path, 'r') as file_handler:
        l_prod_profile = json.loads(file_handler.read());
    l_prod_profile['general_settings']['json_parser'] = False
    update_profile(l_prod_profile)
    #-------------------------------------------------------
    # check we get event from both  custom rules again
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'Host': 'test.com',
        'user-agent': 'monkey',
        'Content-Type': 'application/json',
        'waf-scopes-id': '0050'
    }
    l_body = {
        'email' : 'ps.switch.delivery@gmail.com',
        'origin' : 'mobile',
        'password' : 'ps654321'
    }
    l_r = requests.post(l_uri,
                        headers=l_headers,
                        data=json.dumps(l_body))
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    assert 'audit_profile' in l_r_json
    l_audit_event = l_r_json['audit_profile']
    l_prod_event = l_r_json['prod_profile']
    assert l_audit_event['rule_intercept_status'] == 403
    assert l_audit_event['rule_msg'] == 'testing request bodies in custom rules'
    assert l_prod_event['rule_intercept_status'] == 403
    assert l_prod_event['rule_msg'] == 'testing request bodies in custom rules'
    # ------------------------------------------------------
    # niether of the profiles should fire
    # ------------------------------------------------------
    l_body = { 'PARAMETER1': 'PARAMETER',
                'PARAMETER': 'PARAMETER:\'4\' UNION SELECT 31337,name COLLATE Arabic_CI_AS FROM master..sysdatabases--'
             }
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'Host': 'test.com',
        'user-agent': 'monkey',
        'Content-Type': 'application/json',
        'waf-scopes-id': '0050'
    }
    l_r = requests.post(l_uri,
                        headers=l_headers,
                        data=json.dumps(l_body))
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    assert 'audit_profile' in l_r_json
    l_audit_event = l_r_json['audit_profile']
    l_prod_event = l_r_json['prod_profile']
    assert l_audit_event is None
    assert l_prod_event is None
    # ------------------------------------------------------
    # scenario 3: Audit profile parser on, prod parser off
    # ------------------------------------------------------
    l_audit_profile['general_settings']['json_parser'] = True
    update_profile(l_audit_profile)
    # ------------------------------------------------------
    # Audit profile should alert, prod should not
    # ------------------------------------------------------
    l_body = { 'PARAMETER1': 'PARAMETER',
                'PARAMETER': 'PARAMETER:\'4\' UNION SELECT 31337,name COLLATE Arabic_CI_AS FROM master..sysdatabases--'
             }
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'Host': 'test.com',
        'user-agent': 'monkey',
        'Content-Type': 'application/json',
        'waf-scopes-id': '0050'
    }
    l_r = requests.post(l_uri,
                        headers=l_headers,
                        data=json.dumps(l_body))
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    assert 'audit_profile' in l_r_json
    l_audit_event = l_r_json['audit_profile']
    l_prod_event = l_r_json['prod_profile']
    assert l_audit_event['rule_intercept_status'] == 403
    assert l_audit_event['rule_msg'] == 'Inbound Anomaly Score Exceeded (Total Score: 5): Last Matched Message: '
    assert l_prod_event is None
# ------------------------------------------------------------------------------
# test api gateway behavior
# ------------------------------------------------------------------------------
def test_api_gw_in_scopes(setup_waflz_server_single):
    # ------------------------------------------------------
    # test api_gw for AN 0050
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/bananas.html'
    l_headers = {'host': 'test_api_gw.com',
                 'waf-scopes-id': '0050',
                 'Content-Type': 'application/json'}
    l_data = "{\"message\": \"success\"}"
    l_r = requests.get(l_uri, headers=l_headers, data=l_data)
    l_r_json = l_r.json()
    assert l_r_json['audit_profile']["rule_msg"] == "Request JSON Schema Validation Error"
    assert l_r_json['audit_profile']["sub_event"][0]["rule_msg"] == "required"
    assert l_r_json['audit_profile']["api_gw_config_id"] == "qSMXE66R"
    assert l_r_json['audit_profile']["schema_config_id"] == "A7QPbm0Z"
    assert 'schema_error_offset' in l_r_json['audit_profile']["sub_event"][0]
    assert l_r_json['prod_profile']["rule_msg"] == "Request JSON Schema Validation Error"
    assert l_r_json['prod_profile']["sub_event"][0]["rule_msg"] == "required"
    assert l_r_json['prod_profile']["api_gw_config_id"] == "nif70s89"
    assert l_r_json['prod_profile']["schema_config_id"] == "D58gMFTz"
    assert 'schema_error_offset' in l_r_json['prod_profile']["sub_event"][0]
    # ------------------------------------------------------
    # acl action for prod (Blacklist IP)
    # api gateway action for audit (missing required field)
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/prod.html'
    l_headers = { 'host': 'test_api_gw.com',
                  'x-waflz-ip': '2.2.2.2',
                  'Content-Type': 'application/json',
                  'waf-scopes-id': '0050'}
    l_data = "{ }"
    l_r = requests.get(l_uri, headers=l_headers, data=l_data)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json['audit_profile']["rule_msg"] == "Request JSON Schema Validation Error"
    assert l_r_json['audit_profile']["sub_event"][0]["rule_msg"] == "required"
    assert l_r_json['audit_profile']["api_gw_config_id"] == "qSMXE66R"
    assert l_r_json['audit_profile']["schema_config_id"] == "A7QPbm0Z"
    assert 'schema_error_offset' in l_r_json['audit_profile']["sub_event"][0]
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'Blacklist IP match'
    # ------------------------------------------------------
    # Pass api gateway
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/bananas.html'
    l_headers = {'host': 'test_api_gw.com',
                 'waf-scopes-id': '0050',
                 'Content-Type': 'application/json'}
    l_data = "{\"message\": \"success\", \"timestamp\":0}"
    l_r = requests.get(l_uri, headers=l_headers, data=l_data)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    l_prod_event = l_r_json['prod_profile']
    assert l_prod_event is None