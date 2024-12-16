#!/usr/bin/env python3
'''Test config updates '''
# ------------------------------------------------------------------------------
# Imports
# ------------------------------------------------------------------------------
import subprocess
import os
import json
import time
import datetime
import requests
import pytest
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
# setup scopez server in action mode
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_waflz_server_action():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_geoip2city_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-City.mmdb'))
    l_geoip2ISP_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-ASN.mmdb'))
    l_conf_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf'))
    l_ruleset_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/ruleset'))
    l_scopez_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/scopes'))
    l_waflz_server_path = os.path.abspath(os.path.join(l_file_path, '../../../build/util/waflz_server/waflz_server'))
    l_challenge = os.path.realpath(os.path.join(l_file_path, '../../data/bot/bot-challenges.json'))
    l_ja3_db_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/bot_lmdb'))
    l_subproc = subprocess.Popen([l_waflz_server_path,
                                  '-d', l_conf_dir,
                                  '-b', l_scopez_dir,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path,
                                  '-c', l_challenge,
                                  '-Z', l_ja3_db_dir,
                                  '-j'
                                  ])
    print('cmd: {}'.format(' '.join([l_waflz_server_path,
                                  '-d', l_conf_dir,
                                  '-b', l_scopez_dir,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path,
                                  '-c', l_challenge,
                                  '-Z', l_ja3_db_dir,
                                  '-j'])))
                                  # '-b'])))
    time.sleep(1)
    # ------------------------------------------------------
    # yield...
    # ------------------------------------------------------
    yield setup_waflz_server_action
    # ------------------------------------------------------
    # tear down
    # ------------------------------------------------------
    _, _, _ = run_command('kill -9 %d'%(l_subproc.pid))
    time.sleep(0.5)
# ------------------------------------------------------------------------------
# setup scopez server without action mode
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_waflz_server():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_geoip2city_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-City.mmdb'))
    l_geoip2ISP_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-ASN.mmdb'))
    l_conf_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf'))
    l_ruleset_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/ruleset'))
    l_scopez_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/scopes'))
    l_waflz_server_path = os.path.abspath(os.path.join(l_file_path, '../../../build/util/waflz_server/waflz_server'))
    l_challenge = os.path.realpath(os.path.join(l_file_path, '../../data/bot/bot-challenges.json'))
    l_ja3_db_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/bot_lmdb'))
    l_subproc = subprocess.Popen([l_waflz_server_path,
                                  '-d', l_conf_dir,
                                  '-b', l_scopez_dir,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path,
                                  '-c', l_challenge,
                                  '-Z', l_ja3_db_dir,
                                  ])
    print('cmd: {}'.format(' '.join([l_waflz_server_path,
                                  '-d', l_conf_dir,
                                  '-b', l_scopez_dir,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path,
                                  '-c', l_challenge,
                                  '-Z', l_ja3_db_dir
                                  ])))
    time.sleep(1)
    # ------------------------------------------------------
    # yield...
    # ------------------------------------------------------
    yield setup_waflz_server_action
    # ------------------------------------------------------
    # tear down
    # ------------------------------------------------------
    _, _, _ = run_command('kill -9 %d'%(l_subproc.pid))
    time.sleep(0.5)
# ------------------------------------------------------------------------------
# acl config update
# ------------------------------------------------------------------------------
def test_acl_config_update(setup_waflz_server_action):
    """
    update acl config 0050-ZrLf2KkQ - remove gizoogle from
    user agent black list and test if request returns 200
    """
    # ------------------------------------------------------
    # test an 0050 with user-agent acl 'gizoogle' in the 
    # request
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'monkeez.com',
                 'user-agent': 'gizoogle',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is acl custom response\n'
    #-------------------------------------------------------
    # load acl config and remove gizoogle from blacklist
    # ------------------------------------------------------
    l_conf = {}
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_acl_conf_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/acl/0050-ZrLf2KkQ.acl.json'))
    try:
        with open(l_acl_conf_path) as l_f:
            l_conf = json.load(l_f)
    except Exception as l_e:
        print('error opening config file: %s.  Reason: %s error: %s, doc: %s' % (
            l_acl_conf_path, type(l_e), l_e, l_e.__doc__))
        assert False
    l_conf['user_agent']['blacklist'] = []
    l_conf['last_modified_date'] = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    # ------------------------------------------------------
    # post/update acl conf
    # ------------------------------------------------------
    l_url = '%s/update_acl'%(G_TEST_HOST)
    l_headers = {'Content-Type': 'application/json',
                 'waf-scopes-id': '0050'}
    l_r = requests.post(l_url,
                        headers=l_headers,
                        data=json.dumps(l_conf))
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # blacklist should have been updated and should get 200
    #-------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'monkeez.com',
                 'user-agent': 'gizoogle',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # update blacklist ja3 and test a block
    #-------------------------------------------------------
    l_conf['ja3']['blacklist'] = ["253714f62c0a1e6869fe8ba6a45a0588"]
    l_conf['last_modified_date'] = (datetime.datetime.utcnow() + datetime.timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    # ------------------------------------------------------
    # post/update acl conf
    # ------------------------------------------------------
    l_url = '%s/update_acl'%(G_TEST_HOST)
    l_headers = {'Content-Type': 'application/json',
                 'waf-scopes-id': '0050'}
    l_r = requests.post(l_url,
                        headers=l_headers,
                        data=json.dumps(l_conf))
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # blacklist should have been updated and should get 403
    #-------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'monkeez.com',
                 'user-agent': 'gizoogle',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is acl custom response\n'
    # ------------------------------------------------------
    # update whitelist ja3 and test again
    #-------------------------------------------------------
    l_conf['ja3']['whitelist'] = ["253714f62c0a1e6869fe8ba6a45a0588"]
    l_conf['last_modified_date'] = (datetime.datetime.utcnow() + datetime.timedelta(days=2)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    # ------------------------------------------------------
    # post/update acl conf
    # ------------------------------------------------------
    l_url = '%s/update_acl'%(G_TEST_HOST)
    l_headers = {'Content-Type': 'application/json',
                 'waf-scopes-id': '0050'}
    l_r = requests.post(l_url,
                        headers=l_headers,
                        data=json.dumps(l_conf))
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # ja3 added in whitelist, should get 200
    #-------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'monkeez.com',
                 'user-agent': 'gizoogle',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
# ------------------------------------------------------------------------------
# rules config update
# ------------------------------------------------------------------------------
def test_rules_config_update(setup_waflz_server_action):
    """
    update rules config 0050-ZrLf3KKq.rules.json - change 
    user agent to Donkeez from Monkeez
    """
    # ------------------------------------------------------
    # test an 0050 with user-agent 'Monkeez' in the 
    # request
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'monkeez.com',
                 'user-agent': 'monkeez',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is rules custom response\n'
    #-------------------------------------------------------
    # load rules config and changes monkeez to donkeez in 
    # custom rules
    # ------------------------------------------------------
    l_conf = {}
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_rules_conf_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/rules/0050-ZrLf3KkQ.rules.json'))
    try:
        with open(l_rules_conf_path) as l_f:
            l_conf = json.load(l_f)
    except Exception as l_e:
        print('error opening config file: %s.  Reason: %s error: %s, doc: %s' % (
            l_file_path, type(l_e), l_e, l_e.__doc__))
        assert False
    l_conf['directive'][1]['sec_rule']['operator']['value'] = 'donkeez'
    l_conf['last_modified_date'] = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    # ------------------------------------------------------
    # post/update rules conf
    # ------------------------------------------------------
    l_url = '%s/update_rules'%(G_TEST_HOST)
    l_headers = {'Content-Type': 'application/json',
                 'waf-scopes-id': '0050'}
    l_r = requests.post(l_url,
                        headers=l_headers,
                        data=json.dumps(l_conf))
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # test again with user-agent 'Monkeez' in the 
    # request. It should pass
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'monkeez.com',
                 'user-agent': 'monkeez',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # test with user-agent 'donkeez' in the 
    # request. should be blocked
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'monkeez.com',
                 'user-agent': 'donkeez',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is rules custom response\n'
# ------------------------------------------------------------------------------
# profile config update
# ------------------------------------------------------------------------------
def test_profile_config_update(setup_waflz_server_action):
    """
    update profile config 0050-YrLf3KkQ.wafprof.json - change
    ignore_query_args to test from ignore
    """
    # ------------------------------------------------------
    # test an 0050 with sql injection
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/profile.html?a=%27select%20*%20from%20testing%27'
    l_headers = {'host': 'monkeez.com',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is profile custom response\n'
    # ------------------------------------------------------
    # test an 0050 with sql injection and query_args "ignore"
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/profile.html?ignore=%27select%20*%20from%20testing%27'
    l_headers = {'host': 'monkeez.com',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    #-------------------------------------------------------
    # load profile config and change "ignore_query_args"
    # to "test"
    # ------------------------------------------------------
    l_conf = {}
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_profile_conf_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/profile/0050-YrLf3KkQ.wafprof.json'))
    try:
        with open(l_profile_conf_path) as l_f:
            l_conf = json.load(l_f)
    except Exception as l_e:
        print('error opening config file: %s.  Reason: %s error: %s, doc: %s' % (
            l_profile_conf_path, type(l_e), l_e, l_e.__doc__))
        assert False
    l_conf["general_settings"]["ignore_query_args"] = ["test"]
    l_conf['last_modified_date'] = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    # ------------------------------------------------------
    # post/update profile conf
    # ------------------------------------------------------
    l_url = '%s/update_profile'%(G_TEST_HOST)
    l_headers = {'Content-Type': 'application/json',
                 'waf-scopes-id': '0050'}
    l_r = requests.post(l_url,
                        headers=l_headers,
                        data=json.dumps(l_conf))
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # test an 0050 with sql injection and query_args "ignore"
    # should get 403
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/profile.html?ignore=%27select%20*%20from%20testing%27'
    l_headers = {'host': 'monkeez.com',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is profile custom response\n'
    # ------------------------------------------------------
    # test an 0050 with sql injection and query_args "test"
    # sql injection should be ignored and get 200
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/profile.html?test=%27select%20*%20from%20testing%27'
    l_headers = {'host': 'monkeez.com',
                 'waf-scopes-id': '0050'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
# ------------------------------------------------------------------------------
# limit config update
# ------------------------------------------------------------------------------
def test_limit_config_update(setup_waflz_server_action):
    # ------------------------------------------------------
    # Make 3 request in 2 sec for 3rd and
    # 4th scope. Third request should get rate limited
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'limit.com',
                 'waf-scopes-id': '0050'}
    for _ in range(2):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is ddos custom response\n'
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'test.limit.com',
                 'waf-scopes-id': '0050'}
    for _ in range(2):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'custom response for limits from limit_id_2\n'
    # ------------------------------------------------------
    # sleep for 2 seconds. Enforcements should expire
    # ------------------------------------------------------
    time.sleep(2)
    #-------------------------------------------------------
    # load limit config and change duration_sec to 3
    # ------------------------------------------------------
    l_conf = {}
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_limit_conf_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/limit/0050-MjMhNXMR.limit.json'))
    try:
        with open(l_limit_conf_path) as l_f:
            l_conf = json.load(l_f)
    except Exception as l_e:
        print('error opening config file: %s.  Reason: %s error: %s, doc: %s' % (
            l_limit_conf_path, type(l_e), l_e, l_e.__doc__))
        assert False
    l_conf["num"] = 3
    l_conf['last_modified_date'] = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    #-------------------------------------------------------
    # POST conf
    # ------------------------------------------------------
    l_url = '%s/update_limit'%(G_TEST_HOST)
    l_headers = {'Content-Type': 'application/json',
                 'waf-scopes-id': '0050'}
    l_r = requests.post(l_url,
                        headers=l_headers,
                        data=json.dumps(l_conf))
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # Make 4 request in 2 sec. fourth request should get
    # rate limited. Third request shouldn't be blocked
    # because of the update
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'limit.com',
                 'waf-scopes-id': '0050'}
    for _ in range(3):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is ddos custom response\n'
    # ------------------------------------------------------
    # Make 4 request in 2 sec for fourth scope.
    # verify if 4th scope was also updated
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'test.limit.com',
                 'waf-scopes-id': '0050'}
    for _ in range(3):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'custom response for limits from limit_id_2\n'
# ------------------------------------------------------------------------------
# scopes config update
# ------------------------------------------------------------------------------
def test_scopes_update(setup_waflz_server_action):
    #-------------------------------------------------------
    #  check second scope for AN 0051 working correctly
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/path.html'
    l_headers = {'host': 'www.regexhost.com',
                 'waf-scopes-id':'0051',
                 'User-Agent': 'bananas'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is from RX scope\n'
    #-------------------------------------------------------
    #  change the 'path' value for scope and update.
    #  check if update was successful
    # ------------------------------------------------------
    l_conf = {}
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_scopes_conf_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/scopes/0051.scopes.json'))
    try:
        with open(l_scopes_conf_path) as l_f:
            l_conf = json.load(l_f)
    except Exception as l_e:
        print('error opening config file: %s.  Reason: %s error: %s, doc: %s' % (
            l_scopes_conf_path, type(l_e), l_e, l_e.__doc__))
        assert False 
    l_conf['scopes'][1]['path']['value'] = ".*/test.html"
    l_conf['last_modified_date'] = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    #-------------------------------------------------------
    # POST conf
    # ------------------------------------------------------
    l_url = '%s/update_scopes'%(G_TEST_HOST)
    l_headers = {'Content-Type': 'application/json'}
    l_r = requests.post(l_url,
                        headers=l_headers,
                        data=json.dumps(l_conf))
    assert l_r.status_code == 200
    #-------------------------------------------------------
    # make a request with same path '/path.html',
    # should match GLOB scope
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/path.html'
    l_headers = {'host': 'www.regexhost.com',
                 'waf-scopes-id':'0051',
                 'User-Agent': 'bananas'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is from GLOB scope\n'
    #-------------------------------------------------------
    # make a request with updated path '/test.html',
    # should get 403 with custom response
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'www.regexhost.com',
                 'waf-scopes-id':'0051',
                 'User-Agent': 'bananas'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is from RX scope\n'
# ------------------------------------------------------------------------------
# scopes linkage update
# ------------------------------------------------------------------------------
def test_scopes_linkage_update(setup_waflz_server_action):
    """
    Test linkage update. Update rules config in second scope
    (0050-scopes.json) to 0050-0gG8osWJ.rules.json from
    0050-ZrLf3KkQ.rules.json check if update worked
    """
    #-------------------------------------------------------
    #  check second scope for AN 0050 working correctly
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/path.html'
    l_headers = {'host': 'test.com',
                 'waf-scopes-id':'0050',
                 'User-Agent': 'monkeez'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is rules custom response\n'
    #-------------------------------------------------------
    #  change the 'rules_prod_id' value for second scope 
    #  and update.
    #  check if update was successful
    # ------------------------------------------------------
    l_conf = {}
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_scopes_conf_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/scopes/0050.scopes.json'))
    try:
        with open(l_scopes_conf_path) as l_f:
            l_conf = json.load(l_f)
    except Exception as l_e:
        print('error opening config file: %s.  Reason: %s error: %s, doc: %s' % (
            l_scopes_conf_path, type(l_e), l_e, l_e.__doc__))
        assert False 
    l_conf['scopes'][1]['rules_prod_id'] = "0gG8osWJ"
    l_conf['last_modified_date'] = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    #-------------------------------------------------------
    # POST conf
    # ------------------------------------------------------
    l_url = '%s/update_scopes'%(G_TEST_HOST)
    l_headers = {'Content-Type': 'application/json'}
    l_r = requests.post(l_url,
                        headers=l_headers,
                        data=json.dumps(l_conf))
    assert l_r.status_code == 200
    #-------------------------------------------------------
    # make the same request. should get 200
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/path.html'
    l_headers = {'host': 'test.com',
                 'waf-scopes-id':'0050',
                 'User-Agent': 'monkeez'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    #assert l_r.text == 'This is from GLOB scope\n'
    #-------------------------------------------------------
    # make a request with user-agent bananas
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/path.html'
    l_headers = {'host': 'test.com',
                 'waf-scopes-id':'0050',
                 'User-Agent': 'bananas'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'This is rules custom response\n'
# ------------------------------------------------------------------------------
# test /update_bots endpoint
# ------------------------------------------------------------------------------
def test_update_bots_endpoint(setup_waflz_server_action):
    l_url = G_TEST_HOST + '/update_bots'
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_test_file = os.path.realpath(os.path.join(l_file_path,
                                                '../../data/waf/conf/bots/0052-wHyMHxV7.bots.json'))
    l_test_payload = ''
    # ------------------------------------------------------
    # check setup
    # ------------------------------------------------------
    assert os.path.exists(l_test_file), 'test file not found!'
    # ------------------------------------------------------
    # slurp test file
    # ------------------------------------------------------
    with open(l_test_file) as l_tf:
        l_test_payload = l_tf.read()
    # ------------------------------------------------------
    # check setup
    # ------------------------------------------------------
    assert l_test_payload, 'payload is empty!'
    l_json_payload = json.loads(l_test_payload)
    # ------------------------------------------------------
    # Check that challenge works
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'mybot.com',
                 'user-agent': 'bot-testing',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 401
    # ------------------------------------------------------
    # Update the bot config
    # ------------------------------------------------------
    l_json_payload['directive'][0]['sec_rule']['operator']['value'] = 'chowdah'
    # ------------------------------------------------------
    # update the timestamp, else it will silently do nothing and return 200
    # ref: scopes.cc:load_bots (compare time)
    # ------------------------------------------------------
    l_json_payload['last_modified_date'] = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
    l_result = requests.post(l_url, timeout=3, json=l_json_payload)
    assert l_result.status_code == 200
    assert l_result.json()['status'] == 'success'
    # ------------------------------------------------------
    # Expect 200
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'mybot.com',
                 'user-agent': 'bot-testing',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200,\
        "expecting 200, got {resp_code} since user-agent changed to chowdah".format(resp_code=l_r.status_code)
    # ------------------------------------------------------
    # Expect 401 due to new UA
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'mybot.com',
                 'user-agent': 'chowdah',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 401,\
        "expecting 401, got {resp_code} since user-agent changed to chowdah".format(resp_code=l_r.status_code)
    # ------------------------------------------------------
    # check negative test - missing customer_id field
    # ------------------------------------------------------
    l_cust_id = l_json_payload.pop('customer_id')
    l_n2_result = requests.post(l_url, json=l_json_payload)
    assert l_n2_result.status_code == 500,\
        'expected 500 since customer_id {} is removed'.format(l_cust_id)

# ------------------------------------------------------------------------------
# test /update_bots endpoint with bot manager
# ------------------------------------------------------------------------------
def test_update_bots_endpoint_with_botm(setup_waflz_server_action):
    l_url = G_TEST_HOST + '/update_bots'
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_test_file = os.path.realpath(os.path.join(l_file_path,
                                                '../../data/waf/conf/bots/0052-w12347.bots.json'))
    l_test_payload = ''
    # ------------------------------------------------------
    # check setup
    # ------------------------------------------------------
    assert os.path.exists(l_test_file), 'test file not found!'
    # ------------------------------------------------------
    # slurp test file
    # ------------------------------------------------------
    with open(l_test_file) as l_tf:
        l_test_payload = l_tf.read()
    # ------------------------------------------------------
    # check setup
    # ------------------------------------------------------
    assert l_test_payload, 'payload is empty!'
    l_json_payload = json.loads(l_test_payload)
    # ------------------------------------------------------
    # Check that challenge works
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'allbotmanagerchallenges.com',
                 'user-agent': 'bot-testing',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 401
    # ------------------------------------------------------
    # Check that challenge works from other scope
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'mybotmanager.com',
                 'user-agent': 'bot-testing',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 401
    # ------------------------------------------------------
    # Update the bot config
    # ------------------------------------------------------
    l_json_payload['directive'][0]['sec_rule']['operator']['value'] = 'chowdah'
    # ------------------------------------------------------
    # update the timestamp, else it will silently do nothing and return 200
    # ref: scopes.cc:load_bots (compare time)
    # ------------------------------------------------------
    l_json_payload['last_modified_date'] = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
    print(json.dumps(l_json_payload))
    l_result = requests.post(l_url, timeout=3, json=l_json_payload)
    assert l_result.status_code == 200
    assert l_result.json()['status'] == 'success'
    # ------------------------------------------------------
    # Expect 200 from allbotmanagerchallenges
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'allbotmanagerchallenges.com',
                 'user-agent': 'bot-testing',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200,\
        "expecting 200, got {resp_code} since user-agent changed to chowdah".format(resp_code=l_r.status_code)
    # ------------------------------------------------------
    # Expect 401 due to new UA
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'allbotmanagerchallenges.com',
                 'user-agent': 'chowdah',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 401,\
        "expecting 401, got {resp_code} since user-agent changed to chowdah".format(resp_code=l_r.status_code)
    # ------------------------------------------------------
    # check negative test - missing customer_id field
    # ------------------------------------------------------
    l_cust_id = l_json_payload.pop('customer_id')
    l_n2_result = requests.post(l_url, json=l_json_payload)
    assert l_n2_result.status_code == 500,\
        'expected 500 since customer_id {} is removed'.format(l_cust_id)

# ------------------------------------------------------------------------------
# test /update_api_gw
# ------------------------------------------------------------------------------
def test_update_api_gw(setup_waflz_server_action):
    l_url = G_TEST_HOST + '/update_api_gw'
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_test_file = os.path.realpath(os.path.join(l_file_path,
                                                '../../data/waf/conf/api_gw/0050-nif70s89.api_gw.json'))
    l_test_payload = ''
    # ------------------------------------------------------
    # check setup
    # ------------------------------------------------------
    assert os.path.exists(l_test_file), 'test file not found!'
    # ------------------------------------------------------
    # slurp test file
    # ------------------------------------------------------
    with open(l_test_file) as l_tf:
        l_test_payload = l_tf.read()
    # ------------------------------------------------------
    # check setup
    # ------------------------------------------------------
    assert l_test_payload, 'payload is empty!'
    l_json_payload = json.loads(l_test_payload)
    # ------------------------------------------------------
    # Check that correct payload sends 200 for path test.html
    # from api gateway config nif70s89
    # -----------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'test_api_gw.com',
                 'Content-Type': 'application/json',
                 'waf-scopes-id': '0050'}
    l_data = "{\"name\": \"Bob Bobberson\", \"Employee_ID\":1234}"
    l_r = requests.get(l_uri, headers=l_headers, data=l_data)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # Check that wrong payload fires for path test.html
    # from api gateway config nif70s89
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'test_api_gw.com',
                 'Content-Type': 'application/json',
                 'waf-scopes-id': '0050'}
    l_data = {'name': 1}
    l_r = requests.get(l_uri, headers=l_headers, data=l_data)
    assert l_r.status_code == 403
    # ------------------------------------------------------
    # Change the path in api gateway config from /test.html to
    # /cat.html
    # ------------------------------------------------------
    l_json_payload['rules'][0]['path']['value'] = "/cat.html"
    # ------------------------------------------------------
    # update the timestamp, else it will silently do nothing and return 200
    # ref: scopes.cc:load_api_gw (compare time)
    # ------------------------------------------------------
    l_json_payload['last_modified_date'] = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
    l_result = requests.post(l_url, timeout=3, json=l_json_payload)
    assert l_result.status_code == 200
    assert l_result.json()['status'] == 'success'
    # ------------------------------------------------------
    # Check that wrong payload fires for path cat.html
    # from api gateway config nif70s89
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/cat.html'
    l_headers = {'host': 'test_api_gw.com',
                 'Content-Type': 'application/json',
                 'waf-scopes-id': '0050'}
    l_data = {'name': 1}
    l_r = requests.get(l_uri, headers=l_headers, data=l_data)
    assert l_r.status_code == 403
    # ------------------------------------------------------
    # Check that correct payload send 200 for path cat.html
    # from api gateway config nif70s89
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/cat.html'
    l_headers = {'host': 'test_api_gw.com',
                 'Content-Type': 'application/json',
                 'waf-scopes-id': '0050'}
    l_data = "{\"name\": \"Bob Bobberson\", \"Employee_ID\":1234}"
    l_r = requests.get(l_uri, headers=l_headers, data=l_data)
    assert l_r.status_code == 200
    # sleep to prevent ddos
    time.sleep(2)
    # ------------------------------------------------------
    # old path test.html with wrong payload should give
    # 200
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'test_api_gw.com',
                 'Content-Type': 'application/json',
                 'waf-scopes-id': '0050'}
    l_data = {'name': 1}
    l_r = requests.get(l_uri, headers=l_headers, data=l_data)
    assert l_r.status_code == 200

# ------------------------------------------------------------------------------
# test /update_api_schema
# ------------------------------------------------------------------------------
def test_update_api_schema(setup_waflz_server_action):
    l_url = G_TEST_HOST + '/update_api_schema'
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_test_file = os.path.realpath(os.path.join(l_file_path,
                                                '../../data/waf/conf/api_schema/0050-W9057Zkg.api_schema.json'))
    l_test_payload = ''
    # ------------------------------------------------------
    # check setup
    # ------------------------------------------------------
    assert os.path.exists(l_test_file), 'test file not found!'
    # ------------------------------------------------------
    # slurp test file
    # ------------------------------------------------------
    with open(l_test_file) as l_tf:
        l_test_payload = l_tf.read()
    # ------------------------------------------------------
    # check setup
    # ------------------------------------------------------
    assert l_test_payload, 'payload is empty!'
    l_json_payload = json.loads(l_test_payload)
    # ------------------------------------------------------
    # send wrong payload without employeed id for path test.html
    # from api gateway config nif70s89 and schema 
    # W9057Zkg. shooudl fire 403
    # -----------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'test_api_gw.com',
                 'Content-Type': 'application/json',
                 'waf-scopes-id': '0050'}
    l_data = "{\"name\": \"Bob Bobberson\"}"
    l_r = requests.get(l_uri, headers=l_headers, data=l_data)
    assert l_r.status_code == 403
    # ------------------------------------------------------
    # remove Employee id from required fields
    # ------------------------------------------------------
    l_json_payload['schema']['required'] = ["name"]
    # ------------------------------------------------------
    # update the timestamp, else it will silently do nothing and return 200
    # ref: scopes.cc:load_api_schema (compare time)
    # ------------------------------------------------------
    l_json_payload['last_modified_date'] = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
    l_result = requests.post(l_url, timeout=3, json=l_json_payload)
    assert l_result.status_code == 200
    assert l_result.json()['status'] == 'success'
    # -----------------------------------------------------
    # sending payload without employee id. should get 200
    # -----------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'test_api_gw.com',
                 'Content-Type': 'application/json',
                 'waf-scopes-id': '0050'}
    l_data = "{\"name\": \"Bob Bobberson\"}"
    l_r = requests.get(l_uri, headers=l_headers, data=l_data)
    assert l_r.status_code == 200
# ------------------------------------------------------------------------------
# test custom rules with bot score
# ------------------------------------------------------------------------------
def test_custom_rule_with_bot_score(setup_waflz_server):
    # ------------------------------------------------------
    # test custom rule with bot score and chained rule
    # for a header with pragma no-cache.
    # -----------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'rulestest.com',
                 'user-agent': 'custom_bot_score',
                 'Pragma' : 'no-cache',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'audit_profile' in l_r_json
    assert l_r_json['audit_profile'] == None
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'Bot Score > 50'
    assert l_r_json['prod_profile']['sub_event'][0]['rule_id'] == 66100095
