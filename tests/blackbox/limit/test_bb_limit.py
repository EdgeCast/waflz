#!/usr/bin/env python3
'''Test limit '''
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
# setup waflz server with scopes
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_waflz_server():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_cwd = os.getcwd()
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_scopes_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/scopes'))
    l_conf_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf'))
    l_ruleset_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/ruleset'))
    l_geoip2city_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-City.mmdb'))
    l_geoip2ISP_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-ASN.mmdb'))
    l_ja3_db_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/bot_lmdb'))
    l_waflz_server_path = os.path.abspath(os.path.join(l_file_path, '../../../build/util/waflz_server/waflz_server'))
    l_subproc = subprocess.Popen([l_waflz_server_path,
                                  '-d', l_conf_dir,
                                  '-b', l_scopes_dir,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path,
                                  '-Z', l_ja3_db_dir,
                                  '-L',
                                  '-j'])
    print('cmd: \n{}\n'.format(' '.join([l_waflz_server_path,
                                  '-d', l_conf_dir,
                                  '-b', l_scopes_dir,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path,
                                  '-Z', l_ja3_db_dir,
                                  '-L',
                                  '-j'])))
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
# setup waflz server with only limit and geoip db's
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_waflz_server_limit():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_cwd = os.getcwd()
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_limit_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/limit/0053-kobjYva2.limit.json'))
    l_geoip2city_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-City.mmdb'))
    l_geoip2ISP_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-ASN.mmdb'))
    l_waflz_server_path = os.path.abspath(os.path.join(l_file_path, '../../../build/util/waflz_server/waflz_server'))
    l_subproc = subprocess.Popen([l_waflz_server_path,
                                  '-l', l_limit_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path,
                                  '-j'])
    print('cmd: \n{}\n'.format(' '.join([l_waflz_server_path,
                                  '-l', l_limit_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path,
                                  '-j'])))
    time.sleep(1)
    # ------------------------------------------------------
    # yield...
    # ------------------------------------------------------
    yield setup_waflz_server_limit
    # ------------------------------------------------------
    # tear down
    # ------------------------------------------------------
    l_code, l_out, l_err = run_command('kill -9 %d'%(l_subproc.pid))
    time.sleep(0.5)

# ------------------------------------------------------------------------------
# Test geo condition group
# ------------------------------------------------------------------------------
def test_geo_condition_group(setup_waflz_server):
    # ------------------------------------------------------
    # Make 2 request in 2 sec from brazil IP.
    # 3rd request should get rate limited
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'limitzgeo.com',
                 'waf-scopes-id': '0053',
                 'x-waflz-ip':'200.196.153.102'}
    for x in range(2):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200

    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'geo ddos enforcement\n'

    # Make a request from US ip for the same 
    # scope during enforcement
    # window. Request should get through
    l_headers['x-waflz-ip'] = '34.200.39.53'
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200

    # Change to US ip and make requests above threshold.
    # Requests shouldn't get blocked
    l_headers['x-waflz-ip'] = '34.200.39.53'
    for x in range(5):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200

    #sleep through enforcement period
    time.sleep(2)
# ------------------------------------------------------------------------------
# Test asn condition group
# ------------------------------------------------------------------------------
def test_asn_condition_group(setup_waflz_server):
    # ------------------------------------------------------
    # Make 2 request in 2 sec from Japan IP.
    # 3rd request should get rate limited
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.txt?version=2.2.2'
    l_headers = {'host': 'limitzasn.com',
                 'waf-scopes-id': '0053',
                 'x-waflz-ip':'202.32.115.5'}
    # ------------------------------------------------------
    # Make 2 request in 2 sec from Japan IP & different file
    # ext, .txt and .js. They both should contribute to counts
    # because of condition groups
    # ------------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_uri = G_TEST_HOST+'/test.js?version=2.2.2'
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # 3rd request should get rate limited
    # ------------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert l_r.text == 'asn ddos enforcement\n'
     # ------------------------------------------------------
    # 4rd request should go through because of diff file_ext
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # Make a request from US ip & different file_ext for
    # the same scope during enforcement
    # window. Request should get through
    # ------------------------------------------------------
    l_headers['x-waflz-ip'] = '34.200.39.53'
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200

    # Change to US ip and make requests above threshold.
    # Requests shouldn't get blocked
    l_uri = G_TEST_HOST+'/test.html'
    l_headers['x-waflz-ip'] = '34.200.39.53'
    for x in range(5):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200

    #sleep through enforcement period
    time.sleep(2)
# ------------------------------------------------------------------------------
# Test both geo and asn in single condition group
# ------------------------------------------------------------------------------
def test_asn_and_geo_cg(setup_waflz_server_limit):
    # ------------------------------------------------------
    # Make 2 request in 2 sec from US IP and ASN 15133.
    # 3rd request should get rate limited
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'x-waflz-ip':'192.229.234.2'}
    for x in range(2):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200

    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403

    # Sleep through enforcement period 
    time.sleep(2)

    # Make single request again. should go through
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200

    # Make 4 request from US ip, but from different
    # ASN. All requests should go through
    l_headers['x-waflz-ip'] = '162.115.42.1'
    for x in range(4):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200
# ------------------------------------------------------------------------------
# Test both query params and cookies in single condition group
# ------------------------------------------------------------------------------
def test_query_and_cookie_conditions(setup_waflz_server):
    # ------------------------------------------------------
    # Make 4 request in 2 sec from US IP and ASN 15133.
    # should not be rate limited because its missing the
    # condition groups
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'host': 'limitzquerycookie.com',
        'waf-scopes-id': '0053',
        'x-waflz-ip':'202.32.115.5'
    }
    for _ in range(4):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200
    # ------------------------------------------------------
    # add the condition groups
    # ------------------------------------------------------
    l_params = {"exists": "banana"}
    l_cookies = {"test": "present"} 
    # ------------------------------------------------------
    # Make 2 request in 2 sec from US IP and ASN 15133.
    # should make a rate limit
    # ------------------------------------------------------
    for _ in range(2):
        l_r = requests.get(l_uri, params=l_params, headers=l_headers, cookies=l_cookies)
        assert l_r.status_code == 200
    # ------------------------------------------------------
    # next request should get rate limited
    # ------------------------------------------------------
    l_r = requests.get(l_uri, params=l_params, headers=l_headers, cookies=l_cookies)
    assert l_r.status_code == 403
    # ------------------------------------------------------
    # change cookie val
    # ------------------------------------------------------
    l_cookies = {"test": "diff"} 
    # ------------------------------------------------------
    # request should get through
    # ------------------------------------------------------
    l_r = requests.get(l_uri, params=l_params, headers=l_headers, cookies=l_cookies)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # request should get through without cookies
    # ------------------------------------------------------
    l_r = requests.get(l_uri, params=l_params, headers=l_headers)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # original request still get rate limited
    # ------------------------------------------------------
    l_cookies = {"test": "present"} 
    l_r = requests.get(l_uri, params=l_params, headers=l_headers, cookies=l_cookies)
    assert l_r.status_code == 403
# ------------------------------------------------------------------------------
# Test ja3 condition
# ------------------------------------------------------------------------------
def test_ja3_condition(setup_waflz_server):
    # ------------------------------------------------------
    # Make 2 request in 2 sec from the same ja3 to create
    # an enforcer
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'host': 'limitzja3.com',
        'waf-scopes-id': '0053',
        'x-waflz-ja3':'first_ja3'
    }
    for _ in range(2):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200
    # ------------------------------------------------------
    # next request should get rate limited
    # ------------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    # ------------------------------------------------------
    # change cookie val
    # ------------------------------------------------------
    l_headers['x-waflz-ja3'] = "second_ja3"
    # ------------------------------------------------------
    # request should get through
    # ------------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # original request still get rate limited
    # ------------------------------------------------------
    l_headers['x-waflz-ja3'] = "first_ja3"
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
# ------------------------------------------------------------------------------
# Test multiple condition groups in negated match
# ------------------------------------------------------------------------------
def test_negated_cg(setup_waflz_server):
# ----------------------------------------------------------
    # ------------------------------------------------------
    # Make 4 request which doesn't match any of the
    # condition groups. Since its negated match, it should
    # be rate limited. It should be counted only once and
    # hence we need to make 4 requests to get rate limited
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'host': 'limitzcg.com',
        'waf-scopes-id': '0053',
        'x-waflz-ip':'202.32.115.5'
    }
    for _ in range(3):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200
    # ------------------------------------------------------
    # next request should get rate limited
    # ------------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    # ------------------------------------------------------
    # add the condition group. Only 1 CG will match
    # the rest should still match, count and exit
    # ------------------------------------------------------
    l_headers['x-waflz-ip'] = '5.15.22.155'
    # ------------------------------------------------------
    # Make 3 request should not make a rate limit
    # ------------------------------------------------------
    for _ in range(3):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200
    # ------------------------------------------------------
    # next request should get rate limited
    # ------------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    # ------------------------------------------------------
    # add all cg to match, no rate limit
    # ------------------------------------------------------
    l_headers['User-Agent'] = 'Screaming Frog SEO Spider'
    l_uri = G_TEST_HOST+'/test.pdf'
    # ------------------------------------------------------
    # all 10 request should get through
    # ------------------------------------------------------
    for _ in range(10):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200
# ------------------------------------------------------------------------------
# Test bot score condition
# ------------------------------------------------------------------------------
def test_bot_score_condition(setup_waflz_server):
    # ------------------------------------------------------
    # Make 5 request that should go through without getting
    # enforced on
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'host': 'rl_blackbox_test.com',
        'waf-scopes-id': '0100',
        'x-waflz-ip':'5.15.22.155',
        'User-Agent': 'custom_ip_bot_score',
    }
    for _ in range(5):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200
    # ------------------------------------------------------
    # now lets make request from an ip with a high bot score
    # ------------------------------------------------------
    l_headers['x-waflz-ip'] = '123.45.678.91'
    for _ in range(2):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200
    # ------------------------------------------------------
    # enforcement on third request
    # ------------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
