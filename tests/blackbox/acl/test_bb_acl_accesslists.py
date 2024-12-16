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
    l_acl_path = os.path.realpath(os.path.join(l_file_path, 'test_bb_acl_settings.acl.json'))
    l_waflz_server_path = os.path.abspath(os.path.join(l_file_path, '../../../build/util/waflz_server/waflz_server'))
    l_geoip2city_path = os.path.abspath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-City.mmdb'))
    l_geo_asn_path = os.path.abspath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-ASN.mmdb'))
    l_subproc = subprocess.Popen([l_waflz_server_path,
                                  '-a', l_acl_path, '-g', l_geoip2city_path, '-s', l_geo_asn_path])
    print('cmd: \n{}\n'.format(' '.join([l_waflz_server_path,
                                  '-a', l_acl_path, '-g', l_geoip2city_path, '-s', l_geo_asn_path])))
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
# test_bb_acl_accesslists_01_interactions
# ------------------------------------------------------------------------------
def test_bb_acl_accesslists_01_interactions(setup_waflz_server):
    # ------------------------------------------------------
    # whitelist
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'myhost.com',
                 'User-Agent': 'dogs are cool'
                }
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'status' in l_r_json
    assert l_r_json['status'] == 'ok'
    # ------------------------------------------------------
    # accesslist allow
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'myhost.com',
                 'User-Agent': 'monkeys are cool'
                }
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'status' in l_r_json
    assert l_r_json['status'] == 'ok'
    # ------------------------------------------------------
    # accesslist block
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'myhost.com',
                 'User-Agent': 'monkeys are bad'
                }
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    assert 'Accesslist deny' in l_r_json['rule_msg']
    # ------------------------------------------------------
    # blacklist block
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'myhost.com',
                 'User-Agent': 'cats are cool'
                }
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    assert 'Blacklist User-Agent match' in l_r_json['rule_msg']
    # ------------------------------------------------------
    # accesslist allow
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'myhost.com',
                 'x-waflz-ip': '129.78.46.6',
                 'User-Agent': 'monkeys are cool'
                }
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'status' in l_r_json
    assert l_r_json['status'] == 'ok'
    # ------------------------------------------------------
    # accesslist deny
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'host': 'myhost.com',
                 'x-waflz-ip': '115.146.80.0'
                }
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    assert 'Accesslist deny' in l_r_json['rule_msg']
    l_matched_var_name = 'Accesslist'
    l_matched_var_value = 'ja4 subdivision user-agent'
    assert l_matched_var_name == base64.b64decode(l_r_json['sub_event'][0]['matched_var']['name']).decode("utf-8")
    assert l_matched_var_value == base64.b64decode(l_r_json['sub_event'][0]['matched_var']['value']).decode("utf-8")
    # ------------------------------------------------------
    # Whitelist allow KR IP Address with blacklist UA 
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'x-waflz-ip': '147.46.0.0',
                 'host': 'myhost.com',
                 'User-Agent': 'cats are cool'
                }
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'status' in l_r_json
    assert l_r_json['status'] == 'ok'
    # ------------------------------------------------------
    # Whitelist allow RU-MOW IP Address with blacklist UA 
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'x-waflz-ip': '188.44.49.115',
                 'host': 'myhost.com',
                 'User-Agent': 'cats are cool'
                }
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'status' in l_r_json
    assert l_r_json['status'] == 'ok'
    # ------------------------------------------------------
    # IP Blacklist block AU-NSW IP
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'x-waflz-ip': '129.94.231.205',
                 'host': 'myhost.com'
                }
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    assert 'Blacklist IP match' in l_r_json['rule_msg']
    # ------------------------------------------------------
    # Accesslist Allow GB-EDH IP
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'x-waflz-ip': '84.19.242.119',
                 'host': 'myhost.com'
                }
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'status' in l_r_json
    assert l_r_json['status'] == 'ok'
    # ------------------------------------------------------
    # Subdivision Blacklist Block GB-ENG/LAN IP
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {'x-waflz-ip': '188.31.121.90',
                 'host': 'myhost.com'
                }
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    assert 'Blacklist Subdivision match' in l_r_json['rule_msg']

# ------------------------------------------------------------------------------
# 
# ------------------------------------------------------------------------------
def test_ja4_lists(setup_waflz_server):
    """
    Testing ja4 {white,access}list
    """
    # ------------------------------------------------------
    # whitelist
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {
        'host': 'myhost.com',
        'x-waflz-ja4': "still can access ja4"
    }
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'status' in l_r_json
    assert l_r_json['status'] == 'ok'
    # ------------------------------------------------------
    # accesslist
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {
        'host': 'myhost.com',
        'x-waflz-ja4': "can access ja4"
    }
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'status' in l_r_json
    assert l_r_json['status'] == 'ok'
    # ------------------------------------------------------
    # not acesslist
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {
        'host': 'myhost.com',
        'x-waflz-ja4': "not access list ja4"
    }
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert len(l_r_json) > 0
    assert 'Accesslist deny' in l_r_json['rule_msg']
