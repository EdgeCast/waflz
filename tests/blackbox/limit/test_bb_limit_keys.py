#!/usr/bin/env python3
'''Test limit '''
# ------------------------------------------------------------------------------
# imports
# ------------------------------------------------------------------------------
import pytest
import subprocess
import time
import requests
import time
import pathlib
import base64
# ------------------------------------------------------------------------------
# constants
# ------------------------------------------------------------------------------
G_TEST_HOST = 'http://127.0.0.1:12345'
# ------------------------------------------------------------------------------
# setup waflz server with limit
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_waflz_server():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_blackbox_dir = pathlib.Path(__file__).absolute().parent.parent
    l_limit_file = l_blackbox_dir.parent / "data" / "waf" / "conf" / "limit" / "0100-keys.limit.json"
    l_city_db = l_blackbox_dir.parent / "data" / "waf" / "db" / "GeoLite2-City.mmdb"
    l_isp_db = l_blackbox_dir.parent / "data" / "waf" / "db" / "GeoLite2-ASN.mmdb"
    l_waflz_server_path = l_blackbox_dir.parent.parent / "build" / "util" / "waflz_server" / "waflz_server"
    # ------------------------------------------------------
    # create waflz server cmd
    # ------------------------------------------------------
    l_waflz_server_cmd = [
        str(l_waflz_server_path),
        '-l', str(l_limit_file),
        '-g', str(l_city_db),
        '-s', str(l_isp_db)
    ]
    # ------------------------------------------------------
    # create waflz server process
    # ------------------------------------------------------
    print(f"cmd: {' '.join(l_waflz_server_cmd)}")
    l_subproc = subprocess.Popen(l_waflz_server_cmd)
    time.sleep(1)
    # ------------------------------------------------------
    # yield...
    # ------------------------------------------------------
    yield setup_waflz_server
    # ------------------------------------------------------
    # tear down
    # ------------------------------------------------------
    l_subproc.kill()
# ------------------------------------------------------------------------------
# setup waflz server with limit
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_waflz_server_with_scopes():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_blackbox_dir = pathlib.Path(__file__).absolute().parent.parent
    l_scope_file = l_blackbox_dir.parent / "data" / "waf" / "conf" / "scopes" / "0100.scopes.json"
    l_data_dir = l_blackbox_dir.parent / "data" / "waf" / "conf"
    l_city_db = l_blackbox_dir.parent / "data" / "waf" / "db" / "GeoLite2-City.mmdb"
    l_isp_db = l_blackbox_dir.parent / "data" / "waf" / "db" / "GeoLite2-ASN.mmdb"
    l_waflz_server_path = l_blackbox_dir.parent.parent / "build" / "util" / "waflz_server" / "waflz_server"
    # ------------------------------------------------------
    # create waflz server cmd
    # ------------------------------------------------------
    l_waflz_server_cmd = [
        str(l_waflz_server_path),
        '-b', str(l_scope_file),
        '-d', str(l_data_dir),
        '-g', str(l_city_db),
        '-s', str(l_isp_db)
    ]
    # ------------------------------------------------------
    # create waflz server process
    # ------------------------------------------------------
    print(f"cmd: {' '.join(l_waflz_server_cmd)}")
    l_subproc = subprocess.Popen(l_waflz_server_cmd)
    time.sleep(1)
    # ------------------------------------------------------
    # yield...
    # ------------------------------------------------------
    yield setup_waflz_server
    # ------------------------------------------------------
    # tear down
    # ------------------------------------------------------
    l_subproc.kill()
# ------------------------------------------------------------------------------
# test no partial matching happens
# ------------------------------------------------------------------------------
def test_no_partial_matching(setup_waflz_server):
    # ------------------------------------------------------
    # make request to waflz using the same ip and auth header
    # ------------------------------------------------------
    l_uri = f"{G_TEST_HOST}/test.html"
    l_headers = {
        'x-waflz-ip':'200.196.153.102',
        "Authorization": "test :D"
    }
    # ------------------------------------------------------
    # make request to waflz that would exceed the limit
    # if all the portions of the keys were present.
    # none should trip the limit
    # ------------------------------------------------------
    for _ in range(50):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200
    # ------------------------------------------------------
    # add another portion of the keys
    # ------------------------------------------------------
    l_uri += '?test="another_value"'
    # ------------------------------------------------------
    # make request to waflz that would exceed the limit
    # if all the portions of the keys were present.
    # none should trip the limit
    # ------------------------------------------------------
    for _ in range(50):
        l_r = requests.get(l_uri, headers=l_headers)
        assert l_r.status_code == 200
    # ------------------------------------------------------
    # add the missing portions of the keys
    # ------------------------------------------------------
    l_cookies = { "test_cookie": "value" }
    # ------------------------------------------------------
    # make request to waflz and get enforced on the 4th
    # request
    # ------------------------------------------------------
    for i_index in range(4):
        l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
        assert l_r.status_code == [200, 200, 200, 403][i_index]
    # ------------------------------------------------------
    # sleep to remove enforcements
    # ------------------------------------------------------
    time.sleep(2)
    # ------------------------------------------------------
    # assert enforcements are removed
    # ------------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
    assert l_r.status_code == 200
# ------------------------------------------------------------------------------
# test header counting group
# ------------------------------------------------------------------------------
def test_header_counting_group(setup_waflz_server):
    # ------------------------------------------------------
    # make request to waflz using the same ip and auth header
    # ------------------------------------------------------
    l_uri = f"{G_TEST_HOST}/test.html?test=2"
    l_headers = {
        'x-waflz-ip':'200.196.153.102',
        "Authorization": "test :D"
    }
    l_cookies = { "test_cookie": "value" }
    # ------------------------------------------------------
    # make request to waflz to get close to limit
    # ------------------------------------------------------
    for _ in range(3):
        l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
        assert l_r.status_code == 200
    # ------------------------------------------------------
    # make request to waflz and get enforced
    # ------------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
    assert l_r.status_code == 403
    # ------------------------------------------------------
    # change the authorization header, and confirm we dont
    # get blocked
    # ------------------------------------------------------
    l_headers["Authorization"] = "new value :D"
    l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # make request to waflz and get enforced
    # ------------------------------------------------------
    for i_index in range(3):
        l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
        assert l_r.status_code == [200, 200, 403][i_index]
    # ------------------------------------------------------
    # sleep to remove enforcements
    # ------------------------------------------------------
    time.sleep(2)
    # ------------------------------------------------------
    # assert enforcements are removed
    # ------------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
    assert l_r.status_code == 200
# ------------------------------------------------------------------------------
# test cookie counting group
# ------------------------------------------------------------------------------
def test_cookie_counting_group(setup_waflz_server):
    # ------------------------------------------------------
    # make request to waflz using the same ip and cookies
    # ------------------------------------------------------
    l_uri = f"{G_TEST_HOST}/test.html?test=42"
    l_headers = {
        'x-waflz-ip':'200.196.153.102',
        'Authorization': "another_value",
    }
    l_cookies = {
        "test_cookie": "banana",
        "another_cookie": "yuck"
    }
    # ------------------------------------------------------
    # make request to waflz to get close to limit
    # ------------------------------------------------------
    for _ in range(3):
        l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
        assert l_r.status_code == 200
    # ------------------------------------------------------
    # make request to waflz and get enforced
    # ------------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
    assert l_r.status_code == 403
    # ------------------------------------------------------
    # change the authorization header, and confirm we dont
    # get blocked
    # ------------------------------------------------------
    l_cookies["test_cookie"] = "banana phone!"
    l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # make request to waflz and get enforced
    # ------------------------------------------------------
    for i_index in range(3):
        l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
        assert l_r.status_code == [200, 200, 403][i_index]
    # ------------------------------------------------------
    # sleep to remove enforcements
    # ------------------------------------------------------
    time.sleep(2)
    # ------------------------------------------------------
    # assert enforcements are removed
    # ------------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
    assert l_r.status_code == 200
# ------------------------------------------------------------------------------
# test arg counting group
# ------------------------------------------------------------------------------
def test_arg_counting_group(setup_waflz_server):
    # ------------------------------------------------------
    # make request to waflz using the same ip and query
    # ------------------------------------------------------
    l_uri = f'{G_TEST_HOST}/test.html?test="banana"&another=2'
    l_headers = {
        'x-waflz-ip':'200.196.153.102',
        "Authorization": "test :D"
    }
    l_cookies = { "test_cookie": "value" }
    # ------------------------------------------------------
    # make request to waflz to get close to limit
    # ------------------------------------------------------
    for _ in range(3):
        l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
        assert l_r.status_code == 200
    # ------------------------------------------------------
    # make request to waflz and get enforced
    # ------------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
    assert l_r.status_code == 403
    # ------------------------------------------------------
    # change the authorization header, and confirm we dont
    # get blocked
    # ------------------------------------------------------
    l_uri = f'{G_TEST_HOST}/test.html?test="banana phone"&another=2'
    l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # make request to waflz and get enforced
    # ------------------------------------------------------
    for i_index in range(3):
        l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
        assert l_r.status_code == [200, 200, 403][i_index]
    # ------------------------------------------------------
    # sleep to remove enforcements
    # ------------------------------------------------------
    time.sleep(2)
    # ------------------------------------------------------
    # assert enforcements are removed
    # ------------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
    assert l_r.status_code == 200
# ------------------------------------------------------------------------------
# test ja3 counting group
# ------------------------------------------------------------------------------
def test_ja3_counting_group(setup_waflz_server):
    # ------------------------------------------------------
    # make request to waflz using the same ip and ja3
    # ------------------------------------------------------
    l_uri = f"{G_TEST_HOST}/test.html?test=243"
    l_headers = {
        'x-waflz-ip':'200.196.153.102',
        'Authorization': "test_value",
        "x-waflz-ja3": 'numba_1'
    }
    l_cookies = { "test_cookie": "value" }
    # ------------------------------------------------------
    # make request to waflz to get close to limit
    # ------------------------------------------------------
    for _ in range(3):
        l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
        assert l_r.status_code == 200
    # ------------------------------------------------------
    # make request to waflz and get enforced
    # ------------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
    assert l_r.status_code == 403
    # ------------------------------------------------------
    # change the authorization header, and confirm we dont
    # get blocked
    # ------------------------------------------------------
    l_headers["x-waflz-ja3"] = 'numba_2'
    l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # make request to waflz and get enforced
    # ------------------------------------------------------
    for i_index in range(3):
        l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
        assert l_r.status_code == [200, 200, 403][i_index]
    # ------------------------------------------------------
    # sleep to remove enforcements
    # ------------------------------------------------------
    time.sleep(2)
    # ------------------------------------------------------
    # assert enforcements are removed
    # ------------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
    assert l_r.status_code == 200
# ------------------------------------------------------------------------------
# test multiple counting group
# ------------------------------------------------------------------------------
def test_multi_counting_group(setup_waflz_server):
    # ------------------------------------------------------
    # make request to waflz using the same ip and auth header
    # and ja3
    # ------------------------------------------------------
    l_uri = f"{G_TEST_HOST}/test.html?test=24"
    l_headers = {
        'x-waflz-ip':'200.196.153.102',
        'Authorization': 'test :D',
        "x-waflz-ja3": 'numba_1'
    }
    l_cookies = { "test_cookie": "value" }
    # ------------------------------------------------------
    # make request to waflz to get close to limit
    # ------------------------------------------------------
    for _ in range(3):
        l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
        assert l_r.status_code == 200
    # ------------------------------------------------------
    # make request to waflz and get enforced
    # ------------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
    assert l_r.status_code == 403
    # ------------------------------------------------------
    # change the ja3 and confirm we dont get blocked
    # ------------------------------------------------------
    l_headers["x-waflz-ja3"] = 'numba_2'
    l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # make request to waflz and get enforced
    # ------------------------------------------------------
    for i_index in range(3):
        l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
        assert l_r.status_code == [200, 200, 403][i_index]
    # ------------------------------------------------------
    # make the original request to see we are still blocked
    # ------------------------------------------------------
    l_headers["x-waflz-ja3"] = 'numba_1'
    l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
    assert l_r.status_code == 403
    # ------------------------------------------------------
    # change the auth
    # ------------------------------------------------------
    l_headers["Authorization"] = 'another one :D'
    l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # make request to waflz and get enforced
    # ------------------------------------------------------
    for i_index in range(3):
        l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
        assert l_r.status_code == [200, 200, 403][i_index]
    # ------------------------------------------------------
    # change both dims
    # ------------------------------------------------------
    l_headers["Authorization"] = 'unauthorized!'
    l_headers["x-waflz-ja3"] = 'numba 3'
    l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # make request to waflz and get enforced
    # ------------------------------------------------------
    for i_index in range(3):
        l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
        assert l_r.status_code == [200, 200, 403][i_index]
    # ------------------------------------------------------
    # sleep to remove enforcements
    # ------------------------------------------------------
    time.sleep(2)
    # ------------------------------------------------------
    # assert enforcements are removed
    # ------------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
    assert l_r.status_code == 200
# ------------------------------------------------------------------------------
# test matched rl values are found in alert
# ------------------------------------------------------------------------------
def test_rl_values_key_in_alert(setup_waflz_server_with_scopes):
    # ------------------------------------------------------
    # make request to waflz that will get enforced on by
    # the keys limit
    # ------------------------------------------------------
    l_uri = f"{G_TEST_HOST}/test.html?test=24"
    l_headers = {
        'x-waflz-ip':'200.196.153.102',
        'User-Agent': 'hi',
        'Host': 'rl_blackbox_test.com',
        'Authorization': 'test :D',
        "x-waflz-ja3": 'numba_1'
    }
    l_cookies = { "test_cookie": "value" }
    # ------------------------------------------------------
    # make request to waflz to get close to limit
    # ------------------------------------------------------
    for _ in range(3):
        l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
        assert l_r.status_code == 200
        l_resp_json = l_r.json()
        assert l_resp_json["audit_rate_limit"] is None
    # ------------------------------------------------------
    # make request to waflz and get enforced
    # ------------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers, cookies=l_cookies)
    assert l_r.status_code == 200
    l_resp_json = l_r.json()
    assert l_resp_json["audit_rate_limit"] is not None
    # ------------------------------------------------------
    # check for asn
    # ------------------------------------------------------
    l_rate_limit_event = l_resp_json["audit_rate_limit"]
    assert l_rate_limit_event.get("geoip_asn") == 15256
    # ------------------------------------------------------
    # assert that the log contains the values that tripped
    # the limit
    # ------------------------------------------------------
    l_rate_limit_key = l_rate_limit_event.get("matched_rl_values")
    assert l_rate_limit_key == "200.196.153.102::hi::15256::test :D::numba_1::t12i7512h2_479067518aa3_1188e8eced89::value::24"
    # ------------------------------------------------------
    # assert that threshold/duration is added to the alert
    # ------------------------------------------------------
    l_threshold = l_rate_limit_event.get('limit').get("num")
    assert l_threshold == 3
    l_duration_sec = l_rate_limit_event.get("limit").get("duration_sec")
    assert l_duration_sec == 2
    # ------------------------------------------------------
    # assert that the log contains ja4
    # ------------------------------------------------------
    l_ja4_info = base64.b64decode(l_rate_limit_event.get("req_info").get('virt_ssl_client_ja4'))
    assert str(l_ja4_info, encoding='utf-8') == "t12i7512h2_479067518aa3_1188e8eced89"

