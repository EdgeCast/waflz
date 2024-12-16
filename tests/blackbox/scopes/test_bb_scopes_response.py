#!/usr/bin/env python3
'''Test scopes with response rules'''
# ------------------------------------------------------------------------------
# imports
# ------------------------------------------------------------------------------
import pytest
import subprocess
import time
import pathlib
import requests
# ------------------------------------------------------------------------------
# constants
# ------------------------------------------------------------------------------
G_TEST_HOST = 'http://127.0.0.1'
G_TEST_HOST_STARTING_PORT = 12345
G_STATIC_TEST_HOST = G_TEST_HOST + ":" + str(G_TEST_HOST_STARTING_PORT)
G_ORIGIN_HOST = 'http://127.0.0.1:8080'
# ------------------------------------------------------------------------------
# setup scopez server with scopes dir
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_waflz_with_origin():
    # ------------------------------------------------------
    # file paths
    # ------------------------------------------------------
    l_tests_dir = pathlib.Path(__file__).parent.parent.parent
    l_waf_dir = l_tests_dir / "data" / "waf"
    l_scopes_file = l_waf_dir / "conf" / "scopes" / "0050.scopes.json"
    l_conf_dir = l_waf_dir / "conf"
    l_ruleset_dir = l_waf_dir / "ruleset"
    l_city_geoip = l_waf_dir / "db" / "GeoLite2-City.mmdb"
    l_asn_geoip = l_waf_dir / "db" / "GeoLite2-ASN.mmdb"
    l_waflz_server = l_tests_dir.parent / "build" / "util" / "waflz_server" / "waflz_server"
    # ------------------------------------------------------
    # create origin
    # ------------------------------------------------------
    l_origin_args = [str(l_tests_dir / "blackbox" / "fake_origin.py"), '-p', "8080"]
    print(" ".join(l_origin_args))
    l_origin_proc = subprocess.Popen(l_origin_args)
    # ------------------------------------------------------
    # create waflz_server
    # ------------------------------------------------------
    l_waflz_args = [
        str(l_waflz_server),
        '-d', str(l_conf_dir),
        '-b', str(l_scopes_file),
        '-r', str(l_ruleset_dir),
        '-g', str(l_city_geoip),
        '-s', str(l_asn_geoip),
        '-E', "localhost:7070",
        '-p', str(G_TEST_HOST_STARTING_PORT),
        '-u', G_ORIGIN_HOST
    ]
    print(" ".join(l_waflz_args))
    l_waflz_server_proc = subprocess.Popen(l_waflz_args)
    time.sleep(1)
    # ------------------------------------------------------
    # yield...
    # ------------------------------------------------------
    yield l_origin_proc, l_waflz_server_proc
    # ------------------------------------------------------
    # tear down
    # ------------------------------------------------------
    l_origin_proc.kill()
    l_waflz_server_proc.kill()
# ------------------------------------------------------------------------------
# setup scopez server with scopes dir
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_multi_waflz_with_origin():
    # ------------------------------------------------------
    # file paths
    # ------------------------------------------------------
    l_tests_dir = pathlib.Path(__file__).parent.parent.parent
    l_waf_dir = l_tests_dir / "data" / "waf"
    l_scopes_file = l_waf_dir / "conf" / "scopes" / "0050.scopes.json"
    l_conf_dir = l_waf_dir / "conf"
    l_ruleset_dir = l_waf_dir / "ruleset"
    l_city_geoip = l_waf_dir / "db" / "GeoLite2-City.mmdb"
    l_asn_geoip = l_waf_dir / "db" / "GeoLite2-ASN.mmdb"
    l_waflz_server = l_tests_dir.parent / "build" / "util" / "waflz_server" / "waflz_server"
    # ------------------------------------------------------
    # create origin
    # ------------------------------------------------------
    l_origin_args = [str(l_tests_dir / "blackbox" / "fake_origin.py"), '-p', "8080"]
    print(" ".join(l_origin_args))
    l_origin_proc = subprocess.Popen(l_origin_args)
    # ------------------------------------------------------
    # create waflz_server
    # ------------------------------------------------------
    l_waflz_instances = []
    for i_port_offest in range(2):
        l_waflz_args = [
            str(l_waflz_server),
            '-d', str(l_conf_dir),
            '-b', str(l_scopes_file),
            '-r', str(l_ruleset_dir),
            '-g', str(l_city_geoip),
            '-s', str(l_asn_geoip),
            '-E', "localhost:7070",
            '-L', '-I',
            '-p', str(G_TEST_HOST_STARTING_PORT + i_port_offest),
            '-u', G_ORIGIN_HOST
        ]
        print(" ".join(l_waflz_args))
        l_waflz_instances.append(subprocess.Popen(l_waflz_args))
    time.sleep(1)
    # ------------------------------------------------------
    # yield...
    # ------------------------------------------------------
    yield l_origin_proc, l_waflz_instances
    # ------------------------------------------------------
    # tear down
    # ------------------------------------------------------
    l_origin_proc.kill()
    for l_waflz_instance in l_waflz_instances:
        l_waflz_instance.kill()
# ------------------------------------------------------------------------------
# an 0050
# ------------------------------------------------------------------------------
def test_waflz_response_rule(setup_waflz_with_origin):
    # ------------------------------------------------------
    # send normal request
    # ------------------------------------------------------
    l_r = requests.get(
        G_STATIC_TEST_HOST,
        headers={
            'host': 'monkeez.com',
            'waf-scopes-id': '0050',
            'Host': 'test.client.com'
        }
    )
    # ------------------------------------------------------
    # requst should be fine
    # ------------------------------------------------------
    assert l_r.status_code == 200, "host failed: " + l_r.text
    # ------------------------------------------------------
    # response should contain the response phase
    # with every event = null
    # ------------------------------------------------------
    l_r_json = l_r.json()
    assert l_r_json["phase"] == "response"
    assert l_r_json['audit_profile'] == None
    assert l_r_json['prod_profile'] == None
    # ------------------------------------------------------
    # csp headers should be there
    # ------------------------------------------------------
    l_r_csp = l_r.headers.get("Content-Security-Policy")
    assert l_r_csp == "default-src 'none'; img-src: 'self'; report-uri localhost:7070/0050"
    # ------------------------------------------------------
    # csp headers with enforce set to false should not exist
    # ------------------------------------------------------
    assert l_r.headers.get("ghost") is None
    # ------------------------------------------------------
    # send a request that should be blocked at the requests
    # phase
    # ------------------------------------------------------
    l_r = requests.get(
        G_STATIC_TEST_HOST,
        headers={
            'host': 'monkeez.com',
            'waf-scopes-id': '0050',
            'Host': 'test.client.com',
            'User-Agent': '<script>console.log("hello")</script>'
        }
    )
    # ------------------------------------------------------
    # requst should be fine
    # ------------------------------------------------------
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # response should contain the request phase
    # with an prod event
    # ------------------------------------------------------
    l_r_json = l_r.json()
    assert l_r_json["phase"] == "request"
    assert l_r_json['audit_profile'] == None
    l_r_prod_profile = l_r_json.get('prod_profile')
    assert l_r_prod_profile
    assert l_r_prod_profile["sub_event"][0]["rule_id"] == 941100
    assert l_r_prod_profile["sub_event"][0]["rule_msg"] == "XSS Attack Detected via libinjection"
    # ------------------------------------------------------
    # upodate origin to 'leak' a script
    # ------------------------------------------------------
    requests.get(G_ORIGIN_HOST, headers={"x-waflz-set-response": "#! /test"})
    # ------------------------------------------------------
    # send a request that should be blocked at the response
    # phase
    # ------------------------------------------------------
    l_r = requests.get(
        G_STATIC_TEST_HOST,
        headers={
            'host': 'monkeez.com',
            'waf-scopes-id': '0050',
            'Host': 'test.client.com'
        }
    )
    # ------------------------------------------------------
    # requst should be fine
    # ------------------------------------------------------
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # response should contain the response phase
    # with an prod event
    # ------------------------------------------------------
    l_r_json = l_r.json()
    assert l_r_json["phase"] == "response"
    assert l_r_json['audit_profile'] == None
    l_r_prod_profile = l_r_json.get('prod_profile')
    assert l_r_prod_profile
    assert l_r_prod_profile["sub_event"][0]["rule_id"] == 950140
    assert l_r_prod_profile["sub_event"][0]["rule_msg"] == "CGI source code leakage"

# ------------------------------------------------------------------------------
# an 0050
# ------------------------------------------------------------------------------
def test_waflz_response_rate_limiting(setup_waflz_with_origin):
    # ------------------------------------------------------
    # we are going to send a request that gets a 423, which
    # is in the 400-499 range for status code
    # ------------------------------------------------------
    l_headers = {
        'host': 'monkeez.com',
        'waf-scopes-id': '0050',
        'Host': 'test.response_rl.com',
        'x-waflz-ip': '2606:2800:400c:2::7c',
        'x-waflz-set-status': '423'
    }
    # ------------------------------------------------------
    # requst should be fine for two times
    # ------------------------------------------------------
    l_r = requests.get(G_STATIC_TEST_HOST, headers = l_headers)
    assert l_r.status_code == 200, "host failed: " + l_r.text
    assert l_r.json().get("prod_rate_limit") == None
    l_r = requests.get(G_STATIC_TEST_HOST, headers = l_headers)
    assert l_r.status_code == 200, "host failed: " + l_r.text
    assert l_r.json().get("prod_rate_limit") == None
    # ------------------------------------------------------
    # third request should be blocked
    # ------------------------------------------------------
    l_r = requests.get(G_STATIC_TEST_HOST, headers = l_headers)
    assert l_r.status_code == 200, "host failed: " + l_r.text
    l_r_json = l_r.json()
    l_r_prod_rl = l_r_json.get("prod_rate_limit")
    assert l_r_prod_rl != None
    # ------------------------------------------------------
    # third request should have:
    # geo info
    # ip and status code in rl values
    # ------------------------------------------------------
    assert l_r_prod_rl.get("geoip_country_code2") == "US"
    assert l_r_prod_rl.get("matched_rl_values") == "2606:2800:400c:2::7c::400-499,516"
    # ------------------------------------------------------
    # a request with a different ip should not be blocked
    # ------------------------------------------------------
    l_headers.pop("x-waflz-ip")
    l_r = requests.get(G_STATIC_TEST_HOST, headers = l_headers)
    assert l_r.status_code == 200, "host failed: " + l_r.text
    assert l_r.json().get("prod_rate_limit") == None
    # ------------------------------------------------------
    # a request with the same ip but different status code
    # should still be blocked
    # ------------------------------------------------------
    l_headers["x-waflz-ip"] = "2606:2800:400c:2::7c"
    l_headers["x-waflz-set-status"] = "200"
    l_r = requests.get(G_STATIC_TEST_HOST, headers = l_headers)
    assert l_r.status_code == 200, "host failed: " + l_r.text
    l_r_json = l_r.json()
    l_r_prod_rl = l_r_json.get("prod_rate_limit")
    assert l_r_prod_rl != None
    # ------------------------------------------------------
    # request should have:
    # geo info
    # ip and status code in rl values
    # ------------------------------------------------------
    assert l_r_prod_rl.get("geoip_country_code2") == "US"
    assert l_r_prod_rl.get("geoip_asn") == 15133
    assert l_r_prod_rl.get("matched_rl_values") == "2606:2800:400c:2::7c::400-499,516"
    # ------------------------------------------------------
    # wait 2 seconds
    # ------------------------------------------------------
    time.sleep(2)
    # ------------------------------------------------------
    # request should be fine for request not in the status
    # code range
    # ------------------------------------------------------
    for _ in range(6):
        l_r = requests.get(G_STATIC_TEST_HOST, headers = l_headers)
        assert l_r.status_code == 200, "host failed: " + l_r.text
        assert l_r.json().get("prod_rate_limit") == None
    # ------------------------------------------------------
    # set status code 516 - should kick in RL
    # ------------------------------------------------------
    l_headers["x-waflz-set-status"] = "516"
    # ------------------------------------------------------
    # requst with a status code 516 should kick in RL
    # ------------------------------------------------------
    l_r = requests.get(G_STATIC_TEST_HOST, headers = l_headers)
    assert l_r.status_code == 200, "host failed: " + l_r.text
    assert l_r.json().get("prod_rate_limit") == None
    l_r = requests.get(G_STATIC_TEST_HOST, headers = l_headers)
    assert l_r.status_code == 200, "host failed: " + l_r.text
    assert l_r.json().get("prod_rate_limit") == None
    # ------------------------------------------------------
    # third request should be blocked
    # ------------------------------------------------------
    l_r = requests.get(G_STATIC_TEST_HOST, headers = l_headers)
    assert l_r.status_code == 200, "host failed: " + l_r.text
    l_r_json = l_r.json()
    l_r_prod_rl = l_r_json.get("prod_rate_limit")
    assert l_r_prod_rl != None
    # ------------------------------------------------------
    # third request should have:
    # geo info
    # ip and status code in rl values
    # ------------------------------------------------------
    assert l_r_prod_rl.get("geoip_country_code2") == "US"
    assert l_r_prod_rl.get("geoip_asn") == 15133
    assert l_r_prod_rl.get("matched_rl_values") == "2606:2800:400c:2::7c::400-499,516"
    # ------------------------------------------------------
    # wait 2 seconds
    # ------------------------------------------------------
    time.sleep(2)
    # ------------------------------------------------------
    # requst with a status code 516 should kick in RL
    # ------------------------------------------------------
    l_r = requests.get(G_STATIC_TEST_HOST, headers = l_headers)
    assert l_r.status_code == 200, "host failed: " + l_r.text
    assert l_r.json().get("prod_rate_limit") == None
    l_r = requests.get(G_STATIC_TEST_HOST, headers = l_headers)
    assert l_r.status_code == 200, "host failed: " + l_r.text
    assert l_r.json().get("prod_rate_limit") == None
    # ------------------------------------------------------
    # set status code 486 - should still kick in RL because
    # of the range
    # ------------------------------------------------------
    l_headers["x-waflz-set-status"] = "486"
    # ------------------------------------------------------
    # third request should be blocked
    # ------------------------------------------------------
    l_r = requests.get(G_STATIC_TEST_HOST, headers = l_headers)
    assert l_r.status_code == 200, "host failed: " + l_r.text
    l_r_json = l_r.json()
    l_r_prod_rl = l_r_json.get("prod_rate_limit")
    assert l_r_prod_rl != None
    # ------------------------------------------------------
    # third request should have:
    # geo info
    # ip and status code in rl values
    # ------------------------------------------------------
    assert l_r_prod_rl.get("geoip_country_code2") == "US"
    assert l_r_prod_rl.get("geoip_asn") == 15133
    assert l_r_prod_rl.get("matched_rl_values") == "2606:2800:400c:2::7c::400-499,516"
    # ------------------------------------------------------
    # sleep so the next test is not affected by this one
    # ------------------------------------------------------
    time.sleep(2)

# ------------------------------------------------------------------------------
# 
# ------------------------------------------------------------------------------
def test_waflz_response_rate_limiting_multi_host(setup_multi_waflz_with_origin):
    """
    testing that status code will work across host using the
    same lmdb
    """
    l_first_host = G_TEST_HOST + ":" + str(G_TEST_HOST_STARTING_PORT)
    l_second_host = G_TEST_HOST + ":" + str(G_TEST_HOST_STARTING_PORT + 1)
    # ------------------------------------------------------
    # we are going to send a request that gets a 423, which
    # is in the 400-499 range for status code
    # ------------------------------------------------------
    l_headers = {
        'host': 'monkeez.com',
        'waf-scopes-id': '0050',
        'Host': 'test.response_rl.com',
        'x-waflz-ip': '2606:2800:400c:2::7c',
        'x-waflz-set-status': '423'
    }
    # ------------------------------------------------------
    # requst should be fine for two times
    # ------------------------------------------------------
    l_r = requests.get(l_first_host, headers = l_headers)
    assert l_r.status_code == 200, "host failed: " + l_r.text
    assert l_r.json().get("prod_rate_limit") == None
    l_r = requests.get(l_first_host, headers = l_headers)
    assert l_r.status_code == 200, "host failed: " + l_r.text
    assert l_r.json().get("prod_rate_limit") == None
    # ------------------------------------------------------
    # third request should be blocked
    # ------------------------------------------------------
    l_r = requests.get(l_first_host, headers = l_headers)
    assert l_r.status_code == 200, "host failed: " + l_r.text
    l_r_json = l_r.json()
    l_r_prod_rl = l_r_json.get("prod_rate_limit")
    assert l_r_prod_rl != None
    # ------------------------------------------------------
    # third request should have:
    # geo info
    # ip and status code in rl values
    # ------------------------------------------------------
    assert l_r_prod_rl.get("geoip_country_code2") == "US"
    assert l_r_prod_rl.get("matched_rl_values") == "2606:2800:400c:2::7c::400-499,516"
    # ------------------------------------------------------
    # first request to other waflz should be blocked
    # ------------------------------------------------------
    print("-"*45)
    l_r = requests.get(l_second_host, headers = l_headers)
    assert l_r.status_code == 200, "host failed: " + l_r.text
    l_r_json = l_r.json()
    l_r_prod_rl = l_r_json.get("prod_rate_limit")
    assert l_r_prod_rl != None
    # ------------------------------------------------------
    # third request should have:
    # geo info
    # ip and status code in rl values
    # ------------------------------------------------------
    assert l_r_prod_rl.get("geoip_country_code2") == "US"
    assert l_r_prod_rl.get("matched_rl_values") == "2606:2800:400c:2::7c::400-499,516"
