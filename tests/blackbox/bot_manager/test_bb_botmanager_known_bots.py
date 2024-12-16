#!/usr/bin/env python3
'''Test bot_manager mode and known bots'''
# ------------------------------------------------------------------------------
# Imports
# ------------------------------------------------------------------------------
import subprocess
import os
import json
import time
import re
import requests
import pytest
import base64
import pathlib
import datetime
try:
    from html.parser import HTMLParser
except ImportError:
    # python2 fallback
    from HTMLParser import HTMLParser
# ------------------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------------------
G_TEST_HOST = 'http://127.0.0.1:12345'
# ------------------------------------------------------------------------------
# parse html
# ------------------------------------------------------------------------------
class html_parse(HTMLParser):
   #Store data
   m_data = ""
   def handle_data(self, data):
        if data.startswith('function'):
            self.m_data = data

class custom_html_parse(HTMLParser):
    m_data = ""
    def handle_data(self, data):
        if data.startswith('window.onload'):
            self.m_data = data
# ------------------------------------------------------------------------------
# Solve browser challenge
# TODO: This is based on assumption that the problem will be a simple addition
# operation in js. If problem changes in data file, this needs to be updated
# ------------------------------------------------------------------------------
def solve_challenge(a_html):
    l_problem_p = re.search('val =.[0-9]{3}\+[0-9]{3}', a_html)
    l_problem_vars = l_problem_p.group(0).split("=")[-1].split('+')
    l_solution = int(l_problem_vars[0]) + int(l_problem_vars[1])
    l_ectoken_p = re.search('__ecbmchid=(.*?)"', a_html)
    l_ectoken = l_ectoken_p.group(0)
    return '__eccha=' + str(l_solution) + ';' + l_ectoken[:-1]
# ------------------------------------------------------------------------------
# solve_challenge_for_request
# ------------------------------------------------------------------------------
def helper_bot_request_for_challenge(a_user_agent, a_ip):
    # ------------------------------------------------------
    # test for challenge
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'host': 'mybotmanager.com',
        'user-agent': a_user_agent,
        'x-waflz-ip': a_ip,
        'waf-scopes-id': '0052'
    }
    l_r = requests.get(l_uri, headers=l_headers)
    # ------------------------------------------------------
    # assert we were challenged
    # ------------------------------------------------------
    assert l_r.status_code == 401
    # ------------------------------------------------------
    # solve challenge
    # ------------------------------------------------------
    l_parser = html_parse()
    l_parser.feed(l_r.text)
    assert 'function' in l_parser.m_data
    l_solution_cookies = solve_challenge(l_parser.m_data)
    # ------------------------------------------------------
    # test again with solved challenge and cookies
    # ------------------------------------------------------
    l_headers['Cookie'] = l_solution_cookies
    l_r = requests.get(l_uri, headers=l_headers)
    # ------------------------------------------------------
    # assert we are good
    # ------------------------------------------------------
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json['errors'][0]['message'] == 'OK'
# ------------------------------------------------------------------------------
# helper_bot_request
# ------------------------------------------------------------------------------
def helper_bot_request(a_user_agent, a_ip, a_bot_type, a_spoof=True):
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_bot_info_file = os.path.realpath(os.path.join(l_file_path, '../../data/bot/known_bot_info.json'))
    with open(l_bot_info_file, 'r') as file_handler:
        parsed_info_file = json.loads(file_handler.read())
    # ------------------------------------------------------
    # test for spoof
    # ------------------------------------------------------
    if a_spoof:
        l_uri = G_TEST_HOST+'/test.html'
        l_headers = {
            'host': 'mybotmanager.com',
            'user-agent': a_user_agent,
            'waf-scopes-id': '0052'
        }
        l_r = requests.get(l_uri, headers=l_headers)
        l_r_json = l_r.json()
        assert l_r.status_code == 200
        assert l_r_json["rule_msg"] == "Attempt to spoof a known bot"
        assert l_r_json["sub_event"][0]["rule_id"] == 70000
        assert l_r_json["bot_action"] == "BLOCK_REQUEST"
        assert base64.b64decode(l_r_json['sub_event'][0]["matched_var"]["value"]).decode("utf-8") in parsed_info_file[a_bot_type]["user_agents"]
    # ------------------------------------------------------
    # if we have no ip, finish test
    # ------------------------------------------------------
    if a_ip == None: return 
    # ------------------------------------------------------
    # test with good ip for bot
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'host': 'mybotmanager.com',
        'user-agent': a_user_agent,
        'x-waflz-ip': a_ip,
        'waf-scopes-id': '0052'
    }
    l_r = requests.get(l_uri, headers=l_headers)
    l_r_json = l_r.json()
    assert l_r.status_code == 200
    assert l_r_json['rule_msg'] == "Known bot detected"
    assert l_r_json['sub_event'][0]['rule_id'] == 70001
    assert l_r_json["known_bot_type"] == a_bot_type
# ------------------------------------------------------------------------------
# setup waflz server in bot_manager mode with a known_bot_info file
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_waflz_server_with_bot_info_file():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_file_path = pathlib.Path(__file__).absolute()
    l_waflz_test_dir = l_file_path.parent.parent.parent
    l_conf_dir = l_waflz_test_dir / 'data' / 'waf' / 'conf'
    l_waflz_server_path = l_waflz_test_dir.parent / 'build' / 'util' / 'waflz_server' / 'waflz_server'
    l_bot_info_file = l_waflz_test_dir / 'data' / 'bot' / 'known_bot_info.json'
    l_bot_manager_file = l_conf_dir / 'bot_manager' / '0052-7kDny8RP.bot_manager.json'
    l_city_db = l_waflz_test_dir / "data" / "waf" / "db" / "GeoLite2-City.mmdb"
    l_isp_db = l_waflz_test_dir / "data" / "waf" / "db" / "GeoLite2-ASN.mmdb"
    # ------------------------------------------------------
    # create waflz instance
    # ------------------------------------------------------
    l_waflz_cmd = [
        str(l_waflz_server_path),
        '-Q', str(l_bot_info_file),
        '-B', str(l_bot_manager_file),
        '-g', str(l_city_db),
        '-s', str(l_isp_db),
        '-d', str(l_conf_dir)
    ]
    print(f"cmd: {' '.join(l_waflz_cmd)}")
    l_subproc = subprocess.Popen(l_waflz_cmd)
    time.sleep(1)
    # ------------------------------------------------------
    # yield...
    # ------------------------------------------------------
    yield setup_waflz_server_botmanager_mode
    # ------------------------------------------------------
    # tear down
    # ------------------------------------------------------
    l_subproc.kill()
    time.sleep(0.5)
# ------------------------------------------------------------------------------
# setup waflz server in bot_manager mode
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_waflz_server_botmanager_mode():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_file_path = pathlib.Path(__file__).absolute()
    l_waflz_test_dir = l_file_path.parent.parent.parent
    l_conf_dir = l_waflz_test_dir / 'data' / 'waf' / 'conf'
    l_waflz_server_path = l_waflz_test_dir.parent / 'build' / 'util' / 'waflz_server' / 'waflz_server'
    l_bot_info_file = l_waflz_test_dir / 'data' / 'bot' / 'known_bot_info.json'
    l_bot_manager_file = l_conf_dir / 'bot_manager' / '0052-7kDny8RP.bot_manager.json'
    # ------------------------------------------------------
    # create waflz instance
    # ------------------------------------------------------
    l_waflz_cmd = [
        str(l_waflz_server_path),
        '-B', str(l_bot_manager_file),
        '-Q', str(l_bot_info_file),
        '-d', str(l_conf_dir)
    ]
    print(f"cmd: {' '.join(l_waflz_cmd)}")
    l_subproc = subprocess.Popen(l_waflz_cmd)
    time.sleep(1)
    # ------------------------------------------------------
    # yield...
    # ------------------------------------------------------
    yield setup_waflz_server_botmanager_mode
    # ------------------------------------------------------
    # tear down
    # ------------------------------------------------------
    l_subproc.kill()
    time.sleep(0.5)
# ------------------------------------------------------------------------------
# setup waflz server in bot_manager mode with a browser challenge
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_waflz_server_challenge_botmanager_mode():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_file_path = pathlib.Path(__file__).absolute()
    l_waflz_test_dir = l_file_path.parent.parent.parent
    l_conf_dir = l_waflz_test_dir / 'data' / 'waf' / 'conf'
    l_waflz_server_path = l_waflz_test_dir.parent / 'build' / 'util' / 'waflz_server' / 'waflz_server'
    l_bot_info_file = l_waflz_test_dir / 'data' / 'bot' / 'known_bot_info.json'
    l_challenge_file = l_waflz_test_dir / 'data' / 'bot' / 'bot-challenges.json'
    l_cust_challenge_file = l_waflz_test_dir / 'data' / 'bot' / 'bot-js.txt'
    l_bot_manager_file = l_conf_dir / 'bot_manager' / '0052-3bUjds87.bot_manager.json'
    # ------------------------------------------------------
    # create waflz instance
    # ------------------------------------------------------
    l_waflz_cmd = [
        str(l_waflz_server_path),
        '-B', str(l_bot_manager_file),
        '-Q', str(l_bot_info_file),
        '-d', str(l_conf_dir),
        '-c', str(l_challenge_file),
        '-n', str(l_cust_challenge_file),
        '-j'
    ]
    print(f"cmd: {' '.join(l_waflz_cmd)}")
    l_subproc = subprocess.Popen(l_waflz_cmd)
    time.sleep(1)
    # ------------------------------------------------------
    # yield...
    # ------------------------------------------------------
    yield setup_waflz_server_botmanager_mode
    # ------------------------------------------------------
    # tear down
    # ------------------------------------------------------
    l_subproc.kill()
    time.sleep(0.5)
# ------------------------------------------------------------------------------
# setup waflz server in bot_manager mode with a browser challenge
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_waflz_server_botmanager_mode_with_categories():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_file_path = pathlib.Path(__file__).absolute()
    l_waflz_test_dir = l_file_path.parent.parent.parent
    l_conf_dir = l_waflz_test_dir / 'data' / 'waf' / 'conf'
    l_waflz_server_path = l_waflz_test_dir.parent / 'build' / 'util' / 'waflz_server' / 'waflz_server'
    l_bot_info_file = l_waflz_test_dir / 'data' / 'bot' / 'known_bot_info.json'
    l_challenge_file = l_waflz_test_dir / 'data' / 'bot' / 'bot-challenges.json'
    l_cust_challenge_file = l_waflz_test_dir / 'data' / 'bot' / 'bot-js.txt'
    l_bot_manager_file = l_conf_dir / 'bot_manager' / '0052-cats.bot_manager.json'
    l_city_db = l_waflz_test_dir / "data" / "waf" / "db" / "GeoLite2-City.mmdb"
    l_isp_db = l_waflz_test_dir / "data" / "waf" / "db" / "GeoLite2-ASN.mmdb"
# ------------------------------------------------------
    # create waflz instance
    # ------------------------------------------------------
    l_waflz_cmd = [
        str(l_waflz_server_path),
        '-B', str(l_bot_manager_file),
        '-Q', str(l_bot_info_file),
        '-d', str(l_conf_dir),
        '-c', str(l_challenge_file),
        '-n', str(l_cust_challenge_file),
        '-g', str(l_city_db),
        '-s', str(l_isp_db),
        '-K'
    ]
    print(f"cmd: {' '.join(l_waflz_cmd)}")
    l_subproc = subprocess.Popen(l_waflz_cmd)
    time.sleep(1)
    # ------------------------------------------------------
    # yield...
    # ------------------------------------------------------
    yield setup_waflz_server_botmanager_mode
    # ------------------------------------------------------
    # tear down
    # ------------------------------------------------------
    l_subproc.kill()
    time.sleep(0.5)
# ------------------------------------------------------------------------------
# setup waflz server in event mode with scopes
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_waflz_server_event():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    l_file_path = pathlib.Path(__file__).absolute()
    l_waflz_test_dir = l_file_path.parent.parent.parent
    l_conf_dir = l_waflz_test_dir / 'data' / 'waf' / 'conf'
    l_waflz_server_path = l_waflz_test_dir.parent / 'build' / 'util' / 'waflz_server' / 'waflz_server'
    l_bot_info_file = l_waflz_test_dir / 'data' / 'bot' / 'known_bot_info.json'
    l_city_db = l_waflz_test_dir / "data" / "waf" / "db" / "GeoLite2-City.mmdb"
    l_isp_db = l_waflz_test_dir / "data" / "waf" / "db" / "GeoLite2-ASN.mmdb"
    l_ruleset_dir = l_waflz_test_dir / 'data' / 'waf' / 'ruleset'
    l_captcha_file = l_waflz_test_dir / 'data' / 'bot' / 'bot-captcha.b64'
    l_scopes_dir = l_conf_dir / 'scopes'
    # ------------------------------------------------------
    # create waflz instance
    # ------------------------------------------------------
    l_waflz_cmd = [
        str(l_waflz_server_path),
        '-b', str(l_scopes_dir),
        '-d', str(l_conf_dir),
        '-r', str(l_ruleset_dir),
        '-g', str(l_city_db),
        '-s', str(l_isp_db),
        '-i', str(l_captcha_file),
        '-Q', str(l_bot_info_file),
    ]
    print(f"cmd: {' '.join(l_waflz_cmd)}")
    l_subproc = subprocess.Popen(l_waflz_cmd)
    time.sleep(1)
    # ------------------------------------------------------
    # yield...
    # ------------------------------------------------------
    yield setup_waflz_server_event
    # ------------------------------------------------------
    # tear down
    # ------------------------------------------------------
    l_subproc.kill()
    time.sleep(0.5)
# ------------------------------------------------------------------------------
# test custom challenge in bot manager config
# ------------------------------------------------------------------------------
def test_botmanager_mode(setup_waflz_server_botmanager_mode):
    # ------------------------------------------------------
    # test for normal request
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'mybotmanager.com',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # test for bots with variable ips
    # we have to load from ip file
    # ------------------------------------------------------
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_known_bot_info_file = os.path.realpath(os.path.join(l_file_path, '../../data/bot/known_bot_info.json'))
    # ------------------------------------------------------
    # load file
    # ------------------------------------------------------
    l_google_ip, l_bing_ip = None, None
    with open(l_known_bot_info_file, 'r') as file_handler:
        parsed_file = json.loads(file_handler.read())
        # --------------------------------------------------
        # lambda to parse an entry
        # --------------------------------------------------
        ip_from_cider = lambda cidr: cidr[:cidr.index('/')]
        # --------------------------------------------------
        # save ips for later test
        # --------------------------------------------------
        l_google_ip = ip_from_cider(parsed_file['google']['ips'][0])
        l_bing_ip = ip_from_cider(parsed_file['msn']['ips'][0])
    # ------------------------------------------------------
    # test with found ips
    # ------------------------------------------------------
    helper_bot_request('Googlebot-ImageFake', l_google_ip, 'google')
    helper_bot_request('Cool GooglebotHelloWorld', l_google_ip, 'google')
    helper_bot_request('Im Bingbot:)', l_bing_ip, 'msn')
    # ------------------------------------------------------
    # test for known bot configurations (static ips)
    # ------------------------------------------------------
    helper_bot_request('facEboOkcaTalog', '69.63.176.0', 'facebook')
    helper_bot_request('SDtwItterbotDF', '199.16.156.0', 'twitter')
# ------------------------------------------------------------------------------
# test custom challenge in bot manager config
# ------------------------------------------------------------------------------
def test_botmanager_mode_with_challenge(setup_waflz_server_challenge_botmanager_mode):
    # ------------------------------------------------------
    # test for normal request
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'mybotmanager.com',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # test for bots with variable ips
    # we have to load from ip file
    # ------------------------------------------------------
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_known_bot_info_file = os.path.realpath(os.path.join(l_file_path, '../../data/bot/known_bot_info.json'))
    # ------------------------------------------------------
    # load file
    # ------------------------------------------------------
    l_bing_ip = None
    with open(l_known_bot_info_file, 'r') as file_handler:
        parsed_file = json.loads(file_handler.read())
        # --------------------------------------------------
        # lambda to parse an entry
        # --------------------------------------------------
        ip_from_cider = lambda cidr: cidr[:cidr.index('/')]
        # --------------------------------------------------
        # save ips for later test
        # --------------------------------------------------
        l_bing_ip = ip_from_cider(parsed_file['msn']['ips'][0])
    # ------------------------------------------------------
    # test known_bot with challenge
    # ------------------------------------------------------
    helper_bot_request_for_challenge('Im Bingbot:)', l_bing_ip)
    # ------------------------------------------------------
    # test for known bot without challenge - should still
    # get challenged because spoof action
    # ------------------------------------------------------
    helper_bot_request_for_challenge('facEboOkcaTalog', '127.0.0.1')
    # ------------------------------------------------------
    # test for known bot with valid ip - no challenge
    # ------------------------------------------------------
    helper_bot_request('facEboOkcaTalog', '69.63.176.0', 'facebook', False)
# ------------------------------------------------------------------------------
# test other known bot
# ------------------------------------------------------------------------------
def test_other_known_bot_botmanager_mode(setup_waflz_server_botmanager_mode):
    # ------------------------------------------------------
    # request with user-agent in 'other' category
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'host': 'mybotmanager.com',
        'user-agent': 'Pinterestbot',
        'waf-scopes-id': '0052'
    }
    l_r = requests.get(l_uri, headers=l_headers)
    l_r_json = l_r.json()
    # ------------------------------------------------------
    # assert request was alerted
    # ------------------------------------------------------
    assert l_r.status_code == 200
    assert l_r_json["rule_msg"] == "A known bot user-agent"
    assert l_r_json["sub_event"][0]["rule_id"] == 70002
    assert l_r_json['known_bot_type'] == 'other'
    assert base64.b64decode(l_r_json['sub_event'][0]["matched_var"]["value"]).decode("utf-8") == 'Pinterestbot'
# ------------------------------------------------------------------------------
# test other known bot
# ------------------------------------------------------------------------------
def test_known_bot_actions(setup_waflz_server_challenge_botmanager_mode):
    # ------------------------------------------------------
    # request with user-agent in 'other' category
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'host': 'allbotmanagerchallenges.com',
        'waf-scopes-id': '0052'
    }
    l_r = requests.get(l_uri, headers=l_headers)
    l_r_json = l_r.json()
    # ------------------------------------------------------
    # company information for block and alert
    # ------------------------------------------------------
    l_user_agents = ['twitterbot'   , 'facebookcatalog'  ]
    l_ips =         ['199.16.156.0' , '69.63.176.0'      ]
    l_status =      [403            , 200                ]
    l_company_info = zip(l_user_agents, l_ips, l_status)
    # ------------------------------------------------------
    # assert we can alert and block
    # ------------------------------------------------------
    for i_comp_info in l_company_info:
        # --------------------------------------------------
        # set user agent and ip
        # --------------------------------------------------
        l_headers["user-agent"] = i_comp_info[0]
        l_headers["x-waflz-ip"] = i_comp_info[1]
        # --------------------------------------------------
        # send request
        # --------------------------------------------------
        l_r = requests.get(l_uri, headers=l_headers)
        l_r_json = l_r.json()
        # --------------------------------------------------
        # should have rule msg and event
        # --------------------------------------------------
        assert l_r.status_code == i_comp_info[2]
        assert l_r_json["rule_msg"] == "Known bot detected"
        assert l_r_json["sub_event"][0]["rule_id"] == 70001
    # ------------------------------------------------------
    # assert custom response should work
    # ------------------------------------------------------
    l_headers["user-agent"] = "YandexTurbo"
    l_headers["x-waflz-ip"] = "141.8.142.76"
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.text == "This is profile custom response\n"
    # ------------------------------------------------------
    # assert drop request should work
    # ------------------------------------------------------
    l_headers["user-agent"] = "googlebot"
    l_headers["x-waflz-ip"] = "74.125.218.93"
    with pytest.raises(requests.ConnectionError):
        l_r = requests.get(l_uri, headers=l_headers)
# ------------------------------------------------------------------------------
# test browser challenge creates subevent
# ------------------------------------------------------------------------------
def test_browser_challenge_logging(setup_waflz_server_botmanager_mode):
    # ------------------------------------------------------
    # test for normal request
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'mybotmanager.com',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # assert yandex should have subevent
    # ------------------------------------------------------
    l_headers["user-agent"] = "YandexTurbo"
    l_headers["x-waflz-ip"] = "141.8.142.76"
    l_r = requests.get(l_uri, headers=l_headers)
    l_r_json = l_r.json()
    assert "sub_event" in l_r_json
    # ------------------------------------------------------
    # assert yandex is known bot
    # ------------------------------------------------------
    assert "rule_id" in l_r_json["sub_event"][0]
    assert l_r_json["sub_event"][0]["rule_id"] == 70001
    assert l_r_json["bot_action"] == "BROWSER_CHALLENGE"
    # ------------------------------------------------------
    # assert yandex had browser challenge issued
    # ------------------------------------------------------
    assert "challenge_status" in l_r_json
    assert l_r_json["challenge_status"] == "CHAL_STATUS_NO_TOKEN"
    assert "token_duration_sec" in l_r_json
    assert l_r_json["token_duration_sec"] == 3
# ------------------------------------------------------------------------------
# test bot manager alert mode 
# ------------------------------------------------------------------------------
def test_botmanager_alert_mode(setup_waflz_server_event):
    # ------------------------------------------------------
    # test for normal request
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'botmanagertest.com',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # test alert event for google bot with valid google ip
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'botmanagertest.com',
                 'user-agent': 'googleweblight',
                 'x-waflz-ip': '74.125.218.93',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'bot_event' in l_r_json
    assert l_r_json['bot_event']['sub_event'][0]['rule_id'] == 70001
    assert l_r_json['bot_event']['sub_event'][0]['rule_msg'] == "Known Bot: Explicit Known Bot Token"
    # ------------------------------------------------------
    # send sql injection with UA google bot and valid google ip
    # should be flagged by both waf and bot
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html?a=%27select%20*%20from%20testing%27'
    l_headers = {'host': 'botmanagertest.com',
                 'user-agent': 'googleweblight',
                 'x-waflz-ip': '74.125.218.93',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200, l_r.text
    l_r_json = l_r.json()
    assert 'bot_event' in l_r_json
    assert l_r_json['bot_event']['sub_event'][0]['rule_id'] == 70001
    assert l_r_json['bot_event']['sub_event'][0]['rule_msg'] == "Known Bot: Explicit Known Bot Token"
    assert 'prod_profile' in l_r_json
    assert l_r_json['prod_profile']['waf_profile_id'] == 'KsdoThsq'
    assert l_r_json['prod_profile']['sub_event'][0]['rule_msg'] == 'SQL Injection Attack Detected via libinjection'
# ------------------------------------------------------------------------------
# test other action not spoof
# ------------------------------------------------------------------------------
def test_other_action_not_spoof(setup_waflz_server_challenge_botmanager_mode):
    # ------------------------------------------------------
    # request with user-agent in 'other' category
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'host': 'mybotmanager.com',
        'user-agent': 'Pinterestbot',
        'waf-scopes-id': '0052'
    }
    l_r = requests.get(l_uri, headers=l_headers)
    # ------------------------------------------------------
    # assert request was blocked - not sent browser challenge
    # ------------------------------------------------------
    assert l_r.status_code == 403
# ------------------------------------------------------------------------------
# test known bot specific spoof
# ------------------------------------------------------------------------------
def test_known_bot_specific_spoof_action_type(setup_waflz_server_challenge_botmanager_mode):
    # ------------------------------------------------------
    # request with yandex bot user agent and an IP NOT
    # listed as their ip.
    # ------------------------------------------------------
    l_uri = G_TEST_HOST
    l_headers = {
        'host': 'mybotmanager.com',
        'user-agent': 'YandexVideo',
        'x-waflz-ip': '127.0.0.1',
        'waf-scopes-id': '0052'
    }
    l_r = requests.get(l_uri, headers=l_headers)
    # ------------------------------------------------------
    # assert request was REDIRECT, and not BROWSER_CHALLENGE
    # ------------------------------------------------------
    assert 'google' in l_r.text
# ------------------------------------------------------------------------------
# test known bot strict match
# ------------------------------------------------------------------------------
def test_known_bot_strict_match(setup_waflz_server_with_bot_info_file):
    # ------------------------------------------------------
    # request with bingbot user-agent but a bad ip. should
    # still be considered a good request because this ip
    # comes from asn 15133 - which is an associated asn
    #
    # NOTE: 15133 is not associated with msn, just for the
    # test it is.
    # ------------------------------------------------------
    l_headers = {
        'host': 'mybotmanager.com',
        'user-agent': 'bingbot',
        'x-waflz-ip': '192.229.234.2',
        'waf-scopes-id': '0052'
    }
    l_r = requests.get(G_TEST_HOST, headers=l_headers)
    # ------------------------------------------------------
    # assert request worked
    # ------------------------------------------------------
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # assert log is known bot
    # ------------------------------------------------------
    l_r_json = l_r.json()
    assert l_r_json["rule_msg"] == "Known bot detected"
    assert l_r_json["sub_event"][0]["rule_id"] == 70001
    l_matched_var = base64.b64decode(l_r_json["sub_event"][0]["matched_var"]["value"])
    assert str(l_matched_var, encoding='utf-8') == '15133'
    # ------------------------------------------------------
    # update request to go to google, who has the same asn
    # but has strict matching
    # ------------------------------------------------------
    l_headers = {
        'host': 'mybotmanager.com',
        'user-agent': 'Googlebot',
        'x-waflz-ip': '192.229.234.2',
        'waf-scopes-id': '0052'
    }
    l_r = requests.get(G_TEST_HOST, headers=l_headers)
    # ------------------------------------------------------
    # assert request worked
    # ------------------------------------------------------
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # assert log is spoof
    # ------------------------------------------------------
    l_r_json = l_r.json()
    assert l_r_json["rule_msg"] == "Attempt to spoof a known bot"
    assert l_r_json["sub_event"][0]["rule_id"] == 70000
    l_matched_var = base64.b64decode(l_r_json["sub_event"][0]["matched_var"]["value"])
    assert str(l_matched_var, encoding='utf-8') == 'Googlebot'

def test_known_bot_categories(setup_waflz_server_botmanager_mode_with_categories):
    # ------------------------------------------------------
    # request with bingbot user-agent but a bad ip. should
    # still be considered a good request because this ip
    # comes from asn 15133 - which is an associated asn
    #
    # NOTE: 15133 is not associated with msn, just for the
    # test it is.
    # ------------------------------------------------------
    l_headers = {
        'host': 'mybotmanager.com',
        'user-agent': 'bingbot',
        'x-waflz-ip': '192.229.234.2',
        'waf-scopes-id': '0052'
    }
    l_r = requests.get(G_TEST_HOST, headers=l_headers)
    # ------------------------------------------------------
    # assert request worked
    # ------------------------------------------------------
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # assert log is known bot
    # ------------------------------------------------------
    l_r_json = l_r.json()
    assert l_r_json["rule_msg"] == "Known bot detected"
    assert l_r_json["sub_event"][0]["rule_id"] == 70001
    assert l_r_json["known_bot_type"] == "msn"
    assert l_r_json["known_bot_category"] == "Search Engine/SEO bots"
    l_matched_var = base64.b64decode(l_r_json["sub_event"][0]["matched_var"]["value"])
    assert str(l_matched_var, encoding='utf-8') == '15133'

def test_known_bot_category_not_enabled(setup_waflz_server_botmanager_mode_with_categories):
    # ------------------------------------------------------
    # make a request with adidxbot, which is in a category
    # this config does not have enabled
    # ------------------------------------------------------
    l_headers = {
        'host': 'mybotmanager.com',
        'user-agent': 'adidxbot',
        'x-waflz-ip': '192.229.234.2',
        'waf-scopes-id': '0052'
    }
    l_r = requests.get(G_TEST_HOST, headers=l_headers)
    # ------------------------------------------------------
    # assert request worked
    # ------------------------------------------------------
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # assert known bot was not found
    # ------------------------------------------------------
    l_r_json = l_r.json()
    assert "rule_msg" not in l_r_json
    # ------------------------------------------------------
    # make a request with YandexBot, which is in the search
    # category, but is not enabled
    # ------------------------------------------------------
    l_headers['user-agent'] = 'YandexBot'
    l_r = requests.get(G_TEST_HOST, headers=l_headers)
    # ------------------------------------------------------
    # assert request worked
    # ------------------------------------------------------
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # assert known bot was not found
    # ------------------------------------------------------
    l_r_json = l_r.json()
    assert "rule_msg" not in l_r_json

def test_known_bot_category_specific_and_default_actions(setup_waflz_server_botmanager_mode_with_categories):
    # ------------------------------------------------------
    # make a request with googlebot, which should get the
    # default action of ALERT
    # ------------------------------------------------------
    l_headers = {
        'host': 'mybotmanager.com',
        'user-agent': 'Googlebot',
        'x-waflz-ip': '74.125.218.93',
        'waf-scopes-id': '0052'
    }
    l_r = requests.get(G_TEST_HOST, headers=l_headers)
    # ------------------------------------------------------
    # assert request worked
    # ------------------------------------------------------
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # assert known bot was found with alert (default)
    # ------------------------------------------------------
    l_r_json = l_r.json()
    assert l_r_json["rule_msg"] == "Known bot detected"
    assert l_r_json["sub_event"][0]["rule_id"] == 70001
    assert l_r_json["bot_action"] == "ALERT"
    assert l_r_json["known_bot_type"] == "google"
    assert l_r_json["known_bot_category"] == "Search Engine/SEO bots"
    # ------------------------------------------------------
    # check that spoof is custom response (default)
    # ------------------------------------------------------
    l_headers["x-waflz-ip"] = "127.0.0.1"
    l_r = requests.get(G_TEST_HOST, headers=l_headers)
    # ------------------------------------------------------
    # assert request worked
    # ------------------------------------------------------
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # assert spoofed with CUSTOM_RESPONSE (default)
    # ------------------------------------------------------
    l_r_json = l_r.json()
    assert l_r_json["rule_msg"] == "Attempt to spoof a known bot"
    assert l_r_json["sub_event"][0]["rule_id"] == 70000
    assert l_r_json["bot_action"] == "CUSTOM_RESPONSE"
    assert l_r_json["known_bot_type"] == "google"
    assert l_r_json["known_bot_category"] == "Search Engine/SEO bots"
    # ------------------------------------------------------
    # check that bingbot has browser challenge (specific)
    # ------------------------------------------------------
    l_headers["user-agent"] = "bingbot"
    l_headers["x-waflz-ip"] = "192.229.234.2"
    l_r = requests.get(G_TEST_HOST, headers=l_headers)
    # ------------------------------------------------------
    # assert request worked
    # ------------------------------------------------------
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # assert browser challenge
    # ------------------------------------------------------
    l_r_json = l_r.json()
    assert l_r_json["rule_msg"] == "Known bot detected"
    assert l_r_json["sub_event"][0]["rule_id"] == 70001
    assert l_r_json["bot_action"] == "BROWSER_CHALLENGE"
    assert l_r_json["known_bot_type"] == "msn"
    assert l_r_json["known_bot_category"] == "Search Engine/SEO bots"
    # ------------------------------------------------------
    # check that spoof has ALERT (specific)
    # ------------------------------------------------------
    l_headers["x-waflz-ip"] = "74.125.218.93"
    l_r = requests.get(G_TEST_HOST, headers=l_headers)
    # ------------------------------------------------------
    # assert request worked
    # ------------------------------------------------------
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # assert browser challenge
    # ------------------------------------------------------
    l_r_json = l_r.json()
    assert l_r_json["rule_msg"] == "Attempt to spoof a known bot"
    assert l_r_json["sub_event"][0]["rule_id"] == 70000
    assert l_r_json["bot_action"] == "ALERT"
    assert l_r_json["known_bot_type"] == "msn"
    assert l_r_json["known_bot_category"] == "Search Engine/SEO bots"

def test_known_bot_ignored_category_action(setup_waflz_server_botmanager_mode_with_categories):
    # ------------------------------------------------------
    # make a request with yandex, which has a spoof action
    # of ignore.
    # ------------------------------------------------------
    l_headers = {
        'host': 'mybotmanager.com',
        'user-agent': 'YandexBlogs',
        'waf-scopes-id': '0052'
    }
    l_r = requests.get(G_TEST_HOST, headers=l_headers)
    # ------------------------------------------------------
    # assert request worked
    # ------------------------------------------------------
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # assert bot rule fired - NOT known bot
    # ------------------------------------------------------
    l_r_json = l_r.json()
    assert "rule_msg" not in l_r_json
    # ------------------------------------------------------
    # check that non-spoof does get action
    # ------------------------------------------------------
    l_headers["x-waflz-ip"] = "141.8.142.76"
    l_r = requests.get(G_TEST_HOST, headers=l_headers)
    # ------------------------------------------------------
    # assert request worked
    # ------------------------------------------------------
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # assert event occured
    # ------------------------------------------------------
    l_r_json = l_r.json()
    assert l_r_json["rule_msg"] == "Known bot detected"
    assert l_r_json["sub_event"][0]["rule_id"] == 70001
    assert l_r_json["bot_action"] == "ALERT"
    assert l_r_json["known_bot_type"] == "yandex"
    assert l_r_json["known_bot_category"] == "Miscellaneous"

def test_known_bot_category_works_without_user_agent(setup_waflz_server_botmanager_mode_with_categories):
    # ------------------------------------------------------
    # make a request with googlebot, which should get the
    # default action of ALERT
    # ------------------------------------------------------
    l_headers = {
        'host': 'mybotmanager.com',
        'x-waflz-ip': '74.125.218.93',
        'waf-scopes-id': '0052'
    }
    l_r = requests.get(G_TEST_HOST, headers=l_headers)
    # ------------------------------------------------------
    # assert request worked
    # ------------------------------------------------------
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # assert known bot was found with alert (default)
    # ------------------------------------------------------
    l_r_json = l_r.json()
    assert "rule_msg" not in l_r_json
