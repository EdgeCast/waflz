#!/usr/bin/env python3
'''Test bot_manager bot actions'''
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
import datetime
import base64
from pathlib import Path
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
        if data.strip().startswith('function'):
            self.m_data = data

class custom_html_parse(HTMLParser):
    m_data = ""
    def handle_data(self, data):
        if data.strip().startswith('window.onload'):
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
# update bots
# ------------------------------------------------------------------------------
def update_bots(new_bots):
    # ------------------------------------------------------
    # update bots 
    # ------------------------------------------------------
    new_bots['last_modified_date'] = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
    l_url = f'{G_TEST_HOST}/update_bots'
    l_headers = {'Content-Type': 'application/json',
                 'waf-scopes-id': '0052'}
    l_r = requests.post(l_url,
                        headers=l_headers,
                        data=json.dumps(new_bots))
    # ------------------------------------------------------
    # assert update worked 
    # ------------------------------------------------------
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # sleep so next update will work 
    # ------------------------------------------------------
    time.sleep(1)
# ------------------------------------------------------------------------------
# update bot_manager
# ------------------------------------------------------------------------------
def update_bot_manager(new_bot_manager):
    # ------------------------------------------------------
    # update bots 
    # ------------------------------------------------------
    new_bot_manager['last_modified_date'] = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
    l_url = f'{G_TEST_HOST}/update_bot_manager'
    l_headers = {'Content-Type': 'application/json',
                 'waf-scopes-id': '0052'}
    l_r = requests.post(l_url,
                        headers=l_headers,
                        data=json.dumps(new_bot_manager))
    # ------------------------------------------------------
    # assert update worked 
    # ------------------------------------------------------
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # sleep so next update will work 
    # ------------------------------------------------------
    time.sleep(1)
# ------------------------------------------------------------------------------
# run_command
# ------------------------------------------------------------------------------
def run_command(command):
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    return (p.returncode, stdout, stderr)
# ------------------------------------------------------------------------------
# setup waflz server in action mode
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_waflz_server_action():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    # l_cwd = os.getcwd()
    l_file_path = Path(__file__).absolute()
    l_data_file_path = l_file_path.parent.parent.parent / "data"
    l_geoip2city_path = l_data_file_path / "waf" / "db" / "GeoLite2-City.mmdb"
    l_geoip2ISP_path = l_data_file_path / "waf" / "db" / "GeoLite2-ASN.mmdb"
    l_conf_dir = l_data_file_path / "waf" / "conf"
    l_challenge = l_data_file_path / "bot"/ "bot-challenges.json"
    l_cust_chal_js = l_data_file_path / "bot" / "bot-js.txt"
    l_bot_info_file = l_data_file_path / "bot" / "known_bot_info.json"
    l_ja3_db_dir = l_data_file_path / "waf" / "db" / "bot_lmdb"
    l_ruleset_path = l_data_file_path / "waf" / "ruleset"
    l_scopes_dir = l_conf_dir / "scopes" / "0052.scopes.json"
    l_waflz_server_path = l_data_file_path.parent.parent / "build" / "util" / "waflz_server" / "waflz_server"
    # ------------------------------------------------------
    # create waflz server cmd
    # ------------------------------------------------------
    l_waflz_server_cmd = [
        str(l_waflz_server_path),
        '-Q', str(l_bot_info_file),
        '-Z', str(l_ja3_db_dir),
        '-d', str(l_conf_dir),
        '-b', str(l_scopes_dir),
        '-r', str(l_ruleset_path),
        '-g', str(l_geoip2city_path),
        '-s', str(l_geoip2ISP_path),
        '-c', str(l_challenge),
        '-n', str(l_cust_chal_js),
        '-j'
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
    yield setup_waflz_server_action
    # ------------------------------------------------------
    # tear down
    # ------------------------------------------------------
    l_subproc.kill()
# ------------------------------------------------------------------------------
# setup waflz server with lmdb ja3
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_waflz_server_bot_lmdb():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    # l_cwd = os.getcwd()
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_geoip2city_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-City.mmdb'))
    l_geoip2ISP_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-ASN.mmdb'))
    l_conf_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf'))
    l_challenge = os.path.realpath(os.path.join(l_file_path, '../../data/bot/bot-challenges.json'))
    l_cust_chal_js = os.path.realpath(os.path.join(l_file_path, '../../data/bot/bot-js.txt'))
    l_bot_info_file = os.path.realpath(os.path.join(l_file_path, '../../data/bot/known_bot_info.json'))
    l_ruleset_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/ruleset'))
    l_scopes_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/scopes/0052.scopes.json'))
    l_ja3_db_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/bot_lmdb'))
    l_waflz_server_path = os.path.abspath(os.path.join(l_file_path, '../../../build/util/waflz_server/waflz_server'))
    l_subproc = subprocess.Popen([l_waflz_server_path,
                                  '-Q', l_bot_info_file,
                                  '-d', l_conf_dir,
                                  '-b', l_scopes_dir,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path,
                                  '-c', l_challenge,
                                  '-n', l_cust_chal_js,
                                  '-Z', l_ja3_db_dir,
                                  '-j'])
    print('cmd: \n{}\n'.format(' '.join([l_waflz_server_path,
                                  '-Q', l_bot_info_file,
                                  '-d', l_conf_dir,
                                  '-b', l_scopes_dir,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path,
                                  '-c', l_challenge,
                                  '-n', l_cust_chal_js,
                                  '-Z', l_ja3_db_dir,
                                  '-j'])))
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
# test_bot_actions
# ------------------------------------------------------------------------------
def test_bot_actions(setup_waflz_server_action):
    # ------------------------------------------------------
    # load bot_manager (because we are going to update it)
    # ------------------------------------------------------
    l_bot_rule_config_path = Path(__file__).absolute().parent.parent.parent / "data" / "waf" / "conf" / "bots" / "0052-w12347.bots.json"
    l_bots_config = json.loads(l_bot_rule_config_path.read_text())
    #! -----------------------------------------------------
    #! test the bot action (BROWSER_CHALLENGE)
    #! -----------------------------------------------------
    print("testing browser_challenge")
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'host': 'allbotmanagerchallenges.com',
        'waf-scopes-id': '0052',
        'user-agent': 'bot-testing'
    }
    l_r = requests.get(l_uri, headers=l_headers)
    # ------------------------------------------------------
    # assert we should have been challenged
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
    # ------------------------------------------------------
    # update bot rule to use BLOCK_REQUEST as bot action
    # ------------------------------------------------------
    l_bots_config['directive'][0]['sec_rule']['action']['bot_action'] = 'BLOCK_REQUEST'
    update_bots(l_bots_config)
    #! -----------------------------------------------------
    #! test the bot action (BLOCK_REQUEST)
    #! -----------------------------------------------------
    print("testing block_request....")
    l_r = requests.get(l_uri, headers=l_headers)
    l_r_json = l_r.json()
    # ------------------------------------------------------
    # assert we are blocked
    # ------------------------------------------------------
    assert l_r.status_code == 403
    assert isinstance(l_r_json['bot_event'], dict)
    # ------------------------------------------------------
    # update bot rule to use CUSTOM_RESPONSE as bot action
    # ------------------------------------------------------
    l_bots_config['directive'][0]['sec_rule']['action']['bot_action'] = 'CUSTOM_RESPONSE'
    update_bots(l_bots_config)
    #! -----------------------------------------------------
    #! test the bot action (CUSTOM_RESPONSE)
    #! -----------------------------------------------------
    print("testing custom_response")
    l_r = requests.get(l_uri, headers=l_headers)
    # ------------------------------------------------------
    # assert we get custom response
    # ------------------------------------------------------
    assert l_r.text == "This is profile custom response\n"
    # ------------------------------------------------------
    # update bot rule to use ALERT as bot action
    # ------------------------------------------------------
    l_bots_config['directive'][0]['sec_rule']['action']['bot_action'] = 'ALERT'
    update_bots(l_bots_config)
    #! -----------------------------------------------------
    #! test the bot action (ALERT)
    #! -----------------------------------------------------
    print("testing alert")
    l_r = requests.get(l_uri, headers=l_headers)
    l_r_json = l_r.json()
    # ------------------------------------------------------
    # assert we were alerted
    # ------------------------------------------------------
    assert l_r.status_code == 200
    assert isinstance(l_r_json['bot_event'], dict)
    # ------------------------------------------------------
    # update bot rule to use DROP_REQUEST as bot action
    # ------------------------------------------------------
    l_bots_config['directive'][0]['sec_rule']['action']['bot_action'] = 'DROP_REQUEST'
    update_bots(l_bots_config)
    #! -----------------------------------------------------
    #! test the bot action (DROP_REQUEST)
    #! -----------------------------------------------------
    print("testing drop_request")
    with pytest.raises(requests.ConnectionError):
        l_r = requests.get(l_uri, headers=l_headers)
    # ------------------------------------------------------
    # update bots to use REDIRECT_302 as bot action
    # ------------------------------------------------------
    l_bots_config['directive'][0]['sec_rule']['action']['bot_action'] = 'REDIRECT_302'
    update_bots(l_bots_config)
    #! -----------------------------------------------------
    #! test the bot action (REDIRECT_302)
    #! -----------------------------------------------------
    print("testing redirect_302")
    l_r = requests.get(l_uri, headers=l_headers)
    # ------------------------------------------------------
    # assert we were redirected to google
    # ------------------------------------------------------
    assert 'google' in l_r.text
    # ------------------------------------------------------
    # update bots to use IGNORE_ALERT as bot action
    # ------------------------------------------------------
    l_bots_config['directive'][0]['sec_rule']['action']['bot_action'] = 'IGNORE_ALERT'
    update_bots(l_bots_config)
    #! -----------------------------------------------------
    #! test the bot action (IGNORE_ALERT)
    #! -----------------------------------------------------
    print("testing ignore_alert")
    l_r = requests.get(l_uri, headers=l_headers)
    l_r_json = l_r.json()
    # ------------------------------------------------------
    # assert we got an alert (will get ignored in sailfish)
    # ------------------------------------------------------
    assert l_r.status_code == 200
    assert isinstance(l_r_json['bot_event'], dict)
    assert l_r_json["bot_event"]["bot_action"] == "IGNORE_ALERT"
    # ------------------------------------------------------
    # update bots to use IGNORE_BLOCK as bot action
    # ------------------------------------------------------
    l_bots_config['directive'][0]['sec_rule']['action']['bot_action'] = 'IGNORE_BLOCK'
    update_bots(l_bots_config)
    #! -----------------------------------------------------
    #! test the bot action (IGNORE_BLOCK)
    #! -----------------------------------------------------
    print("testing ignore_block")
    l_r = requests.get(l_uri, headers=l_headers)
    l_r_json = l_r.json()
    # ------------------------------------------------------
    # assert we are blocked (will get ignored in sailfish)
    # ------------------------------------------------------
    assert l_r.status_code == 403
    assert isinstance(l_r_json['bot_event'], dict)
    assert l_r_json["bot_event"]["bot_action"] == "IGNORE_BLOCK"
    # ------------------------------------------------------
    # update bots to use NULL_ALERT as bot action
    # ------------------------------------------------------
    l_bots_config['directive'][0]['sec_rule']['action']['bot_action'] = 'NULL_ALERT'
    update_bots(l_bots_config)
    #! -----------------------------------------------------
    #! test the bot action (NULL_ALERT)
    #! -----------------------------------------------------
    print("testing null_alert")
    l_r = requests.get(l_uri, headers=l_headers)
    l_r_json = l_r.json()
    # ------------------------------------------------------
    # assert we are alerted
    # (will get ignored in sailfish and rtld)
    # ------------------------------------------------------
    assert l_r.status_code == 200
    assert isinstance(l_r_json['bot_event'], dict)
    assert l_r_json["bot_event"]["bot_action"] == "NULL_ALERT"
    # ------------------------------------------------------
    # update bots to use NULL_BLOCK as bot action
    # ------------------------------------------------------
    l_bots_config['directive'][0]['sec_rule']['action']['bot_action'] = 'NULL_BLOCK'
    update_bots(l_bots_config)
    #! -----------------------------------------------------
    #! test the bot action (NULL_BLOCK)
    #! -----------------------------------------------------
    print("testing null_block")
    l_r = requests.get(l_uri, headers=l_headers)
    l_r_json = l_r.json()
    # ------------------------------------------------------
    # assert we are blocked
    # (will get ignored in sailfish and rtld)
    # ------------------------------------------------------
    assert l_r.status_code == 403
    assert isinstance(l_r_json['bot_event'], dict)
    assert l_r_json["bot_event"]["bot_action"] == "NULL_BLOCK"
    # ------------------------------------------------------
    # update bots to use IGNORE_CUSTOM_RESPONSE as bot action
    # ------------------------------------------------------
    l_bots_config['directive'][0]['sec_rule']['action']['bot_action'] = 'IGNORE_CUSTOM_RESPONSE'
    update_bots(l_bots_config)
    #! -----------------------------------------------------
    #! test the bot action (IGNORE_CUSTOM_RESPONSE)
    #! -----------------------------------------------------
    print("testing ignore_custom_response")
    l_r = requests.get(l_uri, headers=l_headers)
    # ------------------------------------------------------
    # assert we are served a custom response
    # (will get ignored in sailfish)
    # ------------------------------------------------------
    assert l_r.status_code == 401
    assert l_r.text == "ignore me :P\n"
# ------------------------------------------------------------------------------
# test_bot_action_types
# ------------------------------------------------------------------------------
def test_bot_action_types(setup_waflz_server_action):
    # ------------------------------------------------------
    # load bot_manager (because we are going to update it)
    # ------------------------------------------------------
    l_bot_manager_config_path = os.path.realpath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        '../../data/waf/conf/bot_manager/0052-3bUjds87.bot_manager.json'
    ))
    l_bot_manager_config = None
    with open(l_bot_manager_config_path, 'r') as file_handler:
        l_bot_manager_config = json.loads(file_handler.read());
    # ------------------------------------------------------
    # update bot_manager known bots to use an action type
    # ------------------------------------------------------
    l_bot_manager_config['known_bots'][0]['action_type'] = "CUSTOM_RESPONSE"
    update_bot_manager(l_bot_manager_config)
    #! -----------------------------------------------------
    #! test the bot action is now custom_response
    #! -----------------------------------------------------
    print("testing custom_response")
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'host': 'allbotmanagerchallenges.com',
        'waf-scopes-id': '0052',
        'user-agent': 'Googlebot',
        'x-waflz-ip': '74.125.218.93'
    }
    l_r = requests.get(l_uri, headers=l_headers)
    # ------------------------------------------------------
    # assert we should have received custom response
    # ------------------------------------------------------
    assert l_r.status_code == 403
    assert 'This is profile custom response\n' == l_r.text
    # ------------------------------------------------------
    # update bot_manager to use spoof action type
    # ------------------------------------------------------
    l_bot_manager_config['spoof_bot_action_type'] = "ALERT"
    update_bot_manager(l_bot_manager_config)
    #! -----------------------------------------------------
    #! test the spoof action is now ALERT
    #! -----------------------------------------------------
    print("testing action")
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'host': 'allbotmanagerchallenges.com',
        'waf-scopes-id': '0052',
        'user-agent': 'Googlebot',
        'x-waflz-ip': '127.0.0.1'
    }
    l_r = requests.get(l_uri, headers=l_headers)
    l_r_json = l_r.json()
    # ------------------------------------------------------
    # assert we should have received custom response
    # ------------------------------------------------------
    assert l_r.status_code == 200
    assert isinstance(l_r_json['bot_event'], dict)
# ------------------------------------------------------------------------------
# test_bot_action_types
# ------------------------------------------------------------------------------
def test_custom_bot_action_types(setup_waflz_server_action):
    # ------------------------------------------------------
    # load bot_manager (because we are going to update it)
    # ------------------------------------------------------
    l_bot_manager_config_path = os.path.realpath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        '../../data/waf/conf/bot_manager/0052-3bUjds87.bot_manager.json'
    ))
    l_bot_manager_config = None
    with open(l_bot_manager_config_path, 'r') as file_handler:
        l_bot_manager_config = json.loads(file_handler.read());
    #! -----------------------------------------------------
    #! test the bot action fires
    #! -----------------------------------------------------
    print("testing browser_challenge in rule")
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'host': 'allbotmanagerchallenges.com',
        'waf-scopes-id': '0052',
        'user-agent': 'bot-testing'
    }
    l_r = requests.get(l_uri, headers=l_headers)
    # ------------------------------------------------------
    # assert we should have been challenged
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
    # ------------------------------------------------------
    # update bot_manager to use a bot action with 
    # action_type set
    # ------------------------------------------------------
    l_bot_manager_config['bots_prod_id'] = "WACKR4"
    update_bot_manager(l_bot_manager_config)
    #! -----------------------------------------------------
    #! test the bot action is now custom_response
    #! -----------------------------------------------------
    print("testing custom_response in rule")
    l_r = requests.get(l_uri, headers=l_headers)
    # ------------------------------------------------------
    # assert we should have received custom response
    # ------------------------------------------------------
    assert l_r.status_code == 403
    assert 'This is profile custom response\n' == l_r.text
    #! -----------------------------------------------------
    #! test a different bot rule for block
    #! -----------------------------------------------------
    print("testing BLOCK_REQUEST in rule")
    l_headers['user-agent'] = 'bot-blocking'
    l_r = requests.get(l_uri, headers=l_headers)
    # ------------------------------------------------------
    # assert we should have received block
    # ------------------------------------------------------
    assert l_r.status_code == 403
    l_r_json = l_r.json()
    assert isinstance(l_r_json['bot_event'], dict)
    assert l_r_json['bot_event']['bot_score'] == 0
    #! -----------------------------------------------------
    #! test a different bot rule for alert
    #! -----------------------------------------------------
    print("testing alert in rule")
    l_headers['user-agent'] = 'bot-alert'
    l_r = requests.get(l_uri, headers=l_headers)
    # ------------------------------------------------------
    # assert we should have received alert
    # ------------------------------------------------------
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json['bot_event']['bot_score'] == 0
    assert isinstance(l_r_json['bot_event'], dict)
# ------------------------------------------------------------------------------
# test_bot_action_types
# ------------------------------------------------------------------------------
def test_custom_bot_score_rule(setup_waflz_server_action):
    # ------------------------------------------------------
    # load bot_manager (because we are going to update it)
    # ------------------------------------------------------
    l_bot_manager_config_path = os.path.realpath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        '../../data/waf/conf/bot_manager/0052-3bUjds87.bot_manager.json'
    ))
    l_bot_manager_config = None
    with open(l_bot_manager_config_path, 'r') as file_handler:
        l_bot_manager_config = json.loads(file_handler.read());
    #! -----------------------------------------------------
    #! test the bot action fires
    #! -----------------------------------------------------
    print("testing custom_response in rule")
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'host': 'allbotmanagerchallenges.com',
        'waf-scopes-id': '0052',
        'user-agent': 'custom_bot_score'
    }
    # ------------------------------------------------------
    # update bot rules that check for bot_score
    # ------------------------------------------------------
    l_bot_manager_config['bots_prod_id'] = "WACKR4"
    update_bot_manager(l_bot_manager_config)
    #! -----------------------------------------------------
    #! test that bot_score fires rule
    #! -----------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers)
    l_r_json = l_r.json()
    # ------------------------------------------------------
    # assert we should have received custom response
    # ------------------------------------------------------
    assert l_r.status_code == 200
    assert isinstance(l_r_json['bot_event'], dict)
    assert l_r_json['bot_event']['sub_event'][0]['rule_id'] == 960009
    assert l_r_json['bot_event']['bot_score'] == 75
    assert l_r_json['bot_event']['sub_event'][0]['rule_msg'] == 'bot score is too high'
    assert l_r_json['bot_event']['bot_action'] == "ALERT"
    assert int(base64.b64decode(l_r_json['bot_event']['sub_event'][0]['matched_var']['value'])) == 75

# ------------------------------------------------------------------------------
# test ja3 from lmdb
# ------------------------------------------------------------------------------
def test_bot_score_from_lmdb(setup_waflz_server_bot_lmdb):
    # ------------------------------------------------------
    # load bot_manager (because we are going to update it)
    # ------------------------------------------------------
    l_bot_manager_config_path = os.path.realpath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        '../../data/waf/conf/bot_manager/0052-3bUjds87.bot_manager.json'
    ))
    l_bot_manager_config = None
    with open(l_bot_manager_config_path, 'r') as file_handler:
        l_bot_manager_config = json.loads(file_handler.read());
    # ------------------------------------------------------
    # update bot rules that check for bot_score
    # ------------------------------------------------------
    l_bot_manager_config['bots_prod_id'] = "WACKR4"
    update_bot_manager(l_bot_manager_config)
    #! -----------------------------------------------------
    #! test the bot action fires
    #! -----------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'host': 'allbotmanagerchallenges.com',
        'waf-scopes-id': '0052',
        'user-agent': 'custom_bot_score'
    }
    #! -----------------------------------------------------
    #! test that bot_score fires rule
    #! -----------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers)
    l_r_json = l_r.json()
    # ------------------------------------------------------
    # assert we should have received custom response
    # ------------------------------------------------------
    assert l_r.status_code == 200
    assert isinstance(l_r_json['bot_event'], dict)
    assert l_r_json['bot_event']['sub_event'][0]['rule_id'] == 960009
    assert l_r_json['bot_event']['bot_score'] == 75
    assert l_r_json['bot_event']['sub_event'][0]['rule_msg'] == 'bot score is too high'
    assert int(base64.b64decode(l_r_json['bot_event']['sub_event'][0]['matched_var']['value'])) == 75
    #! -----------------------------------------------------
    #! test the bot action fires on the ja3 level
    #! -----------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'host': 'allbotmanagerchallenges.com',
        'waf-scopes-id': '0052',
        'x-waflz-ja4': 'full_ja3_level'
    }
    #! -----------------------------------------------------
    #! test that bot_score fires rule
    #! -----------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers)
    l_r_json = l_r.json()
    # ------------------------------------------------------
    # assert we should have received custom response
    # ------------------------------------------------------
    assert l_r.status_code == 200
    assert isinstance(l_r_json['bot_event'], dict)
    assert l_r_json['bot_event']['sub_event'][0]['rule_id'] == 960009
    assert l_r_json['bot_event']['bot_score'] == 99
    #! -----------------------------------------------------
    #! test the bot action fires on the ip+ua level
    #! -----------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'host': 'allbotmanagerchallenges.com',
        'waf-scopes-id': '0052',
        'x-waflz-ip': '123.45.678.91',
        'User-Agent': 'custom_ip_bot_score'
    }
    #! -----------------------------------------------------
    #! test that bot_score fires rule
    #! -----------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers)
    l_r_json = l_r.json()
    # ------------------------------------------------------
    # assert we should have received custom response
    # ------------------------------------------------------
    print(l_r_json)
    assert l_r.status_code == 200
    assert isinstance(l_r_json['bot_event'], dict)
    assert l_r_json['bot_event']['sub_event'][0]['rule_id'] == 960009
    assert l_r_json['bot_event']['bot_score'] == 81
# ------------------------------------------------------------------------------
# test ja3 from lmdb
# ------------------------------------------------------------------------------
def test_bot_score_from_empty_ja3(setup_waflz_server_bot_lmdb):
    # ------------------------------------------------------
    # load bot_manager (because we are going to update it)
    # ------------------------------------------------------
    l_bot_manager_config_path = os.path.realpath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        '../../data/waf/conf/bot_manager/0052-3bUjds87.bot_manager.json'
    ))
    l_bot_manager_config = None
    with open(l_bot_manager_config_path, 'r') as file_handler:
        l_bot_manager_config = json.loads(file_handler.read());
    # ------------------------------------------------------
    # update bot rules that check for bot_score
    # ------------------------------------------------------
    l_bot_manager_config['bots_prod_id'] = "WACKR4"
    update_bot_manager(l_bot_manager_config)
    #! -----------------------------------------------------
    #! test the bot action fires
    #! -----------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'host': 'allbotmanagerchallenges.com',
        'waf-scopes-id': '0052',
        'user-agent': 'custom_bot_score'
    }
    #! -----------------------------------------------------
    #! test that bot_score fires rule
    #! -----------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers)
    l_r_json = l_r.json()
    # ------------------------------------------------------
    # assert we should have received custom response
    # ------------------------------------------------------
    assert l_r.status_code == 200
    assert isinstance(l_r_json['bot_event'], dict)
    assert l_r_json['bot_event']['sub_event'][0]['rule_id'] == 960009
    assert l_r_json['bot_event']['bot_score'] == 75
    assert l_r_json['bot_event']['sub_event'][0]['rule_msg'] == 'bot score is too high'
    assert int(base64.b64decode(l_r_json['bot_event']['sub_event'][0]['matched_var']['value'])) == 75
    #! -----------------------------------------------------
    #! test the bot action fires on the empty ja3
    #! -----------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'host': 'allbotmanagerchallenges.com',
        'waf-scopes-id': '0052',
        'x-waflz-ja4': 'empty'
    }
    #! -----------------------------------------------------
    #! test that bot_score fires rule
    #! -----------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers)
    l_r_json = l_r.json()
    # ------------------------------------------------------
    # assert we should have received custom response
    # ------------------------------------------------------
    assert l_r.status_code == 200
    assert isinstance(l_r_json['bot_event'], dict)
    assert l_r_json['bot_event']['sub_event'][0]['rule_id'] == 960009
    assert l_r_json['bot_event']['bot_score'] == 100

# ------------------------------------------------------------------------------
# test ja4 exception from lmdb
# ------------------------------------------------------------------------------
def test_ja4_exception(setup_waflz_server_bot_lmdb):
    # ------------------------------------------------------
    # load bot_manager (because we are going to update it)
    # ------------------------------------------------------
    l_bot_manager_config_path = os.path.realpath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        '../../data/waf/conf/bot_manager/0052-3bUjds87.bot_manager.json'
    ))
    l_bot_manager_config = None
    with open(l_bot_manager_config_path, 'r') as file_handler:
        l_bot_manager_config = json.loads(file_handler.read());
    # ------------------------------------------------------
    # update bot rules that check for bot_score
    # ------------------------------------------------------
    l_bot_manager_config['bots_prod_id'] = "WACKR4"
    update_bot_manager(l_bot_manager_config)
    #! -----------------------------------------------------
    #! test the bot action fires
    #! -----------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'host': 'allbotmanagerchallenges.com',
        'waf-scopes-id': '0052',
        'user-agent': 'custom_bot_score'
    }
    #! -----------------------------------------------------
    #! test that bot_score fires rule
    #! -----------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers)
    l_r_json = l_r.json()
    # ------------------------------------------------------
    # assert we should have received custom response
    # ------------------------------------------------------
    assert l_r.status_code == 200
    assert isinstance(l_r_json['bot_event'], dict)
    assert l_r_json['bot_event']['sub_event'][0]['rule_id'] == 960009
    assert l_r_json['bot_event']['bot_score'] == 75
    assert l_r_json['bot_event']['sub_event'][0]['rule_msg'] == 'bot score is too high'
    assert int(base64.b64decode(l_r_json['bot_event']['sub_event'][0]['matched_var']['value'])) == 75
    # ------------------------------------------------------
    # use a ja4 that is in the exception list
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'host': 'allbotmanagerchallenges.com',
        'waf-scopes-id': '0052',
        'user-agent': 'custom_bot_score',
        'x-waflz-ja4': 'this_should_be_ignored'
    }
    #! -----------------------------------------------------
    #! test that bot_score does not fire rule
    #! -----------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers)
    l_r_json = l_r.json()
    # ------------------------------------------------------
    # assert we should have not have recieved a custom
    # response
    # ------------------------------------------------------
    assert l_r.status_code == 200
    assert 'bot_event' not in l_r_json
# ------------------------------------------------------------------------------
# test ja3 from lmdb
# ------------------------------------------------------------------------------
def test_eq_for_bot_score(setup_waflz_server_bot_lmdb):
    # ------------------------------------------------------
    # load bot_manager (because we are going to update it)
    # ------------------------------------------------------
    l_bot_manager_config_path = os.path.realpath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        '../../data/waf/conf/bot_manager/0052-3bUjds87.bot_manager.json'
    ))
    l_bot_manager_config = None
    with open(l_bot_manager_config_path, 'r') as file_handler:
        l_bot_manager_config = json.loads(file_handler.read());
    # ------------------------------------------------------
    # update bot rules that check for bot_score
    # ------------------------------------------------------
    l_bot_manager_config['bots_prod_id'] = "eq4ule"
    update_bot_manager(l_bot_manager_config)
    #! -----------------------------------------------------
    #! test the bot action fires on the empty ja3
    #! -----------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'host': 'allbotmanagerchallenges.com',
        'waf-scopes-id': '0052',
        'x-waflz-ja4': 'empty'
    }
    #! -----------------------------------------------------
    #! test that bot_score fires rule
    #! -----------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers)
    l_r_json = l_r.json()
    # ------------------------------------------------------
    # assert we should have received custom response
    # ------------------------------------------------------
    assert l_r.status_code == 200
    assert isinstance(l_r_json['bot_event'], dict)
    assert l_r_json['bot_event']['sub_event'][0]['rule_id'] == 960009
    assert l_r_json['bot_event']['sub_event'][0]['rule_msg'] == "bot score is 100"
    assert l_r_json['bot_event']['bot_score'] == 100

def test_spoof_ip_gets_proper_bot_score(setup_waflz_server_bot_lmdb):
    #! -----------------------------------------------------
    #! test the bot action fires on the ip+ua level
    #! -----------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {
        'host': 'spoof_testing.com',
        'waf-scopes-id': '0052',
        'x-waflz-ip': '123.45.678.91',
        'User-Agent': 'custom_ip_bot_score'
    }
    #! -----------------------------------------------------
    #! test that bot_score fires rule
    #! -----------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers)
    l_r_json = l_r.json()
    # ------------------------------------------------------
    # assert we should have received custom response with
    # score of 81 (coming from origin ip + ua)
    # ------------------------------------------------------
    print(l_r_json)
    assert l_r.status_code == 200
    assert isinstance(l_r_json['bot_event'], dict)
    assert l_r_json['bot_event']['sub_event'][0]['rule_id'] == 960009
    assert l_r_json['bot_event']['bot_score'] == 81
    # ------------------------------------------------------
    # use the spoof header to use a different ip that has
    # a score of 82
    # ------------------------------------------------------
    l_headers['testing_ip'] = '123.45.0.90'
    #! -----------------------------------------------------
    #! test that bot_score fires rule
    #! -----------------------------------------------------
    l_r = requests.get(l_uri, headers=l_headers)
    l_r_json = l_r.json()
    # ------------------------------------------------------
    # assert we should have received custom response with
    # score of 99 (coming from spoofed ip)
    # ------------------------------------------------------
    print(l_r_json)
    assert l_r.status_code == 200
    assert isinstance(l_r_json['bot_event'], dict)
    assert l_r_json['bot_event']['sub_event'][0]['rule_id'] == 960009
    assert l_r_json['bot_event']['bot_score'] == 83
