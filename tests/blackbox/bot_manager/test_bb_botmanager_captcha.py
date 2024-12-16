#!/usr/bin/env python3
'''
Test captcha with bot manager
'''
# ------------------------------------------------------------------------------
# Imports
# ------------------------------------------------------------------------------
import subprocess
import os
import json
import sys
import time
import re
import requests
import pytest
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
# run_command
# ------------------------------------------------------------------------------
def run_command(command):
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    return (p.returncode, stdout, stderr)
# ------------------------------------------------------------------------------
# setup waflz server in event mode
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_waflz_server_event():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    # l_cwd = os.getcwd()
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_geoip2city_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-City.mmdb'))
    l_geoip2ISP_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-ASN.mmdb'))
    l_conf_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf'))
    l_captcha_file = os.path.realpath(os.path.join(l_file_path, '../../data/bot/bot-captcha.b64'))
    l_bot_info_file = os.path.realpath(os.path.join(l_file_path, '../../data/bot/known_bot_info.json'))
    l_ruleset_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/ruleset'))
    l_scopes_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/scopes'))
    l_waflz_server_path = os.path.abspath(os.path.join(l_file_path, '../../../build/util/waflz_server/waflz_server'))
    l_subproc = subprocess.Popen([l_waflz_server_path,
                                  '-d', l_conf_dir,
                                  '-b', l_scopes_dir,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path,
                                  '-i', l_captcha_file,
                                  '-Q', str(l_bot_info_file)])
    print('cmd: \n{}\n'.format(' '.join([l_waflz_server_path,
                                  '-d', l_conf_dir,
                                  '-b', l_scopes_dir,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path,
                                  '-i', l_captcha_file,
                                  '-Q', str(l_bot_info_file)])))
    time.sleep(1)
    # ------------------------------------------------------
    # yield...
    # ------------------------------------------------------
    yield setup_waflz_server_event
    # ------------------------------------------------------
    # tear down
    # ------------------------------------------------------
    _, _, _ = run_command('kill -9 %d'%(l_subproc.pid))
    time.sleep(0.5)
# ------------------------------------------------------------------------------
# setup waflz server in action mode
# ------------------------------------------------------------------------------
@pytest.fixture()
def setup_waflz_server_action():
    # ------------------------------------------------------
    # setup
    # ------------------------------------------------------
    # l_cwd = os.getcwd()
    l_file_path = os.path.dirname(os.path.abspath(__file__))
    l_geoip2city_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-City.mmdb'))
    l_geoip2ISP_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/db/GeoLite2-ASN.mmdb'))
    l_conf_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf'))
    l_captcha_file = os.path.realpath(os.path.join(l_file_path, '../../data/bot/bot-captcha.b64'))
    l_bot_info_file = os.path.realpath(os.path.join(l_file_path, '../../data/bot/known_bot_info.json'))

    l_ruleset_path = os.path.realpath(os.path.join(l_file_path, '../../data/waf/ruleset'))
    l_scopes_dir = os.path.realpath(os.path.join(l_file_path, '../../data/waf/conf/scopes'))
    l_waflz_server_path = os.path.abspath(os.path.join(l_file_path, '../../../build/util/waflz_server/waflz_server'))
    l_subproc = subprocess.Popen([l_waflz_server_path,
                                  '-d', l_conf_dir,
                                  '-b', l_scopes_dir,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path,
                                  '-i', l_captcha_file,
                                  '-Q', str(l_bot_info_file),
                                  '-j'])
    print('cmd: \n{}\n'.format(' '.join([l_waflz_server_path,
                                  '-d', l_conf_dir,
                                  '-b', l_scopes_dir,
                                  '-r', l_ruleset_path,
                                  '-g', l_geoip2city_path,
                                  '-s', l_geoip2ISP_path,
                                  '-i', l_captcha_file,
                                  '-Q', str(l_bot_info_file),
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


def test_captcha_action_for_bot_rules(setup_waflz_server_action):    
	# ------------------------------------------------------
    # test for recieving a bot captcha
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'testcaptcha.com',
                 'user-agent': 'captcha-testing',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 401
    # ------------------------------------------------------
    # reusing a google token from manual test.
    # captcha script can't be executed programmatically,
    # it needs a correct domain name and site key
    # due to token reuse, captcha will fail and second
    # action "custom response" gets implemented
    # ------------------------------------------------------
    l_g_token = "03AEkXODAXXQZDIorggQl9PptE2p6VNVgbGNvidcfLA25RFZZ5i1f1XKYFPANznmNQoRpDbEyNxUs3LbPMFEViRkZ0NVyfHwC5Cwyt7CjbAbGicc3tubCo0kVLXRg4JpQVxdnLl4L3tO_VrKCrFhG1y9pp8qPQX5X26FrZlriiNnNvJe8l_hHpgY5iynyw1R6LoNf2K_pE33Zk5V_WjBRkqveH3yJZPdHmmDWfasGB4DlmjB5qYdqp9BHW_L_rdWO4KBR1iQXjBDtmNIaZDrb-lh6ETmTuiS3wM32i61TE6Gk50S5e2z-gdyag8SaAv7Q3aC_BCmljPqaYDQlNVpPWLXhMpFv1OHPuQbenAxc8_Vc4OUzaF9QT7pFkhd--vubqScrEAGL9NiRni6q5XXkzf5qddSbrJA3B2os-tal91h2FuiFZFuwnKUDuc3j7Xh24KWP--DEwyz7HKtieYLXsJRH-Nsoyl_h7qbrdSeyrAh7_dtrtNhAOKNfdVTVB25PHLR3kzqm9zEgdLw41mrAbJUjDeUKR5F2YcxLtT0ZQwkuKwUWLNSHiL44"
    l_site_cookie = "__ecreha__="+l_g_token
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'testcaptcha.com',
                 'user-agent': 'captcha-testing',
                 'Cookie': l_site_cookie,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert '__ecrever__' in l_r.headers['Set-Cookie']
    l_verified_cookie = l_r.headers['Set-Cookie']
    assert l_r.text == "recaptcha failed. request not allowed\n"
    # ------------------------------------------------------
    # sending valid ec token in cookie.
    # should get 200
    # ------------------------------------------------------

    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'testcaptcha.com',
                 'user-agent': 'captcha-testing',
                 'Cookie': l_verified_cookie,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # sleep for 3 sec. send token again in cookie.
    # captcha should be issued because of token expiry
    # ------------------------------------------------------
    time.sleep(3)
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'testcaptcha.com',
                 'user-agent': 'captcha-testing',
                 'Cookie': l_verified_cookie,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 401


def test_captcha_event_for_bot_rules(setup_waflz_server_event):    
    # ------------------------------------------------------
    # test for recieving a bot captcha
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'testcaptcha.com',
                 'user-agent': 'captcha-testing',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'bot_event' in l_r_json
    assert l_r_json['bot_event']['captcha_status'] == 'CAPTCHA_ISSUED_NO_GOOGLE_TOKEN'
    assert l_r_json['bot_event']['bot_manager_config_id'] == 'DYhGetLq'
    assert l_r_json['bot_event']['bots_config_id'] == '89W3CPRu'
    assert l_r_json['bot_event']['bot_event'] == True
    assert l_r_json['bot_event']['token_duration_sec'] == 3
    # ------------------------------------------------------
    # reusing a google token from manual test.
    # captcha script can't be executed programmatically,
    # it needs a correct domain name and site key
    # should get an event for captcha failure because of token reuse
    # ------------------------------------------------------
    l_g_token = "03AEkXODAXXQZDIorggQl9PptE2p6VNVgbGNvidcfLA25RFZZ5i1f1XKYFPANznmNQoRpDbEyNxUs3LbPMFEViRkZ0NVyfHwC5Cwyt7CjbAbGicc3tubCo0kVLXRg4JpQVxdnLl4L3tO_VrKCrFhG1y9pp8qPQX5X26FrZlriiNnNvJe8l_hHpgY5iynyw1R6LoNf2K_pE33Zk5V_WjBRkqveH3yJZPdHmmDWfasGB4DlmjB5qYdqp9BHW_L_rdWO4KBR1iQXjBDtmNIaZDrb-lh6ETmTuiS3wM32i61TE6Gk50S5e2z-gdyag8SaAv7Q3aC_BCmljPqaYDQlNVpPWLXhMpFv1OHPuQbenAxc8_Vc4OUzaF9QT7pFkhd--vubqScrEAGL9NiRni6q5XXkzf5qddSbrJA3B2os-tal91h2FuiFZFuwnKUDuc3j7Xh24KWP--DEwyz7HKtieYLXsJRH-Nsoyl_h7qbrdSeyrAh7_dtrtNhAOKNfdVTVB25PHLR3kzqm9zEgdLw41mrAbJUjDeUKR5F2YcxLtT0ZQwkuKwUWLNSHiL44"
    l_site_cookie = "__ecreha__="+l_g_token
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'testcaptcha.com',
                 'user-agent': 'captcha-testing',
                 'Cookie': l_site_cookie,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json['bot_event']['captcha_status'] == 'CAPTCHA_FAILED_RESULT_ERROR'
    assert l_r_json['bot_event']['captcha_error_message'] == 'timeout-or-duplicate/'
    assert l_r_json['bot_event']['bot_manager_config_id'] == 'DYhGetLq'
    assert l_r_json['bot_event']['bots_config_id'] == '89W3CPRu'
    assert l_r_json['bot_event']['bot_event'] == True
    assert l_r_json['bot_event']['token_duration_sec'] == 3


def test_captcha_event_for_known_bots(setup_waflz_server_event):
    # ------------------------------------------------------
    # test captcha for known bot from 'other' category
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'testcaptcha.com',
                 'user-agent': 'bingbot',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'bot_event' in l_r_json
    assert l_r_json['bot_event']['captcha_status'] == 'CAPTCHA_ISSUED_NO_GOOGLE_TOKEN'
    assert l_r_json['bot_event']['bot_manager_config_id'] == 'DYhGetLq'
    assert l_r_json['bot_event']['sub_event'][0]['rule_id'] == 70002
    assert l_r_json['bot_event']['sub_event'][0]['rule_msg'] == 'Known Bot: Other Known Bot Categories'
    assert l_r_json['bot_event']['token_duration_sec'] == 3
    # ------------------------------------------------------
    # send fake google token for the same known bot from 
    # other category.
    # captchas hould fail 
    # ------------------------------------------------------
    l_g_token = "03AEkXODAXXQZDIorggQl9PptE2p6VNVgbGNvidcfLA25RFZZ5i1f1XKYFPANznmNQoRpDbEyNxUs3LbPMFEViRkZ0NVyfHwC5Cwyt7CjbAbGicc3tubCo0kVLXRg4JpQVxdnLl4L3tO_VrKCrFhG1y9pp8qPQX5X26FrZlriiNnNvJe8l_hHpgY5iynyw1R6LoNf2K_pE33Zk5V_WjBRkqveH3yJZPdHmmDWfasGB4DlmjB5qYdqp9BHW_L_rdWO4KBR1iQXjBDtmNIaZDrb-lh6ETmTuiS3wM32i61TE6Gk50S5e2z-gdyag8SaAv7Q3aC_BCmljPqaYDQlNVpPWLXhMpFv1OHPuQbenAxc8_Vc4OUzaF9QT7pFkhd--vubqScrEAGL9NiRni6q5XXkzf5qddSbrJA3B2os-tal91h2FuiFZFuwnKUDuc3j7Xh24KWP--DEwyz7HKtieYLXsJRH-Nsoyl_h7qbrdSeyrAh7_dtrtNhAOKNfdVTVB25PHLR3kzqm9zEgdLw41mrAbJUjDeUKR5F2YcxLtT0ZQwkuKwUWLNSHiL44"
    l_site_cookie = "__ecreha__="+l_g_token
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'testcaptcha.com',
                 'user-agent': 'bingbot',
                 'Cookie': l_site_cookie,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert l_r_json['bot_event']['captcha_status'] == 'CAPTCHA_FAILED_RESULT_ERROR'
    assert l_r_json['bot_event']['captcha_error_message'] == 'timeout-or-duplicate/'
    assert l_r_json['bot_event']['bot_manager_config_id'] == 'DYhGetLq'
    assert l_r_json['bot_event']['sub_event'][0]['rule_id'] == 70002
    assert l_r_json['bot_event']['sub_event'][0]['rule_msg'] == 'Known Bot: Other Known Bot Categories'
    assert l_r_json['bot_event']['token_duration_sec'] == 3
    # ------------------------------------------------------
    # test captcha for google bot with valid google ip
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'testcaptcha.com',
                 'user-agent': 'googleweblight',
                 'x-waflz-ip': '74.125.218.93',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'bot_event' in l_r_json
    assert l_r_json['bot_event']['captcha_status'] == 'CAPTCHA_ISSUED_NO_GOOGLE_TOKEN'
    assert l_r_json['bot_event']['bot_manager_config_id'] == 'DYhGetLq'
    assert l_r_json['bot_event']['sub_event'][0]['rule_id'] == 70001
    assert l_r_json['bot_event']['sub_event'][0]['rule_msg'] == 'Known Bot: Explicit Known Bot Token'
    assert l_r_json['bot_event']['token_duration_sec'] == 3
    # ------------------------------------------------------
    # send fake google token for the same known bot
    # captcha should fail
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'testcaptcha.com',
                 'user-agent': 'googleweblight',
                 'x-waflz-ip': '74.125.218.93',
                 'Cookie': l_site_cookie,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'bot_event' in l_r_json
    assert l_r_json['bot_event']['captcha_status'] == 'CAPTCHA_FAILED_RESULT_ERROR'
    assert l_r_json['bot_event']['captcha_error_message'] == 'timeout-or-duplicate/'
    assert l_r_json['bot_event']['bot_manager_config_id'] == 'DYhGetLq'
    assert l_r_json['bot_event']['sub_event'][0]['rule_id'] == 70001
    assert l_r_json['bot_event']['sub_event'][0]['rule_msg'] == 'Known Bot: Explicit Known Bot Token'
    assert l_r_json['bot_event']['token_duration_sec'] == 3
    # ------------------------------------------------------
    # test captcha for google bot with spoof ip
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'testcaptcha.com',
                 'user-agent': 'googleweblight',
                 'x-waflz-ip': '17.121.115.98',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'bot_event' in l_r_json
    assert l_r_json['bot_event']['captcha_status'] == 'CAPTCHA_ISSUED_NO_GOOGLE_TOKEN'
    assert l_r_json['bot_event']['bot_manager_config_id'] == 'DYhGetLq'
    assert l_r_json['bot_event']['sub_event'][0]['rule_id'] == 70000
    assert l_r_json['bot_event']['sub_event'][0]['rule_msg'] == 'Spoofed Bot: Client Impersonating A Known Bot'
    assert l_r_json['bot_event']['token_duration_sec'] == 3
    # ------------------------------------------------------
    # send fake google token for the same known bot
    # captcha should fail
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'testcaptcha.com',
                 'user-agent': 'googleweblight',
                 'x-waflz-ip': '17.121.115.98',
                 'Cookie': l_site_cookie,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    l_r_json = l_r.json()
    assert 'bot_event' in l_r_json
    assert l_r_json['bot_event']['captcha_status'] == 'CAPTCHA_FAILED_RESULT_ERROR'
    assert l_r_json['bot_event']['captcha_error_message'] == 'timeout-or-duplicate/'
    assert l_r_json['bot_event']['bot_manager_config_id'] == 'DYhGetLq'
    assert l_r_json['bot_event']['sub_event'][0]['rule_id'] == 70000
    assert l_r_json['bot_event']['sub_event'][0]['rule_msg'] == 'Spoofed Bot: Client Impersonating A Known Bot'
    assert l_r_json['bot_event']['token_duration_sec'] == 3

def test_captcha_action_for_known_bots(setup_waflz_server_action):
    # ------------------------------------------------------
    # test captcha for known bot from 'other' category
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'testcaptcha.com',
                 'user-agent': 'bingbot',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 401
    # ------------------------------------------------------
    # send fake google token for the same known bot from 
    # other category. captcha should fail
    # should get custom response which is faile_action_type
    # should see verfied cookie in cookie list
    # ------------------------------------------------------
    l_g_token = "03AEkXODAXXQZDIorggQl9PptE2p6VNVgbGNvidcfLA25RFZZ5i1f1XKYFPANznmNQoRpDbEyNxUs3LbPMFEViRkZ0NVyfHwC5Cwyt7CjbAbGicc3tubCo0kVLXRg4JpQVxdnLl4L3tO_VrKCrFhG1y9pp8qPQX5X26FrZlriiNnNvJe8l_hHpgY5iynyw1R6LoNf2K_pE33Zk5V_WjBRkqveH3yJZPdHmmDWfasGB4DlmjB5qYdqp9BHW_L_rdWO4KBR1iQXjBDtmNIaZDrb-lh6ETmTuiS3wM32i61TE6Gk50S5e2z-gdyag8SaAv7Q3aC_BCmljPqaYDQlNVpPWLXhMpFv1OHPuQbenAxc8_Vc4OUzaF9QT7pFkhd--vubqScrEAGL9NiRni6q5XXkzf5qddSbrJA3B2os-tal91h2FuiFZFuwnKUDuc3j7Xh24KWP--DEwyz7HKtieYLXsJRH-Nsoyl_h7qbrdSeyrAh7_dtrtNhAOKNfdVTVB25PHLR3kzqm9zEgdLw41mrAbJUjDeUKR5F2YcxLtT0ZQwkuKwUWLNSHiL44"
    l_site_cookie = "__ecreha__="+l_g_token
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'testcaptcha.com',
                 'user-agent': 'bingbot',
                 'Cookie': l_site_cookie,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert '__ecrever__' in l_r.headers['Set-Cookie']
    l_verified_cookie = l_r.headers['Set-Cookie']
    assert l_r.text == "recaptcha failed. request not allowed\n"
    # ------------------------------------------------------
    # sending valid ec token in cookie.
    # should get 200
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'testcaptcha.com',
                 'user-agent': 'bingbot',
                 'Cookie': l_verified_cookie,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # sleep for 3 sec. send token again in cookie.
    # captcha should be issued because of token expiry
    # ------------------------------------------------------
    time.sleep(3)
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'testcaptcha.com',
                 'user-agent': 'bingbot',
                 'Cookie': l_verified_cookie,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 401

def test_captcha_action_for_spoof_bots(setup_waflz_server_action):
    # ------------------------------------------------------
    # test captcha for google bot with spoof ip
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'testcaptcha.com',
                 'user-agent': 'googleweblight',
                 'x-waflz-ip': '17.121.115.98',
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 401
    # ------------------------------------------------------
    # send fake google token for the same known bot from 
    # other category. captcha should fail.
    # should get custom response which is failed_action_type
    # should see verfied cookie in cookie list
    # ------------------------------------------------------
    l_g_token = "03AEkXODAXXQZDIorggQl9PptE2p6VNVgbGNvidcfLA25RFZZ5i1f1XKYFPANznmNQoRpDbEyNxUs3LbPMFEViRkZ0NVyfHwC5Cwyt7CjbAbGicc3tubCo0kVLXRg4JpQVxdnLl4L3tO_VrKCrFhG1y9pp8qPQX5X26FrZlriiNnNvJe8l_hHpgY5iynyw1R6LoNf2K_pE33Zk5V_WjBRkqveH3yJZPdHmmDWfasGB4DlmjB5qYdqp9BHW_L_rdWO4KBR1iQXjBDtmNIaZDrb-lh6ETmTuiS3wM32i61TE6Gk50S5e2z-gdyag8SaAv7Q3aC_BCmljPqaYDQlNVpPWLXhMpFv1OHPuQbenAxc8_Vc4OUzaF9QT7pFkhd--vubqScrEAGL9NiRni6q5XXkzf5qddSbrJA3B2os-tal91h2FuiFZFuwnKUDuc3j7Xh24KWP--DEwyz7HKtieYLXsJRH-Nsoyl_h7qbrdSeyrAh7_dtrtNhAOKNfdVTVB25PHLR3kzqm9zEgdLw41mrAbJUjDeUKR5F2YcxLtT0ZQwkuKwUWLNSHiL44"
    l_site_cookie = "__ecreha__="+l_g_token
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'testcaptcha.com',
                 'user-agent': 'googleweblight',
                 'x-waflz-ip': '17.121.115.98',
                 'Cookie': l_site_cookie,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 403
    assert '__ecrever__' in l_r.headers['Set-Cookie']
    l_verified_cookie = l_r.headers['Set-Cookie']
    assert l_r.text == "recaptcha failed. request not allowed\n"
    # ------------------------------------------------------
    # sending valid ec token in cookie.
    # should get 200
    # ------------------------------------------------------
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'testcaptcha.com',
                 'user-agent': 'googleweblight',
                 'x-waflz-ip': '17.121.115.98',
                 'Cookie': l_verified_cookie,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 200
    # ------------------------------------------------------
    # sleep for 3 sec. send token again in cookie.
    # captcha should be issued because of token expiry
    # ------------------------------------------------------
    time.sleep(3)
    l_uri = G_TEST_HOST+'/test.html'
    l_headers = {'host': 'testcaptcha.com',
                 'user-agent': 'googleweblight',
                 'x-waflz-ip': '17.121.115.98',
                 'Cookie': l_verified_cookie,
                 'waf-scopes-id': '0052'}
    l_r = requests.get(l_uri, headers=l_headers)
    assert l_r.status_code == 401











    





