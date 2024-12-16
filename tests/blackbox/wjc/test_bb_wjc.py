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
# ------------------------------------------------------------------------------
# globals
# ------------------------------------------------------------------------------
g_file_path = ''
g_ruleset_path = ''
g_wjc_path = ''
# ------------------------------------------------------------------------------
# fixture
# ------------------------------------------------------------------------------
@pytest.fixture(scope='module')
def setup_wjc():
    global g_file_path
    global g_ruleset_path
    global g_wjc_path
    global g_meta_schema_path
    l_cwd = os.getcwd()
    g_file_path = os.path.dirname(os.path.abspath(__file__))
    g_ruleset_path = os.path.realpath(os.path.join(g_file_path, '../../data/waf/ruleset'))
    g_wjc_path = os.path.abspath(os.path.join(g_file_path, '../../../build/util/wjc/wjc'))
    g_meta_schema_path = os.path.abspath(os.path.join(g_file_path, '../../data/JSON_Schema/JSON_Schema_Draft_4.json'))
# ------------------------------------------------------------------------------
# test output with bad regex
# ------------------------------------------------------------------------------
def test_bb_wjc_bad_regex(setup_wjc):
    global g_file_path
    global g_ruleset_path
    global g_wjc_path
    l_profile_path = os.path.realpath(os.path.join(g_file_path, 'test_bb_wjc_bad_regex.waf.prof.json'))
    l_sp = subprocess.Popen([g_wjc_path, '-p', l_profile_path, '-r', g_ruleset_path], stderr=subprocess.PIPE)
    l_sp_stderr = l_sp.communicate()[1]
    #print(l_sp_stderr)
    #print('return code: %d'%(l_sp.returncode))
    assert l_sp.returncode != 0
    assert l_sp_stderr == b'init failed for regex: \'**dogs[]\' in general_settings ignore list. Reason: nothing to repeat -offset: 0\n'
# ------------------------------------------------------------------------------
# test output with bad regex
# ------------------------------------------------------------------------------
def test_bb_wjc_bad_asn(setup_wjc):
    global g_file_path
    global g_ruleset_path
    global g_wjc_path
    l_profile_path = os.path.realpath(os.path.join(g_file_path, 'test_bb_wjc_bad_asn.waf.prof.json'))
    l_sp = subprocess.Popen([g_wjc_path, '-p', l_profile_path, '-r', g_ruleset_path], stderr=subprocess.PIPE)
    l_sp_stderr = l_sp.communicate()[1]
    # print(l_sp_stderr)
    # print('return code: %d'%(l_sp.returncode))
    assert l_sp.returncode != 0
    assert l_sp_stderr == b'expecting type: uint32 for field: \'waflz_pb.acl.lists_asn_t.blacklist\'\n'
# ------------------------------------------------------------------------------
# test output with bad ip
# ------------------------------------------------------------------------------
def test_bb_wjc_bad_ip(setup_wjc):
    global g_file_path
    global g_ruleset_path
    global g_wjc_path
    l_acl_path = os.path.realpath(os.path.join(g_file_path, 'test_bb_wjc_bad_ip.acl.json'))
    l_sp = subprocess.Popen([g_wjc_path, '-a', l_acl_path], stderr=subprocess.PIPE)
    l_sp_stderr = l_sp.communicate()[1]
    # print(l_sp_stderr)
    # print('return code: %d'%(l_sp.returncode))
    assert l_sp.returncode != 0
    assert l_sp_stderr == b'adding ip \'8.8.8.8,\'\n'

# ------------------------------------------------------------------------------
# test output with bad schema
# ------------------------------------------------------------------------------
def test_bb_wjc_bad_schema(setup_wjc):
    global g_file_path
    global g_ruleset_path
    global g_wjc_path
    l_schema_path = os.path.realpath(os.path.join(g_file_path, 'test_bb_wjc_bad_schema.api_schema.json'))
    l_sp = subprocess.Popen([g_wjc_path, '-S', l_schema_path, '-J', g_meta_schema_path], stderr=subprocess.PIPE)
    l_sp_stderr = l_sp.communicate()[1]
    # print(l_sp_stderr)
    # print('return code: %d'%(l_sp.returncode))
    assert l_sp.returncode != 0
    l_ret = "Schema at {} failed meta-schema validation\n".format(l_schema_path)
    l_bytes = l_ret.encode('UTF-8')
    assert l_sp_stderr == l_bytes
