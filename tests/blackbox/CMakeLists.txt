# ------------------------------------------------------------------------------
# Look for required python files
# ------------------------------------------------------------------------------
# TODO: use FindPython (available 3.12) - https://cmake.org/cmake/help/latest/module/FindPython.html
# find_python_module(pytest REQUIRED)
# find_python_module(requests REQUIRED)
# ------------------------------------------------------------------------------
# waflz
# ------------------------------------------------------------------------------
add_test(blackbox_acl_accesslists        ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/acl/test_bb_acl_accesslists.py)
add_test(blackbox_ruleset                ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/ruleset/test_ruleset.py)
add_test(blackbox_rules                  ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/rules/test_bb_rules.py)
add_test(blackbox_rtu                    ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/rules/test_bb_rtu.py)
add_test(blackbox_profile                ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/profile/test_bb_profile.py)
add_test(blackbox_profile_w_custom_score ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/profile/test_bb_profile_custom_score.py)
add_test(blackbox_wjc                    ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/wjc/test_bb_wjc.py)
add_test(blackbox_botm_challenge         ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/bot_manager/test_bb_botmanager_challenge.py)
add_test(blackbox_botm_known             ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/bot_manager/test_bb_botmanager_known_bots.py)
add_test(blackbox_botm_bot_action        ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/bot_manager/test_bb_botmanager_bot_actions.py)
add_test(blackbox_botm_bot_action_new    ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/bot_manager/test_bb_botmanager_bot_actions_new.py)
add_test(blackbox_botm_captcha           ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/bot_manager/test_bb_botmanager_captcha.py)
add_test(blackbox_api_gw                 ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/api_gw/test_bb_api_gw.py)
add_test(blackbox_schema                 ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/schema/test_bb_schema.py)
add_test(blackbox_scopes                 ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/scopes/test_bb_scopes.py)
add_test(blackbox_scopes_updates         ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/scopes/test_bb_scopes_updates.py)
add_test(blackbox_scopes_response        ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/scopes/test_bb_scopes_response.py)
add_test(blackbox_limit_lmdb             ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/limit/test_bb_limit_lmdb.py)
add_test(blackbox_limit                  ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/limit/test_bb_limit.py)
add_test(blackbox_limit_keys             ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh ${CMAKE_CURRENT_SOURCE_DIR}/limit/test_bb_limit_keys.py)
# ------------------------------------------------------------------------------
# tests
# ------------------------------------------------------------------------------
add_custom_target(blackbox
  ${CMAKE_SOURCE_DIR}/tests/blackbox/run_tests.sh
  DEPENDS blackbox
)
