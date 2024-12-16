//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! Includes
//! ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "waflz/def.h"
#include "waflz/captcha.h"
#include "waflz/rqst_ctx.h"
#include "event.pb.h"
#include <unistd.h>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define CAPTCHA_GOOGLE_TOKEN "__ecreha__"
#define CAPTCHA_VERIFIED_TOKEN  "__ecrever__"
/* not bot response
{
    "success": true,
    "challenge_ts": "2022-10-06T17:44:39Z",
    "hostname": "localhost",
    "score": 0.9,
    "action": "homepage"
}
*/
/*
        {
          "success": false,
          "error-codes": [
            "timeout-or-duplicate"
          ]
        }
*/
//! ----------------------------------------------------------------------------
//! Define dummy sub request callbacks
//! ----------------------------------------------------------------------------
static int32_t get_recaptcha_subr_cb_no_success1(const std::string& a_url,
                                                 const std::string& a_post_params,
                                                 std::string& ao_resp,
                                                 void* ,
                                                 void*,
                                                 int)
{
        ao_resp.assign("{"\
                        "\"success\": false,"\
                        "\"error-codes\": ["\
                        "\"timeout-or-duplicate\""\
                        "]"\
                        "}");
        return WAFLZ_STATUS_OK;
}
static int32_t get_recaptcha_subr_cb_no_success2(const std::string& a_url,
                                                 const std::string& a_post_params,
                                                 std::string& ao_resp,
                                                 void*,
                                                 void*,
                                                 int)
{
        ao_resp.assign("{"\
                        "\"success\": false,"\
                        "\"error-codes\": ["\
                        "\"timeout-or-duplicate\","\
                        "\"bad-request\""\
                        "]"\
                        "}");
        return WAFLZ_STATUS_OK;
}
static int32_t get_recaptcha_subr_cb_good_bot_score(const std::string& a_url,
                                                    const std::string& a_post_params,
                                                    std::string& ao_resp,
                                                    void*,
                                                    void*,
                                                    int)
{
        ao_resp.assign("{"\
                       "\"success\": true,"\
                       "\"challenge_ts\": \"2022-10-06T17:44:39Z\","\
                       "\"hostname\": \"localhost\","\
                       "\"score\": 0.9,"\
                       "\"action\": \"homepage\""\
                        "}");
        return WAFLZ_STATUS_OK;
}
static int32_t get_recaptcha_subr_cb_bad_bot_score(const std::string& a_url,
                                                   const std::string& a_post_params,
                                                   std::string& ao_resp,
                                                   void*,
                                                   void*,
                                                   int)
{
        ao_resp.assign("{"\
                       "\"success\": true,"\
                       "\"challenge_ts\": \"2022-10-06T17:44:39Z\","\
                       "\"hostname\": \"localhost\","\
                       "\"score\": 0.4,"\
                       "\"action\": \"homepage\""\
                        "}");
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//!                  VERIFY TESTS
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! test to verify different results from google verify subrequest
//! ----------------------------------------------------------------------------
TEST_CASE("test subrequest results", "test subrequest results]") {
        SECTION("test verify") {
                int32_t l_s;
                waflz_pb::event *l_event = new ::waflz_pb::event();
                ns_waflz::captcha l_ca;
                // -----------------------------------------
                // cb
                // -----------------------------------------
                static ns_waflz::rqst_ctx_callbacks s_callbacks = {
                        NULL,
                        NULL, //get_rqst_host_cb,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL, //get_rqst_header_w_key_cb,
                        NULL,
                        NULL,
                        NULL, //get_rqst_local_addr_cb,
                        NULL, //get_rqst_canonical_port_cb,
                        NULL, //get_rqst_apparent_cache_status_cb,
                        NULL, //get_rqst_bytes_out_cb,
                        NULL, //get_rqst_bytes_in_cb,
                        NULL, //get_rqst_uuid_cb,
                        NULL, //get_cust_id_cb,
                        NULL,
                        get_recaptcha_subr_cb_no_success1
                };
                // -----------------------------------------
                // setup ctx
                // -----------------------------------------
                ns_waflz::rqst_ctx l_ctx(NULL, 0, 0, NULL);
                bool l_issue_captcha = false;
                waflz_pb::enforcement* l_enf = new ::waflz_pb::enforcement();
                l_enf->set_enf_type(::waflz_pb::enforcement_type_t_BLOCK_REQUEST);
                l_enf->set_status(403);
                // -----------------------------------------
                // google token is not set in cookies in
                // ctx
                // -----------------------------------------
                l_s = l_ca.check_google_token(&l_ctx,
                                              l_event,
                                              l_enf,
                                              l_issue_captcha);
                REQUIRE(l_s == WAFLZ_STATUS_ERROR);
                REQUIRE(l_event != NULL);
                REQUIRE(l_event->captcha_status() ==
                        waflz_pb::event_captcha_status_t_CAPTCHA_ISSUED_NO_GOOGLE_TOKEN);
                REQUIRE(l_issue_captcha == true);
                REQUIRE(l_ctx.m_captcha_enf == NULL);
                REQUIRE(l_ctx.m_ec_resp_token.empty());
                REQUIRE(l_ctx.m_resp_token == false);
                // -----------------------------------------
                // set google token in cookies,
                // set no_success1 callback for subrequest.
                // subrequest should be made and the
                // corresponding response should be registered
                // in rqst_ctx. validate_google_token
                // should mark the response as bot and event
                // with error message
                // -----------------------------------------
                bool l_is_bot = false;
                l_ctx.m_callbacks = &s_callbacks;
                l_ctx.m_cookie_map.clear();
                ns_waflz::data_t l_k;
                ns_waflz::data_t l_v;
                l_k.m_data = CAPTCHA_GOOGLE_TOKEN;
                l_k.m_len = strlen(CAPTCHA_GOOGLE_TOKEN);
                l_v.m_data = "testgoogletoken";
                l_v.m_len = strlen("testgoogletoken");
                l_ctx.m_cookie_map[l_k] = l_v;
                l_issue_captcha = false;
                l_s = l_ca.check_google_token(&l_ctx,
                                              l_event,
                                              l_enf,
                                              l_issue_captcha);
                REQUIRE(l_s == WAFLZ_STATUS_WAIT);
                REQUIRE(l_issue_captcha == false);
                REQUIRE(l_ctx.m_captcha_enf != NULL);
                REQUIRE(!l_ctx.m_subr_resp.empty());

                l_s = l_ca.validate_google_token(&l_ctx,
                                                 &l_event,
                                                 l_is_bot);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                REQUIRE(l_is_bot == true);
                REQUIRE(l_event != NULL);
                REQUIRE(l_event->captcha_status() == 
                        waflz_pb::event_captcha_status_t_CAPTCHA_FAILED_RESULT_ERROR);
                REQUIRE(l_event->captcha_error_message() == "timeout-or-duplicate/");
                REQUIRE(l_ctx.m_captcha_enf != NULL);
                waflz_pb::enforcement* l_e = (waflz_pb::enforcement*)l_ctx.m_captcha_enf;
                REQUIRE(l_e->enf_type() == waflz_pb::enforcement_type_t_BLOCK_REQUEST);
                REQUIRE(!l_ctx.m_ec_resp_token.empty());
                REQUIRE(l_ctx.m_resp_token == true);
                // -----------------------------------------
                // set no_success2 callback for subrequest
                // and verify whether event has all the
                // error messages
                // -----------------------------------------
                s_callbacks = {
                        NULL,
                        NULL, //get_rqst_host_cb,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL, //get_rqst_header_w_key_cb,
                        NULL,
                        NULL,
                        NULL, //get_rqst_local_addr_cb,
                        NULL, //get_rqst_canonical_port_cb,
                        NULL, //get_rqst_apparent_cache_status_cb,
                        NULL, //get_rqst_bytes_out_cb,
                        NULL, //get_rqst_bytes_in_cb,
                        NULL, //get_rqst_uuid_cb,
                        NULL, //get_cust_id_cb
                        NULL,
                        get_recaptcha_subr_cb_no_success2
                };
                l_is_bot = false;
                l_ctx.m_callbacks = &s_callbacks;
                l_issue_captcha = false;
                l_s = l_ca.check_google_token(&l_ctx,
                                              l_event,
                                              l_enf,
                                              l_issue_captcha);
                REQUIRE(l_s == WAFLZ_STATUS_WAIT);
                REQUIRE(l_issue_captcha == false);
                REQUIRE(l_ctx.m_captcha_enf != NULL);
                REQUIRE(!l_ctx.m_subr_resp.empty());

                l_s = l_ca.validate_google_token(&l_ctx,
                                                 &l_event,
                                                 l_is_bot);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                REQUIRE(l_is_bot == true);
                REQUIRE(l_event != NULL);
                REQUIRE(l_event->captcha_status() == 
                        waflz_pb::event_captcha_status_t_CAPTCHA_FAILED_RESULT_ERROR);
                REQUIRE(l_event->captcha_error_message() == "timeout-or-duplicate/bad-request/");
                REQUIRE(l_ctx.m_captcha_enf != NULL);
                l_e = (waflz_pb::enforcement*)l_ctx.m_captcha_enf;
                REQUIRE(l_e->enf_type() == waflz_pb::enforcement_type_t_BLOCK_REQUEST);
                REQUIRE(!l_ctx.m_ec_resp_token.empty());
                REQUIRE(l_ctx.m_resp_token == true);
                // -----------------------------------------
                // set low/bad bot score callback 
                // and verify event
                // -----------------------------------------
                s_callbacks = {
                        NULL,
                        NULL, //get_rqst_host_cb,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL, //get_rqst_header_w_key_cb,
                        NULL,
                        NULL,
                        NULL, //get_rqst_local_addr_cb,
                        NULL, //get_rqst_canonical_port_cb,
                        NULL, //get_rqst_apparent_cache_status_cb,
                        NULL, //get_rqst_bytes_out_cb,
                        NULL, //get_rqst_bytes_in_cb,
                        NULL, //get_rqst_uuid_cb,
                        NULL, //get_cust_id_cb
                        NULL,
                        get_recaptcha_subr_cb_bad_bot_score
                };
                l_is_bot = false;
                l_ctx.m_callbacks = &s_callbacks;
                l_issue_captcha = false;
                l_s = l_ca.check_google_token(&l_ctx,
                                              l_event,
                                              l_enf,
                                              l_issue_captcha);
                REQUIRE(l_s == WAFLZ_STATUS_WAIT);
                REQUIRE(l_issue_captcha == false);
                REQUIRE(l_ctx.m_captcha_enf != NULL);
                REQUIRE(!l_ctx.m_subr_resp.empty());

                l_s = l_ca.validate_google_token(&l_ctx,
                                                 &l_event,
                                                 l_is_bot);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                REQUIRE(l_is_bot == true);
                REQUIRE(l_event != NULL);
                REQUIRE(l_event->captcha_status() == 
                        waflz_pb::event_captcha_status_t_CAPTCHA_FAILED_RESULT_BOT);
                REQUIRE(l_event->captcha_bot_score() == 0.4f);
                REQUIRE(l_ctx.m_captcha_enf != NULL);
                l_e = (waflz_pb::enforcement*)l_ctx.m_captcha_enf;
                REQUIRE(l_e->enf_type() == waflz_pb::enforcement_type_t_BLOCK_REQUEST);
                REQUIRE(!l_ctx.m_ec_resp_token.empty());
                REQUIRE(l_ctx.m_resp_token == true);
                // -----------------------------------------
                // set good bot score callback 
                // -----------------------------------------
                s_callbacks = {
                        NULL,
                        NULL, //get_rqst_host_cb,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL, //get_rqst_header_w_key_cb,
                        NULL,
                        NULL,
                        NULL, //get_rqst_local_addr_cb,
                        NULL, //get_rqst_canonical_port_cb,
                        NULL, //get_rqst_apparent_cache_status_cb,
                        NULL, //get_rqst_bytes_out_cb,
                        NULL, //get_rqst_bytes_in_cb,
                        NULL, //get_rqst_uuid_cb,
                        NULL, //get_cust_id_cb
                        NULL,
                       get_recaptcha_subr_cb_good_bot_score
                };
                l_is_bot = false;
                l_ctx.m_captcha_enf = NULL;
                l_ctx.m_callbacks = &s_callbacks;
                l_issue_captcha = false;
                l_s = l_ca.check_google_token(&l_ctx,
                                              l_event,
                                              l_enf,
                                              l_issue_captcha);
                REQUIRE(l_s == WAFLZ_STATUS_WAIT);
                REQUIRE(l_issue_captcha == false);
                REQUIRE(l_ctx.m_captcha_enf != NULL);
                REQUIRE(!l_ctx.m_subr_resp.empty());

                l_s = l_ca.validate_google_token(&l_ctx,
                                                 &l_event,
                                                 l_is_bot);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                REQUIRE(l_is_bot == false);
                REQUIRE(!l_ctx.m_ec_resp_token.empty());
                REQUIRE(l_ctx.m_resp_token == true);
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_event) { delete l_event; l_event = NULL; }
                if(l_enf) { delete l_enf; l_enf = NULL; }
            }
}

//! ----------------------------------------------------------------------------
//! tests for get ectoken and verify ectoken
//! ----------------------------------------------------------------------------
TEST_CASE("test ectoken", "test ectoken]") {
        SECTION("test ectoken") {
                int32_t l_s;
                waflz_pb::event *l_event = new ::waflz_pb::event();
                ns_waflz::captcha l_ca;
                // -----------------------------------------
                // setup ctx
                // -----------------------------------------
                ns_waflz::rqst_ctx l_ctx(NULL, 0, 0, NULL);
                l_ctx.m_src_addr.m_data = "1.1.1.1";
                l_ctx.m_src_addr.m_len = sizeof(l_ctx.m_src_addr.m_data);
                ns_waflz::data_t l_ua;
                l_ua.m_data = "User-Agent";
                l_ua.m_len = strlen(l_ua.m_data);
                ns_waflz::data_t l_ua_chrome;
                l_ua_chrome.m_data = "chrome";
                l_ua_chrome.m_len = strlen(l_ua_chrome.m_data);
                l_ctx.m_header_map[l_ua] = l_ua_chrome;
                l_s = l_ca.set_captcha_verified_ec_token(&l_ctx);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                REQUIRE(l_ctx.m_ec_resp_token.length() > 0);
                REQUIRE(l_ctx.m_resp_token == true);
                // -----------------------------------------
                // verify token should be successful
                // -----------------------------------------
                ns_waflz::data_t l_tok;
                l_tok.m_data = l_ctx.m_ec_resp_token.c_str();
                l_tok.m_len = l_ctx.m_ec_resp_token.length();
                uint32_t l_valid_s = 60;
                bool l_issue_captcha = false;
                l_s = l_ca.verify_ec_token(&l_tok, l_valid_s, &l_ctx, l_issue_captcha, l_event);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                REQUIRE(l_issue_captcha == false);
                // -----------------------------------------
                // change ip in ctx, and verify token should
                // fail
                // -----------------------------------------
                l_ctx.m_src_addr.m_data = "2.2.2.2";
                l_ctx.m_src_addr.m_len = sizeof(l_ctx.m_src_addr.m_data);
                l_issue_captcha = false;
                l_s = l_ca.verify_ec_token(&l_tok, l_valid_s, &l_ctx, l_issue_captcha, l_event);
                REQUIRE(l_s == WAFLZ_STATUS_ERROR);
                REQUIRE(l_event != NULL);
                REQUIRE(l_event->captcha_status() == waflz_pb::event_captcha_status_t_CAPTCHA_ECTOKEN_IP_MISMATCH);
                REQUIRE(l_issue_captcha == true);
                // -----------------------------------------
                // change ua in ctx, and verify token should
                // fail
                // -----------------------------------------
                l_ctx.m_src_addr.m_data = "1.1.1.1";
                l_ctx.m_src_addr.m_len = sizeof(l_ctx.m_src_addr.m_data);
                ns_waflz::data_t l_ua_mozilla;
                l_ua_mozilla.m_data = "mozilla";
                l_ua_mozilla.m_len = strlen(l_ua_mozilla.m_data);
                l_ctx.m_header_map[l_ua] = l_ua_mozilla;
                l_issue_captcha = false;
                l_s = l_ca.verify_ec_token(&l_tok, l_valid_s, &l_ctx, l_issue_captcha, l_event);
                REQUIRE(l_s == WAFLZ_STATUS_ERROR);
                REQUIRE(l_event != NULL);
                REQUIRE(l_event->captcha_status() == waflz_pb::event_captcha_status_t_CAPTCHA_ECTOKEN_UA_MISMATCH);
                REQUIRE(l_issue_captcha == true);
                // -----------------------------------------
                // change time to 1 second, sleep for 1 sec.
                // verify token should fail
                // -----------------------------------------
                l_ctx.m_header_map[l_ua] = l_ua_chrome;
                l_valid_s = 1;
                usleep(2000000);
                l_issue_captcha = false;
                l_s = l_ca.verify_ec_token(&l_tok, l_valid_s, &l_ctx, l_issue_captcha, l_event);
                REQUIRE(l_s == WAFLZ_STATUS_ERROR);
                REQUIRE(l_event != NULL);
                REQUIRE(l_event->captcha_status() == waflz_pb::event_captcha_status_t_CAPTCHA_ECTOKEN_EXPIRED);
                REQUIRE(l_issue_captcha == true);
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_event) { delete l_event; l_event = NULL; }
        }
}
//! ----------------------------------------------------------------------------
//! tests to verify captcha request flow 
//! ----------------------------------------------------------------------------
TEST_CASE("test captcha", "test captcha]") {
        SECTION("test captcha") {
                int32_t l_s;
                waflz_pb::event* l_event = new ::waflz_pb::event();
                waflz_pb::enforcement* l_enf = new::waflz_pb::enforcement();
                l_enf->set_enf_type(::waflz_pb::enforcement_type_t_BLOCK_REQUEST);
                l_enf->set_status(403);
                ns_waflz::captcha l_ca;
                bool l_issue_captcha = false;
                uint32_t l_valid_for_s = 2;
                // -----------------------------------------
                // set up ctx
                // -----------------------------------------
                ns_waflz::rqst_ctx l_ctx(NULL, 0, 0, NULL);
                l_ctx.m_src_addr.m_data = "1.1.1.1";
                l_ctx.m_src_addr.m_len = sizeof(l_ctx.m_src_addr.m_data);
                ns_waflz::data_t l_ua;
                l_ua.m_data = "User-Agent";
                l_ua.m_len = strlen(l_ua.m_data);
                ns_waflz::data_t l_ua_chrome;
                l_ua_chrome.m_data = "chrome";
                l_ua_chrome.m_len = strlen(l_ua_chrome.m_data);
                l_ctx.m_header_map[l_ua] = l_ua_chrome;
                // -----------------------------------------
                // Fresh request without google and ec token
                // -----------------------------------------
                l_s = l_ca.verify(&l_ctx,
                                  l_valid_for_s,
                                  l_event,
                                  l_enf,
                                  l_issue_captcha);
                REQUIRE(l_s == WAFLZ_STATUS_ERROR);
                REQUIRE(l_issue_captcha == true);
                REQUIRE(l_event->captcha_status() == 
                        waflz_pb::event_captcha_status_t_CAPTCHA_ISSUED_NO_GOOGLE_TOKEN);
                REQUIRE(l_ctx.m_captcha_enf == NULL);
                REQUIRE(l_ctx.m_resp_token == false);
                // -----------------------------------------
                // Request with google token and
                // no ec verified token.
                // should get STATUS_WAIT, if the subrequest
                // was issued successfully.
                // enf should have been copied to ctx.
                // subr callback should have set the resp in ctx
                // set up cookies and callbacks in ctx
                // -----------------------------------------
                static ns_waflz::rqst_ctx_callbacks s_callbacks = {
                        NULL,
                        NULL, //get_rqst_host_cb,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL,
                        NULL, //get_rqst_header_w_key_cb,
                        NULL,
                        NULL,
                        NULL, //get_rqst_local_addr_cb,
                        NULL, //get_rqst_canonical_port_cb,
                        NULL, //get_rqst_apparent_cache_status_cb,
                        NULL, //get_rqst_bytes_out_cb,
                        NULL, //get_rqst_bytes_in_cb,
                        NULL, //get_rqst_uuid_cb,
                        NULL, //get_cust_id_cb
                        NULL,
                        get_recaptcha_subr_cb_good_bot_score
                };
                l_ctx.m_callbacks = &s_callbacks;
                l_ctx.m_cookie_map.clear();
                ns_waflz::data_t l_k;
                ns_waflz::data_t l_v;
                l_k.m_data = CAPTCHA_GOOGLE_TOKEN;
                l_k.m_len = strlen(CAPTCHA_GOOGLE_TOKEN);
                l_v.m_data = "testgoogletoken";
                l_v.m_len = strlen("testgoogletoken");
                l_ctx.m_cookie_map[l_k] = l_v;
                l_ctx.m_resp_token = false;
                l_issue_captcha = false;
                l_s = l_ca.verify(&l_ctx,
                                  l_valid_for_s,
                                  l_event,
                                  l_enf,
                                  l_issue_captcha);
                REQUIRE(l_s == WAFLZ_STATUS_WAIT);
                REQUIRE(l_issue_captcha == false);
                REQUIRE(l_ctx.m_captcha_enf != NULL);
                REQUIRE(!l_ctx.m_subr_resp.empty());
                REQUIRE(l_ctx.m_resp_token == false);
                REQUIRE(l_ctx.m_ec_resp_token.empty() == true);
                // -----------------------------------------
                // validate the subr response
                // -----------------------------------------
                bool l_is_bot = false;
                l_s = l_ca.validate_google_token(&l_ctx,
                                                 &l_event,
                                                 l_is_bot);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                REQUIRE(l_is_bot == false);
                REQUIRE(l_ctx.m_resp_token == true);
                REQUIRE(!l_ctx.m_ec_resp_token.empty());
                REQUIRE(l_ctx.m_captcha_enf != NULL);
                // -----------------------------------------
                // Request from second process call
                // issued after getting subr response.
                // no verified token in cookies.
                // should get STATUS_OK based on the 
                // verified token info in ctx.
                // -----------------------------------------
                l_issue_captcha = false;
                l_s = l_ca.verify(&l_ctx,
                                  l_valid_for_s,
                                  l_event,
                                  l_enf,
                                  l_issue_captcha);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                REQUIRE(l_issue_captcha == false);
                // -----------------------------------------
                // Request from verified client
                // with ec verified token from client.
                // add token in cookie map
                // should get STATUS_OK without any new
                // response token
                // -----------------------------------------
                ns_waflz::data_t l_ec_k;
                ns_waflz::data_t  l_ec_v;
                l_ec_k.m_data = CAPTCHA_VERIFIED_TOKEN;
                l_ec_k.m_len = strlen(CAPTCHA_VERIFIED_TOKEN);
                l_ec_v.m_data = l_ctx.m_ec_resp_token.c_str();
                l_ec_v.m_len = l_ctx.m_ec_resp_token.length();
                l_ctx.m_cookie_map[l_ec_k] = l_ec_v;
                l_ctx.m_resp_token = false;
                l_issue_captcha = false;
                l_s = l_ca.verify(&l_ctx,
                                  l_valid_for_s,
                                  l_event,
                                  l_enf,
                                  l_issue_captcha);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                REQUIRE(l_issue_captcha == false);
                REQUIRE( l_ctx.m_resp_token == false);
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_event) { delete l_event; l_event = NULL; }
                if(l_enf) { delete l_enf; l_enf = NULL; }
        }

}