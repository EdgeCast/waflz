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
#include "waflz/challenge.h"
#include "waflz/rqst_ctx.h"
#include "waflz/string_util.h"
#include "support/base64.h"
#include "support/ndebug.h"
#include "scope.pb.h"
#include "event.pb.h"
#include <string.h>
#include <stdint.h>
#include <unistd.h>
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
#define VALID_CHALLENGE_JSON "{"\
    "\"problems\": ["\
        "{"\
        "\"id\" : 1,"\
        "\"response_body_base64\" : \"some random base64 encoded html string1\""\
        "},"\
        "{"\
        "\"id\" : 2,"\
        "\"response_body_base64\" : \"some random base64 encoded html string2\""\
        "},"\
        "{"\
        "\"id\" : 3,"\
        "\"response_body_base64\" : \"some random base64 encoded html string3\""\
        "}"\
    "]"\
"}"
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
#define NO_ID_CHALLENGE_JSON "{"\
    "\"problems\": ["\
        "{"\
        "\"id\" : 1,"\
        "\"response_body_base64\" : \"some random base64 encoded html string\""\
        "},"\
        "{"\
        "\"response_body_base64\" : \"some random base64 encoded html string\""\
        "}"\
    "]"\
"}"
//! ----------------------------------------------------------------------------
//!                     LOAD CHALLENGE TESTS
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! load valid challenge test
//! ----------------------------------------------------------------------------
TEST_CASE( "valid_challenge_test", "[load_valid_challenge]" ) {
        SECTION("Verify challenge") {
                int32_t l_s;
                ns_waflz::challenge l_ch;
                l_s = l_ch.load(VALID_CHALLENGE_JSON, sizeof(VALID_CHALLENGE_JSON));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
        }
}
//! ----------------------------------------------------------------------------
//! load no id challenge test
//! ----------------------------------------------------------------------------
TEST_CASE( "no id challenge test", "[no id challenge test]") {
        SECTION("Verify no id challenge") {
                int32_t l_s;
                ns_waflz::challenge l_ch;
                l_s = l_ch.load(NO_ID_CHALLENGE_JSON, sizeof(NO_ID_CHALLENGE_JSON));
                REQUIRE(l_s == WAFLZ_STATUS_ERROR);
        }
}
//! ----------------------------------------------------------------------------
//! test maps
//! ----------------------------------------------------------------------------
TEST_CASE( "test maps", "[test maps]") {
        // -------------------------------------------------
        // Load challenges
        // -------------------------------------------------
        int32_t l_s;
        ns_waflz::challenge l_ch;
        l_s = l_ch.load(VALID_CHALLENGE_JSON, sizeof(VALID_CHALLENGE_JSON));
        REQUIRE((l_s == WAFLZ_STATUS_OK));
        // -------------------------------------------------
        // Load challenges
        // -------------------------------------------------
        SECTION("Verify prob/answer/challenge in map") {
                // -----------------------------------------
                // verify challenge string
                // -----------------------------------------
                const std::string *l_cs = NULL;
                l_s = l_ch.get_challenge(&l_cs);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((*l_cs == "some random base64 encoded html string1"));
        }
        // -------------------------------------------------
        // get default when id not found
        // -------------------------------------------------
        SECTION("Verify default prob/answer/challenge in map") {
                // -----------------------------------------
                // verify challenge string is defaulted to
                // 1 when id is not found
                // -----------------------------------------
                const std::string *l_cs_1 = NULL;
                l_s = l_ch.get_challenge(&l_cs_1, 100);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((*l_cs_1 == "some random base64 encoded html string1"));
        }	
        // -------------------------------------------------
        // get specific challenge string when id found
        // -------------------------------------------------
        SECTION("Verify random access prob/answer/challenge in map") {
                // -----------------------------------------
                // verify challenge string is the requested
                // id when found
                // -----------------------------------------
                const std::string *l_cs_2 = NULL;
                l_s = l_ch.get_challenge(&l_cs_2, 2);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((*l_cs_2 == "some random base64 encoded html string2"));
        }	
}
//! ----------------------------------------------------------------------------
//! test ectoken
//! ----------------------------------------------------------------------------
TEST_CASE("test ectoken", "[test ectoken]") {
        SECTION("test ectoken") {
                int32_t l_s;
                waflz_pb::event *l_event = new ::waflz_pb::event();
                ns_waflz::challenge l_ch;
                l_s = l_ch.load(VALID_CHALLENGE_JSON, sizeof(VALID_CHALLENGE_JSON));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
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
                l_ctx.m_ans = 200;
                l_ch.set_ectoken(&l_ctx);
                ns_waflz::data_t l_k;
                ns_waflz::data_t l_v;
                l_ctx.m_cookie_map.clear();
                // -----------------------------------------
                // __ecbmchid
                // -----------------------------------------
                l_k.m_data = "__ecbmchid";
                l_k.m_len = sizeof("__ecbmchid") - 1;
                l_v.m_data = l_ctx.m_token.m_data;
                l_v.m_len = l_ctx.m_token.m_len;
                l_ctx.m_cookie_map[l_k] = l_v;
                // -----------------------------------------
                // __eccha
                // -----------------------------------------
                l_k.m_data = "__eccha";
                l_k.m_len = sizeof("__eccha") - 1;
                l_v.m_data = "2";
                l_v.m_len = sizeof("2") - 1;
                l_ctx.m_cookie_map[l_k] = l_v;
                // -----------------------------------------
                // check token...
                // -----------------------------------------
                bool l_pass;
                l_s = l_ch.verify(l_pass, 60, &l_ctx, &l_event);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_pass == true));
                // -----------------------------------------
                // check token -expired...
                // -----------------------------------------
                l_s = l_ch.verify(l_pass, 0, &l_ctx, &l_event);
                REQUIRE((l_s == WAFLZ_STATUS_ERROR));
                REQUIRE((l_pass == false));
                REQUIRE((l_event->challenge_status() == ::waflz_pb::event_chal_status_t_CHAL_STATUS_TOKEN_EXPIRED));
                //NDBG_PRINT("err: %s\n", l_ch.get_err_msg());
                // -----------------------------------------
                // wang ip
                // -----------------------------------------
                l_ctx.m_src_addr.m_data = "1.1.1.2";
                l_ctx.m_src_addr.m_len = sizeof(l_ctx.m_src_addr.m_data);
                l_s = l_ch.verify(l_pass, 60, &l_ctx, &l_event);
                REQUIRE((l_s == WAFLZ_STATUS_ERROR));
                REQUIRE((l_pass == false));
                REQUIRE((l_event->challenge_status() == ::waflz_pb::event_chal_status_t_CHAL_STATUS_IP_MISMATCH));
                //NDBG_PRINT("err: %s\n", l_ch.get_err_msg());
                // put back
                l_ctx.m_src_addr.m_data = "1.1.1.1";
                l_ctx.m_src_addr.m_len = sizeof(l_ctx.m_src_addr.m_data);
                // -----------------------------------------
                // wang user-agent
                // -----------------------------------------
                ns_waflz::data_t l_ua_fastly;
                l_ua_fastly.m_data = "fastly";
                l_ua_fastly.m_len = strlen(l_ua_fastly.m_data);
                l_ctx.m_header_map[l_ua] = l_ua_fastly;
                l_s = l_ch.verify(l_pass, 60, &l_ctx, &l_event);
                REQUIRE((l_s == WAFLZ_STATUS_ERROR));
                REQUIRE((l_pass == false));
                REQUIRE((l_event->challenge_status() == ::waflz_pb::event_chal_status_t_CHAL_STATUS_UA_MISMATCH));
                //NDBG_PRINT("err: %s\n", l_ch.get_err_msg());
                // put back
                l_ctx.m_header_map[l_ua] = l_ua_chrome;
                // -----------------------------------------
                // wang answer
                // -----------------------------------------
                l_k.m_data = "__eccha";
                l_k.m_len = sizeof("__eccha") - 1;
                l_v.m_data = "monkeys";
                l_v.m_len = sizeof("monkeys") - 1;
                l_ctx.m_cookie_map[l_k] = l_v;
                l_s = l_ch.verify(l_pass, 60, &l_ctx, &l_event);
                REQUIRE((l_s == WAFLZ_STATUS_ERROR));
                REQUIRE((l_pass == false));
                REQUIRE((l_event->challenge_status() == ::waflz_pb::event_chal_status_t_CHAL_STATUS_WRONG_ANSWER));
                if(l_event) { delete l_event; l_event=NULL; }
                // -----------------------------------------
                // set correct answer in cookie
                // -----------------------------------------
                l_v.m_data = "200";
                l_v.m_len = sizeof("200") - 1;
                l_ctx.m_cookie_map[l_k] = l_v;
                l_s = l_ch.verify(l_pass, 60, &l_ctx, &l_event);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_pass == true));
        }
}
