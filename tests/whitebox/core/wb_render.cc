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
#include "support/ndebug.h"
#include "waflz/def.h"
#include "waflz/rqst_ctx.h"
#include "waflz/render.h"
#include <string.h>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define RESP_1 "HI I DONT HAVE A TEMPLATE"
#define RESP_2 "HI {{USER_AGENT}} HOW ARE YOU???"
#define RESP_3 "HI {{USER_AGENT}} IS YOUR TOKEN {{EC_TOKEN}}???"
#define RESP_4 "{{AN}}"
//! ----------------------------------------------------------------------------
//! config
//! ----------------------------------------------------------------------------
#define SAMPLE_HTML "<!DOCTYPE HTML>"\
        "<html lang=\"en-US\">"\
        "<head>"\
        "<title>Validating your browser</title>"\
        "<script>"\
        "function challenge()"\
        "{"\
        "var val = 121+120;"\
        "var l_cookie =\"ec_secure=\"+val+\":\"+\"{{EC_TOKEN}}\";"\
        "document.cookie = l_cookie;"\
        "location.reload();"\
        "}"\
        "</script>"\
        "</head>"\
        "<body onload=\"challenge()\">"\
        "<table width=\"100%\" height=\"100%\" cellpadding=\"20\"><tr><td align=\"center\" valign=\"middle\">"\
        "<div class=\"browser-verification\">"\
        "<noscript><h1 data-translate=\"turn_on_js\" style=\"color:#bd2426;\">Please turn JavaScript on and reload the page.</h1></noscript>"\
        "</div></td></tr>"\
        "</table>"\
        "<h1>Validating your browser!</h1>"\
        "</body>"\
        "</html>"
//! ---------------------------------------------------------------------------
//!  config
//! ---------------------------------------------------------------------------
#define SAMPLE_HTML_W_TWO_COOKIES "<!DOCTYPE HTML>"\
        "<html lang=\"en-US\">"\
        "<head>"\
        "<title>Validating your browser</title>"\
        "<script>"\
        "function challenge()"\
        "{"\
        "var val = 121+120;"\
        "var l_tok_cookie =\"ec_secure={{EC_TOKEN}}\";"\
        "var l_ans_cookie =\"ec_answer=\"+val;"\
        "document.cookie = l_tok_cookie;"\
        "document.cookie = l_ans_cookie;"\
        "location.reload();"\
        "}"\
        "</script>"\
        "</head>"\
        "<body onload=\"challenge()\">"\
        "<table width=\"100%\" height=\"100%\" cellpadding=\"20\"><tr><td align=\"center\" valign=\"middle\">"\
        "<div class=\"browser-verification\">"\
        "<noscript><h1 data-translate=\"turn_on_js\" style=\"color:#bd2426;\">Please turn JavaScript on and reload the page.</h1></noscript>"\
        "</div></td></tr>"\
        "</table>"\
        "<h1>Validating your browser!</h1>"\
        "</body>"\
        "</html>"
//! ----------------------------------------------------------------------------
//!                              RENDER HTML TESTS
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! render html test
//! ----------------------------------------------------------------------------
TEST_CASE( "valid_render_html_test", "[load_valid_render_html]" ) {
        SECTION("verify render basic") {
                int32_t l_s;
                char *l_buf = NULL;
                size_t l_len = 0;
                ns_waflz::rqst_ctx *l_ctx = new ns_waflz::rqst_ctx(NULL, 0, 0, NULL);
                // -----------------------------------------
                // no token
                // -----------------------------------------
                l_s = ns_waflz::render(&l_buf, l_len, RESP_1, strlen(RESP_1), l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                const char l_resp_1[] = "HI I DONT HAVE A TEMPLATE";
                REQUIRE((strncmp(l_resp_1, l_buf, sizeof(l_resp_1) - 1) == 0));
                //NDBG_PRINT("l_buf: %s\n", l_buf);
                if(l_buf) { free(l_buf); l_buf = NULL; }
                // -----------------------------------------
                // ua token
                // -----------------------------------------
#define _USER_AGENT "MY_COOL_USER_AGENT"
                ns_waflz::data_t l_ua;
                l_ua.m_data = "User-Agent";
                l_ua.m_len = strlen(l_ua.m_data);
                ns_waflz::data_t l_ua_v;
                l_ua_v.m_data = _USER_AGENT;
                l_ua_v.m_len = strlen(l_ua_v.m_data);
                l_ctx->m_header_map[l_ua] = l_ua_v;
                ns_waflz::const_arg_t l_ua_arg;
                l_ua_arg.m_key = l_ua.m_data;
                l_ua_arg.m_key_len = l_ua.m_len;
                l_ua_arg.m_val = l_ua_v.m_data;
                l_ua_arg.m_val_len = l_ua_v.m_len;
                l_ctx->m_header_list.push_back(l_ua_arg);
                l_s = ns_waflz::render(&l_buf, l_len, RESP_2, strlen(RESP_2), l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                //NDBG_PRINT("l_buf: %s\n", l_buf);
                const char l_resp_2[] = "HI MY_COOL_USER_AGENT HOW ARE YOU???";
                REQUIRE((strncmp(l_resp_2, l_buf, sizeof(l_resp_2) - 1) == 0));
                if(l_buf) { free(l_buf); l_buf = NULL; }
                // -----------------------------------------
                // ua token
                // -----------------------------------------
#define _EC_TOKEN "MY_COOL_EC_TOKEN"
                char *l_tk;
                uint32_t l_tk_len;
                l_tk_len = asprintf(&l_tk, "MY_COOL_EC_TOKEN");
                l_ctx->m_token.m_data = l_tk;
                l_ctx->m_token.m_len = l_tk_len;
                l_s = ns_waflz::render(&l_buf, l_len, RESP_3, strlen(RESP_3), l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                const char l_resp_3[] = "HI MY_COOL_USER_AGENT IS YOUR TOKEN MY_COOL_EC_TOKEN???";
                REQUIRE((strncmp(l_resp_3, l_buf, sizeof(l_resp_3) - 1) == 0));
                if(l_buf) { free(l_buf); l_buf = NULL; }
                // -----------------------------------------
                // cust_id/an
                // -----------------------------------------
                l_ctx->m_an = 108221;
                const char l_resp_4[] = "1A6BD";
                l_s = ns_waflz::render(&l_buf, l_len, RESP_4, strlen(RESP_4), l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((strncmp(l_resp_4, l_buf, sizeof(l_resp_4) - 1)) == 0);
                if(l_buf) { free(l_buf); l_buf = NULL; }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
        }
#if 0
        SECTION("Verify render html") {
                std::string l_input(SAMPLE_HTML);
                ns_waflz::formatted_string l_res_body(l_input);
                std::string l_renedered;
                std::string l_ectoken("some randon string for testing");
                bool l_val = l_res_body.render(&l_renedered,l_ectoken);
                REQUIRE(l_val == true);
                size_t l_npos = l_renedered.find(l_ectoken);
                REQUIRE(l_npos != std::string::npos);
        }
#endif
}
