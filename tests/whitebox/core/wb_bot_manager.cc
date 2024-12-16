//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    wb_bot_manager.cc
//! \details: white box test for bot_manager
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "waflz/engine.h"
#include "waflz/challenge.h"
#include "waflz/captcha.h"
#include "waflz/rqst_ctx.h"
#include "waflz/bot_manager.h"
#include "waflz/kv_db.h"
#include "waflz/lm_db.h"
#include "support/file_util.h"
#include "event.pb.h"
#include "bot_manager.pb.h"
#include <unistd.h>
//! ----------------------------------------------------------------------------
//! callbacks
//! ----------------------------------------------------------------------------
static const char* s_ip = "156.123.12.7";
static int32_t get_rqst_src_addr_cb(const char** a_data, uint32_t* a_len, void* a_ctx)
{
        *a_data = s_ip;
        *a_len = strlen(s_ip);
        return 0;
}
static int32_t get_rqst_header_size_cb(uint32_t* a_val, void* a_ctx)
{
        *a_val = 8;
        return 0;
}
static const char* s_header_user_agent = "twitterbot";
static const char* s_header_accept = "my_cool_accept_value";
static const char* s_header_referer = "my_cool_referer_value";
static const char* s_header_cookie = "__cookie_a=a_value; __cookie_b=b_value; __cookie_c=c_value;";
static const char* s_header_content_type = NULL;
static const char* s_header_content_length = NULL;
static const char* s_host = NULL;
static const char* s_test_header = NULL;
static int32_t get_rqst_header_w_idx_cb(const char** ao_key,
                                        uint32_t* ao_key_len,
                                        const char** ao_val,
                                        uint32_t* ao_val_len,
                                        void* a_ctx,
                                        uint32_t a_idx)
{
        *ao_key = NULL;
        *ao_key_len = 0;
        *ao_val = NULL;
        *ao_val_len = 0;
        switch(a_idx)
        {
        case 0:
        {
                *ao_key = "User-Agent";
                *ao_key_len = strlen("User-Agent");
                *ao_val = s_header_user_agent;
                *ao_val_len = strlen(s_header_user_agent);
                break;
        }
        case 1:
        {
                *ao_key = "Accept";
                *ao_key_len = strlen("Accept");
                *ao_val = s_header_accept;
                *ao_val_len = strlen(s_header_accept);
                break;
        }
        case 2:
        {
                *ao_key = "Referer";
                *ao_key_len = strlen("Referer");
                *ao_val = s_header_referer;
                *ao_val_len = strlen(s_header_referer);
                break;
        }
        case 3:
        {
                *ao_key = "Cookie";
                *ao_key_len = strlen("Cookie");
                *ao_val = s_header_cookie;
                *ao_val_len = strlen(s_header_cookie);
                break;
        }
        case 4:
        {
                if (s_header_content_type)
                {
                        *ao_key = "Content-Type";
                        *ao_key_len = strlen("Content-Type");
                        *ao_val = s_header_content_type;
                        *ao_val_len = strlen(s_header_content_type);
                }
                break;
        }
        case 5:
        {
                if (s_header_content_length)
                {
                        *ao_key = "Content-Length";
                        *ao_key_len = strlen("Content-Length");
                        *ao_val = s_header_content_length;
                        *ao_val_len = strlen(s_header_content_length);
                }
                break;
        }
        case 6:
        {
                if (s_host)
                {
                        *ao_key = "Host";
                        *ao_key_len = strlen("Host");
                        *ao_val = s_host;
                        *ao_val_len = strlen(s_host);
                }
                break;
        }
        case 7:
        {
                if (s_test_header)
                {
                        *ao_key = s_test_header;
                        *ao_key_len = strlen(s_test_header);
                        *ao_val = s_test_header;
                        *ao_val_len = strlen(s_test_header);
                }
                break;
        }
        default:
        {
                break;
        }
        }
        return 0;
}
//! ----------------------------------------------------------------------------
//! instances tests
//! ----------------------------------------------------------------------------
TEST_CASE( "bot_manager test", "[bot_manager]" ) {
    // -----------------------------------------------------
    // callbacks for test
    // -----------------------------------------------------
    int32_t l_s;
    static ns_waflz::rqst_ctx_callbacks s_callbacks = {
            get_rqst_src_addr_cb,
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
            get_rqst_header_size_cb,
            NULL, //get_rqst_header_w_key_cb,
            get_rqst_header_w_idx_cb,
            NULL,
            NULL, //get_rqst_local_addr_cb,
            NULL, //get_rqst_canonical_port_cb,
            NULL, //get_rqst_apparent_cache_status_cb,
            NULL, //get_rqst_bytes_out_cb,
            NULL, //get_rqst_bytes_in_cb,
            NULL, //get_rqst_uuid_cb,
            NULL //get_cust_id_cb
    };
    // -----------------------------------------------------
    // get current working directory
    // -----------------------------------------------------
    char l_cwd[1024];
    REQUIRE(getcwd(l_cwd, sizeof(l_cwd)) != NULL);
    // -----------------------------------------------------
    // get conf dir
    // -----------------------------------------------------
    std::string l_conf_dir = l_cwd;
    l_conf_dir += "/../../../../tests/data/waf/conf";
    // -----------------------------------------------------
    // get info file
    // -----------------------------------------------------
    std::string l_bot_info_file = l_cwd;
    l_bot_info_file += "/../../../../tests/data/bot/known_bot_info.json";
    // -----------------------------------------------------
    // verify engine loading with empty list
    // -----------------------------------------------------
    SECTION("verify engine load with empty list") {
        // -----------------------------------------------------
        // init
        // -----------------------------------------------------
        ns_waflz::engine* l_empty_engine = new ns_waflz::engine();
        l_s = l_empty_engine->init();
        REQUIRE(l_s == WAFLZ_STATUS_OK);
        // -----------------------------------------------------
        // load empty info
        // -----------------------------------------------------
        const char empty_info[] = "{\"test\":{}}";
        l_s = l_empty_engine->load_known_bot(empty_info, strlen(empty_info));
        REQUIRE(l_s == WAFLZ_STATUS_OK);
        // -----------------------------------------------------
        // clean up
        // -----------------------------------------------------
        if (l_empty_engine) { delete l_empty_engine; l_empty_engine = NULL; }
    }
    // -----------------------------------------------------
    // init
    // -----------------------------------------------------
    ns_waflz::engine* l_engine = new ns_waflz::engine();
    l_s = l_engine->init();
    REQUIRE(l_s == WAFLZ_STATUS_OK);
    // -----------------------------------------------------
    // load known bot info
    // -----------------------------------------------------
    l_s = l_engine->load_known_bot_info_file(l_bot_info_file.c_str(), l_bot_info_file.length());
    REQUIRE(l_s == WAFLZ_STATUS_OK);
    // -----------------------------------------------------
    // verify engine loading
    // -----------------------------------------------------
    SECTION("verify engine load") {
        // -------------------------------------------------
        // get user-agents in engine
        // -------------------------------------------------
        ns_waflz::known_bot_info_map_t l_knb_info_map = l_engine->get_known_bot_info_map();
        // -------------------------------------------------
        // test that there are user-agents
        // -------------------------------------------------
        REQUIRE(!l_knb_info_map.empty());
        // -------------------------------------------------
        // test all present
        // -------------------------------------------------
        std::string expected[11] = {
            "ahrefs", "apple", "baidu", "facebook",
            "google", "msn", "semrush", "twitter",
            "uptimerobot", "yandex", "other"
        };
        REQUIRE(l_knb_info_map.size() == 11);
        for (uint32_t index = 0; index < 11; index++ ) {
            std::string company = expected[index];
            REQUIRE(l_knb_info_map.find(company) != l_knb_info_map.end());
        }
    }
    // -----------------------------------------------------
    // verify engine loading
    // -----------------------------------------------------
    SECTION("load bot_manager from protobuf") {
        // -------------------------------------------------
        // create new bot_manager protobuf
        // -------------------------------------------------
        waflz_pb::bot_manager* l_bot_manager_pb = new waflz_pb::bot_manager();
        l_bot_manager_pb->set_id("test_id");
        l_bot_manager_pb->set_customer_id("test_cust_id");
        // -------------------------------------------------
        // create bot_manager
        // -------------------------------------------------
        ns_waflz::challenge* l_challenge = new ns_waflz::challenge();
        ns_waflz::captcha* l_captcha = new ns_waflz::captcha();
        ns_waflz::bot_manager* l_bot_manager = new ns_waflz::bot_manager(*l_engine, *l_challenge, *l_captcha);
        // -------------------------------------------------
        // load from protobuf
        // -------------------------------------------------
        l_s = l_bot_manager->load(l_bot_manager_pb, l_conf_dir);
        REQUIRE(l_s == WAFLZ_STATUS_OK);
        REQUIRE(l_bot_manager->get_id() == "test_id");
        REQUIRE(l_bot_manager->get_cust_id() == "test_cust_id");
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if (l_bot_manager_pb) { delete l_bot_manager_pb; l_bot_manager_pb = NULL; }
        if (l_bot_manager) { delete l_bot_manager; l_bot_manager = NULL; }
        if (l_challenge) { delete l_challenge; l_challenge = NULL; }
        if (l_captcha) { delete l_captcha; l_captcha = NULL; }
    }
    // -----------------------------------------------------
    // make a bot_manager
    // -----------------------------------------------------
    ns_waflz::challenge* l_challenge = new ns_waflz::challenge();
    ns_waflz::captcha* l_captcha = new ns_waflz::captcha();
    ns_waflz::bot_manager* l_bot_manager = new ns_waflz::bot_manager(*l_engine, 
                                                                     *l_challenge,
                                                                     *l_captcha);
    // -----------------------------------------------------
    // read botmanager file
    // -----------------------------------------------------
    char* l_buf;
    uint32_t l_buf_len;
    std::string l_bot_manager_file = l_cwd;
    l_bot_manager_file += "/../../../../tests/data/waf/conf/bot_manager/0052-7kDny8RP.bot_manager.json";
    l_s = ns_waflz::read_file(l_bot_manager_file.c_str(), &l_buf, l_buf_len);
    REQUIRE(l_s == WAFLZ_STATUS_OK);
    // -----------------------------------------------------
    // load botmanager file
    // -----------------------------------------------------
    l_s = l_bot_manager->load(l_buf, l_buf_len, l_conf_dir);
    REQUIRE(l_s == WAFLZ_STATUS_OK);
    if (l_buf) { free(l_buf); l_buf = NULL; }
    // -----------------------------------------------------
    // bot_manager::process_known_bots::spoof 
    // -----------------------------------------------------
    SECTION("bot_manager::process_known_bots::spoof") {
        // -------------------------------------------------
        // create default values for process_known_bots
        // -------------------------------------------------
        waflz_pb::event* l_event = NULL;
        const waflz_pb::enforcement* l_enf = NULL;
        // -------------------------------------------------
        // create request context with twitter spoof
        // -------------------------------------------------
        void* l_ctx = NULL;
        ns_waflz::rqst_ctx* l_rqst_ctx = new ns_waflz::rqst_ctx(
            l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks
        );
        l_rqst_ctx->m_src_addr.m_data = "127.0.0.1";
        l_rqst_ctx->m_src_addr.m_len = 9;
        ns_waflz::data_t ua_key;
        ua_key.m_data = "User-Agent";
        ua_key.m_len = 10;
        ns_waflz::data_t ua_data;
        ua_data.m_data = "twitterbot";
        ua_data.m_len = 10;
        l_rqst_ctx->m_header_map[ua_key] = ua_data;
        // -------------------------------------------------
        // test process_known_bots
        // -------------------------------------------------
        l_s = l_bot_manager->process_known_bots(&l_event, *l_rqst_ctx, &l_enf);
        // -------------------------------------------------
        // should return ok + event
        // -------------------------------------------------
        REQUIRE(l_s == WAFLZ_STATUS_OK);
        REQUIRE(l_event != NULL);
        // -------------------------------------------------
        // should have a bot score and bot type
        // -------------------------------------------------
        REQUIRE(l_event->known_bot_type() == "twitter");
        // -------------------------------------------------
        // should have a subevent of 70000
        // -------------------------------------------------
        REQUIRE(l_event->sub_event_size() >= 1);
        REQUIRE(l_event->sub_event(0).rule_id() == 70000);
        REQUIRE((
            l_event->sub_event(0).rule_msg() 
            == 
            "Spoofed Bot: Client Impersonating A Known Bot"
        ));
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if (l_event) { delete l_event; l_event = NULL; }
        if (l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
    }
    // -----------------------------------------------------
    // bot_manager::process_known_bots::non-spoof
    // -----------------------------------------------------
    SECTION("bot_manager::process_known_bots::non-spoof"){
        // -------------------------------------------------
        // create default values for process_known_bots
        // -------------------------------------------------
        waflz_pb::event* l_event = NULL;
        const waflz_pb::enforcement* l_enf = NULL;
        // -------------------------------------------------
        // create request context with twitter spoof
        // -------------------------------------------------
        void* l_ctx = NULL;
        ns_waflz::rqst_ctx* l_rqst_ctx = new ns_waflz::rqst_ctx(
            l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks
        );
        l_rqst_ctx->m_src_addr.m_data = "199.16.156.0";
        l_rqst_ctx->m_src_addr.m_len = 12;
        ns_waflz::data_t ua_key;
        ua_key.m_data = "User-Agent";
        ua_key.m_len = 10;
        ns_waflz::data_t ua_data;
        ua_data.m_data = "twitterbot";
        ua_data.m_len = 10;
        l_rqst_ctx->m_header_map[ua_key] = ua_data;
        // -------------------------------------------------
        // test process_known_bots
        // -------------------------------------------------
        l_s = l_bot_manager->process_known_bots(&l_event, *l_rqst_ctx, &l_enf);
        // -------------------------------------------------
        // should return ok + event
        // -------------------------------------------------
        REQUIRE(l_s == WAFLZ_STATUS_OK);
        REQUIRE(l_event != NULL);
        // -------------------------------------------------
        // should have a bot score and bot type
        // -------------------------------------------------
        REQUIRE(l_event->known_bot_type() == "twitter");
        // -------------------------------------------------
        // should have a subevent of 70001
        // -------------------------------------------------
        REQUIRE((l_event->sub_event_size() >= 1));
        REQUIRE((l_event->sub_event(0).rule_id() == 70001));
        REQUIRE((
            l_event->sub_event(0).rule_msg() 
            == 
            "Known Bot: Explicit Known Bot Token"
        ));
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if (l_event) { delete l_event; l_event = NULL; }
        if (l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
    }
    // -------------------------------------------------
    // final cleanup
    // -------------------------------------------------
    if (l_bot_manager) { delete l_bot_manager; l_bot_manager = NULL; }
    if (l_challenge) { delete l_challenge; l_challenge = NULL; }
    if (l_captcha) { delete l_captcha; l_captcha = NULL; }
    if (l_engine) { delete l_engine; l_engine = NULL; }
}
