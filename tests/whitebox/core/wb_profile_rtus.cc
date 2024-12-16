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
#include "waflz/engine.h"
#include "waflz/profile.h"
#include "profile.pb.h"
#include "rule.pb.h"
#include "event.pb.h"
#include "waflz/rqst_ctx.h"
#include "support/ndebug.h"
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
//! TODO
//! ----------------------------------------------------------------------------
static waflz_pb::profile *init_std_profile_pb(void)
{
        // -----------------------------------------
        // setup...
        // -----------------------------------------
        waflz_pb::profile *l_pb = NULL;
        l_pb = new waflz_pb::profile();
        l_pb->set_id("my_id");
        l_pb->set_name("my_name");
        l_pb->set_ruleset_id("OWASP-CRS-3.3");
        l_pb->set_ruleset_version("2020-08-05");
        // -----------------------------------------
        // add policy file
        // -----------------------------------------
        std::string *l_policy = l_pb->add_policies();
        l_policy->assign("REQUEST-944-APPLICATION-ATTACK-JAVA.conf");
        // -----------------------------------------
        // general settings -required fields
        // -----------------------------------------
        ::waflz_pb::profile_general_settings_t* l_gx = NULL;
        l_gx = l_pb->mutable_general_settings();
        l_gx->set_process_request_body(true);
        l_gx->set_xml_parser(true);
        l_gx->set_process_response_body(true);
        l_gx->set_validate_utf8_encoding(true);
        l_gx->set_max_num_args(3);
        l_gx->set_arg_name_length(100);
        l_gx->set_arg_length(400);
        l_gx->set_total_arg_length(64000);
        l_gx->set_max_file_size(1048576);
        l_gx->set_combined_file_sizes(1048576);
        l_gx->add_allowed_http_methods("POST");
        l_gx->add_allowed_request_content_types("html");
        // -----------------------------------------
        // anomaly settings -required fields
        // -----------------------------------------
        l_gx->set_anomaly_threshold(1);
        // -----------------------------------------
        // return profile
        // -----------------------------------------
        return l_pb;
}

//! ----------------------------------------------------------------------------
//! profile acl tests
//! ----------------------------------------------------------------------------
TEST_CASE( "profile policies test", "[profile_policies]" )
{
        // -----------------------------------------
        // callbacks for rqst
        // -----------------------------------------
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
        // -----------------------------------------
        // get current working dir
        // -----------------------------------------
        char l_cwd[1024];
        if(getcwd(l_cwd, sizeof(l_cwd)) != NULL)
        {
            //fprintf(stdout, "Current working dir: %s\n", cwd);
        }
        // -----------------------------------------
        // get ruleset dir
        // -----------------------------------------
        std::string l_rule_dir = l_cwd;
        l_rule_dir += "/../../../../tests/data/waf/ruleset/";
        // -----------------------------------------
        // geoip
        // -----------------------------------------
        std::string l_geoip2_city_file = l_cwd;
        std::string l_geoip2_asn_file = l_cwd;
        l_geoip2_city_file += "/../../../../tests/data/waf/db/GeoLite2-City.mmdb";
        l_geoip2_asn_file += "/../../../../tests/data/waf/db/GeoLite2-ASN.mmdb";
        // -------------------------------------------------
        // setup engine
        // -------------------------------------------------
        int32_t l_s;
        ns_waflz::engine *l_engine = new ns_waflz::engine();
        l_engine->set_ruleset_dir(l_rule_dir);
        l_engine->set_geoip2_dbs(l_geoip2_city_file, l_geoip2_asn_file);
        l_s = l_engine->init();
        // -------------------------------------------------
        // assert engine is working
        // -------------------------------------------------
        REQUIRE((l_s == WAFLZ_STATUS_OK));
        // -------------------------------------------------
        // loading a profile
        // -------------------------------------------------
        SECTION("testing profile load") {
                // -----------------------------------------
                // create profile proto
                // -----------------------------------------
                ns_waflz::profile *l_profile = new ns_waflz::profile(*l_engine);
                waflz_pb::profile *l_pb = init_std_profile_pb();
                //-------------------------------------------
                // Load config with default policies
                //-------------------------------------------
                l_s = l_profile->load(l_pb);
                // -----------------------------------------
                // assert profile was loaded
                // -----------------------------------------
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_profile)
                {
                        delete l_profile;
                        l_profile = NULL;
                }
                if(l_pb)
                {
                        delete l_pb;
                        l_pb = NULL;
                }
        }
        // -------------------------------------------------
        // testing an rtu
        // -------------------------------------------------
        SECTION("testing profile rtu load") {
                // -----------------------------------------
                // create profile proto
                // -----------------------------------------
                ns_waflz::profile *l_profile = new ns_waflz::profile(*l_engine);
                waflz_pb::profile *l_pb = init_std_profile_pb();
                //-------------------------------------------
                // add an rtu to the protobuff
                //{
                // "rule_id": "944120",
                // "is_regex": true,
                // "is_negated": true,
                // "target_match": ".*",
                // "target": "ARGS"
                // }
                //-------------------------------------------
                waflz_pb::profile_rule_target_update_t* l_rtu = l_pb->add_rule_target_updates();
                l_rtu->set_rule_id("944130");
                l_rtu->set_is_regex(true);
                l_rtu->set_is_negated(true);
                l_rtu->set_target("REQUEST_BODY");
                l_rtu->set_target_match(".*");
                //-------------------------------------------
                // Load config with default policies
                //-------------------------------------------
                l_s = l_profile->load(l_pb);
                // -----------------------------------------
                // assert profile was loaded
                // -----------------------------------------
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // assert rtu was loaded
                // -----------------------------------------
                ns_waflz::update_variable_map_t* l_rtu_map = l_profile->get_waf()->get_rtu_map();
                REQUIRE((l_rtu_map->size() == 1));
                REQUIRE((l_rtu_map->find("944130_0") != l_rtu_map->end()));
                // -----------------------------------------
                // create request context with body to trip rule
                // -----------------------------------------
                void* l_ctx = NULL;
                waflz_pb::event* l_event = NULL;
                ns_waflz::rqst_ctx* l_rqst_ctx = new ns_waflz::rqst_ctx(
                        l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks
                );
                char* l_body  = (char*)malloc(28 * sizeof(char));
                std::string l_tmp = "java.io.BufferedInputStream";
                strcpy(l_body, l_tmp.c_str());
                l_rqst_ctx->m_body_data = l_body;
                l_rqst_ctx->m_body_len = 28;
                l_rqst_ctx->m_url_enc_body = true;
                // -----------------------------------------
                // process rules
                // -----------------------------------------
                l_s = l_profile->process(&l_event, l_ctx, ns_waflz::PART_MK_WAF, &l_rqst_ctx);
                // -----------------------------------------
                // assert processed correctly
                // -----------------------------------------
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // assert rule didnt fire
                // -----------------------------------------
                REQUIRE(l_event == NULL);
                // -----------------------------------------
                // remove rtu
                // -----------------------------------------
                l_rtu_map->clear();
                // -----------------------------------------
                // process rules
                // -----------------------------------------
                l_s = l_profile->process(&l_event, l_ctx, ns_waflz::PART_MK_WAF, &l_rqst_ctx);
                // -----------------------------------------
                // assert processed correctly
                // -----------------------------------------
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // assert rule should have fired
                // -----------------------------------------
                REQUIRE(l_event != NULL);
                REQUIRE(l_event->sub_event_size() >= 1);
                REQUIRE(l_event->sub_event(0).rule_id() == 944130);
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if (l_profile) { delete l_profile; l_profile = NULL;}
                if (l_pb) { delete l_pb; l_pb = NULL; }
                if (l_event) { delete l_event; l_event = NULL; }
                if (l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
        // -------------------------------------------------
        // cleaning engine
        // -------------------------------------------------
        if(l_engine)
        {
                delete l_engine;
                l_engine = NULL;
        }
}
