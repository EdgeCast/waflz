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
//! init_std_profile_pb
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
        l_pb->set_ruleset_id("OWASP-CRS-4.0");
        l_pb->set_ruleset_version("latest");
        // -----------------------------------------
        // add policy file
        // -----------------------------------------
        std::string *l_policy = l_pb->add_policies();
        l_policy->assign("REQUEST-944-APPLICATION-ATTACK-JAVA.conf");
        l_policy = l_pb->add_policies();
        l_policy->assign("RESPONSE-952-DATA-LEAKAGES-JAVA.conf");
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
        static ns_waflz::rqst_ctx_callbacks s_rqst_callbacks = {
                NULL, //get_rqst_src_addr_cb,
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
                NULL, //get_rqst_header_size_cb,
                NULL, //get_rqst_header_w_key_cb,
                NULL, //get_rqst_header_w_idx_cb,
                NULL,
                NULL, //get_rqst_local_addr_cb,
                NULL, //get_rqst_canonical_port_cb,
                NULL, //get_rqst_apparent_cache_status_cb,
                NULL, //get_rqst_bytes_out_cb,
                NULL, //get_rqst_bytes_in_cb,
                NULL, //get_rqst_uuid_cb,
                NULL //get_cust_id_cb
        };
        static ns_waflz::resp_ctx_callbacks s_resp_callbacks = {
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
            NULL,  // get_resp_header_w_key_cb,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL  // get_rqst_uuid_cb
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
        // loading a bad profile
        // -------------------------------------------------
        SECTION("testing bad profile load") {
                // -----------------------------------------
                // create profile proto
                // -----------------------------------------
                ns_waflz::profile *l_profile = new ns_waflz::profile(*l_engine);
                waflz_pb::profile *l_pb = init_std_profile_pb();
                //-------------------------------------------
                // add a custom score to the protobuff
                // {
                // "rule_id": "944130",
                // "score": 0
                // }
                //-------------------------------------------
                waflz_pb::profile_custom_score_t* l_custom_scores = l_pb->add_custom_scores();
                l_custom_scores->set_rule_id("944130");
                l_custom_scores->set_score(0);
                //-------------------------------------------
                // Load config with default policies
                //-------------------------------------------
                l_s = l_profile->load(l_pb);
                // -----------------------------------------
                // assert profile failed to load
                // -----------------------------------------
                REQUIRE((l_s == WAFLZ_STATUS_ERROR));
                const std::string l_err = l_profile->get_err_msg();
                REQUIRE((strncmp(l_err.c_str(),
                                 "score must be over 0",
                                 l_err.length()) == 0));
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if (l_profile) { delete l_profile; l_profile = NULL;}
                if (l_pb) { delete l_pb; l_pb = NULL; }
        }
        // -------------------------------------------------
        // testing a custom score
        // -------------------------------------------------
        SECTION("testing profile custom scores with rule_id_list") {
                // -----------------------------------------
                // create profile proto
                // -----------------------------------------
                ns_waflz::profile *l_profile = new ns_waflz::profile(*l_engine);
                waflz_pb::profile *l_pb = init_std_profile_pb();
                //-------------------------------------------
                // add a custom score to the protobuff
                //{
                // "rule_id_list": ["944130", "944131"],
                // "score": 100
                // }
                //-------------------------------------------
                waflz_pb::profile_custom_score_t* l_custom_scores = l_pb->add_custom_scores();
                l_custom_scores->add_rule_id_list("944130");
                l_custom_scores->add_rule_id_list("944131");
                l_custom_scores->set_score(100);
                //-------------------------------------------
                // Load config with default policies
                //-------------------------------------------
                l_s = l_profile->load(l_pb);
                // -----------------------------------------
                // assert profile was loaded
                // -----------------------------------------
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // assert custom score was loaded
                // -----------------------------------------
                std::map<std::string, uint32_t>* l_custom_score_map = l_profile->get_waf()->get_custom_score_map();
                REQUIRE((l_custom_score_map->size() == 2));
                REQUIRE((l_custom_score_map->find("944130") != l_custom_score_map->end()));
                REQUIRE((l_custom_score_map->find("944131") != l_custom_score_map->end()));
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if (l_profile) { delete l_profile; l_profile = NULL;}
                if (l_pb) { delete l_pb; l_pb = NULL; }
        }
        // -------------------------------------------------
        // testing a custom score
        // -------------------------------------------------
        SECTION("testing profile custom scores inbound") {
                // -----------------------------------------
                // create profile proto
                // -----------------------------------------
                ns_waflz::profile *l_profile = new ns_waflz::profile(*l_engine);
                waflz_pb::profile *l_pb = init_std_profile_pb();
                //-------------------------------------------
                // add a custom score to the protobuff
                //{
                // "rule_id": "944130",
                // "score": 100
                // }
                //-------------------------------------------
                waflz_pb::profile_custom_score_t* l_custom_scores = l_pb->add_custom_scores();
                l_custom_scores->set_rule_id("944130");
                l_custom_scores->set_score(100);
                //-------------------------------------------
                // Load config with default policies
                //-------------------------------------------
                l_s = l_profile->load(l_pb);
                // -----------------------------------------
                // assert profile was loaded
                // -----------------------------------------
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // assert custom score was loaded
                // -----------------------------------------
                std::map<std::string, uint32_t>* l_custom_score_map = l_profile->get_waf()->get_custom_score_map();
                REQUIRE((l_custom_score_map->size() == 1));
                REQUIRE((l_custom_score_map->find("944130") != l_custom_score_map->end()));
                // -----------------------------------------
                // create request context with body to trip rule
                // -----------------------------------------
                void* l_ctx = NULL;
                waflz_pb::event* l_event = NULL;
                ns_waflz::rqst_ctx* l_rqst_ctx = new ns_waflz::rqst_ctx(
                    l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_rqst_callbacks);
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
                // assert rule fired
                // -----------------------------------------
                REQUIRE(l_event != NULL);
                REQUIRE(l_event->sub_event_size() >= 1);
                REQUIRE(l_event->sub_event(0).rule_id() == 944130);
                // -----------------------------------------
                // assert custom score was applied
                // -----------------------------------------
                REQUIRE(l_event->sub_event(0).total_anomaly_score() == 100);
                // -----------------------------------------
                // remove custom score
                // -----------------------------------------
                l_custom_score_map->clear();
                // -----------------------------------------
                // clear event and reset request
                // -----------------------------------------
                if (l_event) { delete l_event; l_event = NULL; }
                l_rqst_ctx->reset_phase_1();
                // -----------------------------------------
                // process rules
                // -----------------------------------------
                l_s = l_profile->process(&l_event, l_ctx, ns_waflz::PART_MK_WAF, &l_rqst_ctx);
                // -----------------------------------------
                // assert processed correctly
                // -----------------------------------------
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // assert rule fired
                // -----------------------------------------
                REQUIRE(l_event != NULL);
                REQUIRE(l_event->sub_event_size() >= 1);
                REQUIRE(l_event->sub_event(0).rule_id() == 944130);
                // -----------------------------------------
                // assert no custom score was applied
                // -----------------------------------------
                REQUIRE(l_event->sub_event(0).total_anomaly_score() == 5);
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if (l_profile) { delete l_profile; l_profile = NULL;}
                if (l_pb) { delete l_pb; l_pb = NULL; }
                if (l_event) { delete l_event; l_event = NULL; }
                if (l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
        // -------------------------------------------------
        // testing a custom score
        // -------------------------------------------------
        SECTION("testing profile custom scores outbound") {
                // -----------------------------------------
                // create profile proto
                // -----------------------------------------
                ns_waflz::profile *l_profile = new ns_waflz::profile(*l_engine);
                waflz_pb::profile *l_pb = init_std_profile_pb();
                //-------------------------------------------
                // add a custom score to the protobuff
                //{
                // "rule_id": "952100",
                // "score": 100
                // }
                //-------------------------------------------
                waflz_pb::profile_custom_score_t* l_custom_scores = l_pb->add_custom_scores();
                l_custom_scores->set_rule_id("952100");
                l_custom_scores->set_score(100);
                //-------------------------------------------
                // Load config with default policies
                //-------------------------------------------
                l_s = l_profile->load(l_pb);
                // -----------------------------------------
                // assert profile was loaded
                // -----------------------------------------
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // assert custom score was loaded
                // -----------------------------------------
                std::map<std::string, uint32_t>* l_custom_score_map = l_profile->get_waf()->get_custom_score_map();
                REQUIRE((l_custom_score_map->size() == 1));
                REQUIRE((l_custom_score_map->find("952100") != l_custom_score_map->end()));
                // -----------------------------------------
                // create request context with body to trip rule
                // -----------------------------------------
                void* l_ctx = NULL;
                waflz_pb::event* l_event = NULL;
                ns_waflz::resp_ctx* l_resp_ctx = new ns_waflz::resp_ctx(
                    l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_resp_callbacks, -1, NULL);
                char* l_body  = (char*)malloc(11 * sizeof(char));
                std::string l_tmp = ".addheader";
                strcpy(l_body, l_tmp.c_str());
                l_resp_ctx->m_body_data = l_body;
                l_resp_ctx->m_body_len = 11;
                // -----------------------------------------
                // process rules
                // -----------------------------------------
                l_s = l_profile->process_response(
                    &l_event, l_ctx, ns_waflz::PART_MK_WAF, &l_resp_ctx);
                // -----------------------------------------
                // assert processed correctly
                // -----------------------------------------
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // assert rule fired
                // -----------------------------------------
                REQUIRE(l_event != NULL);
                REQUIRE(l_event->sub_event_size() >= 1);
                REQUIRE(l_event->sub_event(0).rule_id() == 952100);
                // -----------------------------------------
                // assert custom score was applied
                // -----------------------------------------
                REQUIRE(l_event->sub_event(0).total_anomaly_score() == 100);
                // -----------------------------------------
                // remove custom score
                // -----------------------------------------
                l_custom_score_map->clear();
                // -----------------------------------------
                // clear event and reset request
                // -----------------------------------------
                if (l_event) { delete l_event; l_event = NULL; }
                l_resp_ctx->reset_phase_3();
                // -----------------------------------------
                // process rules
                // -----------------------------------------
                l_s = l_profile->process_response(
                    &l_event, l_ctx, ns_waflz::PART_MK_WAF, &l_resp_ctx);
                // -----------------------------------------
                // assert processed correctly
                // -----------------------------------------
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // assert rule fired
                // -----------------------------------------
                REQUIRE(l_event != NULL);
                REQUIRE(l_event->sub_event_size() >= 1);
                REQUIRE(l_event->sub_event(0).rule_id() == 952100);
                // -----------------------------------------
                // assert no custom score was applied
                // -----------------------------------------
                REQUIRE(l_event->sub_event(0).total_anomaly_score() == 4);
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if (l_profile) { delete l_profile; l_profile = NULL;}
                if (l_pb) { delete l_pb; l_pb = NULL; }
                if (l_event) { delete l_event; l_event = NULL; }
                if (l_resp_ctx) { delete l_resp_ctx; l_resp_ctx = NULL; }
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
