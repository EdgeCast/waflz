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
//! includes
//! ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "jspb/jspb.h"
#include "support/ndebug.h"
#include "waflz/enforcer.h"
#include "waflz/rqst_ctx.h"
#include "waflz/geoip2_mmdb.h"
#include "waflz/def.h"
#include "limit.pb.h"
#include <string.h>
#include <unistd.h>
//! ----------------------------------------------------------------------------
//! Config
//! ----------------------------------------------------------------------------
#define VALID_ENFORCEMENT_CONFIG_JSON \
"{"\
"  \"version\": 2,"\
"  \"id\": \"181fdc47-d78b-4344-9c43-6cea2d92d3b5AAFD\","\
"  \"name\": \"CAS POST TEST COORDINATOR CONF-c3b05b0a-ae93-4aa6-b804-72d31137ac3f\","\
"  \"type\": \"ENFORCER\","\
"  \"customer_id\": \"DEADDEAD\","\
"  \"enabled_date\": \"02/19/2016\","\
"  \"limits\": ["\
"    {"\
"      \"id\": \"640b3c22-4b68-4b9c-b644-ada917411769AAFD\","\
"      \"disabled\": false,"\
"      \"start_epoch_msec\": 1582764295072,"\
"      \"_reserved_match\": \"this_is__reserved_match\","\
"      \"condition_groups\": ["\
"        {"\
"          \"conditions\": ["\
"            {"\
"              \"target\": {"\
"                \"type\": \"REMOTE_ADDR\""\
"              },"\
"              \"op\": {"\
"                \"type\": \"IPMATCH\","\
"                \"value\": \"192.16.26.2\","\
"                \"is_negated\": false"\
"              }"\
"            },"\
"            {"\
"              \"target\": {"\
"                \"type\": \"REQUEST_HEADERS\","\
"                \"value\": \"User-Agent\""\
"              },"\
"              \"op\": {"\
"                \"type\": \"STREQ\","\
"                \"value\": \"braddock version ASS.KICK.IN\","\
"                \"is_negated\": false"\
"              }"\
"            }"\
"          ]"\
"        }"\
"      ],"\
"      \"action\": {"\
"        \"id\": \"caa9be38-35cf-465c-bf61-7e99f2eea30bAAFD\","\
"        \"name\": \"COOL ACTION NAME\","\
"        \"type\": \"redirect-302\","\
"        \"percentage\": 75,"\
"        \"duration_sec\": 140,"\
"        \"url\": \"https://www.google.com\","\
"        \"enf_type\": \"REDIRECT_302\""\
"      }"\
"    }"\
"  ]"\
"}"
//! ----------------------------------------------------------------------------
//! Config
//! ----------------------------------------------------------------------------
#define MATCH_URI_CONFIG \
"{"\
"  \"version\": 2,"\
"  \"id\": \"181fdc47-d78b-4344-9c43-6cea2d92d3b5AAFD\","\
"  \"name\": \"CAS POST TEST COORDINATOR CONF-c3b05b0a-ae93-4aa6-b804-72d31137ac3f\","\
"  \"type\": \"ENFORCER\","\
"  \"customer_id\": \"DEADDEAD\","\
"  \"enabled_date\": \"02/19/2016\","\
"  \"limits\": ["\
"    {"\
"      \"id\": \"640b3c22-4b68-4b9c-b644-ada917411769AAFD\","\
"      \"disabled\": false,"\
"      \"start_epoch_msec\": 1582764317918,"\
"      \"condition_groups\": ["\
"        {"\
"          \"conditions\": ["\
"            {"\
"              \"target\": {"\
"                \"type\": \"REQUEST_URI\""\
"              },"\
"              \"op\": {"\
"                \"type\": \"STREQ\","\
"                \"value\": \"/bananas/monkey\","\
"                \"is_negated\": false"\
"              }"\
"            }"\
"          ]"\
"        }"\
"      ],"\
"      \"action\": {"\
"        \"id\": \"caa9be38-35cf-465c-bf61-7e99f2eea30bAAFD\","\
"        \"name\": \"COOL ACTION NAME\","\
"        \"type\": \"redirect-302\","\
"        \"percentage\": 75,"\
"        \"duration_sec\": 2,"\
"        \"url\": \"https://www.google.com\","\
"        \"enf_type\": \"REDIRECT_302\""\
"      }"\
"    }"\
"  ]"\
"}"
//! ----------------------------------------------------------------------------
//! Config
//! ----------------------------------------------------------------------------
#define MATCH_URI_OR_CONFIG \
"{"\
"  \"version\": 2,"\
"  \"id\": \"181fdc47-d78b-4344-9c43-6cea2d92d3b5AAFD\","\
"  \"name\": \"CAS POST TEST COORDINATOR CONF-c3b05b0a-ae93-4aa6-b804-72d31137ac3f\","\
"  \"type\": \"ENFORCER\","\
"  \"customer_id\": \"DEADDEAD\","\
"  \"enabled_date\": \"02/19/2016\","\
"  \"limits\": ["\
"    {"\
"      \"id\": \"640b3c22-4b68-4b9c-b644-ada917411769AAFD\","\
"      \"disabled\": false,"\
"      \"start_epoch_msec\": 1582764338177,"\
"      \"condition_groups\": ["\
"        {"\
"          \"conditions\": ["\
"            {"\
"              \"target\": {"\
"                \"type\": \"REQUEST_URI\""\
"              },"\
"              \"op\": {"\
"                \"type\": \"STREQ\","\
"                \"value\": \"/bananas/monkey\","\
"                \"is_negated\": false"\
"              }"\
"            }"\
"          ]"\
"        },"\
"        {"\
"          \"conditions\": ["\
"            {"\
"              \"target\": {"\
"                \"type\": \"REQUEST_URI\""\
"              },"\
"              \"op\": {"\
"                \"type\": \"STREQ\","\
"                \"value\": \"/bonkers/monkey\","\
"                \"is_negated\": false"\
"              }"\
"            }"\
"          ]"\
"        }"\
"      ],"\
"      \"action\": {"\
"        \"id\": \"caa9be38-35cf-465c-bf61-7e99f2eea30bAAFD\","\
"        \"name\": \"COOL ACTION NAME\","\
"        \"type\": \"redirect-302\","\
"        \"percentage\": 75,"\
"        \"duration_sec\": 140,"\
"        \"url\": \"https://www.google.com\","\
"        \"enf_type\": \"REDIRECT_302\""\
"      }"\
"    }"\
"  ]"\
"}"
//! ----------------------------------------------------------------------------
//! Config
//! ----------------------------------------------------------------------------
#define MATCH_URI_REGEX_CONFIG \
"{"\
"  \"version\": 2,"\
"  \"id\": \"181fdc47-d78b-4344-9c43-6cea2d92d3b5AAFD\","\
"  \"name\": \"CAS POST TEST COORDINATOR CONF-c3b05b0a-ae93-4aa6-b804-72d31137ac3f\","\
"  \"type\": \"ENFORCER\","\
"  \"customer_id\": \"DEADDEAD\","\
"  \"enabled_date\": \"02/19/2016\","\
"  \"limits\": ["\
"    {"\
"      \"id\": \"640b3c22-4b68-4b9c-b644-ada917411769AAFD\","\
"      \"disabled\": false,"\
"      \"start_epoch_msec\": 1582764358577,"\
"      \"condition_groups\": ["\
"        {"\
"          \"conditions\": ["\
"            {"\
"              \"target\": {"\
"                \"type\": \"REQUEST_URI\""\
"              },"\
"              \"op\": {"\
"                \"type\": \"RX\","\
"                \"value\": \"/bananas*\","\
"                \"is_regex\": true,"\
"                \"is_negated\": false"\
"              }"\
"            }"\
"          ]"\
"        }"\
"      ],"\
"      \"action\": {"\
"        \"id\": \"caa9be38-35cf-465c-bf61-7e99f2eea30bAAFD\","\
"        \"name\": \"COOL ACTION NAME\","\
"        \"type\": \"redirect-302\","\
"        \"percentage\": 75,"\
"        \"duration_sec\": 140,"\
"        \"url\": \"https://www.google.com\","\
"        \"enf_type\": \"REDIRECT_302\""\
"      }"\
"    }"\
"  ]"\
"}"
//! ----------------------------------------------------------------------------
//! Config
//! ----------------------------------------------------------------------------
#define MATCH_NO_RULES_CONFIG \
"{"\
"  \"version\": 2,"\
"  \"id\": \"181fdc47-d78b-4344-9c43-6cea2d92d3b5AAFD\","\
"  \"name\": \"CAS POST TEST COORDINATOR CONF-c3b05b0a-ae93-4aa6-b804-72d31137ac3f\","\
"  \"type\": \"ENFORCER\","\
"  \"customer_id\": \"DEADDEAD\","\
"  \"enabled_date\": \"02/19/2016\","\
"  \"limits\": ["\
"    {"\
"      \"id\": \"640b3c22-4b68-4b9c-b644-ada917411769AAFD\","\
"      \"disabled\": false,"\
"      \"start_epoch_msec\": 1582764377095,"\
"      \"action\": {"\
"        \"id\": \"caa9be38-35cf-465c-bf61-7e99f2eea30bAAFD\","\
"        \"name\": \"COOL ACTION NAME\","\
"        \"type\": \"redirect-302\","\
"        \"percentage\": 75,"\
"        \"duration_sec\": 140,"\
"        \"url\": \"https://www.google.com\","\
"        \"enf_type\": \"REDIRECT_302\""\
"      }"\
"    }"\
"  ]"\
"}"
//! ----------------------------------------------------------------------------
//! GEO CONFIG
//! ----------------------------------------------------------------------------
#define GEO_CONFIG \
"{"\
"  \"version\": 2,"\
"  \"id\": \"181fdc47-d78b-4344-9c43-6cea2d92d3b5AAFD\","\
"  \"name\": \"CAS POST TEST COORDINATOR CONF-c3b05b0a-ae93-4aa6-b804-72d31137ac3f\","\
"  \"type\": \"ENFORCER\","\
"  \"customer_id\": \"DEADDEAD\","\
"  \"enabled_date\": \"02/19/2016\","\
"  \"limits\": ["\
"    {"\
"      \"id\": \"640b3c22-4b68-4b9c-b644-ada917411769AAFD\","\
"      \"disabled\": false,"\
"      \"start_epoch_msec\": 1582764317918,"\
"      \"condition_groups\": ["\
"        {"\
"          \"conditions\": ["\
"            {"\
"              \"target\": {"\
"                \"type\": \"GEO\""\
"              },"\
"              \"op\": {"\
"                \"type\": \"STREQ\","\
"                \"value\": \"US\","\
"                \"is_negated\": false"\
"              }"\
"            }"\
"          ]"\
"        }"\
"      ],"\
"      \"action\": {"\
"        \"id\": \"caa9be38-35cf-465c-bf61-7e99f2eea30bAAFD\","\
"        \"name\": \"COOL ACTION NAME\","\
"        \"type\": \"redirect-302\","\
"        \"percentage\": 75,"\
"        \"duration_sec\": 2,"\
"        \"url\": \"https://www.google.com\","\
"        \"enf_type\": \"REDIRECT_302\""\
"      }"\
"    }"\
"  ]"\
"}"

//! ----------------------------------------------------------------------------
//! enforcer
//! ----------------------------------------------------------------------------
TEST_CASE( "enforcer test", "[enforcer]" ) {
        // -------------------------------------------------
        // bad config
        // -------------------------------------------------
        SECTION("verify load failures bad json 1") {
                int32_t l_s;
                const char l_json[] = "woop woop [[[ bloop {##{{{{ ]} blop blop %%# &(!(*&!#))";
                ns_waflz::enforcer l_e;
                l_s = l_e.load(l_json, sizeof(l_json));
                //printf("err: %s\n", l_e.get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_ERROR));
        }
        // -------------------------------------------------
        // bad config
        // -------------------------------------------------
        SECTION("verify load failures bad json 2") {
                int32_t l_s;
                const char l_json[] = "blorp";
                ns_waflz::enforcer l_e;
                l_s = l_e.load(l_json, sizeof(l_json));
                //printf("err: %s\n", l_e.get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_ERROR));
        }
        // -------------------------------------------------
        // bad config
        // -------------------------------------------------
        SECTION("verify load failures bad json 3") {
                int32_t l_s;
                const char l_json[] = "[\"b\", \"c\",]";
                ns_waflz::enforcer l_e;
                l_s = l_e.load(l_json, sizeof(l_json));
                //printf("err: %s\n", l_e.get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_ERROR));
        }
        // -------------------------------------------------
        // valid json bad config
        // -------------------------------------------------
        SECTION("verify load failures valid json -bad config") {
                int32_t l_s;
                const char l_json[] = "{\"b\": \"c\"}";
                ns_waflz::enforcer l_e;
                l_s = l_e.load(l_json, sizeof(l_json));
                //printf("err: %s\n", l_e.get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_ERROR));
        }
        // -------------------------------------------------
        // Valid config
        // -------------------------------------------------
        SECTION("verify load success") {
                int32_t l_s;
                ns_waflz::enforcer l_e;
                l_s = l_e.load(VALID_ENFORCEMENT_CONFIG_JSON, sizeof(VALID_ENFORCEMENT_CONFIG_JSON));
                //NDBG_PRINT("err: %s\n", l_e.get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
        }
        // -------------------------------------------------
        // Simple Match URI
        // -------------------------------------------------
        SECTION("verify simple URI match") {
                int32_t l_s;
                ns_waflz::enforcer l_e;
                l_s = l_e.load(MATCH_URI_CONFIG, sizeof(MATCH_URI_CONFIG));
                //printf("err: %s\n", l_e.get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                const waflz_pb::enforcement* l_enfx = NULL;
                ns_waflz::rqst_ctx l_ctx(NULL, 0, 0, NULL);
                // Verify match
                l_ctx.m_uri.m_data = "/bananas/monkey";
                l_ctx.m_uri.m_len = strlen("/bananas/monkey");
                l_s = l_e.process(&l_enfx, &l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enfx != NULL));
                REQUIRE((l_enfx->id() == "caa9be38-35cf-465c-bf61-7e99f2eea30bAAFD"));
                REQUIRE((l_ctx.m_limit != NULL));
                REQUIRE((l_ctx.m_limit->_reserved_match() != "this_is__reserved_match"));
                // Verify no match
                l_ctx.m_uri.m_data = "/bonkers/monkey";
                l_ctx.m_uri.m_len = sizeof("/bonkers/monkey");
                l_s = l_e.process(&l_enfx, &l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enfx == NULL));
        }
        // -------------------------------------------------
        // Match AND config
        // -------------------------------------------------
        SECTION("verify match AND config") {
                int32_t l_s;
                ns_waflz::enforcer l_e;
                l_s = l_e.load(VALID_ENFORCEMENT_CONFIG_JSON, sizeof(VALID_ENFORCEMENT_CONFIG_JSON));
                //printf("err: %s\n", l_e.get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                const waflz_pb::enforcement* l_enfx = NULL;
                ns_waflz::rqst_ctx l_ctx(NULL, 0, 0, NULL);
                // -----------------------------------------
                // add user-agent
                // -----------------------------------------
                ns_waflz::data_t l_d_k;
                l_d_k.m_data = "User-Agent";
                l_d_k.m_len = strlen("User-Agent");
                ns_waflz::data_t l_d_v;
                l_d_v.m_data = "braddock version ASS.KICK.IN";
                l_d_v.m_len = strlen("braddock version ASS.KICK.IN");
                l_ctx.m_header_map[l_d_k] = l_d_v;
                // -----------------------------------------
                // add ip
                // -----------------------------------------
                l_ctx.m_src_addr.m_data = "192.16.26.2";
                l_ctx.m_src_addr.m_len = strlen("192.16.26.2");
                l_s = l_e.process(&l_enfx, &l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enfx != NULL));
                REQUIRE((l_enfx->id() == "caa9be38-35cf-465c-bf61-7e99f2eea30bAAFD"));
                // -----------------------------------------
                // wrong ip
                // -----------------------------------------
                l_ctx.m_src_addr.m_data = "192.16.26.3";
                l_ctx.m_src_addr.m_len = strlen("192.16.26.3");
                l_enfx = NULL;
                l_s = l_e.process(&l_enfx, &l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
        }
        // -------------------------------------------------
        // Match OR config
        // -------------------------------------------------
        SECTION("verify match OR config") {
                int32_t l_s;
                ns_waflz::enforcer l_e;
                l_s = l_e.load(MATCH_URI_OR_CONFIG, sizeof(MATCH_URI_OR_CONFIG));
                //printf("err: %s\n", l_e.get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                const waflz_pb::enforcement* l_enfx = NULL;
                ns_waflz::rqst_ctx l_ctx(NULL, 0, 0, NULL);
                l_ctx.m_uri.m_data = "/bananas/monkey";
                l_ctx.m_uri.m_len = strlen("/bananas/monkey");
                l_s = l_e.process(&l_enfx, &l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enfx != NULL));
                REQUIRE((l_enfx->id() == "caa9be38-35cf-465c-bf61-7e99f2eea30bAAFD"));
                // Verify match
                l_ctx.m_uri.m_data = "/bonkers/monkey";
                l_ctx.m_uri.m_len = strlen("/bonkers/monkey");
                l_enfx = NULL;
                l_s = l_e.process(&l_enfx, &l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enfx != NULL));
                REQUIRE((l_enfx->id() == "caa9be38-35cf-465c-bf61-7e99f2eea30bAAFD"));
        }
        // -------------------------------------------------
        // Match Regex config
        // -------------------------------------------------
        SECTION("verify match regex config") {
                int32_t l_s;
                ns_waflz::enforcer l_e;
                l_s = l_e.load(MATCH_URI_REGEX_CONFIG, sizeof(MATCH_URI_REGEX_CONFIG));
                //printf("err: %s\n", l_e.get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                const waflz_pb::enforcement* l_enfx = NULL;
                ns_waflz::rqst_ctx l_ctx(NULL, 0, 0, NULL);
                // verify match
                l_ctx.m_uri.m_data = "/bananas/monkey";
                l_ctx.m_uri.m_len = strlen("/bananas/monkey");
                l_s = l_e.process(&l_enfx, &l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enfx != NULL));
                REQUIRE((l_enfx->id() == "caa9be38-35cf-465c-bf61-7e99f2eea30bAAFD"));
                // Verify no match
                l_ctx.m_uri.m_data = "/bonkers/monkey";
                l_ctx.m_uri.m_len = sizeof("/bonkers/monkey");
                l_enfx = NULL;
                l_s = l_e.process(&l_enfx, &l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enfx == NULL));
        }
        // -------------------------------------------------
        // No rules
        // -------------------------------------------------
        SECTION("verify match no rules config") {
                int32_t l_s;
                ns_waflz::enforcer l_e;
                l_s = l_e.load(MATCH_NO_RULES_CONFIG, sizeof(MATCH_NO_RULES_CONFIG));
                //NDBG_PRINT("err: %s\n", l_e.get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                //NDBG_PRINT("l_e.get_pb(): %s\n", l_e.get_pb()->ShortDebugString().c_str());
                const waflz_pb::enforcement* l_enfx = NULL;
                ns_waflz::rqst_ctx l_ctx(NULL, 0, 0, NULL);
                l_s = l_e.process(&l_enfx, &l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enfx != NULL));
                REQUIRE((l_enfx->id() == "caa9be38-35cf-465c-bf61-7e99f2eea30bAAFD"));
                l_s = l_e.process(&l_enfx, &l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enfx != NULL));
                REQUIRE((l_enfx->id() == "caa9be38-35cf-465c-bf61-7e99f2eea30bAAFD"));
        }
        // -------------------------------------------------
        // verify expiration
        // -------------------------------------------------
        SECTION("verify expiration") {
                int32_t l_s;
                ns_waflz::enforcer l_e;
                l_s = l_e.load(MATCH_URI_CONFIG, sizeof(MATCH_URI_CONFIG));
                //printf("err: %s\n", l_e.get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                const waflz_pb::enforcement* l_enfx = NULL;
                ns_waflz::rqst_ctx l_ctx(NULL, 0, 0, NULL);
                l_e.update_start_time();
                // verify match
                l_ctx.m_uri.m_data = "/bananas/monkey";
                l_ctx.m_uri.m_len = strlen("/bananas/monkey");
                l_s = l_e.process(&l_enfx, &l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enfx != NULL));
                REQUIRE((l_enfx->id() == "caa9be38-35cf-465c-bf61-7e99f2eea30bAAFD"));
                // verify no match
                l_ctx.m_uri.m_data = "/bonkers/monkey";
                l_ctx.m_uri.m_len = sizeof("/bonkers/monkey");
                l_s = l_e.process(&l_enfx, &l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enfx == NULL));
                // verify match
                l_ctx.m_uri.m_data = "/bananas/monkey";
                l_ctx.m_uri.m_len = strlen("/bananas/monkey");
                l_s = l_e.process(&l_enfx, &l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enfx != NULL));
                REQUIRE((l_enfx->id() == "caa9be38-35cf-465c-bf61-7e99f2eea30bAAFD"));
                // sleep 3 -wait for expiration
                sleep(3);
                l_s = ns_waflz::limit_sweep(*(l_e.get_mutable_pb()));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_e.process(&l_enfx, &l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enfx == NULL));
        }
        // TODO negated
        // -------------------------------------------------
        // verify GEO match
        // -------------------------------------------------
        SECTION("verify GEO match") {
                int32_t l_s;
                ns_waflz::enforcer l_e;
                l_s = l_e.load(GEO_CONFIG, sizeof(GEO_CONFIG));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                const waflz_pb::enforcement* l_enfx = NULL;
                ns_waflz::rqst_ctx l_ctx(NULL, 0, 0, NULL);
                l_e.update_start_time();
                // verify match
                l_ctx.m_geo_data.m_geo_cn2.m_data = "US";
                l_ctx.m_geo_data.m_geo_cn2.m_len = strlen("US");
                l_s = l_e.process(&l_enfx, &l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enfx != NULL));
                REQUIRE((l_enfx->id() == "caa9be38-35cf-465c-bf61-7e99f2eea30bAAFD"));
                // verify no match
                l_ctx.m_geo_data.m_geo_cn2.m_data = "NA";
                l_ctx.m_geo_data.m_geo_cn2.m_len = strlen("NA");
                l_s = l_e.process(&l_enfx, &l_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_enfx == NULL));
        }
}

