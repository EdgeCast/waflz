//: ----------------------------------------------------------------------------
//: Copyright (C) 2017 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    wb_profile_acl.cc
//: \details: TODO
//: \author:  Reed Morrison
//: \date:    12/30/2017
//:
//:   Licensed under the Apache License, Version 2.0 (the "License");
//:   you may not use this file except in compliance with the License.
//:   You may obtain a copy of the License at
//:
//:       http://www.apache.org/licenses/LICENSE-2.0
//:
//:   Unless required by applicable law or agreed to in writing, software
//:   distributed under the License is distributed on an "AS IS" BASIS,
//:   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//:   See the License for the specific language governing permissions and
//:   limitations under the License.
//:
//: ----------------------------------------------------------------------------
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "waflz/engine.h"
#include "waflz/profile.h"
#include "waflz/instances.h"
#include "waflz/rqst_ctx.h"
#include "waflz/geoip2_mmdb.h"
#include "waflz/def.h"
#include "profile.pb.h"
#include "event.pb.h"
#include "support/ndebug.h"
#include <unistd.h>
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static waflz_pb::profile *init_std_profile_pb(void)
{
        // -----------------------------------------
        // setup...
        // -----------------------------------------
        waflz_pb::profile *l_pb = NULL;
        l_pb = new waflz_pb::profile();
        l_pb->set_id("my_id");
        l_pb->set_name("my_name");
        l_pb->set_ruleset_id("OWASP-CRS-2.2.9");
        l_pb->set_ruleset_version("2017-08-01");
        // -----------------------------------------
        // general settings -required fields
        // -----------------------------------------
        ::waflz_pb::profile_general_settings_t* l_gx = NULL;
        l_gx = l_pb->mutable_general_settings();
        l_gx->set_process_request_body(true);
        l_gx->set_xml_parser(true);
        l_gx->set_process_response_body(false);
        l_gx->set_validate_utf8_encoding(true);
        l_gx->set_max_num_args(3);
        l_gx->set_arg_name_length(100);
        l_gx->set_arg_length(400);
        l_gx->set_total_arg_length(64000);
        l_gx->set_max_file_size(1048576);
        l_gx->set_combined_file_sizes(1048576);
        l_gx->add_allowed_http_methods("GET");
        l_gx->add_allowed_request_content_types("html");
        // -----------------------------------------
        // add policies
        // -----------------------------------------
        l_pb->add_policies("modsecurity_crs_21_protocol_anomalies.conf");
        l_pb->add_policies("modsecurity_crs_49_inbound_blocking.conf");
        // -----------------------------------------
        // anomaly settings -required fields
        // -----------------------------------------
        l_gx->set_anomaly_threshold(1);
        // -----------------------------------------
        // access settings -required fields
        // -----------------------------------------
        ::waflz_pb::acl* l_ax = NULL;
        l_ax = l_pb->mutable_access_settings();
        ::waflz_pb::acl_lists_t* l_ax_ip = l_ax->mutable_ip();
        UNUSED(l_ax_ip);
        ::waflz_pb::acl_lists_t* l_ax_cntry = l_ax->mutable_country();
        UNUSED(l_ax_cntry);
        ::waflz_pb::acl_lists_t* l_ax_url = l_ax->mutable_url();
        UNUSED(l_ax_url);
        ::waflz_pb::acl_lists_t* l_ax_refr = l_ax->mutable_referer();
        UNUSED(l_ax_refr);
        return l_pb;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static const char *s_ip = "156.123.12.7";
static int32_t get_rqst_src_addr_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        *a_data = s_ip;
        a_len = strlen(s_ip);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static int32_t get_rqst_line_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        static const char s_line[] = "GET / HTTP/1.1";
        *a_data = s_line;
        a_len = strlen(s_line);
        return 0;
}
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static const char *s_uri = "cats.com";
static int32_t get_rqst_uri_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        *a_data = s_uri;
        a_len = strlen(s_uri);
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_header_size_cb
//: ----------------------------------------------------------------------------
static int32_t get_rqst_header_size_cb(uint32_t &a_val, void *a_ctx)
{
        a_val = 8;
        return 0;
}
//: ----------------------------------------------------------------------------
//: s_get_rqst_method_cb
//: ----------------------------------------------------------------------------
static const char *s_method = "GET";
static int32_t get_rqst_method_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        *a_data = s_method;
        a_len = strlen(s_method);
        return 0;
}
//: ----------------------------------------------------------------------------
//: s_get_rqst_path_cb
//: ----------------------------------------------------------------------------
static const char *s_path = "/my/cool/path_name.html";
static int32_t get_rqst_path_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
{
        *a_data = s_path;
        a_len = strlen(s_path);
        return 0;
}
//: ----------------------------------------------------------------------------
//: get_rqst_header_w_idx_cb
//: ----------------------------------------------------------------------------
#if 0
> User-Agent: curl/7.47.0
> Accept: *
> Referer: google.com
> Cookie:__cfduid=de8f54f306ad55fdcbd9a4b2d74e146011505283099; _ga=GA1.2.1776379976.1505283191; __utmz=214959637.1507590369.3.3.utmcsr=google|utmccn=(organic)|utmcmd=organic|utmctr=(not%20provided); _gid=GA1.2.2014252890.1514820827; _gat_gtag_UA_33089744_1=1; __utma=214959637.1776379976.1505283191.1507590369.1514820827.4; __utmc=214959637; __utmt=1; __utmb=214959637.1.10.1514820827
#endif
static const char *s_header_user_agent = "my_cool_user_agent";
static const char *s_header_accept = "my_cool_accept_value";
static const char *s_header_referer = "my_cool_referer_value";
static const char *s_header_cookie = "__cookie_a=a_value; __cookie_b=b_value; __cookie_c=c_value;";
static const char *s_header_content_type = NULL;
static const char *s_header_content_length = NULL;
static const char *s_host = NULL;
static const char *s_test_header = NULL;
static int32_t get_rqst_header_w_idx_cb(const char **ao_key,
                                        uint32_t &ao_key_len,
                                        const char **ao_val,
                                        uint32_t &ao_val_len,
                                        void *a_ctx,
                                        uint32_t a_idx)
{
        *ao_key = NULL;
        ao_key_len = 0;
        *ao_val = NULL;
        ao_val_len = 0;
        switch(a_idx)
        {
        case 0:
        {
                *ao_key = "User-Agent";
                ao_key_len = strlen("User-Agent");
                *ao_val = s_header_user_agent;
                ao_val_len = strlen(s_header_user_agent);
                break;
        }
        case 1:
        {
                *ao_key = "Accept";
                ao_key_len = strlen("Accept");
                *ao_val = s_header_accept;
                ao_val_len = strlen(s_header_accept);
                break;
        }
        case 2:
        {
                *ao_key = "Referer";
                ao_key_len = strlen("Referer");
                *ao_val = s_header_referer;
                ao_val_len = strlen(s_header_referer);
                break;
        }
        case 3:
        {
                *ao_key = "Cookie";
                ao_key_len = strlen("Cookie");
                *ao_val = s_header_cookie;
                ao_val_len = strlen(s_header_cookie);
                break;
        }
        case 4:
        {
                if(s_header_content_type)
                {
                        *ao_key = "Content-Type";
                        ao_key_len = strlen("Content-Type");
                        *ao_val = s_header_content_type;
                        ao_val_len = strlen(s_header_content_type);
                }
                break;
        }
        case 5:
        {
                if(s_header_content_length)
                {
                        *ao_key = "Content-Length";
                        ao_key_len = strlen("Content-Length");
                        *ao_val = s_header_content_length;
                        ao_val_len = strlen(s_header_content_length);
                }
                break;
        }
        case 6:
        {
                if(s_host)
                {
                        *ao_key = "Host";
                        ao_key_len = strlen("Host");
                        *ao_val = s_host;
                        ao_val_len = strlen(s_host);
                }
                break;
        }
        case 7:
        {
                if(s_test_header)
                {
                        *ao_key = s_test_header;
                        ao_key_len = strlen(s_test_header);
                        *ao_val = s_test_header;
                        ao_val_len = strlen(s_test_header);
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
//: ----------------------------------------------------------------------------
//: profile acl tests
//: ----------------------------------------------------------------------------
TEST_CASE( "acl accesslist test", "[acl accesslist]" )
{
        // -------------------------------------------------
        // get ruleset dir
        // -------------------------------------------------
        char l_cwd[1024];
        if(getcwd(l_cwd, sizeof(l_cwd)) != NULL)
        {
                //fprintf(stdout, "Current working dir: %s\n", cwd);
        }
        std::string l_rule_dir = l_cwd;
        l_rule_dir += "/../../../../tests/data/waf/ruleset/";
        //l_rule_dir += "/../tests/data/waf/ruleset/";
        // -------------------------------------------------
        // geoip
        // -------------------------------------------------
        std::string l_geoip2_city_file = l_cwd;
        std::string l_geoip2_asn_file = l_cwd;
        l_geoip2_city_file += "/../../../../tests/data/waf/db/GeoLite2-City.mmdb";
        l_geoip2_asn_file += "/../../../../tests/data/waf/db/GeoLite2-ASN.mmdb";
        // -------------------------------------------------
        // setup
        // -------------------------------------------------
        ns_waflz::engine *l_engine = new ns_waflz::engine();
        l_engine->set_geoip2_dbs(l_geoip2_city_file, l_geoip2_asn_file);
        l_engine->set_ruleset_dir(l_rule_dir);
        int32_t l_s;
        l_s = l_engine->init();
        REQUIRE((l_s == WAFLZ_STATUS_OK));
        // -------------------------------------------------
        // cb
        // -------------------------------------------------
        ns_waflz::rqst_ctx::s_get_rqst_src_addr_cb = get_rqst_src_addr_cb;
        ns_waflz::rqst_ctx::s_get_rqst_line_cb = get_rqst_line_cb;
        ns_waflz::rqst_ctx::s_get_rqst_uri_cb = get_rqst_uri_cb;
        ns_waflz::rqst_ctx::s_get_rqst_header_size_cb = get_rqst_header_size_cb;
        ns_waflz::rqst_ctx::s_get_rqst_header_w_idx_cb = get_rqst_header_w_idx_cb;
        ns_waflz::rqst_ctx::s_get_rqst_method_cb = get_rqst_method_cb;
        ns_waflz::rqst_ctx::s_get_rqst_path_cb = get_rqst_path_cb;
        //--------------------------------------------------
        // accesslist ip+
        // -------------------------------------------------
        SECTION("acl accesslist ip+ tests") {
                // -----------------------------------------
                // setup profile
                // -----------------------------------------
                ns_waflz::profile *l_profile = new ns_waflz::profile(*l_engine);
                waflz_pb::profile *l_pb = init_std_profile_pb();
                waflz_pb::acl* l_acl = l_pb->mutable_access_settings();
                // *****************************************
                // -----------------------------------------
                // ip settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::acl_lists_t* l_ax_ipl = l_acl->mutable_ip();
                l_ax_ipl->add_accesslist("212.43.2.0/24");
                l_ax_ipl->add_accesslist("243.49.2.7");
                // *****************************************
                // -----------------------------------------
                // country settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::acl_lists_t* l_ax_ctyl = l_acl->mutable_country();
                l_ax_ctyl->add_accesslist("JP");
                l_ax_ctyl->add_accesslist("KW");
                // *****************************************
                // -----------------------------------------
                // asn settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::acl_lists_asn_t* l_ax_asn = l_acl->mutable_asn();
                l_ax_asn->add_accesslist(26496);
                l_ax_asn->add_accesslist(42961);
                // *****************************************
                // -----------------------------------------
                // url settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::acl_lists_t* l_ax_url = l_acl->mutable_url();
                l_ax_url->add_accesslist("/login-confirm/index.html");
                l_ax_url->add_accesslist("\\/banana\\/m.*\\.html");
                // *****************************************
                // -----------------------------------------
                // user-agent settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::acl_lists_t* l_ax_ua = l_acl->mutable_user_agent();
                l_ax_ua->add_accesslist("cats are really cool dude");
                l_ax_ua->add_accesslist("curl\\/.*");
                // *****************************************
                // -----------------------------------------
                // referer settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::acl_lists_t* l_ax_refr = l_acl->mutable_referer();
                l_ax_refr->add_accesslist("bad reefer");
                l_ax_refr->add_accesslist("really\\/bad\\/.*");
                // *****************************************
                // -----------------------------------------
                // cookie settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::acl_lists_t* l_ax_cookie = l_acl->mutable_cookie();
                l_ax_cookie->add_accesslist("bad_[0-9]_key");
                l_ax_cookie->add_accesslist("wonky_key");
                // -----------------------------------------
                // load
                // -----------------------------------------
                l_s = l_profile->load_config(l_pb);
                //NDBG_PRINT("error[%d]: %s\n", l_s, l_profile->get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                if(l_pb) { delete l_pb; l_pb = NULL;}
                void *l_ctx = NULL;
                waflz_pb::event *l_event = NULL;
                ns_waflz::rqst_ctx *l_rqst_ctx = NULL;
                // -----------------------------------------
                // setup
                // -----------------------------------------
                s_path = "/login-confirm/index.html";
                s_uri = "/login-confirm/index.html";
                s_header_user_agent = "cats are really cool dude";
                s_header_cookie = "wonky_key";
                s_header_referer = "bad reefer";
                // *****************************************
                // -----------------------------------------
                //             I P   T E S T
                // -----------------------------------------
                // *****************************************
                // -----------------------------------------
                // validate accesslist block
                // -----------------------------------------
                s_ip = "243.49.2.6";
                l_s = l_profile->process_part(&l_event, l_ctx, ns_waflz::PART_MK_ACL, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Accesslist IP deny"));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
                if(l_event) { delete l_event; l_event = NULL; }
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // validate accesslist pass
                // -----------------------------------------
                s_ip = "243.49.2.7";
                l_s = l_profile->process_part(&l_event, l_ctx, ns_waflz::PART_MK_ACL, &l_rqst_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // validate accesslist pass
                // -----------------------------------------
                s_ip = "212.43.2.5";
                l_event = NULL;
                l_s = l_profile->process_part(&l_event, l_ctx, ns_waflz::PART_MK_ACL, &l_rqst_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // validate accesslist block
                // -----------------------------------------
                s_ip = "212.43.3.5";
                l_event = NULL;
                l_s = l_profile->process_part(&l_event, l_ctx, ns_waflz::PART_MK_ACL, &l_rqst_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Accesslist IP deny"));
                if(l_event) { delete l_event; l_event = NULL; }
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // revert
                // -----------------------------------------
                s_ip = "243.49.2.7";
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_profile) { delete l_profile; l_profile = NULL; }
                if(l_pb) { delete l_pb; l_pb = NULL; }
        }
        //--------------------------------------------------
        // accesslist country
        // -------------------------------------------------
        SECTION("acl accesslist country tests") {
                // -----------------------------------------
                // setup profile
                // -----------------------------------------
                ns_waflz::profile *l_profile = new ns_waflz::profile(*l_engine);
                waflz_pb::profile *l_pb = init_std_profile_pb();
                waflz_pb::acl* l_acl = l_pb->mutable_access_settings();
                // *****************************************
                // -----------------------------------------
                // country settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::acl_lists_t* l_ax_ctyl = l_acl->mutable_country();
                l_ax_ctyl->add_accesslist("JP");
                // -----------------------------------------
                // load
                // -----------------------------------------
                l_s = l_profile->load_config(l_pb);
                //NDBG_PRINT("error[%d]: %s\n", l_s, l_profile->get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                if(l_pb) { delete l_pb; l_pb = NULL;}
                void *l_ctx = NULL;
                waflz_pb::event *l_event = NULL;
                ns_waflz::rqst_ctx *l_rqst_ctx = NULL;
                // -----------------------------------------
                // validate accesslist pass
                // -----------------------------------------
                s_ip = "59.106.218.87";
                l_event = NULL;
                l_s = l_profile->process_part(&l_event, l_ctx, ns_waflz::PART_MK_ACL, &l_rqst_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // validate accesslist block
                // -----------------------------------------
                s_ip = "212.43.3.5";
                l_event = NULL;
                l_s = l_profile->process_part(&l_event, l_ctx, ns_waflz::PART_MK_ACL, &l_rqst_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Accesslist Country deny"));
                if(l_event) { delete l_event; l_event = NULL; }
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_profile) { delete l_profile; l_profile = NULL; }
                if(l_pb) { delete l_pb; l_pb = NULL; }
        }
        //--------------------------------------------------
        // accesslist asn
        // -------------------------------------------------
        SECTION("acl accesslist asn tests") {
                // -----------------------------------------
                // setup profile
                // -----------------------------------------
                ns_waflz::profile *l_profile = new ns_waflz::profile(*l_engine);
                waflz_pb::profile *l_pb = init_std_profile_pb();
                waflz_pb::acl* l_acl = l_pb->mutable_access_settings();
                // *****************************************
                // -----------------------------------------
                // asn settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::acl_lists_asn_t* l_ax_asn = l_acl->mutable_asn();
                l_ax_asn->add_accesslist(9370);
                // -----------------------------------------
                // load
                // -----------------------------------------
                l_s = l_profile->load_config(l_pb);
                //NDBG_PRINT("error[%d]: %s\n", l_s, l_profile->get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                if(l_pb) { delete l_pb; l_pb = NULL;}
                void *l_ctx = NULL;
                waflz_pb::event *l_event = NULL;
                ns_waflz::rqst_ctx *l_rqst_ctx = NULL;
                // -----------------------------------------
                // validate accesslist pass
                // -----------------------------------------
                s_ip = "59.106.218.87";
                l_event = NULL;
                l_s = l_profile->process_part(&l_event, l_ctx, ns_waflz::PART_MK_ACL, &l_rqst_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // validate accesslist block
                // -----------------------------------------
                s_ip = "212.43.3.5";
                l_event = NULL;
                l_s = l_profile->process_part(&l_event, l_ctx, ns_waflz::PART_MK_ACL, &l_rqst_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Accesslist ASN deny"));
                if(l_event) { delete l_event; l_event = NULL; }
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_profile) { delete l_profile; l_profile = NULL; }
                if(l_pb) { delete l_pb; l_pb = NULL; }
        }
        //--------------------------------------------------
        // accesslist url
        // -------------------------------------------------
        SECTION("acl accesslist url tests") {
                // -----------------------------------------
                // setup profile
                // -----------------------------------------
                ns_waflz::profile *l_profile = new ns_waflz::profile(*l_engine);
                waflz_pb::profile *l_pb = init_std_profile_pb();
                waflz_pb::acl* l_acl = l_pb->mutable_access_settings();
                // *****************************************
                // -----------------------------------------
                // url settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::acl_lists_t* l_ax_url = l_acl->mutable_url();
                l_ax_url->add_accesslist("/login-confirm/index.html");
                l_ax_url->add_accesslist("\\/banana\\/t.*\\.html");
                // -----------------------------------------
                // load
                // -----------------------------------------
                l_s = l_profile->load_config(l_pb);
                //NDBG_PRINT("error[%d]: %s\n", l_s, l_profile->get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                if(l_pb) { delete l_pb; l_pb = NULL;}
                void *l_ctx = NULL;
                waflz_pb::event *l_event = NULL;
                ns_waflz::rqst_ctx *l_rqst_ctx = NULL;
                // -----------------------------------------
                // validate accesslist pass
                // -----------------------------------------
                s_uri = "/login-confirm/index.html";
                l_event = NULL;
                l_s = l_profile->process_part(&l_event, l_ctx, ns_waflz::PART_MK_ACL, &l_rqst_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // validate accesslist block
                // -----------------------------------------
                s_uri = "/login-confirm/admin.php";
                l_event = NULL;
                l_s = l_profile->process_part(&l_event, l_ctx, ns_waflz::PART_MK_ACL, &l_rqst_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Accesslist URL deny"));
                if(l_event) { delete l_event; l_event = NULL; }
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // validate accesslist pass
                // -----------------------------------------
                s_uri = "/banana/test.html";
                l_event = NULL;
                l_s = l_profile->process_part(&l_event, l_ctx, ns_waflz::PART_MK_ACL, &l_rqst_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // validate accesslist block
                // -----------------------------------------
                s_uri = "/banana/xest.html";
                l_event = NULL;
                l_s = l_profile->process_part(&l_event, l_ctx, ns_waflz::PART_MK_ACL, &l_rqst_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Accesslist URL deny"));
                if(l_event) { delete l_event; l_event = NULL; }
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_profile) { delete l_profile; l_profile = NULL; }
                if(l_pb) { delete l_pb; l_pb = NULL; }
        }
        //--------------------------------------------------
        // accesslist user-agent
        // -------------------------------------------------
        SECTION("acl accesslist user-agent tests") {
                // -----------------------------------------
                // setup profile
                // -----------------------------------------
                ns_waflz::profile *l_profile = new ns_waflz::profile(*l_engine);
                waflz_pb::profile *l_pb = init_std_profile_pb();
                waflz_pb::acl* l_acl = l_pb->mutable_access_settings();
                // *****************************************
                // -----------------------------------------
                // user-agent settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::acl_lists_t* l_ax_ua = l_acl->mutable_user_agent();
                l_ax_ua->add_accesslist("cats are really cool dude");
                l_ax_ua->add_accesslist("curl\\/.*");
                // -----------------------------------------
                // load
                // -----------------------------------------
                l_s = l_profile->load_config(l_pb);
                //NDBG_PRINT("error[%d]: %s\n", l_s, l_profile->get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                if(l_pb) { delete l_pb; l_pb = NULL;}
                void *l_ctx = NULL;
                waflz_pb::event *l_event = NULL;
                ns_waflz::rqst_ctx *l_rqst_ctx = NULL;
                // -----------------------------------------
                // validate accesslist pass
                // -----------------------------------------
                s_header_user_agent = "cats are really cool dude";
                l_event = NULL;
                l_s = l_profile->process_part(&l_event, l_ctx, ns_waflz::PART_MK_ACL, &l_rqst_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // validate accesslist block
                // -----------------------------------------
                s_header_user_agent = "dogs are really cool dude";
                l_event = NULL;
                l_s = l_profile->process_part(&l_event, l_ctx, ns_waflz::PART_MK_ACL, &l_rqst_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Accesslist User-Agent deny"));
                if(l_event) { delete l_event; l_event = NULL; }
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // validate accesslist pass
                // -----------------------------------------
                s_header_user_agent = "curl/test";
                l_event = NULL;
                l_s = l_profile->process_part(&l_event, l_ctx, ns_waflz::PART_MK_ACL, &l_rqst_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // validate accesslist block
                // -----------------------------------------
                s_header_user_agent = "hurl/test";
                l_event = NULL;
                l_s = l_profile->process_part(&l_event, l_ctx, ns_waflz::PART_MK_ACL, &l_rqst_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Accesslist User-Agent deny"));
                if(l_event) { delete l_event; l_event = NULL; }
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_profile) { delete l_profile; l_profile = NULL; }
                if(l_pb) { delete l_pb; l_pb = NULL; }
        }
        //--------------------------------------------------
        // accesslist referer
        // -------------------------------------------------
        SECTION("acl accesslist referer tests") {
                // -----------------------------------------
                // setup profile
                // -----------------------------------------
                ns_waflz::profile *l_profile = new ns_waflz::profile(*l_engine);
                waflz_pb::profile *l_pb = init_std_profile_pb();
                waflz_pb::acl* l_acl = l_pb->mutable_access_settings();
                // *****************************************
                // -----------------------------------------
                // referer settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::acl_lists_t* l_ax_refr = l_acl->mutable_referer();
                l_ax_refr->add_accesslist("bad reefer");
                l_ax_refr->add_accesslist("really\\/bad\\/.*");
                // -----------------------------------------
                // load
                // -----------------------------------------
                l_s = l_profile->load_config(l_pb);
                //NDBG_PRINT("error[%d]: %s\n", l_s, l_profile->get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                if(l_pb) { delete l_pb; l_pb = NULL;}
                void *l_ctx = NULL;
                waflz_pb::event *l_event = NULL;
                ns_waflz::rqst_ctx *l_rqst_ctx = NULL;
                // -----------------------------------------
                // validate accesslist pass
                // -----------------------------------------
                s_header_referer = "bad reefer";
                l_event = NULL;
                l_s = l_profile->process_part(&l_event, l_ctx, ns_waflz::PART_MK_ACL, &l_rqst_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // validate accesslist block
                // -----------------------------------------
                s_header_referer = "rad beefer";
                l_event = NULL;
                l_s = l_profile->process_part(&l_event, l_ctx, ns_waflz::PART_MK_ACL, &l_rqst_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Accesslist Referer deny"));
                if(l_event) { delete l_event; l_event = NULL; }
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_profile) { delete l_profile; l_profile = NULL; }
                if(l_pb) { delete l_pb; l_pb = NULL; }
        }
        //--------------------------------------------------
        // accesslist cookie
        // -------------------------------------------------
        SECTION("acl accesslist cookie tests") {
                // -----------------------------------------
                // setup profile
                // -----------------------------------------
                ns_waflz::profile *l_profile = new ns_waflz::profile(*l_engine);
                waflz_pb::profile *l_pb = init_std_profile_pb();
                waflz_pb::acl* l_acl = l_pb->mutable_access_settings();
                // *****************************************
                // -----------------------------------------
                // cookie settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::acl_lists_t* l_ax_cookie = l_acl->mutable_cookie();
                l_ax_cookie->add_accesslist("bad_[0-9]_key");
                l_ax_cookie->add_accesslist("wonky_key");
                // -----------------------------------------
                // load
                // -----------------------------------------
                l_s = l_profile->load_config(l_pb);
                //NDBG_PRINT("error[%d]: %s\n", l_s, l_profile->get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                if(l_pb) { delete l_pb; l_pb = NULL;}
                void *l_ctx = NULL;
                waflz_pb::event *l_event = NULL;
                ns_waflz::rqst_ctx *l_rqst_ctx = NULL;
                // -----------------------------------------
                // validate accesslist pass
                // -----------------------------------------
                s_header_cookie = "bad_4_key";
                l_event = NULL;
                l_s = l_profile->process_part(&l_event, l_ctx, ns_waflz::PART_MK_ACL, &l_rqst_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // validate accesslist block
                // -----------------------------------------
                s_header_cookie = "bad_x_key";
                l_event = NULL;
                l_s = l_profile->process_part(&l_event, l_ctx, ns_waflz::PART_MK_ACL, &l_rqst_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Accesslist Cookie deny"));
                if(l_event) { delete l_event; l_event = NULL; }
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_profile) { delete l_profile; l_profile = NULL; }
                if(l_pb) { delete l_pb; l_pb = NULL; }
        }
        //--------------------------------------------------
        // accesslist interaction
        // -------------------------------------------------
        SECTION("acl accesslist interaction tests") {
                // -----------------------------------------
                // setup profile
                // -----------------------------------------
                ns_waflz::profile *l_profile = new ns_waflz::profile(*l_engine);
                waflz_pb::profile *l_pb = init_std_profile_pb();
                waflz_pb::acl* l_acl = l_pb->mutable_access_settings();
                // *****************************************
                // -----------------------------------------
                // ip settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::acl_lists_t* l_ax_ipl = l_acl->mutable_ip();
                l_ax_ipl->add_whitelist("20.43.2.5");
                l_ax_ipl->add_whitelist("212.43.2.5");
                l_ax_ipl->add_accesslist("123.43.2.4");
                l_ax_ipl->add_accesslist("212.43.2.0/24");
                l_ax_ipl->add_blacklist("212.43.2.5");
                l_ax_ipl->add_blacklist("212.43.2.10");
                // -----------------------------------------
                // load
                // -----------------------------------------
                l_s = l_profile->load_config(l_pb);
                //NDBG_PRINT("error[%d]: %s\n", l_s, l_profile->get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                if(l_pb) { delete l_pb; l_pb = NULL;}
                void *l_ctx = NULL;
                waflz_pb::event *l_event = NULL;
                ns_waflz::rqst_ctx *l_rqst_ctx = NULL;
                // -----------------------------------------
                // validate whitelist pass
                // -----------------------------------------
                s_ip = "20.43.2.5";
                l_event = NULL;
                l_s = l_profile->process_part(&l_event, l_ctx, ns_waflz::PART_MK_ACL, &l_rqst_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // validate accesslist pass
                // -----------------------------------------
                s_ip = "212.43.2.20";
                l_event = NULL;
                l_s = l_profile->process_part(&l_event, l_ctx, ns_waflz::PART_MK_ACL, &l_rqst_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // validate accesslist pass
                // -----------------------------------------
                s_ip = "123.43.2.4";
                l_event = NULL;
                l_s = l_profile->process_part(&l_event, l_ctx, ns_waflz::PART_MK_ACL, &l_rqst_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // validate accesslist block
                // -----------------------------------------
                s_ip = "100.43.3.5";
                l_event = NULL;
                l_s = l_profile->process_part(&l_event, l_ctx, ns_waflz::PART_MK_ACL, &l_rqst_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Accesslist IP deny"));
                if(l_event) { delete l_event; l_event = NULL; }
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // validate whitelist pass
                // -----------------------------------------
                s_ip = "212.43.2.5";
                l_event = NULL;
                l_s = l_profile->process_part(&l_event, l_ctx, ns_waflz::PART_MK_ACL, &l_rqst_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // validate blacklist block
                // -----------------------------------------
                s_ip = "212.43.2.10";
                l_event = NULL;
                l_s = l_profile->process_part(&l_event, l_ctx, ns_waflz::PART_MK_ACL, &l_rqst_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist IP match"));
                if(l_event) { delete l_event; l_event = NULL; }
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_profile) { delete l_profile; l_profile = NULL; }
                if(l_pb) { delete l_pb; l_pb = NULL; }
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if(l_engine)
        {
                delete l_engine;
                l_engine = NULL;
        }
}
