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
#include "waflz/engine.h"
#include "waflz/acl.h"
#include "waflz/rqst_ctx.h"
#include "waflz/geoip2_mmdb.h"
#include "waflz/def.h"
#include "acl.pb.h"
#include "event.pb.h"
#include "support/ndebug.h"
#include <unistd.h>
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static waflz_pb::acl *init_std_acl_pb(void)
{
        // -----------------------------------------
        // setup...
        // -----------------------------------------
        waflz_pb::acl *l_pb = NULL;
        l_pb = new waflz_pb::acl();
        l_pb->set_id("my_id");
        l_pb->set_name("my_name");
        // -----------------------------------------
        // request properties
        // -----------------------------------------
        l_pb->set_max_file_size(1048576);
        l_pb->add_allowed_http_methods("GET");
        l_pb->add_allowed_request_content_types("html");
        return l_pb;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static const char *s_ip = "156.123.12.7";
static int32_t get_rqst_src_addr_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        *a_data = s_ip;
        *a_len = strlen(s_ip);
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_rqst_line_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        static const char s_line[] = "GET / HTTP/1.1";
        *a_data = s_line;
        *a_len = strlen(s_line);
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static const char *s_uri = "cats.com";
static int32_t get_rqst_uri_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        *a_data = s_uri;
        *a_len = strlen(s_uri);
        return 0;
}
//! ----------------------------------------------------------------------------
//! get_rqst_header_size_cb
//! ----------------------------------------------------------------------------
static int32_t get_rqst_header_size_cb(uint32_t *a_val, void *a_ctx)
{
        *a_val = 8;
        return 0;
}
//! ----------------------------------------------------------------------------
//! s_get_rqst_method_cb
//! ----------------------------------------------------------------------------
static const char *s_method = "GET";
static int32_t get_rqst_method_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        *a_data = s_method;
        *a_len = strlen(s_method);
        return 0;
}
//! ----------------------------------------------------------------------------
//! get_rqst_ja3_md5
//! ----------------------------------------------------------------------------
static const char *s_ja3 = "253714f62c0a1e6869fe8ba6a45a0588";
static int32_t get_rqst_ja3_md5(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        *a_data = s_ja3;
        *a_len = strlen(s_ja3);
        return 0;
}
//! ----------------------------------------------------------------------------
//! get_rqst_header_w_idx_cb
//! ----------------------------------------------------------------------------
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
                                        uint32_t *ao_key_len,
                                        const char **ao_val,
                                        uint32_t *ao_val_len,
                                        void *a_ctx,
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
                if(s_header_content_type)
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
                if(s_header_content_length)
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
                if(s_host)
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
                if(s_test_header)
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
//! acl tests
//! ----------------------------------------------------------------------------
TEST_CASE( "acl test", "[acl]" )
{
        // -------------------------------------------------
        // get ruleset dir
        // IPs used: BR-SP, US-KY, CN-34, JP, IT-52/AR, IN-MP,
        // US-AZ, US-CA, KW, JP-27, US-TX, FR, KR, CN-34
        // -------------------------------------------------
        char l_cwd[1024];
        if(getcwd(l_cwd, sizeof(l_cwd)) != NULL)
        {
                //fprintf(stdout, "Current working dir: %s\n", cwd);
        }
        // -------------------------------------------------
        // geoip
        // -------------------------------------------------
        std::string l_geoip2_city_file = l_cwd;
        std::string l_geoip2_asn_file = l_cwd;
        l_geoip2_city_file += "/../../../../tests/data/waf/db/GeoLite2-City.mmdb";
        //l_geoip2_city_file += "/../tests/data/waf/db/GeoLite2-City.mmdb";
        l_geoip2_asn_file += "/../../../../tests/data/waf/db/GeoLite2-ASN.mmdb";
        //l_geoip2_asn_file += "/../tests/data/waf/db/GeoLite2-ASN.mmdb";
        //--------------------------------------------------
        // acl
        // -------------------------------------------------
        SECTION("acl tests") {
                // -----------------------------------------
                // setup
                // -----------------------------------------
                ns_waflz::engine *l_engine = new ns_waflz::engine();
                l_engine->set_geoip2_dbs(l_geoip2_city_file, l_geoip2_asn_file);
                int32_t l_s;
                l_s = l_engine->init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                ns_waflz::acl *l_acl = new ns_waflz::acl(*l_engine);
                waflz_pb::acl *l_pb = init_std_acl_pb();
                // *****************************************
                // -----------------------------------------
                // ip settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::acl_lists_t* l_ax_ipl = l_pb->mutable_ip();
                l_ax_ipl->add_blacklist("212.43.2.0/16");
                l_ax_ipl->add_blacklist("243.49.2.7");
                l_ax_ipl->add_whitelist("200.162.133.3");
                l_ax_ipl->add_whitelist("199.167.1.0/8");
                l_ax_ipl->add_blacklist("199.167.1.1");
                // *****************************************
                // -----------------------------------------
                // country settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::acl_lists_t* l_ax_ctyl = l_pb->mutable_country();
                l_ax_ctyl->add_blacklist("CN");
                l_ax_ctyl->add_whitelist("JP");
                // *****************************************
                // -----------------------------------------
                // ja3 settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::acl_lists_t* l_ax_ja3 = l_pb->mutable_ja3();
                l_ax_ja3->add_blacklist("13076cd512934b475069096255d1210b");
                l_ax_ja3->add_whitelist("473cd7cb9faa642487833865d516e578");
                // *****************************************
                // -----------------------------------------
                // subdivision settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::acl_lists_t* l_ax_sd_iso_l = l_pb->mutable_sd_iso();
                l_ax_sd_iso_l->add_blacklist("IT-AR");
                l_ax_sd_iso_l->add_whitelist("IN-MP");
                // *****************************************
                // -----------------------------------------
                // asn settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::acl_lists_asn_t* l_ax_asn = l_pb->mutable_asn();
                l_ax_asn->add_blacklist(26496);
                l_ax_asn->add_whitelist(15133);
                // *****************************************
                // -----------------------------------------
                // url settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::acl_lists_t* l_ax_url = l_pb->mutable_url();
                l_ax_url->add_blacklist("/login-confirm/index.html");
                l_ax_url->add_blacklist("\\/banana\\/m.*\\.html");
                l_ax_url->add_whitelist("/chickenkiller/kill_chickenzz.html");
                // *****************************************
                // -----------------------------------------
                // user-agent settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::acl_lists_t* l_ax_ua = l_pb->mutable_user_agent();
                l_ax_ua->add_blacklist("cats are really cool dude");
                l_ax_ua->add_blacklist("curl\\/.*");
                l_ax_ua->add_whitelist("monkeys luv bananas");
                // *****************************************
                // -----------------------------------------
                // referer settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::acl_lists_t* l_ax_refr = l_pb->mutable_referer();
                l_ax_refr->add_blacklist("bad reefer");
                l_ax_refr->add_blacklist("really\\/bad\\/.*");
                l_ax_refr->add_whitelist("monkeys luv referers");
                // *****************************************
                // -----------------------------------------
                // cookie settings
                // -----------------------------------------
                // *****************************************
                ::waflz_pb::acl_lists_t* l_ax_cookie = l_pb->mutable_cookie();
                l_ax_cookie->add_blacklist("bad_[0-9]_key");
                l_ax_cookie->add_blacklist("wonky_key");
                l_ax_cookie->add_blacklist("wonky_value");
                l_ax_cookie->add_whitelist("monkeys_cookie");
                // *****************************************
                // -----------------------------------------
                // method settings
                // -----------------------------------------
                // *****************************************
                l_pb->add_allowed_http_methods("GET");
                l_pb->add_allowed_http_methods("POST");
                l_pb->add_allowed_http_methods("OPTIONS");
                // *****************************************
                // -----------------------------------------
                // content type settings
                // -----------------------------------------
                // *****************************************
                //::waflz_pb::profile_general_settings_t* l_gx_content_type = l_pb->mutable_general_settings()->mutable_allowed_request_content_types();
                l_pb->add_allowed_request_content_types("application/json");
                l_pb->add_allowed_request_content_types("text/xml");
                // -----------------------------------------
                // disallowed_extensions settings
                // -----------------------------------------
                // *****************************************
                //::waflz_pb::profile_general_settings_t* l_gx_dis_ext = l_pb->mutable_general_settings()->mutable_disallowed_extensions();
                l_pb->add_disallowed_extensions(".txt");
                l_pb->add_disallowed_extensions(".php");
                // -----------------------------------------
                // disallowed_headers settings
                // -----------------------------------------
                // *****************************************
                //::waflz_pb::profile_general_settings_t* l_gx_dis_ext = l_pb->mutable_general_settings()->mutable_disallowed_extensions();
                l_pb->add_disallowed_headers("test");
                // -----------------------------------------
                // load
                // -----------------------------------------
                l_s = l_acl->load(l_pb);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                if(l_pb) { delete l_pb; l_pb = NULL;}
                // -----------------------------------------
                // cb
                // -----------------------------------------
                static ns_waflz::rqst_ctx_callbacks s_callbacks = {
                        get_rqst_src_addr_cb,
                        NULL, //get_rqst_host_cb,
                        NULL,
                        NULL,
                        NULL,
                        get_rqst_line_cb,
                        get_rqst_method_cb,
                        NULL,
                        get_rqst_uri_cb,
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
                        NULL, //get_cust_id_cb
                        get_rqst_ja3_md5
                };
                void *l_ctx = NULL;
                waflz_pb::event *l_event = NULL;
                ns_waflz::rqst_ctx *l_rqst_ctx = NULL;
                // *****************************************
                // -----------------------------------------
                //             I P   T E S T
                // -----------------------------------------
                // *****************************************
                // -----------------------------------------
                // validate blacklist
                // -----------------------------------------
                s_ip = "243.49.2.7";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                bool l_wl = false;
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist IP match"));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->ShortDebugString().c_str());
                if(l_event) { delete l_event; l_event = NULL; }
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // validate blacklist cidr
                // -----------------------------------------
                s_ip = "212.43.8.7";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist IP match"));
                if(l_event) { delete l_event; l_event = NULL; }
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // validate whitelist
                // -----------------------------------------
                s_ip = "200.162.133.3";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE(l_wl == true);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // validate whitelist cidr
                // -----------------------------------------
                s_ip = "199.167.1.17";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE(l_wl == true);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // validate whitelist included in blacklist
                // -----------------------------------------
                s_ip = "199.167.1.1";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE(l_wl == true);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // *****************************************
                // -----------------------------------------
                //         C O U N T R Y   T E S T
                // -----------------------------------------
                // *****************************************
                // -----------------------------------------
                // validate blacklist
                // -----------------------------------------
                s_ip = "45.249.212.124";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist Country match"));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate whitelist
                // -----------------------------------------
                s_ip = "202.32.115.5";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // revert
                // -----------------------------------------
                s_ip = "172.217.4.142";
                // *****************************************
                // -----------------------------------------
                //         J A 3   T E S T
                // -----------------------------------------
                // *****************************************
                // -----------------------------------------
                // validate blacklist
                // -----------------------------------------
                s_ja3 = "13076cd512934b475069096255d1210b";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist Ja3 match"));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate whitelist
                // -----------------------------------------
                s_ja3 = "473cd7cb9faa642487833865d516e578";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // reset
                // -----------------------------------------
                s_ja3 = "253714f62c0a1e6869fe8ba6a45a0588";
                // *****************************************
                // -----------------------------------------
                //         S U B D I V I S I O N   T E S T
                // -----------------------------------------
                // *****************************************
                // -----------------------------------------
                // validate blacklist
                // -----------------------------------------
                s_ip = "80.88.90.86";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist Subdivision match"));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate whitelist
                // -----------------------------------------
                s_ip = "27.7.255.255";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // *****************************************
                // -----------------------------------------
                //             A S N   T E S T
                // -----------------------------------------
                // *****************************************
                // -----------------------------------------
                // validate blacklist
                // -----------------------------------------
                s_ip = "160.153.43.133";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist ASN match"));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate whitelist
                // -----------------------------------------
                s_ip = "72.21.92.7";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // revert
                // -----------------------------------------
                s_ip = "172.217.4.142";
                // *****************************************
                // -----------------------------------------
                //            U R L   T E S T
                // -----------------------------------------
                // *****************************************
                // -----------------------------------------
                // validate blacklist
                // -----------------------------------------
                s_uri = "/login-confirm/index.html";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist URL match"));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate blacklist regex
                // -----------------------------------------
                s_uri = "/banana/monkey.html";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist URL match"));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate whitelist
                // -----------------------------------------
                s_uri = "/chickenkiller/kill_chickenzz.html";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // revert
                // -----------------------------------------
                s_uri = "/blabbleblabble/glubble.html";
                // *****************************************
                // -----------------------------------------
                //     U S E R - A G E N T   T E S T
                // -----------------------------------------
                // *****************************************
                // -----------------------------------------
                // -----------------------------------------
                // validate blacklist
                // -----------------------------------------
                s_header_user_agent = "cats are really cool dude";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist User-Agent match"));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate blacklist regex
                // -----------------------------------------
                s_header_user_agent = "curl/7.47.0";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist User-Agent match"));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate whitelist
                // -----------------------------------------
                s_header_user_agent = "monkeys luv bananas";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE(l_wl == true);
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // revert
                // -----------------------------------------
                s_header_user_agent = "my_cool_user_agent";
                // *****************************************
                // -----------------------------------------
                //        R E F E R E R   T E S T
                // -----------------------------------------
                // *****************************************
                // -----------------------------------------
                // validate blacklist
                // -----------------------------------------
                s_header_referer = "bad reefer";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist Referer match"));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate blacklist regex
                // -----------------------------------------
                s_header_referer = "really/bad/reefer";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist Referer match"));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate whitelist
                // -----------------------------------------
                s_header_referer = "monkeys luv referers";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE(l_wl == true);
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // revert
                // -----------------------------------------
                s_header_referer = "my_cool_referer_value";
                // *****************************************
                // -----------------------------------------
                //        C O O K I E   T E S T
                // -----------------------------------------
                // *****************************************
                // -----------------------------------------
                // validate blacklist key
                // -----------------------------------------
                s_header_cookie = "__cookie_a=a_value; wonky_key=b_value; __cookie_c=c_value;";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist Cookie match"));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate blacklist value
                // -----------------------------------------
                s_header_cookie = "__cookie_a=a_value; __cookie_b=wonky_value; __cookie_c=c_value;";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist Cookie match"));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate blacklist regex
                // -----------------------------------------
                s_header_cookie = "__cookie_a=a_value; bad_7_key=b_value; __cookie_c=c_value;";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Blacklist Cookie match"));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate whitelist
                // -----------------------------------------
                s_header_cookie = "__cookie_a=a_value; monkeys_cookie=b_value; __cookie_c=c_value;";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE(l_wl == true);
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // revert
                // -----------------------------------------
                s_header_cookie = "__cookie_a=a_value; __cookie_b=b_value; __cookie_c=c_value;";
                // *****************************************
                // -----------------------------------------
                //        M E T H O D  C H E C K
                // -----------------------------------------
                // *****************************************
                // -----------------------------------------
                // validate block
                // -----------------------------------------
                s_method = "HEAD";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).rule_id() == 80009));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Method is not allowed by policy"));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate allow
                // -----------------------------------------
                s_method = "GET";
                s_host = "www.google.com";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // revert
                // -----------------------------------------
                s_host = NULL;
                // *****************************************
                // -----------------------------------------
                //      C O N T E N T  T Y P E  C H E C K
                // -----------------------------------------
                // *****************************************
                // -----------------------------------------
                // validate block
                // -----------------------------------------
                s_header_content_type = "garbage type";
                s_header_content_length = "120";
                s_method = "POST";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).rule_id() == 80002));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Request content type is not allowed by policy"));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate allow content for GET
                // -----------------------------------------
                s_method = "GET";
                s_host = "www.google.com";
                s_header_content_length = NULL;
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // validate allow content for OPTIONS
                // -----------------------------------------
                s_method = "OPTIONS";
                s_host = "www.google.com";
                s_header_content_length = NULL;
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // revert
                // -----------------------------------------
                s_host = NULL;
                s_method = "GET";
                s_header_content_type = NULL;
                s_header_content_length = NULL;
                // *****************************************
                // -----------------------------------------
                //      F I L E  E X T  C H E C K
                // -----------------------------------------
                // *****************************************
                // -----------------------------------------
                // validate block
                // -----------------------------------------
                s_uri = "my/path/is/abc.def.php";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).rule_id() == 80005));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "File extension is not allowed by policy"));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate allow
                // -----------------------------------------
                s_host = "www.google.com";
                s_uri = "my/path/is/abc.html";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                REQUIRE((l_event == NULL));
                // -----------------------------------------
                // revert
                // -----------------------------------------
                s_host = NULL;
                s_method = "GET";
                // *****************************************
                // -----------------------------------------
                //      F I L E  S I Z E  C H E C K
                // -----------------------------------------
                // *****************************************
                // -----------------------------------------
                // validate block
                // -----------------------------------------
                s_header_content_type = "text/xml";
                s_host = "www.google.com";
                s_method = "POST";
                s_header_content_length = "1048577";
                NDBG_PRINT("FILE SIZE CHECK TEST\n");
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                //if(l_event) NDBG_PRINT("event: %s\n", l_event->DebugString().c_str());
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).rule_id() == 80006));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Uploaded file size too large"));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate allow
                // -----------------------------------------
                s_header_content_type = "text/xml";
                s_header_content_length = "120";
                s_host = "www.google.com";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // revert
                // -----------------------------------------
                s_host = NULL;
                s_method = "GET";
                s_header_content_length = NULL;
                // *****************************************
                // -----------------------------------------
                //      HEADER  C H E C K
                // -----------------------------------------
                // *****************************************
                // -----------------------------------------
                // validate block
                // -----------------------------------------
                s_test_header = "test";
                s_host = "www.google.com";
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).rule_id() == 80007));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Request header is not allowed by policy"));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // validate allow
                // -----------------------------------------
                s_method = "GET";
                s_host = "www.google.com";
                s_test_header = NULL;
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                // -----------------------------------------
                // revert
                // -----------------------------------------
                s_host = NULL;
                s_method = "GET";
                s_header_content_length = NULL;
                // *****************************************
                // -----------------------------------------
                //      allow_anon  C H E C K
                // -----------------------------------------
                // *****************************************
                // -----------------------------------------
                // validate block
                // -----------------------------------------
                s_method = "GET";
                s_host = "www.google.com";
                s_test_header = NULL;
                l_rqst_ctx = new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, &s_callbacks);
                // -----------------------------------------
                // fake proxy but allow anony
                // -----------------------------------------
                l_rqst_ctx->m_geo_data.m_is_anonymous_proxy = true;
                // l_acl->set_allow_anonymous_proxy(true);
                // -----------------------------------------
                // validate block
                // -----------------------------------------
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event == NULL));
                // -----------------------------------------
                // now dont allow
                // -----------------------------------------
                l_rqst_ctx->m_geo_data.m_is_anonymous_proxy = true;
                l_acl->set_allow_anonymous_proxy(false);
                // -----------------------------------------
                // validate block
                // -----------------------------------------
                l_s = l_acl->process(&l_event, l_wl, l_ctx, &l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_event != NULL));
                REQUIRE((l_event->sub_event_size() >= 1));
                REQUIRE((l_event->sub_event(0).rule_id() == 80014));
                REQUIRE((l_event->sub_event(0).has_rule_msg()));
                REQUIRE((l_event->sub_event(0).rule_msg() == "Anonymous Proxy not allowed"));
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                if(l_event) { delete l_event; l_event = NULL; }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                l_acl->set_allow_anonymous_proxy(true);
                if(l_acl)
                {
                        delete l_acl;
                        l_acl = NULL;
                }
                if(l_pb)
                {
                        delete l_pb;
                        l_pb = NULL;
                }
                if(l_engine)
                {
                        delete l_engine;
                        l_engine = NULL;
                }
        }
}
