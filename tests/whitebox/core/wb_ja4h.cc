//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    wb_ja4h.cc
//! \details: white box tests for ja4h verification
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "waflz/rqst_ctx.h"
#include "waflz/engine.h"
#include "waflz/trace.h"
#include "event.pb.h"
#include <unistd.h>
//! ----------------------------------------------------------------------------
//! callbacks
//! ----------------------------------------------------------------------------
static int32_t get_rqst_header_size_cb(uint32_t* a_val, void* a_ctx)
{
        *a_val = 13;
        return 0;
}
static int32_t get_rqst_header_size_cb_2(uint32_t* a_val, void* a_ctx)
{
        *a_val = 9;
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_rqst_method_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        static const char s_line[] = "GET";
        *a_data = s_line;
        *a_len = strlen(s_line);
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_rqst_scheme_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        static const char s_line[] = "https";
        *a_data = s_line;
        *a_len = strlen(s_line);
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_rqst_protocol_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        static const char s_line[] = "1.1";
        *a_data = s_line;
        *a_len = strlen(s_line);
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_rqst_protocol_cb_1(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        static const char s_line[] = "1";
        *a_data = s_line;
        *a_len = strlen(s_line);
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_rqst_protocol_cb_2(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        static const char s_line[] = "2.0";
        *a_data = s_line;
        *a_len = strlen(s_line);
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_rqst_host_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        static const char s_line[] = "www.cnn.com";
        *a_data = s_line;
        *a_len = strlen(s_line);
        return 0;
}

static const char* s_host = "www.cnn.com";
static const char* s_header_cookie = "FastAB=0=6859,1=8174,2=4183,3=3319,4=3917,5=2557,6=4259,7=6070,8=0804,9=6453,10=1942,11=4435,12=4143,13=9445,14=6957,15=8682,16=1885,17=1825,18=3760,19=0929; sato=1; countryCode=US; stateCode=VA; geoData=purcellville|VA|20132|US|NA|-400|broadband|39.160|-77.700|511; usprivacy=1---; umto=1; _dd_s=logs=1&id=b5c2d770-eaba-4847-8202-390c4552ff9a&created=1686159462724&expire=1686160422726;";
static const char* s_test_header_1 = "Sec-Ch-Ua";
static const char* s_test_header_1_val = "";
static const char* s_test_header_2 = "Sec-Ch-Ua-Mobile";
static const char* s_test_header_2_val = "?0";
static const char* s_header_user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.110 Safari/537.36\r\n";
static const char* s_test_header_3 = "Sec-Ch-Ua-Platform";
static const char* s_test_header_3_val = "\"\"";
static const char* s_header_accept = "*/*";
static const char* s_test_header_4 = "Sec-Fetch-Site";
static const char* s_test_header_4_val = "same-origin";
static const char* s_test_header_5 = "Sec-Fetch-Mode";
static const char* s_test_header_5_val = "cors";
static const char* s_test_header_6 = "Sec-Fetch-Dest";
static const char* s_test_header_6_val = "empty";
static const char* s_header_referer = "https://www.cnn.com/";
static const char* s_test_header_7 = "Accept-Encoding";
static const char* s_test_header_7_val = "gzip, deflate";
static const char* s_test_header_8 = "Accept-Language";
static const char* s_test_header_8_val = "en-US,en;q=0.9";

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
                if (s_host)
                {
                        *ao_key = "Host";
                        *ao_key_len = strlen("Host");
                        *ao_val = s_host;
                        *ao_val_len = strlen(s_host);
                }
                break;
        }
        case 1:
        {
                *ao_key = "Cookie";
                *ao_key_len = strlen("Cookie");
                *ao_val = s_header_cookie;
                *ao_val_len = strlen(s_header_cookie);
                break;
        }
        case 2:
        {
                 if (s_test_header_1)
                {
                        *ao_key = s_test_header_1;
                        *ao_key_len = strlen(s_test_header_1);
                        *ao_val = s_test_header_1_val;
                        *ao_val_len = strlen(s_test_header_1_val);
                }
                break;
        }
        case 3:
        {
                if (s_test_header_2)
                {
                        *ao_key = s_test_header_2;
                        *ao_key_len = strlen(s_test_header_2);
                        *ao_val = s_test_header_2_val;
                        *ao_val_len = strlen(s_test_header_2_val);
                }
                break;
        }
        case 4:
        {
                *ao_key = "User-Agent";
                *ao_key_len = strlen("User-Agent");
                *ao_val = s_header_user_agent;
                *ao_val_len = strlen(s_header_user_agent);
                break;
        }
        case 5:
        {
               if (s_test_header_3)
                {
                        *ao_key = s_test_header_3;
                        *ao_key_len = strlen(s_test_header_3);
                        *ao_val = s_test_header_3_val;
                        *ao_val_len = strlen(s_test_header_3_val);
                }
                break;
        }
        case 6:
        {
                *ao_key = "Accept";
                *ao_key_len = strlen("Accept");
                *ao_val = s_header_accept;
                *ao_val_len = strlen(s_header_accept);
                break;
        }
        case 7:
        {
                if (s_test_header_4)
                {
                        *ao_key = s_test_header_4;
                        *ao_key_len = strlen(s_test_header_4);
                        *ao_val = s_test_header_4_val;
                        *ao_val_len = strlen(s_test_header_4_val);
                }
                break;
        }
        case 8:
        {
               if (s_test_header_5)
                {
                        *ao_key = s_test_header_5;
                        *ao_key_len = strlen(s_test_header_5);
                        *ao_val = s_test_header_5_val;
                        *ao_val_len = strlen(s_test_header_5_val);
                }
                break;
        }
        case 9:
        {
                if (s_test_header_6)
                {
                        *ao_key = s_test_header_6;
                        *ao_key_len = strlen(s_test_header_6);
                        *ao_val = s_test_header_6_val;
                        *ao_val_len = strlen(s_test_header_6_val);
                }
                break;
        }
        case 10:
        {
                *ao_key = "Referer";
                *ao_key_len = strlen("Referer");
                *ao_val = s_header_referer;
                *ao_val_len = strlen(s_header_referer);
                break;
        }
        case 11:
        {
                if (s_test_header_7)
                {
                        *ao_key = s_test_header_7;
                        *ao_key_len = strlen(s_test_header_7);
                        *ao_val = s_test_header_7_val;
                        *ao_val_len = strlen(s_test_header_7_val);
                }
                break;
        }
        case 12:
        {
               if (s_test_header_8)
                {
                        *ao_key = s_test_header_8;
                        *ao_key_len = strlen(s_test_header_8);
                        *ao_val = s_test_header_8_val;
                        *ao_val_len = strlen(s_test_header_8_val);
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

TEST_CASE(  "ja4h verification test", "[ja4h]" ) {
        static ns_waflz::rqst_ctx_callbacks s_callbacks = {
                NULL, //get_rqst_src_addr_cb,
                get_rqst_host_cb,
                NULL, //get_rqst_port_cb,
                get_rqst_scheme_cb,
                get_rqst_protocol_cb,
                NULL, //get_rqst_line_cb,
                get_rqst_method_cb,
                NULL, //get_rqst_url_cb,
                NULL, //get_rqst_uri_cb,
                NULL, //get_rqst_path_cb,
                NULL, //get_rqst_query_str_cb,
                get_rqst_header_size_cb,
                NULL, //get_rqst_header_w_key_cb,
                get_rqst_header_w_idx_cb,
                NULL, //get_rqst_body_str_cb,
                NULL, //get_rqst_local_addr_cb,
                NULL, //get_rqst_canonical_port_cb,
                NULL, //get_rqst_apparent_cache_status_cb,
                NULL, //get_rqst_bytes_out_cb,
                NULL, //get_rqst_bytes_in_cb,
                NULL, //get_rqst_uuid_cb,
                NULL //get_cust_id_cb
        };
        // -------------------------------------------------
        // verify engine loading
        // -------------------------------------------------
        ns_waflz::engine *l_engine = new ns_waflz::engine();
        int32_t l_s;
        l_s = l_engine->init();
        REQUIRE((l_s == WAFLZ_STATUS_OK));
        ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, &s_callbacks, true, true);
        // -------------------------------------------------
        // calling init_phase_1 should generate a ja4h 
        // -------------------------------------------------
        l_rqst_ctx->init_phase_1(*l_engine);
        char l_cwd[1024];
        if(getcwd(l_cwd, sizeof(l_cwd)) != NULL)
        {
                //fprintf(stdout, "Current working dir: %s\n", cwd);
        }
        //NDBG_PRINT("%s:\n", l_rqst_ctx->m_virt_ssl_client_ja4h.c_str());
        REQUIRE((l_rqst_ctx->m_virt_ssl_client_ja4h.length() > 0));
        REQUIRE(strncmp(l_rqst_ctx->m_virt_ssl_client_ja4h.c_str(),"ge11cr11enus_974ebe531c03_0f2659b474bf_161698816dab", l_rqst_ctx->m_virt_ssl_client_ja4h.length())==0);
        // -----------------------------------------
        // cleanup
        // -----------------------------------------
        if(l_engine) { delete l_engine; l_engine = NULL; }
        if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
}

TEST_CASE(  "ja4h verification test no accept lang", "[ja4h_no_accept_lang]" ) {
        s_test_header_8 = "";
        s_test_header_8_val = "";
        static ns_waflz::rqst_ctx_callbacks s_callbacks = {
                NULL, //get_rqst_src_addr_cb,
                get_rqst_host_cb,
                NULL, //get_rqst_port_cb,
                get_rqst_scheme_cb,
                get_rqst_protocol_cb,
                NULL, //get_rqst_line_cb,
                get_rqst_method_cb,
                NULL, //get_rqst_url_cb,
                NULL, //get_rqst_uri_cb,
                NULL, //get_rqst_path_cb,
                NULL, //get_rqst_query_str_cb,
                get_rqst_header_size_cb,
                NULL, //get_rqst_header_w_key_cb,
                get_rqst_header_w_idx_cb,
                NULL, //get_rqst_body_str_cb,
                NULL, //get_rqst_local_addr_cb,
                NULL, //get_rqst_canonical_port_cb,
                NULL, //get_rqst_apparent_cache_status_cb,
                NULL, //get_rqst_bytes_out_cb,
                NULL, //get_rqst_bytes_in_cb,
                NULL, //get_rqst_uuid_cb,
                NULL //get_cust_id_cb
        };
        // -------------------------------------------------
        // verify engine loading
        // -------------------------------------------------
        ns_waflz::engine *l_engine = new ns_waflz::engine();
        int32_t l_s;
        l_s = l_engine->init();
        REQUIRE((l_s == WAFLZ_STATUS_OK));
        ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, &s_callbacks, true, true);
        // -------------------------------------------------
        // calling init_phase_1 should generate a ja4h 
        // -------------------------------------------------
        l_rqst_ctx->init_phase_1(*l_engine);
        char l_cwd[1024];
        if(getcwd(l_cwd, sizeof(l_cwd)) != NULL)
        {
                //fprintf(stdout, "Current working dir: %s\n", cwd);
        }
        //NDBG_PRINT("%s:\n", l_rqst_ctx->m_virt_ssl_client_ja4h.c_str());
        REQUIRE((l_rqst_ctx->m_virt_ssl_client_ja4h.length() == 51));
        REQUIRE(strncmp(l_rqst_ctx->m_virt_ssl_client_ja4h.c_str(),"ge11cr110000_5c1185612b7b_0f2659b474bf_161698816dab", l_rqst_ctx->m_virt_ssl_client_ja4h.length())==0);
        // -----------------------------------------
        // cleanup
        // -----------------------------------------
        if(l_engine) { delete l_engine; l_engine = NULL; }
        if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
}

TEST_CASE(  "ja4h verification test no cookies", "[ja4h_no_cookies]" ) {
        s_header_cookie = "";
        static ns_waflz::rqst_ctx_callbacks s_callbacks = {
                NULL, //get_rqst_src_addr_cb,
                get_rqst_host_cb,
                NULL, //get_rqst_port_cb,
                get_rqst_scheme_cb,
                get_rqst_protocol_cb,
                NULL, //get_rqst_line_cb,
                get_rqst_method_cb,
                NULL, //get_rqst_url_cb,
                NULL, //get_rqst_uri_cb,
                NULL, //get_rqst_path_cb,
                NULL, //get_rqst_query_str_cb,
                get_rqst_header_size_cb,
                NULL, //get_rqst_header_w_key_cb,
                get_rqst_header_w_idx_cb,
                NULL, //get_rqst_body_str_cb,
                NULL, //get_rqst_local_addr_cb,
                NULL, //get_rqst_canonical_port_cb,
                NULL, //get_rqst_apparent_cache_status_cb,
                NULL, //get_rqst_bytes_out_cb,
                NULL, //get_rqst_bytes_in_cb,
                NULL, //get_rqst_uuid_cb,
                NULL //get_cust_id_cb
        };
        // -------------------------------------------------
        // verify engine loading
        // -------------------------------------------------
        ns_waflz::engine *l_engine = new ns_waflz::engine();
        int32_t l_s;
        l_s = l_engine->init();
        REQUIRE((l_s == WAFLZ_STATUS_OK));
        ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, &s_callbacks, true, true);
        // -------------------------------------------------
        // calling init_phase_1 should generate a ja4h 
        // -------------------------------------------------
        l_rqst_ctx->init_phase_1(*l_engine);
        char l_cwd[1024];
        if(getcwd(l_cwd, sizeof(l_cwd)) != NULL)
        {
                //fprintf(stdout, "Current working dir: %s\n", cwd);
        }
        //NDBG_PRINT("%s:\n", l_rqst_ctx->m_virt_ssl_client_ja4h.c_str());
        REQUIRE((l_rqst_ctx->m_virt_ssl_client_ja4h.length() == 51));
        REQUIRE(strncmp(l_rqst_ctx->m_virt_ssl_client_ja4h.c_str(),"ge11nr110000_5c1185612b7b_000000000000_000000000000", l_rqst_ctx->m_virt_ssl_client_ja4h.length())==0);
        // -----------------------------------------
        // cleanup
        // -----------------------------------------
        if(l_engine) { delete l_engine; l_engine = NULL; }
        if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
}

TEST_CASE(  "ja4h verification test req header size", "[ja4h_req_header_size]" ) {
        s_header_cookie = "";
        static ns_waflz::rqst_ctx_callbacks s_callbacks = {
                NULL, //get_rqst_src_addr_cb,
                get_rqst_host_cb,
                NULL, //get_rqst_port_cb,
                get_rqst_scheme_cb,
                get_rqst_protocol_cb,
                NULL, //get_rqst_line_cb,
                get_rqst_method_cb,
                NULL, //get_rqst_url_cb,
                NULL, //get_rqst_uri_cb,
                NULL, //get_rqst_path_cb,
                NULL, //get_rqst_query_str_cb,
                get_rqst_header_size_cb_2,
                NULL, //get_rqst_header_w_key_cb,
                get_rqst_header_w_idx_cb,
                NULL, //get_rqst_body_str_cb,
                NULL, //get_rqst_local_addr_cb,
                NULL, //get_rqst_canonical_port_cb,
                NULL, //get_rqst_apparent_cache_status_cb,
                NULL, //get_rqst_bytes_out_cb,
                NULL, //get_rqst_bytes_in_cb,
                NULL, //get_rqst_uuid_cb,
                NULL //get_cust_id_cb
        };
        // -------------------------------------------------
        // verify engine loading
        // -------------------------------------------------
        ns_waflz::engine *l_engine = new ns_waflz::engine();
        int32_t l_s;
        l_s = l_engine->init();
        REQUIRE((l_s == WAFLZ_STATUS_OK));
        ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, &s_callbacks, true, true);
        // -------------------------------------------------
        // calling init_phase_1 should generate a ja4h 
        // -------------------------------------------------
        l_rqst_ctx->init_phase_1(*l_engine);
        char l_cwd[1024];
        if(getcwd(l_cwd, sizeof(l_cwd)) != NULL)
        {
                //fprintf(stdout, "Current working dir: %s\n", cwd);
        }
        REQUIRE((l_rqst_ctx->m_virt_ssl_client_ja4h.length() == 51));
        REQUIRE(strncmp(l_rqst_ctx->m_virt_ssl_client_ja4h.c_str(),"ge11nn080000_f3d52f9db338_000000000000_000000000000", l_rqst_ctx->m_virt_ssl_client_ja4h.length())==0);
        // -----------------------------------------
        // cleanup
        // -----------------------------------------
        if(l_engine) { delete l_engine; l_engine = NULL; }
        if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
}

TEST_CASE(  "ja4h verification verify protocol 1", "[ja4h_verify_protocol_1]" ) {
        s_header_cookie = "";
        static ns_waflz::rqst_ctx_callbacks s_callbacks = {
                NULL, //get_rqst_src_addr_cb,
                get_rqst_host_cb,
                NULL, //get_rqst_port_cb,
                get_rqst_scheme_cb,
                get_rqst_protocol_cb_1,
                NULL, //get_rqst_line_cb,
                get_rqst_method_cb,
                NULL, //get_rqst_url_cb,
                NULL, //get_rqst_uri_cb,
                NULL, //get_rqst_path_cb,
                NULL, //get_rqst_query_str_cb,
                get_rqst_header_size_cb,
                NULL, //get_rqst_header_w_key_cb,
                get_rqst_header_w_idx_cb,
                NULL, //get_rqst_body_str_cb,
                NULL, //get_rqst_local_addr_cb,
                NULL, //get_rqst_canonical_port_cb,
                NULL, //get_rqst_apparent_cache_status_cb,
                NULL, //get_rqst_bytes_out_cb,
                NULL, //get_rqst_bytes_in_cb,
                NULL, //get_rqst_uuid_cb,
                NULL //get_cust_id_cb
        };
        // -------------------------------------------------
        // verify engine loading
        // -------------------------------------------------
        ns_waflz::engine *l_engine = new ns_waflz::engine();
        int32_t l_s;
        l_s = l_engine->init();
        REQUIRE((l_s == WAFLZ_STATUS_OK));
        ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, &s_callbacks, true, true);
        // -------------------------------------------------
        // calling init_phase_1 should generate a ja4h 
        // -------------------------------------------------
        l_rqst_ctx->init_phase_1(*l_engine);
        char l_cwd[1024];
        if(getcwd(l_cwd, sizeof(l_cwd)) != NULL)
        {
                //fprintf(stdout, "Current working dir: %s\n", cwd);
        }
        REQUIRE((l_rqst_ctx->m_virt_ssl_client_ja4h.length() == 51));
        REQUIRE(strncmp(l_rqst_ctx->m_virt_ssl_client_ja4h.c_str(),"ge10nr110000_5c1185612b7b_000000000000_000000000000", l_rqst_ctx->m_virt_ssl_client_ja4h.length())==0);
        // -----------------------------------------
        // cleanup
        // -----------------------------------------
        if(l_engine) { delete l_engine; l_engine = NULL; }
        if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
}

TEST_CASE(  "ja4h verification verify protocol 2", "[ja4h_verify_protocol_2]" ) {
        s_header_cookie = "";
        static ns_waflz::rqst_ctx_callbacks s_callbacks = {
                NULL, //get_rqst_src_addr_cb,
                get_rqst_host_cb,
                NULL, //get_rqst_port_cb,
                get_rqst_scheme_cb,
                get_rqst_protocol_cb_2,
                NULL, //get_rqst_line_cb,
                get_rqst_method_cb,
                NULL, //get_rqst_url_cb,
                NULL, //get_rqst_uri_cb,
                NULL, //get_rqst_path_cb,
                NULL, //get_rqst_query_str_cb,
                get_rqst_header_size_cb,
                NULL, //get_rqst_header_w_key_cb,
                get_rqst_header_w_idx_cb,
                NULL, //get_rqst_body_str_cb,
                NULL, //get_rqst_local_addr_cb,
                NULL, //get_rqst_canonical_port_cb,
                NULL, //get_rqst_apparent_cache_status_cb,
                NULL, //get_rqst_bytes_out_cb,
                NULL, //get_rqst_bytes_in_cb,
                NULL, //get_rqst_uuid_cb,
                NULL //get_cust_id_cb
        };
        // -------------------------------------------------
        // verify engine loading
        // -------------------------------------------------
        ns_waflz::engine *l_engine = new ns_waflz::engine();
        int32_t l_s;
        l_s = l_engine->init();
        REQUIRE((l_s == WAFLZ_STATUS_OK));
        ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, &s_callbacks, true, true);
        // -------------------------------------------------
        // calling init_phase_1 should generate a ja4h 
        // -------------------------------------------------
        l_rqst_ctx->init_phase_1(*l_engine);
        char l_cwd[1024];
        if(getcwd(l_cwd, sizeof(l_cwd)) != NULL)
        {
                //fprintf(stdout, "Current working dir: %s\n", cwd);
        }
        REQUIRE((l_rqst_ctx->m_virt_ssl_client_ja4h.length() == 51));
        REQUIRE(strncmp(l_rqst_ctx->m_virt_ssl_client_ja4h.c_str(),"ge20nr110000_5c1185612b7b_000000000000_000000000000", l_rqst_ctx->m_virt_ssl_client_ja4h.length())==0);
        // -----------------------------------------
        // cleanup
        // -----------------------------------------
        if(l_engine) { delete l_engine; l_engine = NULL; }
        if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
}

TEST_CASE(  "ja4h verification verify accept lang truncated", "[ja4h_verify_accept_lang_trunc]" ) {
        s_test_header_8 = "Accept-Language";
        s_test_header_8_val = "en,";
        static ns_waflz::rqst_ctx_callbacks s_callbacks = {
                NULL, //get_rqst_src_addr_cb,
                get_rqst_host_cb,
                NULL, //get_rqst_port_cb,
                get_rqst_scheme_cb,
                get_rqst_protocol_cb,
                NULL, //get_rqst_line_cb,
                get_rqst_method_cb,
                NULL, //get_rqst_url_cb,
                NULL, //get_rqst_uri_cb,
                NULL, //get_rqst_path_cb,
                NULL, //get_rqst_query_str_cb,
                get_rqst_header_size_cb,
                NULL, //get_rqst_header_w_key_cb,
                get_rqst_header_w_idx_cb,
                NULL, //get_rqst_body_str_cb,
                NULL, //get_rqst_local_addr_cb,
                NULL, //get_rqst_canonical_port_cb,
                NULL, //get_rqst_apparent_cache_status_cb,
                NULL, //get_rqst_bytes_out_cb,
                NULL, //get_rqst_bytes_in_cb,
                NULL, //get_rqst_uuid_cb,
                NULL //get_cust_id_cb
        };
        // -------------------------------------------------
        // verify engine loading
        // -------------------------------------------------
        ns_waflz::engine *l_engine = new ns_waflz::engine();
        int32_t l_s;
        l_s = l_engine->init();
        REQUIRE((l_s == WAFLZ_STATUS_OK));
        ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, &s_callbacks, true, true);
        // -------------------------------------------------
        // calling init_phase_1 should generate a ja4h 
        // -------------------------------------------------
        l_rqst_ctx->init_phase_1(*l_engine);
        char l_cwd[1024];
        if(getcwd(l_cwd, sizeof(l_cwd)) != NULL)
        {
                //fprintf(stdout, "Current working dir: %s\n", cwd);
        }
        //NDBG_PRINT("%s:\n", l_rqst_ctx->m_virt_ssl_client_ja4h.c_str());
        REQUIRE((l_rqst_ctx->m_virt_ssl_client_ja4h.length() == 51));
        REQUIRE(strncmp(l_rqst_ctx->m_virt_ssl_client_ja4h.c_str(),"ge11nr11en00_974ebe531c03_000000000000_000000000000", l_rqst_ctx->m_virt_ssl_client_ja4h.length())==0);
        // -----------------------------------------
        // cleanup
        // -----------------------------------------
        if(l_engine) { delete l_engine; l_engine = NULL; }
        if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
}

// NOTE: semi-colon is a part of ja4h accept-language as per spec
TEST_CASE(  "ja4h verification verify accept lang extra char", "[ja4h_verify_accept_lang_trunc_extra_char]" ) {
        s_test_header_8 = "Accept-Language";
        s_test_header_8_val = "en;,";
        static ns_waflz::rqst_ctx_callbacks s_callbacks = {
                NULL, //get_rqst_src_addr_cb,
                get_rqst_host_cb,
                NULL, //get_rqst_port_cb,
                get_rqst_scheme_cb,
                get_rqst_protocol_cb,
                NULL, //get_rqst_line_cb,
                get_rqst_method_cb,
                NULL, //get_rqst_url_cb,
                NULL, //get_rqst_uri_cb,
                NULL, //get_rqst_path_cb,
                NULL, //get_rqst_query_str_cb,
                get_rqst_header_size_cb,
                NULL, //get_rqst_header_w_key_cb,
                get_rqst_header_w_idx_cb,
                NULL, //get_rqst_body_str_cb,
                NULL, //get_rqst_local_addr_cb,
                NULL, //get_rqst_canonical_port_cb,
                NULL, //get_rqst_apparent_cache_status_cb,
                NULL, //get_rqst_bytes_out_cb,
                NULL, //get_rqst_bytes_in_cb,
                NULL, //get_rqst_uuid_cb,
                NULL //get_cust_id_cb
        };
        // -------------------------------------------------
        // verify engine loading
        // -------------------------------------------------
        ns_waflz::engine *l_engine = new ns_waflz::engine();
        int32_t l_s;
        l_s = l_engine->init();
        REQUIRE((l_s == WAFLZ_STATUS_OK));
        ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, &s_callbacks, true, true);
        // -------------------------------------------------
        // calling init_phase_1 should generate a ja4h 
        // -------------------------------------------------
        l_rqst_ctx->init_phase_1(*l_engine);
        char l_cwd[1024];
        if(getcwd(l_cwd, sizeof(l_cwd)) != NULL)
        {
                //fprintf(stdout, "Current working dir: %s\n", cwd);
        }
        //NDBG_PRINT("%s:\n", l_rqst_ctx->m_virt_ssl_client_ja4h.c_str());
        REQUIRE((l_rqst_ctx->m_virt_ssl_client_ja4h.length() == 51));
        REQUIRE(strncmp(l_rqst_ctx->m_virt_ssl_client_ja4h.c_str(),"ge11nr11en;0_974ebe531c03_000000000000_000000000000", l_rqst_ctx->m_virt_ssl_client_ja4h.length())==0);
        // -----------------------------------------
        // cleanup
        // -----------------------------------------
        if(l_engine) { delete l_engine; l_engine = NULL; }
        if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
}
