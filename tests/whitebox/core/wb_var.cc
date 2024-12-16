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
#include "waflz/engine.h"
#include "waflz/rqst_ctx.h"
#include "waflz/geoip2_mmdb.h"
#include "core/var.h"
#include "support/ndebug.h"
#include <string.h>
#include <unistd.h>
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_rqst_src_addr_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        static const char s_ip[] = "172.217.5.206";
        *a_data = s_ip;
        *a_len = strlen(s_ip);
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_rqst_url_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        static const char s_line[] = "bananas.com/800050/origin.testsuite.com/sec_arg_check/info.html?you=crazy&screws=loose";
        *a_data = s_line;
        *a_len = strlen(s_line);
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_rqst_line_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        static const char s_line[] = "GET /800050/origin.testsuite.com/sec_arg_check/info.html?you=crazy&screws=loose HTTP/1.1";
        *a_data = s_line;
        *a_len = strlen(s_line);
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_rqst_method_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        static const char s_line[] = "GETZ";
        *a_data = s_line;
        *a_len = strlen(s_line);
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_rqst_protocol_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        static const char s_line[] = "HTTP/1.1";
        *a_data = s_line;
        *a_len = strlen(s_line);
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_rqst_scheme_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        static const char s_line[] = "http";
        *a_data = s_line;
        *a_len = strlen(s_line);
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_rqst_port_cb(uint32_t *a_val, void *a_ctx)
{
        *a_val = 80;
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_rqst_uri_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        static const char s_line[] = "/800050/origin.testsuite.com/sec_arg_check/info.html?you=crazy&screws=loose";
        *a_data = s_line;
        *a_len = strlen(s_line);
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_rqst_path_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        static const char s_line[] = "/800050/origin.testsuite.com/sec_arg_check/info.html";
        *a_data = s_line;
        *a_len = strlen(s_line);
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_rqst_query_str_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        static const char s_line[] = "you=crazy&screws=loose";
        *a_data = s_line;
        *a_len = strlen(s_line);
        return 0;
}
//! ----------------------------------------------------------------------------
//! get_rqst_body_str_cb
//! ----------------------------------------------------------------------------
#define _RQST_BODY_JSON "{\"monkeys\": \"bananas\", \"koalas\": \"fruitloops\", \"seamonkeys\": \"plankton\"}"
#define _RQST_BODY_XML "<monkeys><gorilla>coco</gorilla><mandrill>dooby</mandrill><baboon>groovy</baboon></monkeys>"
static const char *g_body_str = _RQST_BODY_JSON;
static int32_t get_rqst_body_str_cb(char *ao_data,
                                    uint32_t *ao_data_len,
                                    bool *ao_is_eos,
                                    void *a_ctx,
                                    uint32_t a_to_read)
{
        *ao_data_len = strlen(g_body_str);
        memcpy(ao_data, g_body_str, *ao_data_len);
        *ao_is_eos = true;
        return 0;
}
//! ----------------------------------------------------------------------------
//! get_rqst_header_size_cb
//! ----------------------------------------------------------------------------
static int32_t get_rqst_header_size_cb(uint32_t *a_val, void *a_ctx)
{
        *a_val = 7;
        return 0;
}
//! ----------------------------------------------------------------------------
//! get_rqst_header_w_idx_cb
//! ----------------------------------------------------------------------------
static const char *g_header_user_agent = "my_cool_user_agent";
static const char *g_header_accept = "my_cool_accept_value";
static const char *g_header_referer = "my_cool_referer_value";
static const char *g_header_cookie = "__cookie_a=a_value; __cookie_b=b_value; __cookie_c=c_value;";
static const char *s_xff_header = "X-Forwarded-For";
static const char *s_xff_ip = "104.10.167.54, 127.0.0.1, 172.217.5.206";

#define _RQST_CONTENT_TYPE_JSON "application/json"
#define _RQST_CONTENT_TYPE_XML "text/xml"
#define _RQST_CONTENT_TYPE_URL_ENCODED "application/x-www-form-urlencoded"
static const char *g_header_content_type = _RQST_CONTENT_TYPE_JSON;
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
        static char s_cl[16];
        switch(a_idx)
        {
        case 0:
        {
                *ao_key = "User-Agent";
                *ao_key_len = strlen("User-Agent");
                *ao_val = g_header_user_agent;
                *ao_val_len = strlen(g_header_user_agent);
                break;
        }
        case 1:
        {
                *ao_key = "Accept";
                *ao_key_len = strlen("Accept");
                *ao_val = g_header_accept;
                *ao_val_len = strlen(g_header_accept);
                break;
        }
        case 2:
        {
                *ao_key = "Referer";
                *ao_key_len = strlen("Referer");
                *ao_val = g_header_referer;
                *ao_val_len = strlen(g_header_referer);
                break;
        }
        case 3:
        {
                *ao_key = "Cookie";
                *ao_key_len = strlen("Cookie");
                *ao_val = g_header_cookie;
                *ao_val_len = strlen(g_header_cookie);
                break;
        }
        case 4:
        {
                *ao_key = "Content-Type";
                *ao_key_len = strlen("Content-Type");
                *ao_val = g_header_content_type;
                *ao_val_len = strlen(g_header_content_type);
                break;
        }
        case 5:
        {
                *ao_key = "Content-Length";
                *ao_key_len = strlen("Content-Length");
                snprintf(s_cl, 16, "%d", (int)strlen(g_body_str));
                *ao_val = s_cl;
                *ao_val_len = strlen(s_cl);
                break;
        }
        case 6:
        {
                if(s_xff_header)
                {
                        *ao_key = s_xff_header;
                        *ao_key_len = strlen(s_xff_header);
                        *ao_val = s_xff_ip;
                        *ao_val_len = strlen(s_xff_ip);
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
//! parse
//! ----------------------------------------------------------------------------
TEST_CASE( "test var", "[var]" ) {
        ns_waflz::geoip2_mmdb l_geoip2_mmdb;
        ns_waflz::init_var_cb_vector();
        
        static ns_waflz::rqst_ctx_callbacks s_callbacks = {
                get_rqst_src_addr_cb,
                NULL, //get_rqst_host_cb,
                get_rqst_port_cb,
                get_rqst_scheme_cb,
                get_rqst_protocol_cb,
                get_rqst_line_cb,
                get_rqst_method_cb,
                get_rqst_url_cb,
                get_rqst_uri_cb,
                get_rqst_path_cb,
                get_rqst_query_str_cb,
                get_rqst_header_size_cb,
                NULL, //get_rqst_header_w_key_cb,
                get_rqst_header_w_idx_cb,
                get_rqst_body_str_cb,
                NULL, //get_rqst_local_addr_cb,
                NULL, //get_rqst_canonical_port_cb,
                NULL, //get_rqst_apparent_cache_status_cb,
                NULL, //get_rqst_bytes_out_cb,
                NULL, //get_rqst_bytes_in_cb,
                NULL, //get_rqst_uuid_cb,
                NULL //get_cust_id_cb
        };
        ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, &s_callbacks, true, true);
        // -----------------------------------------
        // geoip
        // -----------------------------------------
        char l_cwd[1024];
        if(getcwd(l_cwd, sizeof(l_cwd)) != NULL)
        {
                //fprintf(stdout, "Current working dir: %s\n", cwd);
        }
        std::string l_geoip2_city_file = l_cwd;
        std::string l_geoip2_asn_file = l_cwd;
        l_geoip2_city_file += "/../../../../tests/data/waf/db/GeoLite2-City.mmdb";
        //l_geoip2_city_file += "/../tests/data/waf/db/GeoLite2-City.mmdb";
        l_geoip2_asn_file += "/../../../../tests/data/waf/db/GeoLite2-ASN.mmdb";
        //l_geoip2_asn_file += "/../tests/data/waf/db/GeoLite2-ASN.mmdb";
        int32_t l_s;
        // -------------------------------------------------
        // verify engine loading
        // -------------------------------------------------
        ns_waflz::engine *l_engine = new ns_waflz::engine();
        l_engine->set_geoip2_dbs(l_geoip2_city_file, l_geoip2_asn_file);
        l_s = l_engine->init();
        REQUIRE((l_s == WAFLZ_STATUS_OK));
        // -------------------------------------------------
        // *************************************************
        //         Content-Type --> parser map
        // *************************************************
        // -------------------------------------------------
        ns_waflz::ctype_parser_map_t l_ctype_parser_map;
        l_ctype_parser_map["application/x-www-form-urlencoded"] = ns_waflz::PARSER_URL_ENCODED;
        l_ctype_parser_map["text/xml"]                          = ns_waflz::PARSER_XML;
        l_ctype_parser_map["application/xml"]                   = ns_waflz::PARSER_XML;
        l_ctype_parser_map["application/json"]                  = ns_waflz::PARSER_JSON;
        l_ctype_parser_map["multipart/form-data"]               = ns_waflz::PARSER_MULTIPART;
        l_rqst_ctx->init_phase_1(*l_engine);
        l_rqst_ctx->init_phase_2(l_ctype_parser_map);
        // -------------------------------------------------
        // ARGS
        // -------------------------------------------------
        SECTION("ARGS") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_ARGS);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_ARGS);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // check inspect body flag. Turn it off
                // -----------------------------------------
                l_rqst_ctx->m_inspect_body = false;
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 2));
                // -----------------------------------------
                // check inspect body flag. Turn it on
                // -----------------------------------------
                l_rqst_ctx->m_inspect_body = true;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);

                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 5));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        switch(i_idx)
                        {
                        case 2:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "monkeys", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "bananas", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                }
                // -----------------------------------------
                // w/ match
                // -----------------------------------------
                ::waflz_pb::variable_t_match_t* l_m = l_var->add_match();
                l_m->set_value("seamonkeys");
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "seamonkeys", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "plankton", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // ARGS_NAMES
        // -------------------------------------------------
        SECTION("ARGS_NAMES") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_ARGS_NAMES);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_ARGS_NAMES);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // check inspect body flag. Turn it off
                // -----------------------------------------
                l_rqst_ctx->m_inspect_body = false;
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 2));
                // -----------------------------------------
                // check inspect body flag. Turn it on
                // -----------------------------------------
                l_rqst_ctx->m_inspect_body = true;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 5));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        switch(i_idx)
                        {
                        case 2:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "monkeys", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "monkeys", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                }
                // -----------------------------------------
                // w/ match
                // -----------------------------------------
                ::waflz_pb::variable_t_match_t* l_m = l_var->add_match();
                l_m->set_value("seamonkeys");
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "seamonkeys", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "seamonkeys", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // ARGS_GET
        // -------------------------------------------------
        SECTION("ARGS_GET") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_ARGS_GET);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_ARGS_GET);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 2));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        switch(i_idx)
                        {
                        case 1:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "screws", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "loose", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                }
                // -----------------------------------------
                // w/ match
                // -----------------------------------------
                ::waflz_pb::variable_t_match_t* l_m = l_var->add_match();
                l_m->set_value("you");
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "you", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "crazy", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // ARGS_GET_NAMES
        // -------------------------------------------------
        SECTION("ARGS_GET_NAMES") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_ARGS_GET_NAMES);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_ARGS_GET_NAMES);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 2));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        switch(i_idx)
                        {
                        case 1:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "screws", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "screws", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                }
                // -----------------------------------------
                // w/ match
                // -----------------------------------------
                ::waflz_pb::variable_t_match_t* l_m = l_var->add_match();
                l_m->set_value("you");
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "you", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "you", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // ARGS_POST
        // -------------------------------------------------
        SECTION("ARGS_POST") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_ARGS_POST);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_ARGS_POST);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // check inspect body flag. Turn it off
                // -----------------------------------------
                l_rqst_ctx->m_inspect_body = false;
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 0));
                // -----------------------------------------
                // check inspect body flag. Turn it on
                // -----------------------------------------
                l_rqst_ctx->m_inspect_body = true;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 3));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "monkeys", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "bananas", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // w/ match
                // -----------------------------------------
                ::waflz_pb::variable_t_match_t* l_m = l_var->add_match();
                l_m->set_value("seamonkeys");
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "seamonkeys", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "plankton", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // ARGS_POST_NAMES
        // -------------------------------------------------
        SECTION("ARGS_POST_NAMES") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_ARGS_POST_NAMES);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_ARGS_POST_NAMES);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // check inspect body flag. Turn it off
                // -----------------------------------------
                l_rqst_ctx->m_inspect_body = false;
                                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 0));
                // -----------------------------------------
                // check inspect body flag. Turn it on
                // -----------------------------------------
                l_rqst_ctx->m_inspect_body = true;
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 3));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "monkeys", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "monkeys", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // w/ match
                // -----------------------------------------
                ::waflz_pb::variable_t_match_t* l_m = l_var->add_match();
                l_m->set_value("seamonkeys");
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "seamonkeys", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "seamonkeys", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // ARGS_COMBINED_SIZE
        // -------------------------------------------------
        SECTION("ARGS_COMBINED_SIZE") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_ARGS_COMBINED_SIZE);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_ARGS_COMBINED_SIZE);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "ARGS_COMBINED_SIZE", i_a->m_key_len) == 0));
                                REQUIRE((i_a->m_val_len == 67));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // QUERY_STRING
        // -------------------------------------------------
        SECTION("QUERY_STRING") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_QUERY_STRING);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_QUERY_STRING);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                //REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                //REQUIRE((strncmp(i_a->m_key, "QUERY_STRING", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "you=crazy&screws=loose", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // REQUEST_BASENAME
        // -------------------------------------------------
        SECTION("REQUEST_BASENAME") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REQUEST_BASENAME);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REQUEST_BASENAME);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                //REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                //REQUIRE((strncmp(i_a->m_key, "REQUEST_BASENAME", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "info.html", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // REQUEST_FILENAME
        // -------------------------------------------------
        SECTION("REQUEST_FILENAME") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REQUEST_FILENAME);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REQUEST_FILENAME);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                //REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                //REQUIRE((strncmp(i_a->m_key, "REQUEST_FILENAME", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "/800050/origin.testsuite.com/sec_arg_check/info.html", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // REQUEST_COOKIES
        // -------------------------------------------------
        SECTION("REQUEST_COOKIES") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REQUEST_COOKIES);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REQUEST_COOKIES);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 3));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 1:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "__cookie_b", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "b_value", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // w/ match
                // -----------------------------------------
                ::waflz_pb::variable_t_match_t* l_m = l_var->add_match();
                l_m->set_value("__cookie_c");
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "__cookie_c", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "c_value", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // REQUEST_COOKIES_NAMES
        // -------------------------------------------------
        SECTION("REQUEST_COOKIES_NAMES") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REQUEST_COOKIES_NAMES);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REQUEST_COOKIES_NAMES);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 3));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 1:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "__cookie_b", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "__cookie_b", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // w/ match
                // -----------------------------------------
                ::waflz_pb::variable_t_match_t* l_m = l_var->add_match();
                l_m->set_value("__cookie_c");
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "__cookie_c", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "__cookie_c", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // REQUEST_HEADERS
        // -------------------------------------------------
        SECTION("REQUEST_HEADERS") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REQUEST_HEADERS);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REQUEST_HEADERS);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 7));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 1:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "Accept", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "my_cool_accept_value", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // w/ match
                // -----------------------------------------
                ::waflz_pb::variable_t_match_t* l_m = l_var->add_match();
                l_m->set_value("Referer");
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "Referer", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "my_cool_referer_value", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // REQUEST_HEADERS_NAMES
        // -------------------------------------------------
        SECTION("REQUEST_HEADERS_NAMES") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REQUEST_HEADERS_NAMES);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REQUEST_HEADERS_NAMES);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 7));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 1:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "Accept", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "Accept", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // w/ match
                // -----------------------------------------
                ::waflz_pb::variable_t_match_t* l_m = l_var->add_match();
                l_m->set_value("Referer");
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "Referer", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "Referer", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // REQUEST_LINE
        // -------------------------------------------------
        SECTION("REQUEST_LINE") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REQUEST_LINE);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REQUEST_LINE);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                //REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                //REQUIRE((strncmp(i_a->m_key, "REQUEST_LINE", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "GET /800050/origin.testsuite.com/sec_arg_check/info.html?you=crazy&screws=loose HTTP/1.1", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // REQUEST_METHOD
        // -------------------------------------------------
        SECTION("REQUEST_METHOD") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REQUEST_METHOD);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REQUEST_METHOD);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                //REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                //REQUIRE((strncmp(i_a->m_key, "REQUEST_METHOD", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "GETZ", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // REQUEST_PROTOCOL
        // -------------------------------------------------
        SECTION("REQUEST_PROTOCOL") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REQUEST_PROTOCOL);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REQUEST_PROTOCOL);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                //REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                //REQUIRE((strncmp(i_a->m_key, "REQUEST_PROTOCOL", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "HTTP/1.1", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // REQUEST_URI
        // -------------------------------------------------
        SECTION("REQUEST_URI") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REQUEST_URI);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REQUEST_URI);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                //REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                //REQUIRE((strncmp(i_a->m_key, "REQUEST_URI", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "/800050/origin.testsuite.com/sec_arg_check/info.html?you=crazy&screws=loose", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // REQUEST_URI_RAW
        // -------------------------------------------------
        SECTION("REQUEST_URI_RAW") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REQUEST_URI_RAW);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REQUEST_URI_RAW);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                //REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                //REQUIRE((strncmp(i_a->m_key, "REQUEST_URI_RAW", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "bananas.com/800050/origin.testsuite.com/sec_arg_check/info.html?you=crazy&screws=loose", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // TX
        // -------------------------------------------------
        SECTION("TX") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_TX);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_TX);
                ::waflz_pb::variable_t_match_t* l_m = l_var->add_match();
                l_m->set_value("pAnDAs");
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                l_rqst_ctx->m_cx_tx_map["MONKEYS"] = "BANANAS";
                l_rqst_ctx->m_cx_tx_map["PANDAS"] = "TREES";
                l_rqst_ctx->m_cx_tx_map["FLEAS"] = "DOGS";
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                //REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "PANDAS", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "TREES", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // MATCHED_VAR
        // -------------------------------------------------
        SECTION("MATCHED_VAR") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_MATCHED_VAR);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_MATCHED_VAR);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                l_rqst_ctx->m_cx_matched_var_name = "MONKEYS";
                l_rqst_ctx->m_cx_matched_var = "BANANAS";
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "MONKEYS", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "BANANAS", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // MATCHED_VARS
        // -------------------------------------------------
        SECTION("MATCHED_VARS") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_MATCHED_VARS);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_MATCHED_VARS);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                l_rqst_ctx->m_cx_matched_var_name = "MONKEYS";
                l_rqst_ctx->m_cx_matched_var = "BANANAS";
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "MONKEYS", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "BANANAS", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // MATCHED_VAR_NAME
        // -------------------------------------------------
        SECTION("MATCHED_VAR_NAME") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_MATCHED_VAR_NAME);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_MATCHED_VAR_NAME);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                l_rqst_ctx->m_cx_matched_var_name = "MONKEYS";
                l_rqst_ctx->m_cx_matched_var = "BANANAS";
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "MONKEYS", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "MONKEYS", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // MATCHED_VAR_NAME
        // -------------------------------------------------
        SECTION("MATCHED_VARS_NAMES") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_MATCHED_VARS_NAMES);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_MATCHED_VARS_NAMES);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                l_rqst_ctx->m_cx_matched_var_name = "MONKEYS";
                l_rqst_ctx->m_cx_matched_var = "BANANAS";
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "MONKEYS", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "MONKEYS", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // XML
        // -------------------------------------------------
        SECTION("XML") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_XML);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_XML);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                g_body_str = _RQST_BODY_XML;
                g_header_content_type = _RQST_CONTENT_TYPE_XML;
                // make new..
                if(l_rqst_ctx)
                {
                        delete l_rqst_ctx;
                        l_rqst_ctx = NULL;
                        l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, &s_callbacks, true);
                }
                l_rqst_ctx->m_content_type_list.clear();
                l_rqst_ctx->init_phase_1(*l_engine);
                l_rqst_ctx->init_phase_2(l_ctype_parser_map);
                // -----------------------------------------
                // check inspect body flag. Turn it off
                // -----------------------------------------
                l_rqst_ctx->m_inspect_body = false;
                                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 0));
                // -----------------------------------------
                // check inspect body flag. Turn it on
                // -----------------------------------------
                l_rqst_ctx->m_inspect_body = true;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "XML", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "[XML document tree]", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // w/ match
                // -----------------------------------------
                ::waflz_pb::variable_t_match_t* l_m = l_var->add_match();
                l_m->set_value("/monkeys/mandrill");
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "/monkeys/mandrill", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "dooby", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // reset
                // -----------------------------------------
                g_body_str = _RQST_BODY_JSON;
                g_header_content_type = _RQST_CONTENT_TYPE_JSON;
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // REQBODY_ERROR
        // -------------------------------------------------
        SECTION("REQBODY_ERROR") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REQBODY_ERROR);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REQBODY_ERROR);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                g_body_str = _RQST_BODY_JSON;
                // Set incorrect type to generate parsing error
                g_header_content_type = _RQST_CONTENT_TYPE_XML;
                // make new
                if(l_rqst_ctx)
                {
                        delete l_rqst_ctx;
                        l_rqst_ctx = NULL;
                        l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, &s_callbacks, true);
                }
                l_rqst_ctx->m_content_type_list.clear();
                l_rqst_ctx->init_phase_1(*l_engine);
                l_rqst_ctx->init_phase_2(l_ctype_parser_map);
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "REQBODY_ERROR", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "1", i_a->m_val_len) == 0));
                                REQUIRE(i_a->m_val_len == 1);
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // reset
                // -----------------------------------------
                g_body_str = _RQST_BODY_JSON;
                g_header_content_type = _RQST_CONTENT_TYPE_JSON;
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // REQUEST_BODY
        // -------------------------------------------------
        SECTION("REQUEST_BODY") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REQUEST_BODY);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REQUEST_BODY);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // check inspect body flag. Turn it off
                // -----------------------------------------
                l_rqst_ctx->m_inspect_body = false;
                                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 0));
                // -----------------------------------------
                // check inspect body flag. Turn it on
                // -----------------------------------------
                l_rqst_ctx->m_inspect_body = true;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                //REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                //REQUIRE((strncmp(i_a->m_key, "REQUEST_BODY", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, g_body_str, i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // REMOTE_ADDR
        // -------------------------------------------------
        SECTION("REMOTE_ADDR") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REMOTE_ADDR);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REMOTE_ADDR);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                //REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                //REQUIRE((strncmp(i_a->m_key, "REMOTE_ADDR", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "172.217.5.206", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
         // -------------------------------------------------
        // REMOTE_ADDR with xff set
        // -------------------------------------------------
        SECTION("REMOTE_ADDR_XFF") {
                l_rqst_ctx->set_src_ip_from_spoof_header("X-Forwarded-For");
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REMOTE_ADDR);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REMOTE_ADDR);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                //REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                //REQUIRE((strncmp(i_a->m_key, "REMOTE_ADDR", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "104.10.167.54", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // add garbage values to xff
                // -----------------------------------------
                s_xff_ip = "172.217.5.191,,,hello.s..s.";
                // make new
                if(l_rqst_ctx)
                {
                        delete l_rqst_ctx;
                        l_rqst_ctx = NULL;
                        l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, &s_callbacks, true);
                }
                l_rqst_ctx->init_phase_1(*l_engine);
                l_rqst_ctx->set_src_ip_from_spoof_header("x-forwarded-for");
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                //REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                //REQUIRE((strncmp(i_a->m_key, "REMOTE_ADDR", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "172.217.5.191", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // add bad ip, it should default to real ip
                // -----------------------------------------
                s_xff_ip = "garbage, garbage, garbage,g arbage, 172.217.5.192blajffh";
                // make new
                if(l_rqst_ctx)
                {
                        delete l_rqst_ctx;
                        l_rqst_ctx = NULL;
                        l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, &s_callbacks, true);
                }
                l_rqst_ctx->init_phase_1(*l_engine);
                l_rqst_ctx->set_src_ip_from_spoof_header("X-Forwarded-For");
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        //NDBG_PRINT("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                        switch(i_idx)
                        {
                        case 0:
                        {
                                //REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                //REQUIRE((strncmp(i_a->m_key, "REMOTE_ADDR", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "172.217.5.206", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
                l_rqst_ctx->init_phase_1(*l_engine);
        }
        // -------------------------------------------------
        // REMOTE_ASN
        // -------------------------------------------------
        SECTION("REMOTE_ASN") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_REMOTE_ASN);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_REMOTE_ASN);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        switch(i_idx)
                        {
                        case 0:
                        {
                                //REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                //REQUIRE((strncmp(i_a->m_key, "REMOTE_ASN", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "15169", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        // -------------------------------------------------
        // GEO:COUNTRY
        // -------------------------------------------------
        SECTION("GEO:COUNTRY_CODE") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_GEO);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_GEO);
                l_var->add_match()->set_value("COUNTRY_CODE");
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 1));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        switch(i_idx)
                        {
                        case 0:
                        {
                                //REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                //REQUIRE((strncmp(i_a->m_key, "GEO:COUNTRY", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "US", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        SECTION("DETECT JSON AND VERIFY ARGS_POST") {
                ns_waflz::get_var_t l_cb = NULL;
                l_cb = ns_waflz::get_var_cb(waflz_pb::variable_t_type_t_ARGS_POST);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_ARGS_POST);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // JSON structure starts after 11 chars
                g_body_str = "\t\n   \n  [\t\t\n\n{\
                                \"PARAMETER1\": \"PARAMETER\",\
                                \"PARAMETER\": \"PARAMETER:'4' UNION SELECT 31337,name COLLATE Arabic_CI_AS FROM master..sysdatabases--\"\
                             }";
                // Set url_encode content type for a json body, the engine should detect JSON
                g_header_content_type = _RQST_CONTENT_TYPE_URL_ENCODED;
                // make new
                if(l_rqst_ctx)
                {
                        delete l_rqst_ctx;
                        l_rqst_ctx = NULL;
                        l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, &s_callbacks, true, true);
                }
                l_rqst_ctx->m_content_type_list.clear();
                l_rqst_ctx->init_phase_1(*l_engine);
                l_rqst_ctx->init_phase_2(l_ctype_parser_map);
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_rqst_ctx);

                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 2));
                i_idx = 0;
                for(ns_waflz::const_arg_list_t::iterator i_a = l_al.begin();
                    i_a != l_al.end();
                    ++i_a, ++i_idx)
                {
                        switch(i_idx)
                        {
                        case 0:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "PARAMETER1", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "PARAMETER", i_a->m_val_len) == 0));
                                break;
                        }
                        case 1:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                REQUIRE((strncmp(i_a->m_key, "PARAMETER", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "PARAMETER:'4' UNION SELECT 31337,name COLLATE Arabic_CI_AS FROM master..sysdatabases--", i_a->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_var) { delete l_var; l_var = NULL; }
        }
        if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        if(l_engine) { delete l_engine; l_engine = NULL; }
}
