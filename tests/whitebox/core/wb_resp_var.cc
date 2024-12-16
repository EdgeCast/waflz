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
#include "waflz/resp_ctx.h"
#include "core/var.h"
#include "support/ndebug.h"
#include "waflz/geoip2_mmdb.h"
#include <string.h>
#include <unistd.h>
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_rqst_src_addr_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        static const char s_uri[] = "172.217.5.206";
        *a_data = s_uri;
        *a_len = strlen(s_uri);
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_resp_local_addr_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        static const char s_uri[] = "172.217.5.206";
        *a_data = s_uri;
        *a_len = strlen(s_uri);
        return 0;
}
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
static int32_t get_resp_cust_id_cb(uint32_t *a_val, void *a_ctx)
{
        *a_val = 800050;
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_resp_host_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        static const char s_line[] = "bananas.com";
        *a_data = s_line;
        *a_len = strlen(s_line);
        return 0;
}
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
static int32_t get_resp_status_cb(uint32_t *a_val, void *a_ctx)
{
        *a_val = 403;
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_resp_uri_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        static const char s_line[] = "/800050/origin.testsuite.com/sec_arg_check/info.html?you=crazy&screws=loose";
        *a_data = s_line;
        *a_len = strlen(s_line);
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_resp_content_type_list_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        static const char s_line[] = "text/html";
        *a_data = s_line;
        *a_len = strlen(s_line);
        return 0;
}
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
static int32_t get_resp_content_length_cb(uint32_t *a_val, void *a_ctx)
{
        *a_val = 345;
        return 0;
}
//! ----------------------------------------------------------------------------
//! get_resp_body_str_cb
//! ----------------------------------------------------------------------------
#define _RESP_BODY_JSON "{\"monkeys\": \"bananas\", \"koalas\": \"fruitloops\", \"seamonkeys\": \"plankton\"}"
static const char *g_body_str = _RESP_BODY_JSON;
static int32_t get_resp_body_str_cb(char **ao_data,
                                    uint32_t *ao_data_len,
                                    bool *ao_is_eos,
                                    void *a_ctx,
                                    uint32_t a_to_read)
{
        *ao_data_len = strlen(g_body_str);
        memcpy(*ao_data, g_body_str, *ao_data_len);
        *ao_is_eos = true;
        return 0;
}
//! ----------------------------------------------------------------------------
//! get_resp_header_size_cb
//! ----------------------------------------------------------------------------
static int32_t get_resp_header_size_cb(uint32_t *a_val, void *a_ctx)
{
        *a_val = 2;
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
//! get_resp_header_w_idx_cb
//! ----------------------------------------------------------------------------
#define _RESP_CONTENT_TYPE_JSON "application/json"
static const char *g_header_content_type = _RESP_CONTENT_TYPE_JSON;
static int32_t get_resp_header_w_idx_cb(const char **ao_key,
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
                *ao_key = "Content-Type";
                *ao_key_len = strlen("Content-Type");
                *ao_val = g_header_content_type;
                *ao_val_len = strlen(g_header_content_type);
                break;
        }
        case 1:
        {
                *ao_key = "Content-Length";
                *ao_key_len = strlen("Content-Length");
                snprintf(s_cl, 16, "%d", (int)strlen(g_body_str));
                *ao_val = s_cl;
                *ao_val_len = strlen(s_cl);
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
        char l_cwd[1024];
        if(getcwd(l_cwd, sizeof(l_cwd)) != NULL)
        {
            //fprintf(stdout, "Current working dir: %s\n", l_cwd);
        }
        std::string l_geoip2_city_file = l_cwd;
        std::string l_geoip2_asn_file = l_cwd;
        l_geoip2_city_file += "/../../../../tests/data/waf/db/GeoLite2-City.mmdb";
        l_geoip2_asn_file += "/../../../../tests/data/waf/db/GeoLite2-ASN.mmdb";
        // -------------------------------------------------
        // init geodb
        // -------------------------------------------------
        ns_waflz::geoip2_mmdb *l_geoip2_mmdb = new ns_waflz::geoip2_mmdb();
        int32_t l_s;
        l_s = l_geoip2_mmdb->init(l_geoip2_city_file, l_geoip2_asn_file);
        REQUIRE((l_s == WAFLZ_STATUS_OK));
        // -------------------------------------------------
        // init other stuff
        // -------------------------------------------------
        ns_waflz::init_resp_var_cb_vector();
        static ns_waflz::resp_ctx_callbacks s_callbacks = {
                get_resp_local_addr_cb,
                get_resp_host_cb,
                get_rqst_port_cb,
                get_rqst_method_cb,
                get_rqst_url_cb,
                get_resp_uri_cb,
                get_resp_status_cb,
                get_resp_content_type_list_cb,
                get_resp_content_length_cb,
                get_resp_header_size_cb,
                NULL,  //get_resp_header_w_key_cb,
                get_resp_header_w_idx_cb,
                get_resp_body_str_cb,
                get_resp_cust_id_cb,
                get_rqst_src_addr_cb,
                NULL   //get_rqst_uuid_cb
        };
        ns_waflz::resp_ctx *l_resp_ctx = new ns_waflz::resp_ctx(NULL, 1024, 1024, &s_callbacks, -1, NULL);
        l_resp_ctx->init_phase_3(*l_geoip2_mmdb);
        l_resp_ctx->init_phase_4();
        // -------------------------------------------------
        // RESPONSE_HEADERS
        // -------------------------------------------------
        SECTION("RESPONSE_HEADERS") {
                ns_waflz::get_resp_var_t l_cb = NULL;
                l_cb = ns_waflz::get_resp_var_cb(waflz_pb::variable_t_type_t_RESPONSE_HEADERS);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_RESPONSE_HEADERS);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_resp_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 2));
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
                                //printf("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                                REQUIRE((strncmp(i_a->m_key, "Content-Type", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "application/json", i_a->m_val_len) == 0));
                                break;
                        }
                        case 1:
                        {
                                REQUIRE((i_a->m_key_len > 0));
                                REQUIRE((i_a->m_val_len > 0));
                                //printf("%.*s: %.*s\n", i_a->m_key_len, i_a->m_key, i_a->m_val_len, i_a->m_val);
                                REQUIRE((strncmp(i_a->m_key, "Content-Length", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "72", i_a->m_val_len) == 0));
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
                l_m->set_value("Content-Type");
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_resp_ctx);
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
                                REQUIRE((strncmp(i_a->m_key, "Content-Type", i_a->m_key_len) == 0));
                                REQUIRE((strncmp(i_a->m_val, "application/json", i_a->m_val_len) == 0));
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
        // RESPONSE_HEADERS_NAMES
        // -------------------------------------------------
        /*SECTION("RESPONSE_HEADERS_NAMES") {
                ns_waflz::get_resp_var_t l_cb = NULL;
                l_cb = ns_waflz::get_resp_var_cb(waflz_pb::variable_t_type_t_RESPONSE_HEADERS_NAMES);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_RESPONSE_HEADERS_NAMES);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_resp_ctx);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_al.size() == 6));
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
                l_s = l_cb(l_al, l_count, *l_var, l_resp_ctx);
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
        }*/
        // -------------------------------------------------
        // TX
        // -------------------------------------------------
        SECTION("TX") {
                ns_waflz::get_resp_var_t l_cb = NULL;
                l_cb = ns_waflz::get_resp_var_cb(waflz_pb::variable_t_type_t_TX);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_TX);
                ::waflz_pb::variable_t_match_t* l_m = l_var->add_match();
                l_m->set_value("pAnDAs");
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                l_resp_ctx->m_cx_tx_map["MONKEYS"] = "BANANAS";
                l_resp_ctx->m_cx_tx_map["PANDAS"] = "TREES";
                l_resp_ctx->m_cx_tx_map["FLEAS"] = "DOGS";
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_resp_ctx);
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
                ns_waflz::get_resp_var_t l_cb = NULL;
                l_cb = ns_waflz::get_resp_var_cb(waflz_pb::variable_t_type_t_MATCHED_VAR);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_MATCHED_VAR);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                l_resp_ctx->m_cx_matched_var_name = "MONKEYS";
                l_resp_ctx->m_cx_matched_var = "BANANAS";
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_resp_ctx);
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
                ns_waflz::get_resp_var_t l_cb = NULL;
                l_cb = ns_waflz::get_resp_var_cb(waflz_pb::variable_t_type_t_MATCHED_VARS);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_MATCHED_VARS);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                l_resp_ctx->m_cx_matched_var_name = "MONKEYS";
                l_resp_ctx->m_cx_matched_var = "BANANAS";
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_resp_ctx);
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
                ns_waflz::get_resp_var_t l_cb = NULL;
                l_cb = ns_waflz::get_resp_var_cb(waflz_pb::variable_t_type_t_MATCHED_VAR_NAME);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_MATCHED_VAR_NAME);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                l_resp_ctx->m_cx_matched_var_name = "MONKEYS";
                l_resp_ctx->m_cx_matched_var = "BANANAS";
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_resp_ctx);
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
                ns_waflz::get_resp_var_t l_cb = NULL;
                l_cb = ns_waflz::get_resp_var_cb(waflz_pb::variable_t_type_t_MATCHED_VARS_NAMES);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_MATCHED_VARS_NAMES);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                l_resp_ctx->m_cx_matched_var_name = "MONKEYS";
                l_resp_ctx->m_cx_matched_var = "BANANAS";
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_resp_ctx);
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
        // RESPONSE_BODY
        // -------------------------------------------------
        SECTION("RESPONSE_BODY") {
                ns_waflz::get_resp_var_t l_cb = NULL;
                l_cb = ns_waflz::get_resp_var_cb(waflz_pb::variable_t_type_t_RESPONSE_BODY);
                REQUIRE((l_cb != NULL));
                ns_waflz::const_arg_list_t l_al;
                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                l_var->set_type(waflz_pb::variable_t_type_t_RESPONSE_BODY);
                int32_t l_s;
                uint32_t l_count = 0;
                uint32_t i_idx = 0;
                // -----------------------------------------
                // get all
                // -----------------------------------------
                l_al.clear();
                l_s = l_cb(l_al, l_count, *l_var, l_resp_ctx);
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
                                REQUIRE((i_a->m_val_len > 0));
                                //REQUIRE((strncmp(i_a->m_key, "RESPONSE_BODY", i_a->m_key_len) == 0));
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
        if(l_resp_ctx) { delete l_resp_ctx; l_resp_ctx = NULL; }
        if(l_geoip2_mmdb) { delete l_geoip2_mmdb; l_geoip2_mmdb = NULL; }
}
