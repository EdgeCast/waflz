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
#include "waflz/arg.h"
#include "waflz/string_util.h"
#include "core/decode.h"
#include "support/ndebug.h"
#include <string.h>
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef struct _entry {
        const char *m_in;
        const char *m_out;
        const uint32_t m_size;
} entry_t;
typedef struct _kv_struct {
        const char *m_k;
        const char *m_v;
} _kv_t;
//! ----------------------------------------------------------------------------
//! support
//! ----------------------------------------------------------------------------
void check_cookie_list(const char *a_ck, const _kv_t* a_ck_exp)
{
#define CHECK_KEY_EQ(_str) \
        REQUIRE((strncmp(i_h->m_key, (_str), i_h->m_key_len) == 0))
#define CHECK_VAL_EQ(_str) \
        REQUIRE((strncmp(i_h->m_val, (_str), i_h->m_val_len) == 0))
        int32_t l_s;
        ns_waflz::const_arg_list_t l_cookie_list;
        l_s = ns_waflz::parse_cookies(l_cookie_list, a_ck, strlen(a_ck));
        REQUIRE((l_s == WAFLZ_STATUS_OK));
        int i_idx = 0;
        for(ns_waflz::const_arg_list_t::const_iterator i_h = l_cookie_list.begin();
            i_h != l_cookie_list.end();
            ++i_h, ++i_idx)
        {
                //NDBG_PRINT("[%d] [%d]%.*s: [%d]%.*s\n",
                //        i_idx,
                //        (int)i_h->m_key_len, i_h->m_key_len, i_h->m_key,
                //        (int)i_h->m_val_len, i_h->m_val_len, i_h->m_val);
                CHECK_KEY_EQ(a_ck_exp[i_idx].m_k);
                CHECK_VAL_EQ(a_ck_exp[i_idx].m_v);
        }
}
//! ----------------------------------------------------------------------------
//! parse
//! ----------------------------------------------------------------------------
TEST_CASE( "test parse", "[parse]" ) {
        // -------------------------------------------------
        // basic test
        // -------------------------------------------------
        SECTION("normalize") {
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"/pagead/osd.js?a='select * from testing'&b=c&c=d",
                         "/pagead/osd.js?a='select * from testing'&b=c&c=d",
                         0},
                        // 2.
                        {"/pagead/monkey/../banana",
                         "/pagead/banana",
                         0},
                        // 3.
                        {"/pagead/./././banana",
                         "/pagead/banana",
                         0},
                };
                uint32_t l_size = ARRAY_SIZE(l_vec);
                for(uint32_t i_p = 0; i_p < l_size; ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        const char *l_out = l_vec[i_p].m_out;
                        char *l_buf = NULL;
                        uint32_t l_len = 0;
                        l_s = ns_waflz::normalize_path(&l_buf, l_len, l_in, strlen(l_in), false);
                        //NDBG_PRINT("l_buf: %.*s\n", l_len, l_buf);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_len != 0));
                        REQUIRE((strncmp(l_buf, l_out, strlen(l_out)) == 0));
                        if(l_buf) { free(l_buf); l_buf = NULL; l_len = 0;}
                }
        }
        SECTION("parse query str"){
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"&utm_source=anonymous_email&&utm_medium=email&utm_term=ad_view&utm_campaign=vivamail&utm_content=gmail.com",
                         "utm_sourceanonymous_emailutm_mediumemailutm_termad_viewutm_campaignvivamailutm_contentgmail.com",
                          5},
                        // 2.
                        {"&a=&b=",
                         "ab",
                         2},
                        // 3.
                        {"=&b=a&=c",
                         "bac",
                         3},
                        {"a=b&c=d&e=f",
                         "abcdef",
                         3}
                };
                uint32_t l_size = ARRAY_SIZE(l_vec);
                for(uint32_t i_p = 0; i_p < l_size; ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        char *l_buf = NULL;
                        uint32_t l_invalid_cnt = 0;
                        ns_waflz::arg_list_t l_arg_list;
                        ns_waflz::data_unordered_map_t l_arg_map;
                        l_s = ns_waflz::parse_args(l_arg_list,
                                                   l_arg_map,
                                                   l_invalid_cnt,
                                                   l_in,
                                                   strlen(l_in),
                                                   '&');
                        std::string l_out;
                        for(ns_waflz::arg_list_t::iterator i_t = l_arg_list.begin();
                            i_t != l_arg_list.end();
                            ++i_t)
                        {
                                if(i_t->m_key)
                                {
                                        l_out.append(i_t->m_key);
                                        free(i_t->m_key);
                                }
                                if(i_t->m_val)
                                {
                                        l_out.append(i_t->m_val);
                                        free(i_t->m_val);
                                }
                        }
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_arg_list.size() == l_vec[i_p].m_size));
                        REQUIRE((strncmp(l_out.c_str(), l_vec[i_p].m_out, l_out.length()) == 0));
                        if(l_buf) { free(l_buf); l_buf = NULL;}
                }
        }
        SECTION("parse cookies"){
                // -----------------------------------------
                // vector
                // -----------------------------------------
                {
                const char *l_ck = "aaa=bbb;abc=def  ";
                _kv_t l_ck_exp[] = {
                        {"aaa", "bbb"},
                        {"abc", "def"}
                };
                check_cookie_list(l_ck, l_ck_exp);
                }
                // -----------------------------------------
                // vector
                // -----------------------------------------
                {
                const char *l_ck = "a=b; b=c; c=d";
                _kv_t l_ck_exp[] = {
                        {"a", "b"},
                        {"b", "c"},
                        {"c", "d"}
                };
                check_cookie_list(l_ck, l_ck_exp);
                }
                // -----------------------------------------
                // vector
                // -----------------------------------------
                {
                const char *l_ck = " a=b; b=c; c=ddddddd";
                _kv_t l_ck_exp[] = {
                        {"a", "b"},
                        {"b", "c"},
                        {"c", "ddddddd"}
                };
                check_cookie_list(l_ck, l_ck_exp);
                }
        }
}
