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
#include "rule.pb.h"
#include "core/op.h"
#include "core/macro.h"
#include "waflz/nms.h"
#include "waflz/ac.h"
#include "op/byte_range.h"
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
        const char *m_op_val;
        bool m_match;
} entry_t;
//! ----------------------------------------------------------------------------
//! parse
//! ----------------------------------------------------------------------------
TEST_CASE( "test op", "[op]" ) {
        ns_waflz::init_op_cb_vector();
        // -------------------------------------------------
        // BEGINSWITH
        // -------------------------------------------------
        SECTION("BEGINSWITH") {
                ns_waflz::op_t l_cb = NULL;
                l_cb = ns_waflz::get_op_cb(waflz_pb::sec_rule_t_operator_t_type_t_BEGINSWITH);
                REQUIRE((l_cb != NULL));
                ns_waflz::macro l_macro;
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, NULL, false);
                waflz_pb::sec_rule_t_operator_t l_op;
                l_op.set_type(waflz_pb::sec_rule_t_operator_t_type_t_BEGINSWITH);
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"I am a banana",
                         "I am a",
                        true},
                        // 2.
                        {"monkeymonkey",
                         "mon",
                        true},
                        // 3.
                        {"I am a banana",
                         "You am a",
                         false},
                        // 4.
                        {"monkeymonkey",
                         "fuzzy",
                         false},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        char *l_buf = NULL;
                        uint32_t l_len = 0;
                        bool l_match = false;
                        l_op.set_value(l_vec[i_p].m_op_val);
                        l_s = l_cb(l_match, l_op, l_in, strlen(l_in), &l_macro, l_rqst_ctx, NULL);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_match == l_vec[i_p].m_match));
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
        // -------------------------------------------------
        // CONTAINS
        // -------------------------------------------------
        SECTION("CONTAINS") {
                ns_waflz::op_t l_cb = NULL;
                l_cb = ns_waflz::get_op_cb(waflz_pb::sec_rule_t_operator_t_type_t_CONTAINS);
                REQUIRE((l_cb != NULL));
                ns_waflz::macro l_macro;
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, NULL, false);
                waflz_pb::sec_rule_t_operator_t l_op;
                l_op.set_type(waflz_pb::sec_rule_t_operator_t_type_t_CONTAINS);
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"I am a banana",
                         "am",
                        true},
                        // 2.
                        {"dog scouts are cool cuz they eat all the cookies",
                         "scouts",
                        true},
                        // 3.
                        {")(*@)$*@^*&!(&!*)(*&!@()*!&_",
                         "&!(&!*)(",
                         true},
                        // 4.
                        {"monkeymonkey",
                         "fuzzy",
                         false},
                        // 5.
                        {")(*@)$*@^*&!(&!*)(*&!@()*!&_",
                         "@@##",
                         false},
                        // 6.
                        {"monkeymonkey",
                         "monkeymonkeymonkeymonkey",
                         false},

                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        char *l_buf = NULL;
                        uint32_t l_len = 0;
                        bool l_match = false;
                        l_op.set_value(l_vec[i_p].m_op_val);
                        l_s = l_cb(l_match, l_op, l_in, strlen(l_in), &l_macro, l_rqst_ctx, NULL);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_match == l_vec[i_p].m_match));
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
        // -------------------------------------------------
        // CONTAINS
        // -------------------------------------------------
        SECTION("CONTAINSWORD") {
                ns_waflz::op_t l_cb = NULL;
                l_cb = ns_waflz::get_op_cb(waflz_pb::sec_rule_t_operator_t_type_t_CONTAINSWORD);
                REQUIRE((l_cb != NULL));
                ns_waflz::macro l_macro;
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, NULL, false);
                waflz_pb::sec_rule_t_operator_t l_op;
                l_op.set_type(waflz_pb::sec_rule_t_operator_t_type_t_CONTAINSWORD);
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"abc",
                         "b",
                         false},
                        {" a ",
                         "a",
                         true},
                        {"abd\\got him",
                         "got",
                         true},
                        {"abd\\got him",
                         "got",
                         true},
                        {"abd\\got him",
                         "abd",
                         true},
                        {"abd\\got him",
                         "him",
                         true},
                        {"abd\\got hims",
                         "him",
                         false},
                        {"abcdefghijkl",
                         "abc",
                         false},
                        {"abcdefghijkl",
                        "jkl",
                         false},
                        {"unhide-abc-defghijkl",
                         "abc",
                         true},
                        {"",
                         "",
                         true},
                        {"test",
                         "",
                         true},
                        {"",
                         "test",
                         false},
                        {"hidingX<-not on word boundary, but is later on->hiding",
                         "hiding",
                         true},

                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        char *l_buf = NULL;
                        uint32_t l_len = 0;
                        bool l_match = false;
                        l_op.set_value(l_vec[i_p].m_op_val);
                        l_s = l_cb(l_match, l_op, l_in, strlen(l_in), &l_macro, l_rqst_ctx, NULL);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_match == l_vec[i_p].m_match));
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
        // -------------------------------------------------
        // DETECTSQLI
        // -------------------------------------------------
        SECTION("DETECTSQLI") {
                ns_waflz::op_t l_cb = NULL;
                l_cb = ns_waflz::get_op_cb(waflz_pb::sec_rule_t_operator_t_type_t_DETECTSQLI);
                REQUIRE((l_cb != NULL));
                ns_waflz::macro l_macro;
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, NULL, false);
                waflz_pb::sec_rule_t_operator_t l_op;
                l_op.set_type(waflz_pb::sec_rule_t_operator_t_type_t_DETECTSQLI);
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"I am a banana",
                         "",
                         false},
                        // 2.
                        {"dog scouts are cool cuz they eat all the cookies",
                         "",
                         false},
                        // 3.
                        {")(*@)$*@^*&!(&!*)(*&!@()*!&_",
                         "",
                         false},
                         // 4.
                         {"'select * from testing'",
                          "",
                          true},
                         // 5.
                         {"src=\"http://url.to.file.which/not.exist\" onerror=alert(document.cookie)",
                          "",
                          false},

                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        char *l_buf = NULL;
                        uint32_t l_len = 0;
                        bool l_match = false;
                        l_op.set_value(l_vec[i_p].m_op_val);
                        l_s = l_cb(l_match, l_op, l_in, strlen(l_in), &l_macro, l_rqst_ctx, NULL);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_match == l_vec[i_p].m_match));
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
        // -------------------------------------------------
        // DETECTXSS
        // -------------------------------------------------
        SECTION("DETECTXSS") {
                ns_waflz::op_t l_cb = NULL;
                l_cb = ns_waflz::get_op_cb(waflz_pb::sec_rule_t_operator_t_type_t_DETECTXSS);
                REQUIRE((l_cb != NULL));
                ns_waflz::macro l_macro;
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, NULL, false);
                waflz_pb::sec_rule_t_operator_t l_op;
                l_op.set_type(waflz_pb::sec_rule_t_operator_t_type_t_DETECTXSS);
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"I am a banana",
                         "",
                         false},
                        // 2.
                        {"dog scouts are cool cuz they eat all the cookies",
                         "",
                         false},
                        // 3.
                        {")(*@)$*@^*&!(&!*)(*&!@()*!&_",
                         "",
                         false},
                        // 4.
                        {"'select * from testing'",
                         "",
                         false},
                        // 5.
                        {"src=\"http://url.to.file.which/not.exist\" onerror=alert(document.cookie)",
                         "",
                         true},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        char *l_buf = NULL;
                        uint32_t l_len = 0;
                        bool l_match = false;
                        l_op.set_value(l_vec[i_p].m_op_val);
                        l_s = l_cb(l_match, l_op, l_in, strlen(l_in), &l_macro, l_rqst_ctx, NULL);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_match == l_vec[i_p].m_match));
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
        // -------------------------------------------------
        // ENDSWITH
        // -------------------------------------------------
        SECTION("ENDSWITH") {
                ns_waflz::op_t l_cb = NULL;
                l_cb = ns_waflz::get_op_cb(waflz_pb::sec_rule_t_operator_t_type_t_ENDSWITH);
                REQUIRE((l_cb != NULL));
                ns_waflz::macro l_macro;
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, NULL, false);
                waflz_pb::sec_rule_t_operator_t l_op;
                l_op.set_type(waflz_pb::sec_rule_t_operator_t_type_t_ENDSWITH);
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"I am a banana",
                         "nana",
                        true},
                        // 2.
                        {"dog scouts are cool cuz they eat all the cookies",
                         "okies",
                        true},
                        // 3.
                        {")(*@)$*@^*&!(&!*)(*&!@()*!&_",
                         "@()*!&_",
                         true},
                        // 4.
                        {")(*@)$*@^*&!(&!*)(*&!@()*!&_",
                         "$*@^*&!",
                         false},
                        // 5.
                        {"dog scouts are cool cuz they eat all the cookies",
                         "are cool cuz",
                         false},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        char *l_buf = NULL;
                        uint32_t l_len = 0;
                        bool l_match = false;
                        l_op.set_value(l_vec[i_p].m_op_val);
                        l_s = l_cb(l_match, l_op, l_in, strlen(l_in), &l_macro, l_rqst_ctx, NULL);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_match == l_vec[i_p].m_match));
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
        // -------------------------------------------------
        // EQ
        // -------------------------------------------------
        SECTION("EQ") {
                ns_waflz::op_t l_cb = NULL;
                l_cb = ns_waflz::get_op_cb(waflz_pb::sec_rule_t_operator_t_type_t_EQ);
                REQUIRE((l_cb != NULL));
                ns_waflz::macro l_macro;
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, NULL, false);
                waflz_pb::sec_rule_t_operator_t l_op;
                l_op.set_type(waflz_pb::sec_rule_t_operator_t_type_t_EQ);
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"1",
                         "1",
                        true},
                        // 2.
                        {"dog scouts are cool cuz they eat all the cookies",
                         "okies",
                        false},
                        // 3.
                        {"345",
                         "346",
                        false},
                        // 4.
                        {"345",
                         "345",
                        true},
                        // 5.
                        {"345",
                         "I am a bananas",
                        false},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        char *l_buf = NULL;
                        uint32_t l_len = 0;
                        bool l_match = false;
                        l_op.set_value(l_vec[i_p].m_op_val);
                        l_s = l_cb(l_match, l_op, l_in, strlen(l_in), &l_macro, l_rqst_ctx, NULL);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_match == l_vec[i_p].m_match));
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
        // -------------------------------------------------
        // GE
        // -------------------------------------------------
        SECTION("GE") {
                ns_waflz::op_t l_cb = NULL;
                l_cb = ns_waflz::get_op_cb(waflz_pb::sec_rule_t_operator_t_type_t_GE);
                REQUIRE((l_cb != NULL));
                ns_waflz::macro l_macro;
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, NULL, false);
                waflz_pb::sec_rule_t_operator_t l_op;
                l_op.set_type(waflz_pb::sec_rule_t_operator_t_type_t_GE);
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"1",
                         "1",
                        true},
                        // 1.
                        {"2",
                         "1",
                        true},
                        // 3.
                        {"dog scouts are cool cuz they eat all the cookies",
                         "okies",
                        false},
                        // 4.
                        {"345",
                         "346",
                        false},
                        // 5.
                        {"345",
                         "345",
                        true},
                        // 6.
                        {"345",
                         "I am a bananas",
                        false},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        char *l_buf = NULL;
                        uint32_t l_len = 0;
                        bool l_match = false;
                        l_op.set_value(l_vec[i_p].m_op_val);
                        l_s = l_cb(l_match, l_op, l_in, strlen(l_in), &l_macro, l_rqst_ctx, NULL);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_match == l_vec[i_p].m_match));
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
        // -------------------------------------------------
        // GT
        // -------------------------------------------------
        SECTION("GT") {
                ns_waflz::op_t l_cb = NULL;
                l_cb = ns_waflz::get_op_cb(waflz_pb::sec_rule_t_operator_t_type_t_GT);
                REQUIRE((l_cb != NULL));
                ns_waflz::macro l_macro;
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, NULL, false);
                waflz_pb::sec_rule_t_operator_t l_op;
                l_op.set_type(waflz_pb::sec_rule_t_operator_t_type_t_GT);
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"1",
                         "1",
                        false},
                        // 1.
                        {"2",
                         "1",
                        true},
                        // 3.
                        {"dog scouts are cool cuz they eat all the cookies",
                         "okies",
                        false},
                        // 4.
                        {"345",
                         "346",
                        false},
                        // 5.
                        {"345",
                         "345",
                        false},
                        // 6.
                        {"345",
                         "I am a bananas",
                        false},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        char *l_buf = NULL;
                        uint32_t l_len = 0;
                        bool l_match = false;
                        l_op.set_value(l_vec[i_p].m_op_val);
                        l_s = l_cb(l_match, l_op, l_in, strlen(l_in), &l_macro, l_rqst_ctx, NULL);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_match == l_vec[i_p].m_match));
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
        // -------------------------------------------------
        // LT
        // -------------------------------------------------
        SECTION("LT") {
                ns_waflz::op_t l_cb = NULL;
                l_cb = ns_waflz::get_op_cb(waflz_pb::sec_rule_t_operator_t_type_t_LT);
                REQUIRE((l_cb != NULL));
                ns_waflz::macro l_macro;
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, NULL, false);
                waflz_pb::sec_rule_t_operator_t l_op;
                l_op.set_type(waflz_pb::sec_rule_t_operator_t_type_t_LT);
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"1",
                         "1",
                        false},
                        // 2.
                        {"2",
                         "1",
                        false},
                        // 3.
                        {"dog scouts are cool cuz they eat all the cookies",
                         "okies",
                        false},
                        // 4.
                        {"345",
                         "346",
                        true},
                        // 5.
                        {"345",
                         "345",
                        false},
                        // 6.
                        {"345",
                         "I am a bananas",
                        false},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        char *l_buf = NULL;
                        uint32_t l_len = 0;
                        bool l_match = false;
                        l_op.set_value(l_vec[i_p].m_op_val);
                        l_s = l_cb(l_match, l_op, l_in, strlen(l_in), &l_macro, l_rqst_ctx, NULL);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_match == l_vec[i_p].m_match));
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
         // -------------------------------------------------
        // LT
        // -------------------------------------------------
        SECTION("LE") {
                ns_waflz::op_t l_cb = NULL;
                l_cb = ns_waflz::get_op_cb(waflz_pb::sec_rule_t_operator_t_type_t_LE);
                REQUIRE((l_cb != NULL));
                ns_waflz::macro l_macro;
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, NULL, false);
                waflz_pb::sec_rule_t_operator_t l_op;
                l_op.set_type(waflz_pb::sec_rule_t_operator_t_type_t_LT);
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"1",
                         "1",
                        true},
                        // 2.
                        {"2",
                         "1",
                        false},
                        // 3.
                        {"dog scouts are cool cuz they eat all the cookies",
                         "okies",
                        false},
                        // 4.
                        {"345",
                         "346",
                        true},
                        // 5.
                        {"345",
                         "345",
                        true},
                        // 6.
                        {"345",
                         "I am a bananas",
                        false},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        char *l_buf = NULL;
                        uint32_t l_len = 0;
                        bool l_match = false;
                        l_op.set_value( l_vec[i_p].m_op_val);
                        l_s = l_cb(l_match, l_op, l_in, strlen(l_in), &l_macro, l_rqst_ctx, NULL);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_match == l_vec[i_p].m_match));
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
        // -------------------------------------------------
        // IPMATCH
        // -------------------------------------------------
        SECTION("IPMATCH") {
                ns_waflz::op_t l_cb = NULL;
                l_cb = ns_waflz::get_op_cb(waflz_pb::sec_rule_t_operator_t_type_t_IPMATCH);
                REQUIRE((l_cb != NULL));
                ns_waflz::macro l_macro;
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, NULL, false);
                waflz_pb::sec_rule_t_operator_t l_op;
                l_op.set_type(waflz_pb::sec_rule_t_operator_t_type_t_IPMATCH);
                // -----------------------------------------
                // create ac obj...
                // -----------------------------------------
                int32_t l_s;
                ns_waflz::nms *l_nms = NULL;
                l_s = ns_waflz::create_nms_from_str(&l_nms , "88.88.88.88, 12.34.56.89");
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_nms !=NULL));
                l_op.set__reserved_1((uint64_t)l_nms);
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"127.0.0.1",
                         "",
                        false},
                        // 2.
                        {"88.88.88.88",
                         "",
                         true},
                        // 3.
                        {"55.55.45.87",
                         "",
                        false},
                        // 4.
                        {"12.34.56.89",
                         "",
                        true},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        char *l_buf = NULL;
                        uint32_t l_len = 0;
                        bool l_match = false;
                        l_s = l_cb(l_match, l_op, l_in, strlen(l_in), &l_macro, l_rqst_ctx, NULL);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_match == l_vec[i_p].m_match));
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                if(l_nms) { delete l_nms; l_nms = NULL; }
        }
        // -------------------------------------------------
        // IPMATCHF
        // -------------------------------------------------
        SECTION("IPMATCHF") {
                ns_waflz::op_t l_cb = NULL;
                l_cb = ns_waflz::get_op_cb(waflz_pb::sec_rule_t_operator_t_type_t_IPMATCHF);
                REQUIRE((l_cb != NULL));
                ns_waflz::macro l_macro;
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, NULL, false);
                waflz_pb::sec_rule_t_operator_t l_op;
                l_op.set_type(waflz_pb::sec_rule_t_operator_t_type_t_IPMATCHF);
                // -----------------------------------------
                // create ac obj...
                // -----------------------------------------
                int32_t l_s;
                ns_waflz::nms *l_nms = NULL;
                l_s = ns_waflz::create_nms_from_str(&l_nms , "88.88.88.88, 12.34.56.89");
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_nms !=NULL));
                l_op.set__reserved_1((uint64_t)l_nms);
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"127.0.0.1",
                         "",
                        false},
                        // 2.
                        {"88.88.88.88",
                         "",
                         true},
                        // 3.
                        {"55.55.45.87",
                         "",
                        false},
                        // 4.
                        {"12.34.56.89",
                         "",
                        true},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        char *l_buf = NULL;
                        uint32_t l_len = 0;
                        bool l_match = false;
                        l_s = l_cb(l_match, l_op, l_in, strlen(l_in), &l_macro, l_rqst_ctx, NULL);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_match == l_vec[i_p].m_match));
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                if(l_nms) { delete l_nms; l_nms = NULL; }
        }
        // -------------------------------------------------
        // IPMATCHFROMFILE
        // -------------------------------------------------
        SECTION("IPMATCHFROMFILE") {
                ns_waflz::op_t l_cb = NULL;
                l_cb = ns_waflz::get_op_cb(waflz_pb::sec_rule_t_operator_t_type_t_IPMATCHFROMFILE);
                REQUIRE((l_cb != NULL));
                ns_waflz::macro l_macro;
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, NULL, false);
                waflz_pb::sec_rule_t_operator_t l_op;
                l_op.set_type(waflz_pb::sec_rule_t_operator_t_type_t_IPMATCHFROMFILE);
                // -----------------------------------------
                // create ac obj...
                // -----------------------------------------
                int32_t l_s;
                ns_waflz::nms *l_nms = NULL;
                l_s = ns_waflz::create_nms_from_str(&l_nms , "88.88.88.88, 12.34.56.89");
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_nms !=NULL));
                l_op.set__reserved_1((uint64_t)l_nms);
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"127.0.0.1",
                         "",
                        false},
                        // 2.
                        {"88.88.88.88",
                         "",
                         true},
                        // 3.
                        {"55.55.45.87",
                         "",
                        false},
                        // 4.
                        {"12.34.56.89",
                         "",
                        true},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        char *l_buf = NULL;
                        uint32_t l_len = 0;
                        bool l_match = false;
                        l_s = l_cb(l_match, l_op, l_in, strlen(l_in), &l_macro, l_rqst_ctx, NULL);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_match == l_vec[i_p].m_match));
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                if(l_nms) { delete l_nms; l_nms = NULL; }
        }
        // -------------------------------------------------
        // PM
        // -------------------------------------------------
        SECTION("PM") {
                ns_waflz::op_t l_cb = NULL;
                l_cb = ns_waflz::get_op_cb(waflz_pb::sec_rule_t_operator_t_type_t_PM);
                REQUIRE((l_cb != NULL));
                ns_waflz::macro l_macro;
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, NULL, false);
                waflz_pb::sec_rule_t_operator_t l_op;
                l_op.set_type(waflz_pb::sec_rule_t_operator_t_type_t_PM);
                // -----------------------------------------
                // create ac obj...
                // -----------------------------------------
                int32_t l_s;
                ns_waflz::ac *l_ac = NULL;
                l_s = ns_waflz::create_ac_from_str(&l_ac , "cats dogs monkeys bananas");
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_ac !=NULL));
                l_op.set__reserved_1((uint64_t)l_ac);
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"monkey",
                         "",
                        false},
                        // 2.
                        {"monkeys",
                         "",
                         true},
                        // 3.
                        {"bananas",
                         "",
                        true},
                        // 4.
                        {"dog scouts are cool cuz they monkeys all the cookies",
                         "",
                        true},
                        // 5.
                        {"345",
                         "",
                        false},
                        // 6.
                        {"dog",
                         "",
                        false},
                        // 7.
                        {"why do I have so many cats, they aren't very nice",
                         "",
                        true},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        char *l_buf = NULL;
                        uint32_t l_len = 0;
                        bool l_match = false;
                        l_s = l_cb(l_match, l_op, l_in, strlen(l_in), &l_macro, l_rqst_ctx, NULL);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_match == l_vec[i_p].m_match));
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                if(l_ac) { delete l_ac; l_ac = NULL; }
        }
        // -------------------------------------------------
        // PMF
        // -------------------------------------------------
        SECTION("PMF") {
                ns_waflz::op_t l_cb = NULL;
                l_cb = ns_waflz::get_op_cb(waflz_pb::sec_rule_t_operator_t_type_t_PMF);
                REQUIRE((l_cb != NULL));
                ns_waflz::macro l_macro;
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, NULL, false);
                waflz_pb::sec_rule_t_operator_t l_op;
                l_op.set_type(waflz_pb::sec_rule_t_operator_t_type_t_PMF);
                // -----------------------------------------
                // create ac obj...
                // -----------------------------------------
                int32_t l_s;
                ns_waflz::ac *l_ac = NULL;
                l_s = ns_waflz::create_ac_from_str(&l_ac , "cats dogs monkeys bananas");
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_ac !=NULL));
                l_op.set__reserved_1((uint64_t)l_ac);
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"monkey",
                         "",
                        false},
                        // 2.
                        {"monkeys",
                         "",
                         true},
                        // 3.
                        {"bananas",
                         "",
                        true},
                        // 4.
                        {"dog scouts are cool cuz they monkeys all the cookies",
                         "",
                        true},
                        // 5.
                        {"345",
                         "",
                        false},
                        // 6.
                        {"dog",
                         "",
                        false},
                        // 7.
                        {"why do I have so many cats, they aren't very nice",
                         "",
                        true},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        char *l_buf = NULL;
                        uint32_t l_len = 0;
                        bool l_match = false;
                        l_s = l_cb(l_match, l_op, l_in, strlen(l_in), &l_macro, l_rqst_ctx, NULL);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_match == l_vec[i_p].m_match));
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                if(l_ac) { delete l_ac; l_ac = NULL; }
        }
        // -------------------------------------------------
        // PMFROMFILE
        // -------------------------------------------------
        SECTION("PMFROMFILE") {
                ns_waflz::op_t l_cb = NULL;
                l_cb = ns_waflz::get_op_cb(waflz_pb::sec_rule_t_operator_t_type_t_PMFROMFILE);
                REQUIRE((l_cb != NULL));
                ns_waflz::macro l_macro;
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, NULL, false);
                waflz_pb::sec_rule_t_operator_t l_op;
                l_op.set_type(waflz_pb::sec_rule_t_operator_t_type_t_PMFROMFILE);
                // -----------------------------------------
                // create ac obj...
                // -----------------------------------------
                int32_t l_s;
                ns_waflz::ac *l_ac = NULL;
                l_s = ns_waflz::create_ac_from_str(&l_ac , "cats dogs monkeys bananas");
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_ac !=NULL));
                l_op.set__reserved_1((uint64_t)l_ac);
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"monkey",
                         "",
                        false},
                        // 2.
                        {"monkeys",
                         "",
                         true},
                        // 3.
                        {"bananas",
                         "",
                        true},
                        // 4.
                        {"dog scouts are cool cuz they monkeys all the cookies",
                         "",
                        true},
                        // 5.
                        {"345",
                         "",
                        false},
                        // 6.
                        {"dog",
                         "",
                        false},
                        // 7.
                        {"why do I have so many cats, they aren't very nice",
                         "",
                        true},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        char *l_buf = NULL;
                        uint32_t l_len = 0;
                        bool l_match = false;
                        l_s = l_cb(l_match, l_op, l_in, strlen(l_in), &l_macro, l_rqst_ctx, NULL);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_match == l_vec[i_p].m_match));
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                if(l_ac) { delete l_ac; l_ac = NULL; }
        }
        // -------------------------------------------------
        // RX
        // -------------------------------------------------
        SECTION("RX") {
                ns_waflz::op_t l_cb = NULL;
                l_cb = ns_waflz::get_op_cb(waflz_pb::sec_rule_t_operator_t_type_t_RX);
                REQUIRE((l_cb != NULL));
                ns_waflz::macro l_macro;
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, NULL, false);
                waflz_pb::sec_rule_t_operator_t l_op;
                l_op.set_type(waflz_pb::sec_rule_t_operator_t_type_t_RX);
                // -----------------------------------------
                // create regex obj...
                // -----------------------------------------
                int32_t l_s;
                ns_waflz::regex *l_rx = NULL;
                l_rx = new ns_waflz::regex();
                const char l_rx_str[] = "\\d{4}-ca[t|n]";
                l_s = l_rx->init(l_rx_str, strlen(l_rx_str));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_rx !=NULL));
                l_op.set__reserved_1((uint64_t)l_rx);
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"monkey",
                         "",
                        false},
                        // 2.
                        {"cat",
                         "",
                         false},
                        // 3.
                        {"1234-cat",
                         "",
                         true},
                        // 4.
                        {"1234-can",
                         "",
                         true},
                        // 5.
                        {"1234-car",
                         "",
                         false},
                        // 6.
                        {"12A4-can",
                         "",
                         false},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        char *l_buf = NULL;
                        uint32_t l_len = 0;
                        bool l_match = false;
                        l_s = l_cb(l_match, l_op, l_in, strlen(l_in), &l_macro, l_rqst_ctx, NULL);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_match == l_vec[i_p].m_match));
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                if(l_rx) { delete l_rx; l_rx = NULL; }
        }
        // -------------------------------------------------
        // STREQ
        // -------------------------------------------------
        SECTION("STREQ") {
                ns_waflz::op_t l_cb = NULL;
                l_cb = ns_waflz::get_op_cb(waflz_pb::sec_rule_t_operator_t_type_t_STREQ);
                REQUIRE((l_cb != NULL));
                ns_waflz::macro l_macro;
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, NULL, false);
                waflz_pb::sec_rule_t_operator_t l_op;
                l_op.set_type(waflz_pb::sec_rule_t_operator_t_type_t_STREQ);
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"I am a banana",
                         "I am a banana",
                        true},
                        // 2.
                        {"dog scouts are cool cuz they eat all the cookies",
                         "dog scouts are cool cuz they eat all the cookies",
                        true},
                        // 3.
                        {"dog Scouts are cool cuz they eat all the cookies",
                         "dog sCouts Are cool cUz they eat all the cookies",
                        false},
                        // 4.
                        {")(*@)$*@^*&!(&!*)(*&!@()*!&_",
                         ")(*@)$*@^*&!(&!*)(*&!@()*!&_",
                         true},
                        // 5.
                        {")(*@)$*@^*&!(&!*)(*&!@()*!&_",
                         "$*@^*&!",
                         false},
                        // 6.
                        {"dog Scouts are cool cuz they eat all the cookiesy",
                         "dog sCouts Are cool cUz they eat all the cookies",
                         false},
                        // 7.
                        {"U am a banana",
                         "I am a banana",
                         false},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                int32_t l_s;
                bool l_match = false;
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        const char *l_in = l_vec[i_p].m_in;
                        char *l_buf = NULL;
                        uint32_t l_len = 0;
                        //NDBG_PRINT("COMP: %.*s == %.*s\n", (int)strlen(l_in), l_in, (int)strlen(l_vec[i_p].m_op_val), l_vec[i_p].m_op_val);
                        l_op.set_value(l_vec[i_p].m_op_val);
                        l_s = l_cb(l_match, l_op, l_in, strlen(l_in), &l_macro, l_rqst_ctx, NULL);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_match == l_vec[i_p].m_match));
                }
                // -----------------------------------------
                // check op.values
                // -----------------------------------------
                l_op.clear_value();
                l_op.add_values("test1");
                l_op.add_values("test2");
                l_s = l_cb(l_match, l_op, "test", strlen("test"), &l_macro, l_rqst_ctx, NULL);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_match == false));
                l_s = l_cb(l_match, l_op, "test2", strlen("test2"), &l_macro, l_rqst_ctx, NULL);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_match == true));
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if (l_rqst_ctx)
                {
                        delete l_rqst_ctx;
                        l_rqst_ctx = NULL;
                }
        }
        // -------------------------------------------------
        // STRMATCH
        // -------------------------------------------------
        SECTION("STRMATCH") {
                ns_waflz::op_t l_cb = NULL;
                l_cb = ns_waflz::get_op_cb(waflz_pb::sec_rule_t_operator_t_type_t_STRMATCH);
                REQUIRE((l_cb != NULL));
                ns_waflz::macro l_macro;
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, NULL, false);
                waflz_pb::sec_rule_t_operator_t l_op;
                l_op.set_type(waflz_pb::sec_rule_t_operator_t_type_t_STRMATCH);
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"I am a banana",
                         "I am a banana",
                        true},
                        // 2.
                        {"I am a banana",
                         "banana",
                        true},
                        // 3.
                        {")(*@)$*@^*&!(&!*)(*&!@()*!&_",
                         "@^*&!(",
                         true},
                        // 4.
                        {")(*@)$*@^*&!(&!*)(*&!@()*!&_",
                         "@^*&!(@@",
                        false},
                        // 5.
                        {"I am a banana",
                         "Banana",
                        false},
                        // 6.
                        {"I am a banana",
                         "I am a bananas",
                        false},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        char *l_buf = NULL;
                        uint32_t l_len = 0;
                        bool l_match = false;
                        //NDBG_PRINT("COMP: %.*s == %.*s\n", (int)strlen(l_in), l_in, (int)strlen(l_vec[i_p].m_op_val), l_vec[i_p].m_op_val);
                        l_op.set_value(l_vec[i_p].m_op_val);
                        l_s = l_cb(l_match, l_op, l_in, strlen(l_in), &l_macro, l_rqst_ctx, NULL);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_match == l_vec[i_p].m_match));
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
        // -------------------------------------------------
        // VERIFYCC
        // -------------------------------------------------
        SECTION("VERIFYCC") {
                ns_waflz::op_t l_cb = NULL;
                l_cb = ns_waflz::get_op_cb(waflz_pb::sec_rule_t_operator_t_type_t_VERIFYCC);
                REQUIRE((l_cb != NULL));
                ns_waflz::macro l_macro;
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, NULL, false);
                waflz_pb::sec_rule_t_operator_t l_op;
                l_op.set_type(waflz_pb::sec_rule_t_operator_t_type_t_VERIFYCC);
                // -----------------------------------------
                // create regex obj...
                // -----------------------------------------
                int32_t l_s;
                ns_waflz::regex *l_rx = NULL;
                l_rx = new ns_waflz::regex();
                const char l_rx_str[] = "(?:^|[^\\d])(\\d{4}\\-?\\d{4}\\-?\\d{2}\\-?\\d{2}\\-?\\d{1,4})(?:[^\\d]|$)";
                l_s = l_rx->init(l_rx_str, strlen(l_rx_str));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_rx !=NULL));
                l_op.set__reserved_1((uint64_t)l_rx);
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"4532-8622-7821-8872",
                         "",
                        true},
                        // 2.
                        {"9999-9999-9999-9999",
                         "",
                         false},
                        // 3.
                        {"1234-cat",
                         "",
                         false}
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        char *l_buf = NULL;
                        uint32_t l_len = 0;
                        bool l_match = false;
                        l_s = l_cb(l_match, l_op, l_in, strlen(l_in), &l_macro, l_rqst_ctx, NULL);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_match == l_vec[i_p].m_match));
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                if(l_rx) { delete l_rx; l_rx = NULL; }
        }
        // -------------------------------------------------
        // VALIDATEBYTERANGE
        // -------------------------------------------------
        SECTION("VALIDATEBYTERANGE") {
                ns_waflz::op_t l_cb = NULL;
                l_cb = ns_waflz::get_op_cb(waflz_pb::sec_rule_t_operator_t_type_t_VALIDATEBYTERANGE);
                REQUIRE((l_cb != NULL));
                ns_waflz::macro l_macro;
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, NULL, false);
                waflz_pb::sec_rule_t_operator_t l_op;
                l_op.set_type(waflz_pb::sec_rule_t_operator_t_type_t_VALIDATEBYTERANGE);
                // -----------------------------------------
                // create regex obj...
                // -----------------------------------------
                int32_t l_s;
                ns_waflz::byte_range *l_br = NULL;
                l_br = new ns_waflz::byte_range();
                REQUIRE((l_br !=NULL));
                // C-I, s-w
                const char l_bf_str[] = "67-73,115-119";
                l_s = l_br->init(l_bf_str, strlen(l_bf_str));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_op.set__reserved_1((uint64_t)l_br);
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"ssCCIIsssssttttuuuuvvvwwww",
                         "",
                        false},
                        // 2.
                        {"ssCCIIsasssttttuuuuvvvwwww",
                         "",
                         true},
                        // 3.
                        {"1234-cat",
                         "",
                         true},
                        // 4.
                        {"1234",
                         "",
                         true},
                        // 5.
                        {"DFu",
                         "",
                        false},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        char *l_buf = NULL;
                        uint32_t l_len = 0;
                        bool l_match = false;
                        l_s = l_cb(l_match, l_op, l_in, strlen(l_in), &l_macro, l_rqst_ctx, NULL);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_match == l_vec[i_p].m_match));
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_br) { delete l_br; l_br = NULL; }
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
        // -------------------------------------------------
        // VALIDATEUTF8ENCODING
        // -------------------------------------------------
        SECTION("VALIDATEUTF8ENCODING") {
                ns_waflz::op_t l_cb = NULL;
                l_cb = ns_waflz::get_op_cb(waflz_pb::sec_rule_t_operator_t_type_t_VALIDATEUTF8ENCODING);
                REQUIRE((l_cb != NULL));
                ns_waflz::macro l_macro;
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, NULL, false);
                waflz_pb::sec_rule_t_operator_t l_op;
                l_op.set_type(waflz_pb::sec_rule_t_operator_t_type_t_VALIDATEUTF8ENCODING);
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"ssCCIIsssssttttuuuuvvvwwww",
                         "",
                        false},
                        // 2.
                        {"ssCCIIsasssttttuuuuvvvwwww",
                         "",
                         false},
                        // 3.
                        {"1234-cat",
                         "",
                         false},
                        // 3.
                        {"\xa0\xa1\x63",
                         "",
                         true},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        char *l_buf = NULL;
                        uint32_t l_len = 0;
                        bool l_match = false;
                        l_s = l_cb(l_match, l_op, l_in, strlen(l_in), &l_macro, l_rqst_ctx, NULL);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_match == l_vec[i_p].m_match));
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
        // -------------------------------------------------
        // VALIDATEURLENCODING
        // -------------------------------------------------
        SECTION("VALIDATEURLENCODING") {
                ns_waflz::op_t l_cb = NULL;
                l_cb = ns_waflz::get_op_cb(waflz_pb::sec_rule_t_operator_t_type_t_VALIDATEURLENCODING);
                REQUIRE((l_cb != NULL));
                ns_waflz::macro l_macro;
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, NULL, false);
                waflz_pb::sec_rule_t_operator_t l_op;
                l_op.set_type(waflz_pb::sec_rule_t_operator_t_type_t_VALIDATEURLENCODING);
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"ssCCIIsssssttttuuuuvvvwwww",
                         "",
                        false},
                        // 2.
                        {"ssCCIIsasssttttuuuuvvvwwww",
                         "",
                         false},
                        // 3.
                        {"1234-cat",
                         "",
                         false},
                        // 2.
                        {"ssCCIIs%ZZssttttuuuuvvvwwww",
                         "",
                         true},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        char *l_buf = NULL;
                        uint32_t l_len = 0;
                        bool l_match = false;
                        l_s = l_cb(l_match, l_op, l_in, strlen(l_in), &l_macro, l_rqst_ctx, NULL);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_match == l_vec[i_p].m_match));
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
        // -------------------------------------------------
        // WITHIN
        // -------------------------------------------------
        SECTION("WITHIN") {
                ns_waflz::op_t l_cb = NULL;
                l_cb = ns_waflz::get_op_cb(waflz_pb::sec_rule_t_operator_t_type_t_WITHIN);
                REQUIRE((l_cb != NULL));
                ns_waflz::macro l_macro;
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 1024, 1024, NULL, false);
                waflz_pb::sec_rule_t_operator_t l_op;
                l_op.set_type(waflz_pb::sec_rule_t_operator_t_type_t_WITHIN);
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"am",
                        "I am a banana",
                        true},
                        // 2.
                        {"scouts",
                         "dog scouts are cool cuz they eat all the cookies",
                        true},
                        // 3.
                        {"&!(&!*)(",
                         ")(*@)$*@^*&!(&!*)(*&!@()*!&_",
                         true},
                        // 4.
                        {"fuzzy",
                         "monkeymonkey",
                         false},
                        // 5.
                        {"@@##",
                         ")(*@)$*@^*&!(&!*)(*&!@()*!&_",
                         false},
                        // 6.
                        {"monkeymonkeymonkeymonkey",
                         "monkeymonkey",
                         false},
                        // 7.
                        {"e",
                         "a b c d e f g h i",
                         true},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        char *l_buf = NULL;
                        uint32_t l_len = 0;
                        bool l_match = false;
                        l_op.set_value(l_vec[i_p].m_op_val);
                        l_s = l_cb(l_match, l_op, l_in, strlen(l_in), &l_macro, l_rqst_ctx, NULL);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_match == l_vec[i_p].m_match));
                }
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
        // -------------------------------------------------
        // TODO
        // 1. macro expansion test
        // 2. value test
        // -------------------------------------------------
}
