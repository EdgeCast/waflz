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
#include "waflz/string_util.h"
#include "rule.pb.h"
#include "core/tx.h"
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
        uint32_t m_len;
} entry_t;
//! ----------------------------------------------------------------------------
//! parse
//! ----------------------------------------------------------------------------
TEST_CASE( "test tx", "[tx]" ) {
        ns_waflz::init_tx_cb_vector();
        // -------------------------------------------------
        // COMPRESSWHITESPACE
        // -------------------------------------------------
        SECTION("COMPRESSWHITESPACE") {
                ns_waflz::tx_cb_t l_cb = NULL;
                l_cb = ns_waflz::get_tx_cb(waflz_pb::sec_action_t_transformation_type_t_COMPRESSWHITESPACE);
                REQUIRE((l_cb != NULL));
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"I                   \tlove\n\r\v margaritas",
                         "I love margaritas",
                         0},
                        // 2.
                        {"I          love ma\x20rgaritas",
                         "I love ma rgaritas",
                         0},
                        // 3.
                        {"Sea s a l t             ",
                         "Sea s a l t "},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        uint32_t l_len = 0;
                        char *l_tx_data = NULL;
                        uint32_t l_tx_len = 0;
                        l_s = l_cb(&l_tx_data, l_tx_len, l_in, strlen(l_in));
                        std::string l_out(l_tx_data, l_tx_len);
                        //NDBG_PRINT("\nin:  %s\nout: %s\n and out len %u", l_in, l_out.c_str(), l_tx_len);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_out == l_vec[i_p].m_out));
                        if(l_tx_data){ free(l_tx_data); l_tx_data = NULL;}
                }
        }
        // -------------------------------------------------
        // REMOVEWHITESPACE
        // -------------------------------------------------
        SECTION("REMOVEWHITESPACE") {
                ns_waflz::tx_cb_t l_cb = NULL;
                l_cb = ns_waflz::get_tx_cb(waflz_pb::sec_action_t_transformation_type_t_REMOVEWHITESPACE);
                REQUIRE((l_cb != NULL));
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"I                   \tlove\n\r\v margaritas",
                         "Ilovemargaritas",
                         0},
                        // 2.
                        {"I          love ma\x20rgaritas",
                         "Ilovemargaritas",
                         0},
                        // 3.
                        {"Seasalt             ",
                         "Seasalt",
                         0},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        uint32_t l_len = 0;
                        char *l_tx_data = NULL;
                        uint32_t l_tx_len = 0;
                        l_s = l_cb(&l_tx_data, l_tx_len, l_in, strlen(l_in));
                        std::string l_out(l_tx_data, l_tx_len);
                        //NDBG_PRINT("\nin:  %s\nout: %s\n and out len %u", l_in, l_out.c_str(), l_tx_len);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_out == l_vec[i_p].m_out));
                        if(l_tx_data){ free(l_tx_data); l_tx_data = NULL;}
                }
        }
        // -------------------------------------------------
        // REMOVENULLS
        // -------------------------------------------------
        SECTION("REMOVENULLS") {
                ns_waflz::tx_cb_t l_cb = NULL;
                l_cb = ns_waflz::get_tx_cb(waflz_pb::sec_action_t_transformation_type_t_REMOVENULLS);
                REQUIRE((l_cb != NULL));
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"party""\0""\0""at my place",
                         "party  at my place",
                         18},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        uint32_t l_len = 0;
                        char *l_tx_data = NULL;
                        uint32_t l_tx_len = 0;
                        l_s = l_cb(&l_tx_data, l_tx_len, l_in, l_vec[i_p].m_len);
                        std::string l_out(l_tx_data, l_tx_len);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_out == l_vec[i_p].m_out));
                        if(l_tx_data){ free(l_tx_data); l_tx_data = NULL;}
                }
        }
        // -------------------------------------------------
        // HEXENCODE
        // -------------------------------------------------
        SECTION("HEXENCODE") {
                ns_waflz::tx_cb_t l_cb = NULL;
                l_cb = ns_waflz::get_tx_cb(waflz_pb::sec_action_t_transformation_type_t_HEXENCODE);
                REQUIRE((l_cb != NULL));
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"xyz",
                         "78797a",
                         0},
                        {"two shots of h2o",
                         "74776f2073686f7473206f662068326f",
                         0},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        uint32_t l_len = 0;
                        char *l_tx_data = NULL;
                        uint32_t l_tx_len = 0;
                        l_s = l_cb(&l_tx_data, l_tx_len, l_in, strlen(l_in));
                        std::string l_out(l_tx_data, l_tx_len);
                        //NDBG_PRINT("in:  %s:\nout: %s:\n and out len %u", l_in, l_out.c_str(), l_tx_len);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_out == l_vec[i_p].m_out));
                        if(l_tx_data){ free(l_tx_data); l_tx_data = NULL;}
                }
        }
        // -------------------------------------------------
        // LOWERCASE
        // -------------------------------------------------
        SECTION("LOWERCASE") {
                ns_waflz::tx_cb_t l_cb = NULL;
                l_cb = ns_waflz::get_tx_cb(waflz_pb::sec_action_t_transformation_type_t_LOWERCASE);
                REQUIRE((l_cb != NULL));
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"PARTy At mY PlAce",
                         "party at my place",
                         0},
                        // 2
                        {"AT 3 A.m",
                         "at 3 a.m",
                         0}
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        uint32_t l_len = 0;
                        char *l_tx_data = NULL;
                        uint32_t l_tx_len = 0;
                        l_s = l_cb(&l_tx_data, l_tx_len, l_in, strlen(l_in));
                        std::string l_out(l_tx_data, l_tx_len);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_out == l_vec[i_p].m_out));
                        if(l_tx_data){ free(l_tx_data); l_tx_data = NULL;}
                }
        }
        // -------------------------------------------------
        // LOWERCASE
        // -------------------------------------------------
        SECTION("LOWERCASE") {
                ns_waflz::tx_cb_t l_cb = NULL;
                l_cb = ns_waflz::get_tx_cb(waflz_pb::sec_action_t_transformation_type_t_LOWERCASE);
                REQUIRE((l_cb != NULL));
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"PARTy At mY PlAce",
                         "party at my place",
                         0},
                        // 2
                        {"AT 3 A.m",
                         "at 3 a.m",
                         0}
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        uint32_t l_len = 0;
                        char *l_tx_data = NULL;
                        uint32_t l_tx_len = 0;
                        l_s = l_cb(&l_tx_data, l_tx_len, l_in, strlen(l_in));
                        std::string l_out(l_tx_data, l_tx_len);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((l_out == l_vec[i_p].m_out));
                        if(l_tx_data){ free(l_tx_data); l_tx_data = NULL;}
                }
        }
        // -------------------------------------------------
        // NORMALISEPATH
        // -------------------------------------------------
        SECTION("NORMALISEPATH") {
                ns_waflz::tx_cb_t l_cb = NULL;
                l_cb = ns_waflz::get_tx_cb(waflz_pb::sec_action_t_transformation_type_t_NORMALISEPATH);
                REQUIRE((l_cb != NULL));
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"/don't/puke/in/my/party?mix='select * from bar'&eat='prunes'",
                         "/don't/puke/in/my/party?mix='select * from bar'&eat='prunes'",
                         0},
                        // 2
                        {"/don't/puke/in/my/party/../../yourparty/do/./././whatyouwant/././",
                         "/don't/puke/in/yourparty/do/whatyouwant/",
                         0}
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        uint32_t l_len = 0;
                        char *l_tx_data = NULL;
                        uint32_t l_tx_len = 0;
                        l_s = l_cb(&l_tx_data, l_tx_len, l_in, strlen(l_in));
                        std::string l_out(l_tx_data, l_tx_len);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        //NDBG_PRINT("in:  %s:\nout: %s:\n and out len %u", l_in, l_out.c_str(), l_tx_len);
                        REQUIRE((strncmp(l_tx_data, l_vec[i_p].m_out, l_tx_len)) == 0);
                        if(l_tx_data){ free(l_tx_data); l_tx_data = NULL;}
                }
        }
        // -------------------------------------------------
        // NORMALIZEPATH
        // -------------------------------------------------
        SECTION("NORMALIZEPATH") {
                ns_waflz::tx_cb_t l_cb = NULL;
                l_cb = ns_waflz::get_tx_cb(waflz_pb::sec_action_t_transformation_type_t_NORMALIZEPATH);
                REQUIRE((l_cb != NULL));
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"/don't/puke/in/my/party?mix='select * from bar'&eat='prunes'",
                         "/don't/puke/in/my/party?mix='select * from bar'&eat='prunes'",
                         0},
                        // 2
                        {"/don't/puke/in/my/party/../../yourparty/do/./././whatyouwant/././",
                         "/don't/puke/in/yourparty/do/whatyouwant/",
                         0}
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        uint32_t l_len = 0;
                        char *l_tx_data = NULL;
                        uint32_t l_tx_len = 0;
                        l_s = l_cb(&l_tx_data, l_tx_len, l_in, strlen(l_in));
                        std::string l_out(l_tx_data, l_tx_len);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        //NDBG_PRINT("in:  %s:\nout: %s:\n and out len %u", l_in, l_out.c_str(), l_tx_len);
                        REQUIRE((strncmp(l_tx_data, l_vec[i_p].m_out, l_tx_len)) == 0);
                        if(l_tx_data){ free(l_tx_data); l_tx_data = NULL;}
                }
        }
        // -------------------------------------------------
        // NORMALIZEPATHWIN
        // -------------------------------------------------
        SECTION("NORMALIZEPATHWIN") {
                ns_waflz::tx_cb_t l_cb = NULL;
                l_cb = ns_waflz::get_tx_cb(waflz_pb::sec_action_t_transformation_type_t_NORMALIZEPATHWIN);
                REQUIRE((l_cb != NULL));
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"/don't/puke/in/my/party?mix='select * from bar'&eat='prunes'",
                         "/don't/puke/in/my/party?mix='select * from bar'&eat='prunes'",
                         0},
                        // 2
                        {"/don't/puke/in/my/party/../../yourparty/do/./././whatyouwant/././",
                         "/don't/puke/in/yourparty/do/whatyouwant/",
                         0},
                        // 3
                        {"/don't/puke/in/my\\party/you\\monkey",
                         "/don't/puke/in/my/party/you/monkey",
                         0}
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        uint32_t l_len = 0;
                        char *l_tx_data = NULL;
                        uint32_t l_tx_len = 0;
                        l_s = l_cb(&l_tx_data, l_tx_len, l_in, strlen(l_in));
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((strncmp(l_tx_data, l_vec[i_p].m_out, l_tx_len)) == 0);
                        if(l_tx_data){ free(l_tx_data); l_tx_data = NULL;}
                }
        }
        // -------------------------------------------------
        // CSSDECODE
        // -------------------------------------------------
        SECTION("CSSDECODE") {
                ns_waflz::tx_cb_t l_cb = NULL;
                l_cb = ns_waflz::get_tx_cb(waflz_pb::sec_action_t_transformation_type_t_CSSDECODE);
                REQUIRE((l_cb != NULL));
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"Test\0Case",
                         "Test\0Case",
                         9},
                        {"test\\a\\b\\f\\n\\r\\t\\v\\?\\'\\\"\\0\\12\\123\\1234\\12345\\123456\\ff01\\ff5e\\\n\\0  string",
                         "test\x0a\x0b\x0fnrtv?\'\"\x00\x12\x23\x34\x45\x56\x21\x7e\x00 string",
                         74},
                        // 2
                        {"test\\",
                         "test",
                         5},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        uint32_t l_len = 0;
                        char *l_tx_data = NULL;
                        uint32_t l_tx_len = 0;
                        l_s = l_cb(&l_tx_data, l_tx_len, l_in, l_vec[i_p].m_len);
                        std::string l_out(l_tx_data, l_tx_len);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((strncmp(l_tx_data, l_vec[i_p].m_out, l_tx_len)) == 0);
                        if(l_tx_data){ free(l_tx_data); l_tx_data = NULL;}
                }
        }
        // -------------------------------------------------
        // HTMLENTITYDECODE
        // -------------------------------------------------
        SECTION("HTMLENTITYDECODE") {
                ns_waflz::tx_cb_t l_cb = NULL;
                l_cb = ns_waflz::get_tx_cb(waflz_pb::sec_action_t_transformation_type_t_HTMLENTITYDECODE);
                REQUIRE((l_cb != NULL));
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"TestCase",
                         "TestCase",
                         8},
                        {"&#x0&#X0&#x20&#X20&#0&#32\0&#100&quot&amp&lt&gt&nbsp",
                         "\0\0\x20\x20\0\x20\0\x64\"&<>\xa0",
                         52},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        uint32_t l_len = 0;
                        char *l_tx_data = NULL;
                        uint32_t l_tx_len = 0;
                        l_s = l_cb(&l_tx_data, l_tx_len, l_in, l_vec[i_p].m_len);
                        std::string l_out(l_tx_data, l_tx_len);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((strncmp(l_tx_data, l_vec[i_p].m_out, l_tx_len)) == 0);
                        if(l_tx_data){ free(l_tx_data); l_tx_data = NULL;}
                }
        }
        // -------------------------------------------------
        // JSDECODE
        // -------------------------------------------------
        SECTION("JSDECODE") {
                ns_waflz::tx_cb_t l_cb = NULL;
                l_cb = ns_waflz::get_tx_cb(waflz_pb::sec_action_t_transformation_type_t_JSDECODE);
                REQUIRE((l_cb != NULL));
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"Testcase",
                         "Testcase",
                         8},
                        {"\\x\\x0",
                         "xx0",
                         5},
                        {"\\x\\x0\0",
                         "xx0\0",
                         6},
                        {"\\u\\u0\\u01\\u012",
                         "uu0u01u012",
                         14}
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        uint32_t l_len = 0;
                        char *l_tx_data = NULL;
                        uint32_t l_tx_len = 0;
                        l_s = l_cb(&l_tx_data, l_tx_len, l_in, l_vec[i_p].m_len);
                        std::string l_out(l_tx_data, l_tx_len);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((strncmp(l_tx_data, l_vec[i_p].m_out, l_tx_len)) == 0);
                        if(l_tx_data){ free(l_tx_data); l_tx_data = NULL;}
                }
        }
        // -------------------------------------------------
        // CMDLINE
        // -------------------------------------------------
        SECTION("CMDLINE") {
                ns_waflz::tx_cb_t l_cb = NULL;
                l_cb = ns_waflz::get_tx_cb(waflz_pb::sec_action_t_transformation_type_t_CMDLINE);
                REQUIRE((l_cb != NULL));
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"c^ommand /c ",
                         "command/c "},
                        {"\"command\" /c",
                         "command/c"}
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        uint32_t l_len = 0;
                        char *l_tx_data = NULL;
                        uint32_t l_tx_len = 0;
                        l_s = l_cb(&l_tx_data, l_tx_len, l_in, strlen(l_vec[i_p].m_in));
                        std::string l_out(l_tx_data, l_tx_len);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((strncmp(l_tx_data, l_vec[i_p].m_out, l_tx_len)) == 0);
                        if(l_tx_data){ free(l_tx_data); l_tx_data = NULL;}
                }
        }
        // -------------------------------------------------
        // REPLACECOMMENTS
        // -------------------------------------------------
        SECTION("REPLACECOMMENTS") {
                ns_waflz::tx_cb_t l_cb = NULL;
                l_cb = ns_waflz::get_tx_cb(waflz_pb::sec_action_t_transformation_type_t_REPLACECOMMENTS);
                REQUIRE((l_cb != NULL));
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"/*hey lets remove comments */",
                         " "},
                        {"before /*hey lets remove comments */",
                         "before  "},
                        {"/*hey lets remove comments */After",
                         " After"},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        uint32_t l_len = 0;
                        char *l_tx_data = NULL;
                        uint32_t l_tx_len = 0;
                        l_s = l_cb(&l_tx_data, l_tx_len, l_in, strlen(l_vec[i_p].m_in));
                        std::string l_out(l_tx_data, l_tx_len);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((strncmp(l_tx_data, l_vec[i_p].m_out, l_tx_len)) == 0);
                        if(l_tx_data){ free(l_tx_data); l_tx_data = NULL;}
                }
        }
        // -------------------------------------------------
        // REMOVECOMMENTS
        // -------------------------------------------------
        SECTION("REMOVECOMMENTS") {
                ns_waflz::tx_cb_t l_cb = NULL;
                l_cb = ns_waflz::get_tx_cb(waflz_pb::sec_action_t_transformation_type_t_REMOVECOMMENTS);
                REQUIRE((l_cb != NULL));
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"/*hey lets remove comments */",
                         ""},
                        // 2
                        {"howdy<!--hey lets remove comments-->",
                         "howdy"},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        uint32_t l_len = 0;
                        char *l_tx_data = NULL;
                        uint32_t l_tx_len = 0;
                        l_s = l_cb(&l_tx_data, l_tx_len, l_in, strlen(l_vec[i_p].m_in));
                        std::string l_out(l_tx_data, l_tx_len);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((strncmp(l_tx_data, l_vec[i_p].m_out, l_tx_len)) == 0);
                        if(l_tx_data){ free(l_tx_data); l_tx_data = NULL;}
                }
        }
        // -------------------------------------------------
        // LENGTH
        // -------------------------------------------------
        SECTION("LENGTH") {
                ns_waflz::tx_cb_t l_cb = NULL;
                l_cb = ns_waflz::get_tx_cb(waflz_pb::sec_action_t_transformation_type_t_LENGTH);
                REQUIRE((l_cb != NULL));
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"0123456789\tabcdef",
                         "",
                         17},
                        // 2
                        {"Howdy\0dude",
                         "",
                         9},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        uint32_t l_len = 0;
                        char *l_tx_data = NULL;
                        uint32_t l_tx_len = 0;
                        l_s = l_cb(&l_tx_data, l_tx_len, l_in, l_vec[i_p].m_len);
                        std::string l_out(l_tx_data, l_tx_len);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE(l_tx_data == ns_waflz::to_string(l_vec[i_p].m_len));
                        if(l_tx_data){ free(l_tx_data); l_tx_data = NULL;}
                }
        }
        // -------------------------------------------------
        // URLDECODE
        // -------------------------------------------------
        SECTION("URLDECODE") {
                ns_waflz::tx_cb_t l_cb = NULL;
                l_cb = ns_waflz::get_tx_cb(waflz_pb::sec_action_t_transformation_type_t_URLDECODE);
                REQUIRE((l_cb != NULL));
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"%%",
                         "%%",
                         2},
                        {"%0g%20",
                         "%0g ",
                         6},
                        {"%0g%1g%2g%3g%4g%5g%6g%7g%8g%9g%0g%ag%bg%cg%dg%eg%fg",
                         "%0g%1g%2g%3g%4g%5g%6g%7g%8g%9g%0g%ag%bg%cg%dg%eg%fg",
                          51}
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        uint32_t l_len = 0;
                        char *l_tx_data = NULL;
                        uint32_t l_tx_len = 0;
                        l_s = l_cb(&l_tx_data, l_tx_len, l_in, l_vec[i_p].m_len);
                        std::string l_out(l_tx_data, l_tx_len);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((strncmp(l_tx_data, l_vec[i_p].m_out, l_tx_len)) == 0);
                        if(l_tx_data){ free(l_tx_data); l_tx_data = NULL;}
                }
        }
        #if 0
        NOT supported
        // -------------------------------------------------
        // URLDECODEUNI
        // -------------------------------------------------
        #endif
        // -------------------------------------------------
        // UTF8TOUNICODE
        // -------------------------------------------------
        SECTION("UTF8TOUNICODE") {
                ns_waflz::tx_cb_t l_cb = NULL;
                l_cb = ns_waflz::get_tx_cb(waflz_pb::sec_action_t_transformation_type_t_UTF8TOUNICODE);
                REQUIRE((l_cb != NULL));
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {" ⟀ ⟁ ⟂ ⟃ ⟄ ⟅ ⟆ ⟇ ⟈ ⟉ ⟊ ⟌ ⟐ ⟑ ⟒ ⟓ ⟔ ⟕ ⟖ ⟗ ⟘ ⟙ ⟚ ⟛ ⟜ ⟝ ⟞ ⟟ ⟠ ⟡ ⟢ ⟣ ⟤ ⟥ ⟦ ⟧ ⟨ ⟩ ⟪ ⟫ ⟬ ⟭ ⟮ ⟯",
                         " %u27c0 %u27c1 %u27c2 %u27c3 %u27c4 %u27c5 %u27c6 %u27c7 %u27c8 %u27c9 %u27ca %u27cc %u27d0 %u27d1 %u27d2 %u27d3 %u27d4 %u27d5 %u27d6 %u27d7 %u27d8 %u27d9 %u27da %u27db %u27dc %u27dd %u27de %u27df %u27e0 %u27e1 %u27e2 %u27e3 %u27e4 %u27e5 %u27e6 %u27e7 %u27e8 %u27e9 %u27ea %u27eb %u27ec %u27ed %u27ee %u27ef"},
                        {" ⟰ ⟱ ⟲ ⟳ ⟴ ⟵ ⟶ ⟷ ⟸ ⟹ ⟺ ⟻ ⟼ ⟽ ⟾ ⟿",
                         " %u27f0 %u27f1 %u27f2 %u27f3 %u27f4 %u27f5 %u27f6 %u27f7 %u27f8 %u27f9 %u27fa %u27fb %u27fc %u27fd %u27fe %u27ff"},
                         " ب ة ت ث ج ح خ د ذ ر ز س ش ص ض ط ظ ع غ ـ ف ق ك ل م ن ه و ى ي ٖ ٗ ٘ ٙ ٠ ١ ٢ ٣ ٤ ٥ ٦ ٧ ٨ ٩ ٪ ٫ ٬ ٭ ٮ ٯ ٱ ٲ ٳ ٴ ٵ ٶ ٷ ٸ ٹ ٺ ٻ ټ ٽ پ ٿ ڀ ځ ڂ ڃ ڄ څ چ ڇ ڈ ډ ڊ ڋ ڌ ڍ ڎ ڏ ڐ ڑ ڒ ړ ڔ ڕ ږ ڗ ژ ڙ ښ ڛ ڜ ڝ ڞ ڟ ڠ ڡ ڢ ڣ ڤ ڥ ڦ ڧ ڨ ک ڪ ګ ڬ ڭ ڮ گ ڰ ڱ ڲ ڳ ڴ ڵ ڶ ڷ ڸ ڹ ں ڻ ڼ ڽ ھ ڿ ۀ ہ ۂ ۃ ۄ ۅ ۆ ۇ ۈ ۉ ۊ ۋ ی ۍ ێ ۏ ې ۑ ے ۓ ۔ ە ۝ ۞ ۥ ۦ ۩ ۮ ۯ ۰ ۱ ۲ ۳ ۴ ۵ ۶ ۷ ۸ ۹ ۺ ۻ ۼ ۽ ۾ ",
                         " %u0628 %u0629 %u062a %u062b %u062c %u062d %u062e %u062f %u0630 %u0631 %u0632 %u0633 %u0634 %u0635 %u0636 %u0637 %u0638 %u0639 %u063a %u0640 %u0641 %u0642 %u0643 %u0644 %u0645 %u0646 %u0647 %u0648 %u0649 %u064a %u0656 %u0657 %u0658 %u0659 %u0660 %u0661 %u0662 %u0663 %u0664 %u0665 %u0666 %u0667 %u0668 %u0669 %u066a %u066b %u066c %u066d %u066e %u066f %u0671 %u0672 %u0673 %u0674 %u0675 %u0676 %u0677 %u0678 %u0679 %u067a %u067b %u067c %u067d %u067e %u067f %u0680 %u0681 %u0682 %u0683 %u0684 %u0685 %u0686 %u0687 %u0688 %u0689 %u068a %u068b %u068c %u068d %u068e %u068f %u0690 %u0691 %u0692 %u0693 %u0694 %u0695 %u0696 %u0697 %u0698 %u0699 %u069a %u069b %u069c %u069d %u069e %u069f %u06a0 %u06a1 %u06a2 %u06a3 %u06a4 %u06a5 %u06a6 %u06a7 %u06a8 %u06a9 %u06aa %u06ab %u06ac %u06ad %u06ae %u06af %u06b0 %u06b1 %u06b2 %u06b3 %u06b4 %u06b5 %u06b6 %u06b7 %u06b8 %u06b9 %u06ba %u06bb %u06bc %u06bd %u06be %u06bf %u06c0 %u06c1 %u06c2 %u06c3 %u06c4 %u06c5 %u06c6 %u06c7 %u06c8 %u06c9 %u06ca %u06cb %u06cc %u06cd %u06ce %u06cf %u06d0 %u06d1 %u06d2 %u06d3 %u06d4 %u06d5 %u06dd %u06de %u06e5 %u06e6 %u06e9 %u06ee %u06ef %u06f0 %u06f1 %u06f2 %u06f3 %u06f4 %u06f5 %u06f6 %u06f7 %u06f8 %u06f9 %u06fa %u06fb %u06fc %u06fd %u06fe "
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        uint32_t l_len = 0;
                        char *l_tx_data = NULL;
                        uint32_t l_tx_len = 0;
                        l_s = l_cb(&l_tx_data, l_tx_len, l_in, strlen(l_vec[i_p].m_in));
                        std::string l_out(l_tx_data, l_tx_len);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((strncmp(l_tx_data, l_vec[i_p].m_out, l_tx_len)) == 0);
                        if(l_tx_data){ free(l_tx_data); l_tx_data = NULL;}
                }
        }
        // -------------------------------------------------
        // SHA1
        // -------------------------------------------------
        SECTION("SHA1") {
                ns_waflz::tx_cb_t l_cb = NULL;
                l_cb = ns_waflz::get_tx_cb(waflz_pb::sec_action_t_transformation_type_t_SHA1);
                REQUIRE((l_cb != NULL));
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"TestCase",
                         "\xa7\x0c\xe3\x83\x89\xe3\x18\xbd\x2b\xe1\x8a\x01\x11\xc6\xdc\x76\xbd\x2c\xd9\xed"},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        uint32_t l_len = 0;
                        char *l_tx_data = NULL;
                        uint32_t l_tx_len = 0;
                        l_s = l_cb(&l_tx_data, l_tx_len, l_in, strlen(l_in));
                        std::string l_out(l_tx_data, l_tx_len);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((strncmp(l_tx_data, l_vec[i_p].m_out, l_tx_len)) == 0);
                        if(l_tx_data){ free(l_tx_data); l_tx_data = NULL;}
                }
        }
        // -------------------------------------------------
        // MD5
        // -------------------------------------------------
        SECTION("MD5") {
                ns_waflz::tx_cb_t l_cb = NULL;
                l_cb = ns_waflz::get_tx_cb(waflz_pb::sec_action_t_transformation_type_t_MD5);
                REQUIRE((l_cb != NULL));
                // -----------------------------------------
                // vector
                // -----------------------------------------
                entry_t l_vec[] = {
                        // 1.
                        {"TestCase",
                         "\xc9\xab\xa2\xc3\xe6\x01\x26\x16\x9e\x80\xe9\xa2\x6b\xa2\x73\xc1"},
                };
                // -----------------------------------------
                // loop
                // -----------------------------------------
                for(uint32_t i_p = 0; i_p < ARRAY_SIZE(l_vec); ++i_p)
                {
                        int32_t l_s;
                        const char *l_in = l_vec[i_p].m_in;
                        uint32_t l_len = 0;
                        char *l_tx_data = NULL;
                        uint32_t l_tx_len = 0;
                        l_s = l_cb(&l_tx_data, l_tx_len, l_in, strlen(l_in));
#if 0
                        for(uint32_t i = 0; i < l_tx_len; ++i)
                        {
                                NDBG_PRINT("%02x\n", l_tx_data[i]);
                        }
#endif
                        std::string l_out(l_tx_data, l_tx_len);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                        REQUIRE((strncmp(l_tx_data, l_vec[i_p].m_out, l_tx_len)) == 0);
                        if(l_tx_data){ free(l_tx_data); l_tx_data = NULL;}
                }
        }
}
