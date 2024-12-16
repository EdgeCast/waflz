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
#include "support/ndebug.h"
#include "waflz/limit.h"
#include "waflz/rqst_ctx.h"
#include "waflz/def.h"
#include "limit.pb.h"
#include "waflz/lm_db.h"
#include <string.h>
#include <unistd.h>
#include <iostream>
//! ----------------------------------------------------------------------------
//! limits
//! ----------------------------------------------------------------------------
TEST_CASE( "limit test", "[limit]" ) {
        // -------------------------------------------------
        // create lmdb for limit
        // -------------------------------------------------
        ns_waflz::kv_db* l_db = NULL;
        l_db = reinterpret_cast<ns_waflz::kv_db *>(new ns_waflz::lm_db());
        // -------------------------------------------------
        // test status code parsing
        // -------------------------------------------------
        SECTION("test bad status_code key parsing") {
                // -----------------------------------------
                // create a limit to test
                // -----------------------------------------
                ns_waflz::limit l_limit(*l_db, false);
                // -----------------------------------------
                // bad status code
                // no numbers
                // -----------------------------------------
                uint32_t l_status = l_limit.load_status_codes_key("STATUS_CODE:just straight bad,example");
                // -----------------------------------------
                // should fail to parse
                // -----------------------------------------
                REQUIRE((l_status != WAFLZ_STATUS_OK));
                REQUIRE(strcmp(l_limit.get_err_msg(),
                               "failed to parse token: 'just straight bad' in entry: 'STATUS_CODE:just straight bad,example'") == 0);
                // -----------------------------------------
                // bad status code
                // same thing, with a good entry before
                // -----------------------------------------
                l_status = l_limit.load_status_codes_key("STATUS_CODE:500,just straight bad,example");
                // -----------------------------------------
                // should fail to parse
                // -----------------------------------------
                REQUIRE((l_status != WAFLZ_STATUS_OK));
                REQUIRE(strcmp(l_limit.get_err_msg(),
                               "failed to parse token: 'just straight bad' in entry: 'STATUS_CODE:500,just straight bad,example'") == 0);
                // -----------------------------------------
                // bad status code
                // negative number (should be seen as an
                // incomplete range)
                // -----------------------------------------
                l_status = l_limit.load_status_codes_key("STATUS_CODE:-1");
                // -----------------------------------------
                // should fail to parse
                // -----------------------------------------
                REQUIRE((l_status != WAFLZ_STATUS_OK));
                REQUIRE(strcmp(l_limit.get_err_msg(),
                               "failed to parse token: '-1' in entry: 'STATUS_CODE:-1'") == 0);
                // -----------------------------------------
                // bad status code
                // bad range
                // -----------------------------------------
                l_status = l_limit.load_status_codes_key("STATUS_CODE:1-");
                // -----------------------------------------
                // should fail to parse
                // -----------------------------------------
                REQUIRE((l_status != WAFLZ_STATUS_OK));
                REQUIRE(strcmp(l_limit.get_err_msg(),
                               "failed to parse token: '1-' in entry: 'STATUS_CODE:1-'") == 0);
                // -----------------------------------------
                // bad status code
                // bad number in second half of range
                // -----------------------------------------
                l_status = l_limit.load_status_codes_key("STATUS_CODE:1--");
                // -----------------------------------------
                // should fail to parse
                // -----------------------------------------
                REQUIRE((l_status != WAFLZ_STATUS_OK));
                REQUIRE(strcmp(l_limit.get_err_msg(),
                               "failed to parse token: '1--' in entry: 'STATUS_CODE:1--'") == 0);
                // -----------------------------------------
                // bad status code
                // negative number (should be seen as an
                // incomplete range)
                // -----------------------------------------
                l_status = l_limit.load_status_codes_key("STATUS_CODE:1-test");
                // -----------------------------------------
                // should fail to parse
                // -----------------------------------------
                REQUIRE((l_status != WAFLZ_STATUS_OK));
                REQUIRE(strcmp(l_limit.get_err_msg(),
                               "failed to parse token: '1-test' in entry: 'STATUS_CODE:1-test'") == 0);
                // -----------------------------------------
                // bad status code
                // crazy number! should be uint32_t overflow
                // -----------------------------------------
                l_status = l_limit.load_status_codes_key("STATUS_CODE:4294967298");
                // -----------------------------------------
                // should fail to parse
                // -----------------------------------------
                REQUIRE((l_status != WAFLZ_STATUS_OK));
                REQUIRE(strcmp(l_limit.get_err_msg(),
                               "failed to parse token: '4294967298' in entry: 'STATUS_CODE:4294967298'") == 0);
                // -----------------------------------------
                // bad status code
                // crazy number! should be uint64_t overflow
                // -----------------------------------------
                l_status = l_limit.load_status_codes_key("STATUS_CODE:999999999999999999999999999999999999999999999999");
                // -----------------------------------------
                // should fail to parse
                // -----------------------------------------
                REQUIRE((l_status != WAFLZ_STATUS_OK));
                REQUIRE(strcmp(l_limit.get_err_msg(),
                               "failed to parse token: '999999999999999999999999999999999999999999999999' in entry: 'STATUS_CODE:999999999999999999999999999999999999999999999999'") == 0);
                // -----------------------------------------
                // bad status code
                // not a number
                // -----------------------------------------
                l_status = l_limit.load_status_codes_key("STATUS_CODE:1test");
                // -----------------------------------------
                // should fail to parse
                // -----------------------------------------
                REQUIRE((l_status != WAFLZ_STATUS_OK));
                REQUIRE(strcmp(l_limit.get_err_msg(),
                               "failed to parse token: '1test' in entry: 'STATUS_CODE:1test'") == 0);
                // -----------------------------------------
                // bad status code
                // not a number
                // -----------------------------------------
                l_status = l_limit.load_status_codes_key("STATUS_CODE:,,");
                // -----------------------------------------
                // should fail to parse
                // -----------------------------------------
                REQUIRE((l_status != WAFLZ_STATUS_OK));
                REQUIRE(strcmp(l_limit.get_err_msg(),
                               "failed to parse token: '' in entry: 'STATUS_CODE:,,'") == 0);
        }
        // -------------------------------------------------
        // test more status code parsing
        // -------------------------------------------------
        SECTION("test good status_code key parsing") {
                // -----------------------------------------
                // create a limit to test
                // -----------------------------------------
                ns_waflz::limit l_limit(*l_db, false);
                // -----------------------------------------
                // good number - just 100
                // -----------------------------------------
                uint32_t l_status = l_limit.load_status_codes_key("STATUS_CODE:100");
                // -----------------------------------------
                // should have a range of 100-100
                // -----------------------------------------
                REQUIRE((l_status == WAFLZ_STATUS_OK));
                auto l_codes = l_limit.get_status_codes();
                REQUIRE(l_codes->size() == 1);
                REQUIRE((*l_codes)[0].m_start == 100);
                REQUIRE((*l_codes)[0].m_end == 100);
                l_limit.clear_status_codes();
                // -----------------------------------------
                // good number - range 100 to 200
                // -----------------------------------------
                l_status = l_limit.load_status_codes_key("STATUS_CODE:100-200");
                // -----------------------------------------
                // should have a range of 100-200
                // -----------------------------------------
                REQUIRE((l_status == WAFLZ_STATUS_OK));
                l_codes = l_limit.get_status_codes();
                REQUIRE(l_codes->size() == 1);
                REQUIRE((*l_codes)[0].m_start == 100);
                REQUIRE((*l_codes)[0].m_end == 200);
                l_limit.clear_status_codes();
                // -----------------------------------------
                // good number - 100 and 324
                // -----------------------------------------
                l_status = l_limit.load_status_codes_key("STATUS_CODE:100,324");
                // -----------------------------------------
                // should have a two ranges: 100-100, 324-324
                // -----------------------------------------
                REQUIRE((l_status == WAFLZ_STATUS_OK));
                l_codes = l_limit.get_status_codes();
                REQUIRE(l_codes->size() == 2);
                REQUIRE((*l_codes)[0].m_start == 100);
                REQUIRE((*l_codes)[0].m_end == 100);
                REQUIRE((*l_codes)[1].m_start == 324);
                REQUIRE((*l_codes)[1].m_end == 324);
                l_limit.clear_status_codes();
                // -----------------------------------------
                // good number - 100 and 785 and 320-328
                // -----------------------------------------
                l_status = l_limit.load_status_codes_key("STATUS_CODE:100,785,320-328");
                // -----------------------------------------
                // should have a three ranges:
                // 100-100,
                // 785-785
                // 320-328
                // -----------------------------------------
                REQUIRE((l_status == WAFLZ_STATUS_OK));
                l_codes = l_limit.get_status_codes();
                REQUIRE(l_codes->size() == 3);
                REQUIRE((*l_codes)[0].m_start == 100);
                REQUIRE((*l_codes)[0].m_end == 100);
                REQUIRE((*l_codes)[1].m_start == 785);
                REQUIRE((*l_codes)[1].m_end == 785);
                REQUIRE((*l_codes)[2].m_start == 320);
                REQUIRE((*l_codes)[2].m_end == 328);
                l_limit.clear_status_codes();
                // -----------------------------------------
                // good number - 128-200
                // bad order, but we can fix it.
                // -----------------------------------------
                l_status = l_limit.load_status_codes_key("STATUS_CODE:200-128");
                // -----------------------------------------
                // should have a 1 ranges: 128-200
                // -----------------------------------------
                REQUIRE((l_status == WAFLZ_STATUS_OK));
                l_codes = l_limit.get_status_codes();
                REQUIRE(l_codes->size() == 1);
                REQUIRE((*l_codes)[0].m_start == 128);
                REQUIRE((*l_codes)[0].m_end == 200);
                l_limit.clear_status_codes();
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if (l_db) { delete l_db; l_db = NULL; }
}

