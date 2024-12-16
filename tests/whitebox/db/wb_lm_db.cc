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
#include "waflz/def.h"
#include "waflz/lm_db.h"
#include "support/time_util.h"
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define MONKEY_KEY "TEST::KEY::MONKEY::BONGO"
#define BANANA_KEY "TEST::KEY::BANANA::SMELLY"
#define TEST_KEY "TEST::KEY::TEST::NONE"
//!-----------------------------------------------------------------------------
//! get db dir path
//! ----------------------------------------------------------------------------
static void get_lmdb_path(std::string& a_path)
{
        std::string l_file(__FILE__);
        size_t l_pos = l_file.find("whitebox");
        a_path.assign(l_file.substr(0, l_pos));
        a_path.append("data/waf/db/test_lmdb");
}
//!-----------------------------------------------------------------------------
//! lm_db
//! ----------------------------------------------------------------------------
TEST_CASE( "lmdb test", "[lmdb]" ) {
        SECTION("validate bad init") {
                int32_t l_s;
                ns_waflz::lm_db l_db;
                const char l_bad_db_dir[] = "/fish/fish/fish";
                l_s = l_db.set_opt(ns_waflz::lm_db::OPT_LMDB_DIR_PATH, l_bad_db_dir, strlen(l_bad_db_dir));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_db.init();
                REQUIRE((l_s == WAFLZ_STATUS_ERROR));
        }
        SECTION("validate good init") {
                int32_t l_s;
                ns_waflz::lm_db l_db;
                // get lmdb dir path
                std::string l_db_dir;
                get_lmdb_path(l_db_dir);
                // init
                l_db.set_opt(ns_waflz::lm_db::OPT_LMDB_DIR_PATH, l_db_dir.c_str(), l_db_dir.length());
                l_db.set_opt(ns_waflz::lm_db::OPT_LMDB_READERS, NULL, 6);
                l_db.set_opt(ns_waflz::lm_db::OPT_LMDB_MMAP_SIZE, NULL, 10485760);
                l_s = l_db.init();
                REQUIRE(l_s == WAFLZ_STATUS_OK);
        }
        SECTION("validate increment key and expiration") {
                int32_t l_s;
                ns_waflz::lm_db l_db;
                bool l_dummy;
                // get lmdb dir path
                std::string l_db_dir;
                get_lmdb_path(l_db_dir);
                // init
                l_db.set_opt(ns_waflz::lm_db::OPT_LMDB_DIR_PATH, l_db_dir.c_str(), l_db_dir.length());
                l_db.set_opt(ns_waflz::lm_db::OPT_LMDB_READERS, NULL, 6);
                l_db.set_opt(ns_waflz::lm_db::OPT_LMDB_MMAP_SIZE, NULL, 10485760);
                l_s = l_db.init();
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                int64_t l_result;
                l_s = l_db.increment_key(l_result, MONKEY_KEY, 2000, false, l_dummy);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                REQUIRE(l_result == 1);
                l_s = l_db.increment_key(l_result, MONKEY_KEY, 2000, false, l_dummy);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                REQUIRE(l_result == 2);
                l_s = l_db.increment_key(l_result, BANANA_KEY, 4000, false, l_dummy);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                REQUIRE(l_result == 1);
                l_s = l_db.increment_key(l_result, BANANA_KEY, 4000, false, l_dummy);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                REQUIRE(l_result == 2);
                // sleep for 2 seconds, monkey key should have been expired
                usleep(2000000);
                // increment the test key, this should have cleared monkey key
                l_s = l_db.increment_key(l_result, TEST_KEY, 1000, false, l_dummy);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                l_s = l_db.get_key(l_result, MONKEY_KEY, strlen(MONKEY_KEY));
                REQUIRE(l_s == WAFLZ_STATUS_ERROR);
                l_s = l_db.get_key(l_result, BANANA_KEY, strlen(BANANA_KEY));
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                REQUIRE(l_result == 2);
                // sleep for 2 more seconds, banana key should have been expired
                usleep(2000000);
                // increment the test key, this should have cleared banana key
                l_s = l_db.increment_key(l_result, TEST_KEY, 1000, false, l_dummy);
                l_s = l_db.get_key(l_result, BANANA_KEY, strlen(BANANA_KEY));
                REQUIRE(l_s == WAFLZ_STATUS_ERROR);
        }
        SECTION("validate sweep db - test if sweeping deletes expired keys from db") {
                int32_t l_s;
                ns_waflz::lm_db l_db;
                bool l_dummy;
                // get lmdb dir path
                std::string l_db_dir;
                get_lmdb_path(l_db_dir);
                // init
                l_db.set_opt(ns_waflz::lm_db::OPT_LMDB_DIR_PATH, l_db_dir.c_str(), l_db_dir.length());
                l_db.set_opt(ns_waflz::lm_db::OPT_LMDB_READERS, NULL, 6);
                l_db.set_opt(ns_waflz::lm_db::OPT_LMDB_MMAP_SIZE, NULL, 10485760);
                l_s = l_db.init();
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                int64_t l_result;
                l_s = l_db.increment_key(l_result, MONKEY_KEY, 2000, false, l_dummy);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                REQUIRE(l_result == 1);
                l_s = l_db.increment_key(l_result, BANANA_KEY, 4000, false, l_dummy);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                REQUIRE(l_result == 1);
                // sweep db
                l_s = l_db.sweep();
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                int64_t l_out_val = -1;
                // verify sweep db didn't delete keys before expiry
                l_s = l_db.get_key(l_out_val, MONKEY_KEY, strlen(MONKEY_KEY));
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                REQUIRE(l_out_val == 1);
                l_s = l_db.get_key(l_out_val, BANANA_KEY, strlen(BANANA_KEY));
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                REQUIRE(l_out_val == 1);
                // sleep for 2 seconds and sweep db. Monkey key should have been
                // deleted
                usleep(3000000);
                l_s = l_db.sweep();
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                l_s = l_db.get_key(l_out_val, MONKEY_KEY, strlen(MONKEY_KEY));
                REQUIRE(l_s == WAFLZ_STATUS_ERROR);
                l_s = l_db.get_key(l_out_val, BANANA_KEY, strlen(BANANA_KEY));
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                // sleep for 2 more seconds and sweep db. Banana key should have been
                // deleted
                usleep(2000000);
                l_s = l_db.sweep();
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                l_s = l_db.get_key(l_out_val, BANANA_KEY, strlen(BANANA_KEY));
                REQUIRE(l_s == WAFLZ_STATUS_ERROR);
        }
}

