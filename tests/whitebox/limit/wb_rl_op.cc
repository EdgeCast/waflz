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
#include "op/regex.h"
#include "waflz/nms.h"
#include "waflz/def.h"
#include "waflz/scopes.h"
#include "waflz/rl_obj.h"
#include "limit.pb.h"
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
#ifndef ARRAY_SIZE
  #define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif
#ifndef ELEM_AT
  #define ELEM_AT(a, i, v) ((unsigned int) (i) < ARRAY_SIZE(a) ? (a)[(i)] : (v))
#endif
//! ----------------------------------------------------------------------------
//! rl obj
//! ----------------------------------------------------------------------------
TEST_CASE( "op test", "[op]" ) {
        // -------------------------------------------------
        // test streq
        // -------------------------------------------------
        SECTION("rl_run_op streq test") {
                bool l_matched = false;
                int32_t l_s;
                waflz_pb::op_t* l_op = NULL;
                l_op = new waflz_pb::op_t();
                l_op->set_type(waflz_pb::op_t_type_t_STREQ);
                l_op->set_value("monkeys");
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "monkeys", strlen("monkeys"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == true));
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "bananas", strlen("bananas"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == false));
                if(l_op) { delete(l_op); l_op = NULL; }
        }
        // -------------------------------------------------
        // test glob
        // -------------------------------------------------
        SECTION("rl_run_op glob test") {
                bool l_matched = false;
                int32_t l_s;
                waflz_pb::op_t* l_op = new waflz_pb::op_t();
                l_op->set_type(waflz_pb::op_t_type_t_GLOB);
                l_op->set_value("*");
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "cat", strlen("cat"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == true));
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "/cat/dog/monkey", strlen("/cat/dog/monkey"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == true));
                l_op->set_value("ca*");
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "cat", strlen("cat"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == true));
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "/cat/dog/monkey", strlen("/cat/dog/monkey"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == false));
                l_op->set_value("/ca*");
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "/cat/dog/monkey", strlen("/cat/dog/monkey"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == true));
                l_op->set_value("/cat/dog*");
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "/cat/dog/monkey", strlen("/cat/dog/monkey"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == true));
                l_op->set_value("/cat/dog/*");
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "/cat/dog/monkey", strlen("/cat/dog/monkey"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == true));
                l_op->set_value("/cat/dog/monkey/banana*");
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "/cat/dog/monkey", strlen("/cat/dog/monkey"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == false));
                l_op->set_value("ca[r-t]");
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "cat", strlen("cat"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == true));
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "car", strlen("car"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == true));
                l_op->set_value("ca[!r-t]");
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "cat", strlen("cat"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == false));
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "can", strlen("can"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == true));
                if(l_op) { delete(l_op); l_op = NULL; }
        }
        // -------------------------------------------------
        // test regex
        // -------------------------------------------------
        SECTION("rl_run_op regex test") {
                bool l_matched = false;
                int32_t l_s;
                waflz_pb::op_t* l_op = NULL;
                ns_waflz::regex* l_rx = NULL;
                std::string l_val;
                // -----------------------------------------
                // basic regex
                // -----------------------------------------
                l_op = new waflz_pb::op_t();
                l_op->set_type(waflz_pb::op_t_type_t_RX);
                l_op->set_value("ca.*");
                l_rx = new ns_waflz::regex();
                l_val = l_op->value();
                l_s = l_rx->init(l_val.c_str(), l_val.length());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_op->set__reserved_1((uint64_t)l_rx);
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "cat", strlen("cat"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == true));
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "dog", strlen("dog"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == false));
                if(l_op) { delete(l_op); l_op = NULL; }
                if(l_rx) { delete(l_rx); l_rx = NULL; }
                // -----------------------------------------
                // range regex
                // -----------------------------------------
                l_op = new waflz_pb::op_t();
                l_op->set_type(waflz_pb::op_t_type_t_RX);
                l_op->set_value("t[ao]p");
                l_rx = new ns_waflz::regex();
                l_val = l_op->value();
                l_s = l_rx->init(l_val.c_str(), l_val.length());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_op->set__reserved_1((uint64_t)l_rx);
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "tap", strlen("tap"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == true));
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "top", strlen("top"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == true));
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "flop", strlen("flop"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == false));
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_op) { delete(l_op); l_op = NULL; }
                if(l_rx) { delete(l_rx); l_rx = NULL; }
        }
        // -------------------------------------------------
        // test ipmatch
        // -------------------------------------------------
        SECTION("rl_run_op ipmatch test") {
                bool l_matched = false;
                int32_t l_s;
                waflz_pb::op_t* l_op = NULL;
                ns_waflz::nms* l_nms = NULL;
                std::string l_val;
                // -----------------------------------------
                // init nms
                // -----------------------------------------
                l_nms = new ns_waflz::nms();
                l_op = new waflz_pb::op_t();
                l_op->set_type(waflz_pb::op_t_type_t_IPMATCH);
                // ipv4
                l_s = l_nms->add("127.0.0.1", sizeof("127.0.0.1"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // ipv4 cidr
                l_s = l_nms->add("192.168.100.0/24", sizeof("192.168.100.0/24"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // ipv6 cidr
                l_s = l_nms->add("2001:0db8:85a3:0000:0000:8a2e:0370:7334", sizeof("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_op->set__reserved_1((uint64_t)l_nms);
                // -----------------------------------------
                // match
                // -----------------------------------------
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "127.0.0.1", strlen("127.0.0.1"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == true));
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "127.0.0.2", strlen("127.0.0.2"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == false));
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "2001:0db8:85a3:0000:0000:8a2e:0370:7334", strlen("2001:0db8:85a3:0000:0000:8a2e:0370:7334"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == true));
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "2001:0db8:85a3:0000:0000:8a2f:0370:7334", strlen("2001:0db8:85a3:0000:0000:8a2f:0370:7334"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == false));
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_op) { delete(l_op); l_op = NULL; }
                if(l_nms) { delete(l_nms); l_nms = NULL; }
        }
        
        // -------------------------------------------------
        // test em case sensitive
        // -------------------------------------------------
        SECTION("rl_run_op em test case sensitive") {
                bool l_matched = false;
                int32_t l_s;
                waflz_pb::op_t* l_op = NULL;
                ns_waflz::data_set_t* l_ds = NULL;
                std::string l_val;
                const char l_str_list[][32] = {
                                "cat",
                                "dog",
                                "monkey",
                                "monkeysbananas",
                                "monkey:443"
                };
                // -----------------------------------------
                // init data_set_t
                // -----------------------------------------
                l_ds = new ns_waflz::data_set_t();
                for(uint32_t i = 0; i < ARRAY_SIZE(l_str_list); ++i)
                {
                        ns_waflz::data_t l_d;
                        l_d.m_data = l_str_list[i];
                        l_d.m_len = strlen(l_str_list[i]);
                        l_ds->insert(l_d);
                }
                l_op = new waflz_pb::op_t();
                l_op->set_type(waflz_pb::op_t_type_t_EM);
                l_op->set__reserved_1((uint64_t)l_ds);
                // -----------------------------------------
                // match
                // -----------------------------------------
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "cat", strlen("cat"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == true));
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "cAt", strlen("cAt"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == false));
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "cats", strlen("cats"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == false));
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "scats", strlen("scats"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == false));
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "monkey", strlen("monkey"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == true));
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "monKey", strlen("monKey"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == false));
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "monkeysbananas", strlen("monkeysbananas"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == true));
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "monkey:443", strlen("monkey:443"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == true));
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "MONKEY:443", strlen("MONKEY:443"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == false));
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_op) { delete(l_op); l_op = NULL; }
                if(l_ds) { delete(l_ds); l_ds = NULL; }

        }
        // -------------------------------------------------
        // test em case insensitive
        // -------------------------------------------------
        SECTION("rl_run_op em test case insensitive") {
                bool l_matched = false;
                int32_t l_s;
                waflz_pb::op_t* l_op = NULL;
                ns_waflz::data_case_i_set_t* l_ds = NULL;
                std::string l_val;
                const char l_str_list[][32] = {
                                "cat",
                                "dog",
                                "monkey",
                                "monkey:443",
                                "monkeys"
                };
                // -----------------------------------------
                // init data_case_i_set_t
                // -----------------------------------------
                l_ds = new ns_waflz::data_case_i_set_t();
                for(uint32_t i = 0; i < ARRAY_SIZE(l_str_list); ++i)
                {
                        ns_waflz::data_t l_d;
                        l_d.m_data = l_str_list[i];
                        l_d.m_len = strlen(l_str_list[i]);
                        l_ds->insert(l_d);
                }
                l_op = new waflz_pb::op_t();
                l_op->set_type(waflz_pb::op_t_type_t_EM);
                l_op->set__reserved_1((uint64_t)l_ds);
                l_op->set_is_case_insensitive(true);
                // -----------------------------------------
                // match
                // -----------------------------------------
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "cat", strlen("cat"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == true));
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "cAt", strlen("cAt"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == true));
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "cats", strlen("cats"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == false));
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "scats", strlen("scats"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == false));
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "monkey", strlen("monkey"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == true));
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "monkey:443", strlen("monkey:443"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == true));
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "MONKEY:443", strlen("MONKEY:443"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == true));
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "monKey", strlen("monKey"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == true));
                l_s = ns_waflz::rl_run_op(l_matched, *l_op, "monkeys", strlen("monkeys"), false);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_matched == true));
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_op) { delete(l_op); l_op = NULL; }
                if(l_ds) { delete(l_ds); l_ds = NULL; }
        }
}
