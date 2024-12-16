//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    wb_api_gw.cc
//! \details: white box test for api_gw
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "waflz/resp_ctx.h"
#include "waflz/engine.h"
#include "support/file_util.h"
#include "event.pb.h"
#include "client_waf.pb.h"
#include "waflz/client_waf.h"
#include <unistd.h>
#include <cstring>
//! ----------------------------------------------------------------------------
//! callbacks
//! ----------------------------------------------------------------------------
static const char* s_ip = "156.123.12.7";
//! ----------------------------------------------------------------------------
//! instances tests
//! ----------------------------------------------------------------------------
TEST_CASE("api_gw test", "[api_gw]")
{
        // -------------------------------------------------
        // callbacks for test
        // -------------------------------------------------
        int32_t l_s;
        // -------------------------------------------------
        // get current working directory
        // -------------------------------------------------
        char l_cwd[1024];
        REQUIRE(getcwd(l_cwd, sizeof(l_cwd)) != NULL);
        // -------------------------------------------------
        // get conf dir
        // -------------------------------------------------
        std::string l_conf_dir = l_cwd;
        l_conf_dir += "/../../../../tests/data/waf/conf";
        // -------------------------------------------------
        // verify engine loading
        // -------------------------------------------------
        ns_waflz::engine *l_engine = new ns_waflz::engine();
        l_s = l_engine->init();
        REQUIRE((l_s == WAFLZ_STATUS_OK));
        // -------------------------------------------------
        // try loading client waf
        // -------------------------------------------------
        SECTION("load client_waf from protobuf")
        {
                // -----------------------------------------
                // create new client_waf protobuf
                // -----------------------------------------
                waflz_pb::client_waf* l_cs_proto =
                    new waflz_pb::client_waf();
                // -----------------------------------------
                // create client_waf
                // -----------------------------------------
                ns_waflz::client_waf* l_cs =
                    new ns_waflz::client_waf(*l_engine);
                // -----------------------------------------
                // load from protobuf
                // -----------------------------------------
                l_s = l_cs->load(l_cs_proto);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if (l_cs_proto) { delete l_cs_proto; l_cs_proto = NULL; }
                if (l_cs) { delete l_cs; l_cs = NULL; }
        }
        SECTION("Process Response")
        {
                // -----------------------------------------
                // create new client_waf protobuf
                // -----------------------------------------
                waflz_pb::client_waf* l_cs_proto =
                    new waflz_pb::client_waf();
                // -----------------------------------------
                // set name and id so we can check that
                // event has these values
                // -----------------------------------------
                l_cs_proto->set_id("123");
                l_cs_proto->set_name("blah :D");
                // -----------------------------------------
                // add default source directive
                // -----------------------------------------
                waflz_pb::enforcement_header_t* l_entry_1 = l_cs_proto->add_headers();
                l_entry_1->set_key("Content-Security-Policy");
                l_entry_1->set_value("default-src 'none'");
                l_entry_1->set_overwrite(true);
                l_entry_1->set_enforce(true);
                // -----------------------------------------
                // add font source directive for report only
                // -----------------------------------------
                waflz_pb::enforcement_header_t* l_entry_2 = l_cs_proto->add_headers();
                l_entry_2->set_key("Content-Security-Policy-Report-Only");
                l_entry_2->set_value("font-src http:");
                l_entry_2->set_overwrite(false);
                l_entry_2->set_enforce(true);
                // -----------------------------------------
                // create client_waf
                // -----------------------------------------
                ns_waflz::client_waf* l_cs =
                    new ns_waflz::client_waf(*l_engine);
                // -----------------------------------------
                // load from protobuf
                // -----------------------------------------
                l_s = l_cs->load(l_cs_proto);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                // -----------------------------------------
                // get headers from the client waf object
                // -----------------------------------------
                ns_waflz::header_map_t* l_headers_added = l_cs->get_headers();
                // -----------------------------------------
                // should be two headers
                // -----------------------------------------
                REQUIRE(l_headers_added->size() == 2);
                // -----------------------------------------
                // csp header should exist
                // -----------------------------------------
                std::string l_key = "Content-Security-Policy";
                ns_waflz::header_map_t::iterator l_header = l_headers_added->find(l_key);
                REQUIRE(l_header != l_headers_added->end());
                REQUIRE(l_header->first == l_key);
                REQUIRE(l_header->second.m_val == "default-src 'none'");
                REQUIRE(l_header->second.m_overwrite);
                // -----------------------------------------
                // cspro header should exist
                // -----------------------------------------
                l_key = "Content-Security-Policy-Report-Only";
                l_header = l_headers_added->find(l_key);
                REQUIRE(l_header != l_headers_added->end());
                REQUIRE(l_header->first == l_key);
                REQUIRE(l_header->second.m_val == "font-src http:");
                REQUIRE(l_header->second.m_overwrite == false);
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if (l_cs_proto) { delete l_cs_proto; l_cs_proto = NULL; }
                if (l_cs) { delete l_cs; l_cs = NULL; }
        }
        // -------------------------------------------------
        // add csp endpoint
        // -------------------------------------------------
        l_engine->set_csp_endpoint_uri("http://localhost:7070/");
        // -------------------------------------------------
        // check if csp endpoint gets added to config
        // -------------------------------------------------
        SECTION("Process Response with csp endpoint")
        {
                // -----------------------------------------
                // create new client_waf protobuf
                // -----------------------------------------
                waflz_pb::client_waf* l_cs_proto =
                    new waflz_pb::client_waf();
                // -----------------------------------------
                // set name and id so we can check that
                // event has these values
                // -----------------------------------------
                l_cs_proto->set_id("123");
                l_cs_proto->set_customer_id("example");
                l_cs_proto->set_name("blah :D");
                // -----------------------------------------
                // add default source directive
                // -----------------------------------------
                waflz_pb::enforcement_header_t* l_entry_1 = l_cs_proto->add_headers();
                l_entry_1->set_key("Content-Security-Policy");
                l_entry_1->set_value("default-src 'none'");
                l_entry_1->set_overwrite(true);
                l_entry_1->set_enforce(true);
                // -----------------------------------------
                // add font source directive for report only
                // -----------------------------------------
                waflz_pb::enforcement_header_t* l_entry_2 = l_cs_proto->add_headers();
                l_entry_2->set_key("Content-Security-Policy-Report-Only");
                l_entry_2->set_value("font-src http:");
                l_entry_2->set_overwrite(false);
                l_entry_2->set_enforce(true);
                // -----------------------------------------
                // create client_waf
                // -----------------------------------------
                ns_waflz::client_waf* l_cs =
                    new ns_waflz::client_waf(*l_engine);
                // -----------------------------------------
                // load from protobuf
                // -----------------------------------------
                l_s = l_cs->load(l_cs_proto);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                // -----------------------------------------
                // get headers from the client waf object
                // -----------------------------------------
                ns_waflz::header_map_t* l_headers_added = l_cs->get_headers();
                // -----------------------------------------
                // should be two headers
                // -----------------------------------------
                REQUIRE(l_headers_added->size() == 2);
                // -----------------------------------------
                // csp header should exist
                // -----------------------------------------
                std::string l_key = "Content-Security-Policy";
                ns_waflz::header_map_t::iterator l_header = l_headers_added->find(l_key);
                REQUIRE(l_header != l_headers_added->end());
                REQUIRE(l_header->first == l_key);
                REQUIRE(l_header->second.m_val == "default-src 'none'; report-uri http://localhost:7070/example");
                REQUIRE(l_header->second.m_overwrite);
                // -----------------------------------------
                // cspro header should exist
                // -----------------------------------------
                l_key = "Content-Security-Policy-Report-Only";
                l_header = l_headers_added->find(l_key);
                REQUIRE(l_header != l_headers_added->end());
                REQUIRE(l_header->first == l_key);
                REQUIRE(l_header->second.m_val == "font-src http:; report-uri http://localhost:7070/example");
                REQUIRE(l_header->second.m_overwrite == false);
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if (l_cs_proto) { delete l_cs_proto; l_cs_proto = NULL; }
                if (l_cs) { delete l_cs; l_cs = NULL; }
        }
        // -------------------------------------------------
        // check that enforce key decides if an entry is
        // added to the list
        // -------------------------------------------------
        SECTION("Check that enforce key works on headers")
        {
                // -----------------------------------------
                // create new client_waf protobuf
                // -----------------------------------------
                waflz_pb::client_waf* l_cs_proto =
                    new waflz_pb::client_waf();
                // -----------------------------------------
                // set name and id so we can check that
                // event has these values
                // -----------------------------------------
                l_cs_proto->set_id("123");
                l_cs_proto->set_customer_id("example");
                l_cs_proto->set_name("blah :D");
                // -----------------------------------------
                // add default source directive
                // -----------------------------------------
                waflz_pb::enforcement_header_t* l_entry_1 = l_cs_proto->add_headers();
                l_entry_1->set_key("Content-Security-Policy");
                l_entry_1->set_value("default-src 'none'");
                l_entry_1->set_overwrite(true);
                l_entry_1->set_enforce(true);
                // -----------------------------------------
                // add font source directive for report only
                // enforce set to false, so shouldnt be added
                // -----------------------------------------
                waflz_pb::enforcement_header_t* l_entry_2 = l_cs_proto->add_headers();
                l_entry_2->set_key("Content-Security-Policy-Report-Only");
                l_entry_2->set_value("font-src http:");
                l_entry_2->set_overwrite(false);
                l_entry_2->set_enforce(false);
                // -----------------------------------------
                // create client_waf
                // -----------------------------------------
                ns_waflz::client_waf* l_cs =
                    new ns_waflz::client_waf(*l_engine);
                // -----------------------------------------
                // load from protobuf
                // -----------------------------------------
                l_s = l_cs->load(l_cs_proto);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                // -----------------------------------------
                // get headers from the client waf object
                // -----------------------------------------
                ns_waflz::header_map_t* l_headers_added = l_cs->get_headers();
                // -----------------------------------------
                // should be one headers
                // -----------------------------------------
                REQUIRE(l_headers_added->size() == 1);
                // -----------------------------------------
                // csp header should exist
                // -----------------------------------------
                std::string l_key = "Content-Security-Policy";
                ns_waflz::header_map_t::iterator l_header = l_headers_added->find(l_key);
                REQUIRE(l_header != l_headers_added->end());
                REQUIRE(l_header->first == l_key);
                REQUIRE(l_header->second.m_val == "default-src 'none'; report-uri http://localhost:7070/example");
                REQUIRE(l_header->second.m_overwrite);
                // -----------------------------------------
                // cspro header should NOT exist
                // -----------------------------------------
                l_key = "Content-Security-Policy-Report-Only";
                l_header = l_headers_added->find(l_key);
                REQUIRE(l_header == l_headers_added->end());
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if (l_cs_proto) { delete l_cs_proto; l_cs_proto = NULL; }
                if (l_cs) { delete l_cs; l_cs = NULL; }
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if (l_engine) { delete l_engine; l_engine = NULL; }
}
