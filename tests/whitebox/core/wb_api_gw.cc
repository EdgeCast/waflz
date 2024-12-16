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
#include "waflz/engine.h"
#include "waflz/rqst_ctx.h"
#include "waflz/resp_ctx.h"
#include "support/file_util.h"
#include "event.pb.h"
#include "api_gw.pb.h"
#include "waflz/schema.h"
#include "waflz/api_gw.h"
#include <unistd.h>
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
        SECTION("load api_gw from protobuf")
        {
                ns_waflz::engine* l_engine = new ns_waflz::engine();
                l_s = l_engine->init();
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                // -----------------------------------------
                // create new api_gw protobuf
                // -----------------------------------------
                waflz_pb::api_gw* l_api_gw_pb =
                    new waflz_pb::api_gw();
                // -----------------------------------------
                // create api_gw
                // -----------------------------------------
                ns_waflz::api_gw* l_api_gw =
                    new ns_waflz::api_gw(*l_engine);
                // -----------------------------------------
                // load from protobuf
                // -----------------------------------------
                l_s = l_api_gw->load(l_api_gw_pb, l_conf_dir);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if (l_engine) { delete l_engine; }
                if (l_api_gw_pb)
                {
                        delete l_api_gw_pb;
                        l_api_gw_pb = NULL;
                }
                if (l_api_gw)
                {
                        delete l_api_gw;
                        l_api_gw = NULL;
                }
        }
        SECTION("Try global op_t")
        {
                ns_waflz::engine* l_engine = new ns_waflz::engine();
                l_s = l_engine->init();
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                // -----------------------------------------
                // make an api_gw
                // -----------------------------------------
                ns_waflz::api_gw* l_api_gw =
                    new ns_waflz::api_gw(*l_engine);
                // -----------------------------------------
                // read api_gw file
                // -----------------------------------------
                char* l_buf;
                uint32_t l_buf_len;
                std::string l_api_gw_file = l_conf_dir;
                l_api_gw_file +=
                    "/api_gw/0050-qSMXE66R.api_gw.json";
                l_s = ns_waflz::read_file(
                    l_api_gw_file.c_str(), &l_buf, l_buf_len);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                // -----------------------------------------
                // load api_gw file
                // -----------------------------------------
                l_s = l_api_gw->load(l_buf, l_buf_len, l_conf_dir);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                if (l_buf)
                {
                        free(l_buf);
                        l_buf = NULL;
                }
                // -----------------------------------------
                // Check that 1 schema is added
                // -----------------------------------------
                REQUIRE(l_api_gw->get_schema_map().size() == 1);
                auto i_t = l_api_gw->get_schema_map().begin();
                REQUIRE(i_t->first == "A7QPbm0Z");
                REQUIRE(i_t->second != NULL);
                waflz_pb::event* l_event = NULL;
                void* l_ctx = NULL;
                ns_waflz::rqst_ctx* l_rqst_ctx =
                    new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, NULL);
                // -----------------------------------------
                // Set request data
                // -----------------------------------------
                l_rqst_ctx->m_uri.m_data = "/test.html";
                l_rqst_ctx->m_uri.m_len = 10;
                l_rqst_ctx->m_method.m_data = "GET";
                l_rqst_ctx->m_method.m_len = 3;
                l_rqst_ctx->m_json_body = true;
                std::string l_body = "{\"name\":\"badregex\"}";
                int32_t l_input_buf_len = l_body.length();
                char* l_input_buf =
                    (char*)malloc(sizeof(char) * l_input_buf_len);
                std::strncpy(l_input_buf, l_body.c_str(), l_input_buf_len);
                l_rqst_ctx->m_body_data = l_input_buf;
                l_rqst_ctx->m_body_len = l_input_buf_len;
                // -----------------------------------------
                // Process request through api_gw
                // -----------------------------------------
                l_s = l_api_gw->process(&l_event, l_ctx, &l_rqst_ctx);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                REQUIRE(l_event);
                REQUIRE(l_event->api_gw_config_id() == "qSMXE66R");
                REQUIRE(l_event->schema_config_id() == "A7QPbm0Z");
                REQUIRE(l_event->sub_event_size()==1);
                REQUIRE(l_event->sub_event(0).rule_msg() == "pattern");
                REQUIRE(l_event->sub_event(0).schema_error_location() == "#/properties/name");
                REQUIRE(l_event->sub_event(0).body_schema_error_location() == "#/name");
                if (l_event)
                {
                        delete l_event;
                        l_event = NULL;
                }
                if (l_input_buf)
                {
                        free(l_input_buf);
                        l_input_buf = NULL;
                }
                l_rqst_ctx->m_uri.m_data = "/monkey.html";
                l_rqst_ctx->m_uri.m_len = 13;
                l_rqst_ctx->m_method.m_data = "GET";
                l_rqst_ctx->m_method.m_len = 3;
                l_rqst_ctx->m_json_body = true;
                l_body = "{\"name\":\"Bob Bobberson\", \"Employee_ID\":1234}";
                l_input_buf_len = l_body.length();
                l_input_buf = (char*)malloc(sizeof(char) * l_input_buf_len);
                std::strncpy(l_input_buf, l_body.c_str(), l_input_buf_len);
                l_rqst_ctx->m_body_data = l_input_buf;
                l_rqst_ctx->m_body_len = l_input_buf_len;
                // -----------------------------------------
                // Process request through api_gw
                // -----------------------------------------
                l_s = l_api_gw->process(&l_event, l_ctx, &l_rqst_ctx);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                REQUIRE(l_event == NULL);
                // -----------------------------------------
                // final cleanup
                // -----------------------------------------
                if (l_rqst_ctx) { delete l_rqst_ctx; }
                if (l_event) { delete l_event; }
                if (l_engine) { delete l_engine; }
                if (l_api_gw) { delete l_api_gw; }
        }
        SECTION("Try EM op_t")
        {
                ns_waflz::engine* l_engine = new ns_waflz::engine();
                l_s = l_engine->init();
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                // -----------------------------------------
                // make an api_gw
                // -----------------------------------------
                ns_waflz::api_gw* l_api_gw =
                    new ns_waflz::api_gw(*l_engine);
                // -----------------------------------------
                // read api_gw file
                // -----------------------------------------
                char* l_buf;
                uint32_t l_buf_len;
                std::string l_api_gw_file = l_conf_dir;
                l_api_gw_file +=
                    "/api_gw/0050-qSMXE66R.api_gw.json";
                l_s = ns_waflz::read_file(
                    l_api_gw_file.c_str(), &l_buf, l_buf_len);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                // -----------------------------------------
                // load api_gw file
                // -----------------------------------------
                l_s = l_api_gw->load(l_buf, l_buf_len, l_conf_dir);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                if (l_buf)
                {
                        free(l_buf);
                        l_buf = NULL;
                }
                // -----------------------------------------
                // Check that 1 schema is added
                // -----------------------------------------
                REQUIRE(l_api_gw->get_schema_map().size() == 1);
                auto i_t = l_api_gw->get_schema_map().begin();
                REQUIRE(i_t->first == "A7QPbm0Z");
                REQUIRE(i_t->second != NULL);
                waflz_pb::event* l_event = NULL;
                void* l_ctx = NULL;
                ns_waflz::rqst_ctx* l_rqst_ctx =
                    new ns_waflz::rqst_ctx(l_ctx, DEFAULT_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, NULL);
                // -----------------------------------------
                // Set request data
                // -----------------------------------------
                l_rqst_ctx->m_uri.m_data = "/test.html";
                l_rqst_ctx->m_uri.m_len = 10;
                l_rqst_ctx->m_method.m_data = "PUT";
                l_rqst_ctx->m_method.m_len = 3;
                l_rqst_ctx->m_json_body = true;
                std::string l_body = "{\"name\":1}";
                int32_t l_input_buf_len = l_body.length();
                char* l_input_buf =
                    (char*)malloc(sizeof(char) * l_input_buf_len);
                std::strncpy(l_input_buf, l_body.c_str(), l_input_buf_len);
                l_rqst_ctx->m_body_data = l_input_buf;
                l_rqst_ctx->m_body_len = l_input_buf_len;
                // -----------------------------------------
                // Process request through api_gw
                // -----------------------------------------
                l_s = l_api_gw->process(&l_event, l_ctx, &l_rqst_ctx);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                REQUIRE(l_event);
                REQUIRE(l_event->api_gw_config_id() == "qSMXE66R");
                REQUIRE(l_event->schema_config_id() == "A7QPbm0Z");
                REQUIRE(l_event->sub_event_size()==1);
                REQUIRE(l_event->sub_event(0).rule_msg() == "type");
                REQUIRE(l_event->sub_event(0).schema_error_location() == "#/properties/name");
                REQUIRE(l_event->sub_event(0).body_schema_error_location() == "#/name");
                // -----------------------------------------
                // final cleanup
                // -----------------------------------------
                if (l_rqst_ctx) { delete l_rqst_ctx; }
                if (l_event) { delete l_event; }
                if (l_engine) { delete l_engine; }
                if (l_api_gw) { delete l_api_gw; }
        }
        SECTION("Try Response")
        {
                ns_waflz::engine* l_engine = new ns_waflz::engine();
                l_s = l_engine->init();
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                // -----------------------------------------
                // make an api_gw
                // -----------------------------------------
                ns_waflz::api_gw* l_api_gw =
                    new ns_waflz::api_gw(*l_engine);
                // -----------------------------------------
                // read api_gw file
                // -----------------------------------------
                char* l_buf;
                uint32_t l_buf_len;
                std::string l_api_gw_file = l_conf_dir;
                l_api_gw_file +=
                    "/api_gw/0050-qSMXE66R.api_gw.json";
                l_s = ns_waflz::read_file(
                    l_api_gw_file.c_str(), &l_buf, l_buf_len);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                // -----------------------------------------
                // load api_gw file
                // -----------------------------------------
                l_s = l_api_gw->load(l_buf, l_buf_len, l_conf_dir);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                if (l_buf)
                {
                        free(l_buf);
                        l_buf = NULL;
                }
                // -----------------------------------------
                // Check that 1 schema is added
                // -----------------------------------------
                waflz_pb::event* l_event = NULL;
                void* l_ctx = NULL;
                // -----------------------------------------
                // Set response data
                // -----------------------------------------
                std::string l_body = "{\"name\":1}";
                ns_waflz::resp_ctx* l_resp_ctx = new ns_waflz::resp_ctx(l_ctx, DEFAULT_RESP_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, NULL,l_body.length(), NULL);
                l_resp_ctx->m_uri.m_data = "/test.html";
                l_resp_ctx->m_uri.m_len = 10;
                l_resp_ctx->m_method.m_data = "POST";
                l_resp_ctx->m_method.m_len = 4;
                int32_t l_resp_buf_len = l_body.length();
                char* l_resp_buf =
                    (char*)malloc(sizeof(char) * l_resp_buf_len);
                std::strncpy(l_resp_buf, l_body.c_str(), l_resp_buf_len);
                l_resp_ctx->m_body_data = l_resp_buf;
                l_resp_ctx->m_body_len = l_resp_buf_len;
                l_resp_ctx->m_resp_status = 200;
                // -----------------------------------------
                // Process request through api_gw
                // -----------------------------------------
                l_s = l_api_gw->process_response(&l_event, l_ctx, &l_resp_ctx);
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                REQUIRE(l_event);
                REQUIRE(l_event->api_gw_config_id() == "qSMXE66R");
                REQUIRE(l_event->schema_config_id() == "A7QPbm0Z");
                REQUIRE(l_event->sub_event_size()==1);
                REQUIRE(l_event->sub_event(0).rule_msg() == "type");
                REQUIRE(l_event->sub_event(0).schema_error_location() == "#/properties/name");
                REQUIRE(l_event->sub_event(0).body_schema_error_location() == "#/name");
                // -----------------------------------------
                // final cleanup
                // -----------------------------------------
                if (l_resp_ctx) { delete l_resp_ctx; }
                if (l_event) { delete l_event; }
                if (l_engine) { delete l_engine; }
                if (l_api_gw) { delete l_api_gw; }
        }
}
