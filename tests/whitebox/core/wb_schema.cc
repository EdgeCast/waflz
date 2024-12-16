//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    wb_schema.cc
//! \details: whitebox test for JSON schema validation
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <unistd.h>

#include <iomanip>
#include <list>

#include "catch/catch.hpp"
#include "event.pb.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "support/file_util.h"
#include "support/ndebug.h"
#include "waflz/def.h"
#include "waflz/rqst_ctx.h"
#include "waflz/schema.h"
#include "waflz/engine.h"
static const uint32_t g_body_len_max = 128 * 1024;
void run_schema_test(std::string a_test_name)
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
        // engine
        // -------------------------------------------------
        ns_waflz::engine *l_engine = new ns_waflz::engine();
        l_s = l_engine->init();
        REQUIRE(l_s == WAFLZ_STATUS_OK);
        // -------------------------------------------------
        // get conf dir
        // -------------------------------------------------
        std::string l_conf_dir = l_cwd;
        l_conf_dir += "/../../../../tests/whitebox/data/schema_test_suite/";
        void *l_ctx = NULL;
        // -------------------------------------------------
        // test json path
        // -------------------------------------------------
        std::string l_test_json = l_conf_dir + a_test_name + ".json";
        // -------------------------------------------------
        // Read file from test suite
        // -------------------------------------------------
        char *l_test_buf = NULL;
        uint32_t l_test_buf_len = 0;
        ns_waflz::read_file(l_test_json.c_str(), &l_test_buf, l_test_buf_len);
        // -------------------------------------------------
        // Parse file from test suite
        // -------------------------------------------------
        rapidjson::Document l_doc;
        l_doc.Parse(l_test_buf, l_test_buf_len);
        free(l_test_buf);
        REQUIRE(l_doc.IsArray());
        // -------------------------------------------------
        // For every schema in a test suite file
        // -------------------------------------------------
        for (int32_t i = 0; i < l_doc.GetArray().Size(); ++i)
        {
                // -----------------------------------------
                // Extract Schema
                // -----------------------------------------
                REQUIRE(l_doc[i]["schema"].IsObject());
                ns_waflz::schema *l_schema = new ns_waflz::schema(*l_engine);
                rapidjson::Value l_schema_val = l_doc[i]["schema"].GetObject();
                rapidjson::SchemaDocument *l_schema_doc =
                    new rapidjson::SchemaDocument(l_schema_val);
                // -----------------------------------------
                // Set Schema
                // -----------------------------------------
                l_schema->set_schema_document(l_schema_doc);
                // -----------------------------------------
                // Iterate through one test file
                // -----------------------------------------
                REQUIRE(l_doc[i]["tests"].IsArray());
                // -----------------------------------------
                // For every test input
                // -----------------------------------------
                for (int32_t j = 0; j < l_doc[i]["tests"].GetArray().Size();
                     ++j)
                {
                        // ---------------------------------
                        // Extract Test input
                        // ---------------------------------
                        rapidjson::StringBuffer l_sb;
                        rapidjson::Writer<rapidjson::StringBuffer> l_writer(
                            l_sb);
                        l_doc[i]["tests"][j]["data"].Accept(l_writer);
                        uint32_t l_input_buf_len =
                            std::strlen(l_sb.GetString());
                        if (l_input_buf_len == 0) break;
                        // ---------------------------------
                        // Get field in test data indicating
                        // whether json data is valid
                        // ---------------------------------
                        REQUIRE(l_doc[i]["tests"][j]["valid"].IsBool());
                        bool l_is_valid =
                            l_doc[i]["tests"][j]["valid"].GetBool();
                        // ---------------------------------
                        // check if json data is valid
                        // against schema
                        // ---------------------------------
                        waflz_pb::event *l_event = NULL;
                        l_s = l_schema->process(&l_event, l_ctx, l_sb.GetString(), l_input_buf_len);
                        REQUIRE(l_s == WAFLZ_STATUS_OK);
                        // ---------------------------------
                        // Event should not
                        // occur if valid
                        // ---------------------------------
                        if (l_is_valid) { REQUIRE(l_event == NULL); }
                        else { REQUIRE(l_event != NULL); }
                        // ---------------------------------
                        // Cleanup
                        // ---------------------------------
                        if (l_event) delete l_event;
                }
                delete l_schema;
        }
        delete l_engine;
}

TEST_CASE("schema test", "[schema]")
{
        std::list<std::string> test_types = {
            "additionalItems",
            "maximum",
            "additionalProperties",
            "minItems",
            "allOf",
            "minLength",
            "anyOf",
            "minProperties",
            //"boolean_schema", // Works, need to pass to schema differently
            "minimum",
            "default",
            "multipleOf",
            //"definitions",  // Remote Schema not Supported
            "not",
            "dependencies",
            "oneOf",
            "enum",
            "pattern",
            "format",
            "patternProperties",
            //"id",         //Remote Schema not supported
            "properties",
            "infinite-loop-detection",
            "ref",
            "items",
            "required",
            "maxItems",
            "type",
            "maxLength",
            "uniqueItems"};
        for (std::list<std::string>::iterator l_list_it = test_types.begin();
             l_list_it != test_types.end();
             ++l_list_it)
        {
                SECTION(*l_list_it) { run_schema_test(*l_list_it); }
        }
}
