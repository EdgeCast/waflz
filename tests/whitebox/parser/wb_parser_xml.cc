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
#include "waflz/rqst_ctx.h"
#include "parser/parser_xml.h"
#include "support/ndebug.h"
#include <string.h>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define XML_SHORT "<monkeys><gorilla>coco</gorilla><mandrill>dooby</mandrill><baboon>groovy</baboon></monkeys>"
#define XML_W_XXE "<?xml version=\"1.0\" encoding=\"UTF-8\"?> <!DOCTYPE foo [ <!ENTITY writer \"Donald Duck.\"> <!ENTITY copyright \"Copyright W3Schools.\"> <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]> <body>   <type>default</type>   <way>my_cool_method</way>   <person>     <name>joeblow</name>     <email>who@what.com</email>     <!-- <hash>abc1234</hash> -->   </person>   <thing>BONKERS</thing>   <thang>EATATJOES</thang>   <reference>BANANAS</reference> </body>"
#define XML_W_STACK_BOMB "<?xml version=\"1.0\" encoding=\"utf-8\"?><!DOCTYPE foo[ <!ENTITY xeekabut0 \"tpsox\"><!ENTITY xeekabut1 \"&xeekabut0;&xeekabut0;\"><!ENTITY xeekabut2 \"&xeekabut1;&xeekabut1;\">]><tns:QueryProcInstReq xmlns:tns=\"http://xml.sap.com/2010/03/sbc/bpf\">&xeekabut2;</tns:QueryProcInstReq>"
//! ----------------------------------------------------------------------------
//! json parse
//! ----------------------------------------------------------------------------
TEST_CASE( "xml parse basic test", "[xml_parse_basic]" ) {
        // -------------------------------------------------
        // basic test
        // -------------------------------------------------
        SECTION("xml parse basic") {
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 8096, 8096, NULL, true);
                ns_waflz::parser_xml *l_p_xml = new ns_waflz::parser_xml(l_rqst_ctx);
                l_rqst_ctx->m_body_parser = l_p_xml;
                int32_t l_s;
                l_s = l_p_xml->init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_p_xml->process_chunk(XML_SHORT, strlen(XML_SHORT));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_p_xml->finish();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                xmlDocPtr l_doc = l_p_xml->m_doc;
                // -----------------------------------------
                // basic document validation
                // -----------------------------------------
                REQUIRE((l_p_xml->well_formed() == true));
                REQUIRE((l_doc != NULL));
                REQUIRE((l_doc->type == XML_DOCUMENT_NODE));
                REQUIRE((l_doc->children != NULL));
                REQUIRE((l_doc->children->type == XML_ELEMENT_NODE));
                REQUIRE((l_doc->children->name != NULL));
                REQUIRE((strcmp((const char*)l_doc->children->name,"monkeys")==0));
                REQUIRE((l_rqst_ctx->m_body_arg_list.size() == 0));
                // -----------------------------------------
                // display...
                // -----------------------------------------
                //NDBG_PRINT("l_doc->type: %d\n", l_doc->type);
                //NDBG_PRINT("l_doc->children->type: %d\n", l_doc->children->type);
                //NDBG_PRINT("l_doc->children->name: %s\n", l_doc->children->name);
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
        // -------------------------------------------------
        // basic test
        // -------------------------------------------------
        SECTION("xml parse no xxe") {
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 8096, 8096, NULL, true);
                ns_waflz::parser_xml *l_p_xml = new ns_waflz::parser_xml(l_rqst_ctx);
                l_rqst_ctx->m_body_parser = l_p_xml;
                int32_t l_s;
                l_s = l_p_xml->init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_p_xml->process_chunk(XML_W_XXE, strlen(XML_W_XXE));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_p_xml->finish();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                xmlDocPtr l_doc = l_p_xml->m_doc;
                // -----------------------------------------
                // display...
                // -----------------------------------------
                //NDBG_PRINT("l_doc->type: %d\n", l_doc->type);
                //NDBG_PRINT("l_doc->children->type: %d\n", l_doc->children->type);
                //NDBG_PRINT("l_doc->children->name: %s\n", l_doc->children->name);
                // -----------------------------------------
                // basic document validation
                // -----------------------------------------
                REQUIRE((l_p_xml->well_formed() == true));
                REQUIRE((l_doc != NULL));
                REQUIRE((l_doc->type == XML_DOCUMENT_NODE));
                REQUIRE((l_doc->children != NULL));
                REQUIRE((l_doc->children->type == XML_DTD_NODE));
                REQUIRE((l_doc->children->name != NULL));
                REQUIRE((strcmp((const char*)l_doc->children->name,"foo")==0));
                REQUIRE((l_rqst_ctx->m_body_arg_list.size() == 0));
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
        // -------------------------------------------------
        // basic test
        // -------------------------------------------------
        SECTION("xml parse xxe") {
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 8096, 8096, NULL, true);
                ns_waflz::parser_xml *l_p_xml = new ns_waflz::parser_xml(l_rqst_ctx);
                l_rqst_ctx->m_body_parser = l_p_xml;
                l_p_xml->set_capture_xxe(true);
                int32_t l_s;
                l_s = l_p_xml->init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_p_xml->process_chunk(XML_W_XXE, strlen(XML_W_XXE));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_p_xml->finish();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                xmlDocPtr l_doc = l_p_xml->m_doc;
                // -----------------------------------------
                // display...
                // -----------------------------------------
                //NDBG_PRINT("l_doc->type: %d\n", l_doc->type);
                //NDBG_PRINT("l_doc->children->type: %d\n", l_doc->children->type);
                //NDBG_PRINT("l_doc->children->name: %s\n", l_doc->children->name);
                // -----------------------------------------
                // basic document validation
                // -----------------------------------------
                REQUIRE((l_p_xml->well_formed() == true));
                REQUIRE((l_doc != NULL));
                REQUIRE((l_doc->type == XML_DOCUMENT_NODE));
                REQUIRE((l_doc->children != NULL));
                REQUIRE((l_rqst_ctx->m_body_arg_list.size() == 3));
                uint32_t i_arg = 0;
                for(ns_waflz::arg_list_t::const_iterator i_q = l_rqst_ctx->m_body_arg_list.begin();
                    i_q != l_rqst_ctx->m_body_arg_list.end();
                    ++i_q, ++i_arg)
                {
                        //NDBG_PRINT(": [%d]%.*s: [%d]%.*s\n",
                        //           i_q->m_key_len, i_q->m_key_len, i_q->m_key,
                        //           i_q->m_val_len, i_q->m_val_len, i_q->m_val);
                        switch(i_arg)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_q->m_key, "writer", i_q->m_key_len) == 0));
                                REQUIRE((strncmp(i_q->m_val, "Donald Duck.", i_q->m_val_len) == 0));
                                break;
                        }
                        case 1:
                        {
                                REQUIRE((strncmp(i_q->m_key, "copyright", i_q->m_key_len) == 0));
                                REQUIRE((strncmp(i_q->m_val, "Copyright W3Schools.", i_q->m_val_len) == 0));
                                break;
                        }
                        case 2:
                        {
                                REQUIRE((strncmp(i_q->m_key, "xxe", i_q->m_key_len) == 0));
                                REQUIRE((strncmp(i_q->m_val, "file:///etc/passwd", i_q->m_val_len) == 0));
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
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
        // -------------------------------------------------
        // basic test
        // -------------------------------------------------
        SECTION("xml parse with recursive entity replacements") {
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 8096, 8096, NULL, true);
                ns_waflz::parser_xml *l_p_xml = new ns_waflz::parser_xml(l_rqst_ctx);
                l_rqst_ctx->m_body_parser = l_p_xml;
                l_p_xml->set_capture_xxe(true);
                int32_t l_s;
                l_s = l_p_xml->init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_p_xml->process_chunk(XML_W_STACK_BOMB, strlen(XML_W_STACK_BOMB));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_p_xml->finish();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                xmlDocPtr l_doc = l_p_xml->m_doc;
                // -----------------------------------------
                // display...
                // -----------------------------------------
                //NDBG_PRINT("l_doc->type: %d\n", l_doc->type);
                //NDBG_PRINT("l_doc->children->type: %d\n", l_doc->children->type);
                //NDBG_PRINT("l_doc->children->name: %s\n", l_doc->children->name);
                // -----------------------------------------
                // basic document validation
                // -----------------------------------------
                REQUIRE((l_p_xml->well_formed() == true));
                REQUIRE((l_doc != NULL));
                REQUIRE((l_doc->type == XML_DOCUMENT_NODE));
                REQUIRE((l_doc->children != NULL));
                REQUIRE((l_rqst_ctx->m_body_arg_list.size() == 3));
                uint32_t i_arg = 0;
                for(ns_waflz::arg_list_t::const_iterator i_q = l_rqst_ctx->m_body_arg_list.begin();
                    i_q != l_rqst_ctx->m_body_arg_list.end();
                    ++i_q, ++i_arg)
                {
                        //NDBG_PRINT(": [%d]%.*s: [%d]%.*s\n",
                        //           i_q->m_key_len, i_q->m_key_len, i_q->m_key,
                        //           i_q->m_val_len, i_q->m_val_len, i_q->m_val);
                        switch(i_arg)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_q->m_key, "xeekabut0", i_q->m_key_len) == 0));
                                REQUIRE((strncmp(i_q->m_val, "tpsox.", i_q->m_val_len) == 0));
                                break;
                        }
                        case 1:
                        {
                                REQUIRE((strncmp(i_q->m_key, "xeekabut1", i_q->m_key_len) == 0));
                                REQUIRE((strncmp(i_q->m_val, "&xeekabut0;&xeekabut0;", i_q->m_val_len) == 0));
                                break;
                        }
                        case 2:
                        {
                                REQUIRE((strncmp(i_q->m_key, "xeekabut2", i_q->m_key_len) == 0));
                                REQUIRE((strncmp(i_q->m_val, "&xeekabut1;&xeekabut1;", i_q->m_val_len) == 0));
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
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
}
