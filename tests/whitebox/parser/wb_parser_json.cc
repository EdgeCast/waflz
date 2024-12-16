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
#include "parser/parser_json.h"
#include "support/ndebug.h"
#include <string.h>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define JSON_SHORT "{\"pets\": {\"cat\": \"fish\", \"dog\": \"bone\"}}"
#define JSON_LONG_FIELD_NAMES "{\"_data_1_0_bananaMonday_1088888_bananas_rc_Banana_Monkey_ttp_cat_fish_dog_koala_puid_XXX_XXXXXXXXXXXXXXXXXXXX_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_XXXXXXXXXXXXXXXXXX_XXXXXXXXXXXXX_XXXXXXXXXXX_XXXX_XXXXXXXXX_XXXXXXXXXXXXXXXXXXX_XXXXXXXXXXXXXXX_XXXXXXXXXXXXX_status_strikeThroughText\":{\"url\":\"/data/1.0/Bananas/8888888/monkeys?rc=Banana_Monkeez&ttp=a_b_c_d_e&banana=AAAAABBBCCCCCDDDDD&monkeez=2019_01_01_2019_01_01&bananas=1_2&rn=2&fields=bananaMonkeez,complete,bananasMonkey,bananaMonkey&bananaMonkeez=data,bananas,bananaMonkeez,catDogs,catDogFish,status,wangWangWang\"}}"
#define JSON_PARSER_JSON_PREFIX_LEN_MAX "{ \"id\": \"fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj\", \"ext\" : { \"source\": \"secure_darla\" }, \"site\": { \"id\": \"brxd232561\", \"page\": \"https://hk.yahoo.com/\" , \"publisher\": { \"id\": \"brxd25533108522\", \"ext\": { \"adclntid\": 1004, \"hotlistpubid\": \"25533108522\" } }, \"ext\": { \"hotlistsiteid\": \"205061\" } }, \"device\": { \"ua\": \"Mozilla/5.0 (Windows NT 6.1; rv:66.0) Gecko/20100101 Firefox/66.0\" , \"ip\" : \"112.118.170.249\" }, \"user\": { \"id\": \"7dgj7vpe7u297&b=3&s=l1\" , \"ext\": { } }, \"regs\" :{ \"ext\" : { \"gdpr\" : 0 } }, \"imp\": [ { \"id\": \"0\", \"secure\": 1, \"ext\": { \"pos\": \"y400353\", \"pvid\": \"fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj\", \"spaceid\": \"1197745128\", \"adposition\": \"EU\", \"lmsid\": \"\", \"publisherblob\" : \"|fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj|1197745128|EU|fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj\", \"rs\": \"\", \"kvs\" : {\"pgcolo\":\"gq1\",\"secure\":\"true\",\"secure-darla\":\"3-6-3|ysd|1\",\"ssp\":\"brxd\",\"y-bucket\":\"lugia-836510\"} , \"sectionid\" : \"73373061\" }, \"banner\": { \"w\": 1, \"h\": 1 } },{ \"id\": \"1\", \"secure\": 1, \"ext\": { \"pos\": \"y400354\", \"pvid\": \"fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj\", \"spaceid\": \"1197745128\", \"adposition\": \"EU3\", \"lmsid\": \"\", \"publisherblob\" : \"|fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj|1197745128|EU3|fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj\", \"rs\": \"\", \"kvs\" : {\"pgcolo\":\"gq1\",\"secure\":\"true\",\"secure-darla\":\"3-6-3|ysd|1\",\"ssp\":\"brxd\",\"y-bucket\":\"lugia-836510\"} , \"sectionid\" : \"73373061\" }, \"banner\": { \"w\": 140, \"h\": 100 } },{ \"id\": \"2\", \"secure\": 1, \"ext\": { \"pos\": \"y400355\", \"pvid\": \"fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj\", \"spaceid\": \"1197745128\", \"adposition\": \"EU4\", \"lmsid\": \"\", \"publisherblob\" : \"|fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj|1197745128|EU4|fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj\", \"rs\": \"\", \"kvs\" : {\"pgcolo\":\"gq1\",\"secure\":\"true\",\"secure-darla\":\"3-6-3|ysd|1\",\"ssp\":\"brxd\",\"y-bucket\":\"lugia-836510\"} , \"sectionid\" : \"73373061\" }, \"banner\": { \"w\": 1, \"h\": 1 } },{ \"id\": \"3\", \"secure\": 1, \"ext\": { \"pos\": \"y400356\", \"pvid\": \"fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj\", \"spaceid\": \"1197745128\", \"adposition\": \"FPAD\", \"lmsid\": \"\", \"publisherblob\" : \"|fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj|1197745128|FPAD|fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj\", \"rs\": \"\", \"kvs\" : {\"pgcolo\":\"gq1\",\"secure\":\"true\",\"secure-darla\":\"3-6-3|ysd|1\",\"ssp\":\"brxd\",\"y-bucket\":\"lugia-836510\"} , \"sectionid\" : \"73373061\" }, \"banner\": { \"w\": 1, \"h\": 1 } },{ \"id\": \"4\", \"secure\": 1, \"ext\": { \"pos\": \"y400357\", \"pvid\": \"fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj\", \"spaceid\": \"1197745128\", \"adposition\": \"FPL\", \"lmsid\": \"\", \"publisherblob\" : \"|fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj|1197745128|FPL|fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj\", \"rs\": \"\", \"kvs\" : {\"pgcolo\":\"gq1\",\"secure\":\"true\",\"secure-darla\":\"3-6-3|ysd|1\",\"ssp\":\"brxd\",\"y-bucket\":\"lugia-836510\"} , \"sectionid\" : \"73373061\" }, \"banner\": { \"w\": 635, \"h\": 100 } },{ \"id\": \"5\", \"secure\": 1, \"ext\": { \"pos\": \"y400358\", \"pvid\": \"fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj\", \"spaceid\": \"1197745128\", \"adposition\": \"FPR\", \"lmsid\": \"\", \"publisherblob\" : \"|fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj|1197745128|FPR|fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj\", \"rs\": \"\", \"kvs\" : {\"pgcolo\":\"gq1\",\"secure\":\"true\",\"secure-darla\":\"3-6-3|ysd|1\",\"ssp\":\"brxd\",\"y-bucket\":\"lugia-836510\"} , \"sectionid\" : \"73373061\" }, \"banner\": { \"w\": 374, \"h\": 226 } },{ \"id\": \"6\", \"secure\": 1, \"ext\": { \"pos\": \"y400359\", \"pvid\": \"fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj\", \"spaceid\": \"1197745128\", \"adposition\": \"FPR1\", \"lmsid\": \"\", \"publisherblob\" : \"|fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj|1197745128|FPR1|fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj\", \"rs\": \"\", \"kvs\" : {\"pgcolo\":\"gq1\",\"secure\":\"true\",\"secure-darla\":\"3-6-3|ysd|1\",\"ssp\":\"brxd\",\"y-bucket\":\"lugia-836510\"} , \"sectionid\" : \"73373061\" }, \"banner\": { \"w\": 1, \"h\": 1 } },{ \"id\": \"7\", \"secure\": 1, \"ext\": { \"pos\": \"y400360\", \"pvid\": \"fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj\", \"spaceid\": \"1197745128\", \"adposition\": \"FPR2\", \"lmsid\": \"\", \"publisherblob\" : \"|fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj|1197745128|FPR2|fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj\", \"rs\": \"\", \"kvs\" : {\"pgcolo\":\"gq1\",\"secure\":\"true\",\"secure-darla\":\"3-6-3|ysd|1\",\"ssp\":\"brxd\",\"y-bucket\":\"lugia-836510\"} , \"sectionid\" : \"73373061\" }, \"banner\": { \"w\": 1, \"h\": 1 } },{ \"id\": \"8\", \"secure\": 1, \"ext\": { \"pos\": \"y400361\", \"pvid\": \"fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj\", \"spaceid\": \"1197745128\", \"adposition\": \"FPT\", \"lmsid\": \"\", \"publisherblob\" : \"|fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj|1197745128|FPT|fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj\", \"rs\": \"\", \"kvs\" : {\"pgcolo\":\"gq1\",\"secure\":\"true\",\"secure-darla\":\"3-6-3|ysd|1\",\"ssp\":\"brxd\",\"y-bucket\":\"lugia-836510\"} , \"sectionid\" : \"73373061\" }, \"banner\": { \"w\": 374, \"h\": 110 } },{ \"id\": \"9\", \"secure\": 1, \"ext\": { \"pos\": \"y400362\", \"pvid\": \"fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj\", \"spaceid\": \"1197745128\", \"adposition\": \"MBAR\", \"lmsid\": \"\", \"publisherblob\" : \"|fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj|1197745128|MBAR|fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj\", \"rs\": \"\", \"kvs\" : {\"pgcolo\":\"gq1\",\"secure\":\"true\",\"secure-darla\":\"3-6-3|ysd|1\",\"ssp\":\"brxd\",\"y-bucket\":\"lugia-836510\"} , \"sectionid\" : \"73373061\" }, \"banner\": { \"w\": 300, \"h\": 250 } },{ \"id\": \"10\", \"secure\": 1, \"ext\": { \"pos\": \"y400364\", \"pvid\": \"fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj\", \"spaceid\": \"1197745128\", \"adposition\": \"TL1\", \"lmsid\": \"\", \"publisherblob\" : \"|fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj|1197745128|TL1|fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj\", \"rs\": \"\", \"kvs\" : {\"pgcolo\":\"gq1\",\"secure\":\"true\",\"secure-darla\":\"3-6-3|ysd|1\",\"ssp\":\"brxd\",\"y-bucket\":\"lugia-836510\"} , \"sectionid\" : \"73373061\" }, \"banner\": { \"w\": 120, \"h\": 45 } },{ \"id\": \"11\", \"secure\": 1, \"ext\": { \"pos\": \"y400365\", \"pvid\": \"fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj\", \"spaceid\": \"1197745128\", \"adposition\": \"TL3\", \"lmsid\": \"\", \"publisherblob\" : \"|fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj|1197745128|TL3|fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj\", \"rs\": \"\", \"kvs\" : {\"pgcolo\":\"gq1\",\"secure\":\"true\",\"secure-darla\":\"3-6-3|ysd|1\",\"ssp\":\"brxd\",\"y-bucket\":\"lugia-836510\"} , \"sectionid\" : \"73373061\" }, \"banner\": { \"w\": 120, \"h\": 60 } } ] }"
//! ----------------------------------------------------------------------------
//! json parse
//! ----------------------------------------------------------------------------
TEST_CASE( "json parse basic test", "[json_parse_basic]" ) {
        // -------------------------------------------------
        // basic test
        // -------------------------------------------------
        SECTION("json parse basic") {
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 8096, 8096, NULL, true);
                ns_waflz::parser_json *l_p_json = new ns_waflz::parser_json(l_rqst_ctx);
                l_rqst_ctx->m_body_parser = l_p_json;
                int32_t l_s;
                l_s = l_p_json->init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_p_json->process_chunk(JSON_SHORT, strlen(JSON_SHORT));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_rqst_ctx->m_body_arg_list.size() == 2));
                uint32_t i_arg = 0;
                for(ns_waflz::arg_list_t::const_iterator i_q = l_rqst_ctx->m_body_arg_list.begin();
                    i_q != l_rqst_ctx->m_body_arg_list.end();
                    ++i_q, ++i_arg)
                {
                        //NDBG_OUTPUT(": [%d]%.*s: [%d]%.*s\n",
                        //            i_q->m_key_len, i_q->m_key_len, i_q->m_key,
                        //            i_q->m_val_len, i_q->m_val_len, i_q->m_val);
                        switch(i_arg)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_q->m_key, "pets.cat", i_q->m_key_len) == 0));
                                REQUIRE((strncmp(i_q->m_val, "fish", i_q->m_val_len) == 0));
                                break;
                        }
                        case 1:
                        {
                                REQUIRE((strncmp(i_q->m_key, "pets.dog", i_q->m_key_len) == 0));
                                REQUIRE((strncmp(i_q->m_val, "bone", i_q->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
        // -------------------------------------------------
        // long field names
        // -------------------------------------------------
        SECTION("json parse long field names") {
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 8096, 8096, NULL, true);
                ns_waflz::parser_json *l_p_json = new ns_waflz::parser_json(l_rqst_ctx);
                l_rqst_ctx->m_body_parser = l_p_json;
                int32_t l_s;
                l_s = l_p_json->init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_p_json->process_chunk(JSON_LONG_FIELD_NAMES, strlen(JSON_LONG_FIELD_NAMES));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_rqst_ctx->m_body_arg_list.size() == 1));
                uint32_t i_arg = 0;
                for(ns_waflz::arg_list_t::const_iterator i_q = l_rqst_ctx->m_body_arg_list.begin();
                    i_q != l_rqst_ctx->m_body_arg_list.end();
                    ++i_q, ++i_arg)
                {
                        switch(i_arg)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_q->m_key, "_data_1_0_bananaMonday_1088888_bananas_rc_Banana_Monkey_ttp_cat_fish_dog_koala_puid_XXX_XXXXXXXXXXXXXXXXXXXX_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_XXXXXXXXXXXXXXXXXX_XXXXXXXXXXXXX_XXXXXXXXXXX_XXXX_XXXXXXXXX_XXXXX.url", i_q->m_key_len) == 0));
                                REQUIRE((strncmp(i_q->m_val, "/data/1.0/Bananas/8888888/monkeys?rc=Banana_Monkeez&ttp=a_b_c_d_e&banana=AAAAABBBCCCCCDDDDD&monkeez=2019_01_01_2019_01_01&bananas=1_2&rn=2&fields=bananaMonkeez,complete,bananasMonkey,bananaMonkey&bananaMonkeez=data,bananas,bananaMonkeez,catDogs,catDogFish,status,wangWangWang", i_q->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
        // -------------------------------------------------
        // long field names
        // -------------------------------------------------
        SECTION("json parse 256 byte prefix") {
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 8096, 8069, NULL, true);
                ns_waflz::parser_json *l_p_json = new ns_waflz::parser_json(l_rqst_ctx);
                l_rqst_ctx->m_body_parser = l_p_json;
                int32_t l_s;
                l_s = l_p_json->init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_p_json->process_chunk(JSON_PARSER_JSON_PREFIX_LEN_MAX, strlen(JSON_PARSER_JSON_PREFIX_LEN_MAX));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_rqst_ctx->m_body_arg_list.size() == 216));
                uint32_t i_arg = 0;
                for(ns_waflz::arg_list_t::const_iterator i_q = l_rqst_ctx->m_body_arg_list.begin();
                    i_q != l_rqst_ctx->m_body_arg_list.end();
                    ++i_q, ++i_arg)
                {
                        //NDBG_PRINT(":IARG[%d] [%d]%.*s: [%d]%.*s\n",
                        //            i_arg,
                        //            i_q->m_key_len, i_q->m_key_len, i_q->m_key,
                        //            i_q->m_val_len, i_q->m_val_len, i_q->m_val);
                        switch(i_arg)
                        {
                        case 0:
                        {
                                REQUIRE((strncmp(i_q->m_key, "id", i_q->m_key_len) == 0));
                                REQUIRE((strncmp(i_q->m_val, "fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj", i_q->m_val_len) == 0));
                                break;
                        }
                        case 206:
                        {
                                REQUIRE((strncmp(i_q->m_key, "ext.site.publisher.ext.ext.device.user.ext.regs.ext.imp.ext.kvs.banner.h.ext.kvs.banner.h.ext.kvs.banner.h.ext.kvs.banner.h.ext.kvs.banner.h.ext.kvs.banner.h.ext.kvs.banner.h.ext.kvs.banner.h.ext.kvs.banner.h.ext.kvs.banner.h.ext.kvs.banner.h.ext.publisherblob", i_q->m_key_len) == 0));
                                REQUIRE((strncmp(i_q->m_val, "|fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj|1197745128|TL3|fiGn2jEwLjJ2wmf.XH8JJ0_PMTEyLgAAAABHaWMj", i_q->m_val_len) == 0));
                                break;
                        }
                        default:
                        {
                                break;
                        }
                        }
                }
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
        SECTION("json parse length") {
                ns_waflz::rqst_ctx *l_rqst_ctx = new ns_waflz::rqst_ctx(NULL, 8096, 16, NULL, true);
                ns_waflz::parser_json *l_p_json = new ns_waflz::parser_json(l_rqst_ctx);
                l_rqst_ctx->m_body_parser = l_p_json;
                int32_t l_s;
                l_s = l_p_json->init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                std::string l_body = "{\"key1\":\"val1\", \"key2\":\"val2\"}";
                l_s = l_p_json->process_chunk(l_body.c_str(), 16);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_rqst_ctx->m_body_arg_list.size() == 1));
                uint32_t i_arg = 0;
                ns_waflz::arg_list_t::const_iterator l_list_it = l_rqst_ctx->m_body_arg_list.begin();
                REQUIRE(strncmp(l_list_it->m_key, "key1", l_list_it->m_key_len) == 0);
                REQUIRE(strncmp(l_list_it->m_val, "val1", l_list_it->m_val_len) == 0);
                if(l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        }
}
