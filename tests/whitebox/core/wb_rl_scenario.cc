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
#include <unistd.h>
#include "waflz/engine.h"
#include "waflz/def.h"
#include "waflz/scopes.h"
#include "waflz/lm_db.h"
#include "waflz/rqst_ctx.h"
#include "waflz/limit.h"
#include "support/ndebug.h"
#include "waflz/captcha.h"
#include "support/file_util.h"
#include "waflz/challenge.h"
#include <rapidjson/error/en.h>
#include "jspb/jspb.h"
#include "limit.pb.h"
#include <sys/stat.h>
#include <string.h>
//! ----------------------------------------------------------------------------
//! request callbacks
//! ----------------------------------------------------------------------------
static const char* s_ip = "156.123.12.7";
static int32_t get_rqst_src_addr_cb(const char** a_data, uint32_t* a_len, void* a_ctx)
{
        *a_data = s_ip;
        *a_len = strlen(s_ip);
        return 0;
}
static const char* s_host = "rl_test.com";
static int32_t get_rqst_host_cb(const char** a_host, uint32_t* a_host_len, void* a_ctx)
{
        *a_host = s_host;
        *a_host_len = strlen(s_host);
        return 0;
}
static const char* s_uri = "/test.html";
static int32_t get_rqst_uri_cb(const char** a_uri, uint32_t* a_uri_len, void* a_ctx)
{
        *a_uri = s_uri;
        *a_uri_len = strlen(s_uri);
        return 0;
}
//! ----------------------------------------------------------------------------
//! create_lmdb
//! ----------------------------------------------------------------------------
ns_waflz::kv_db* create_lmdb( std::string a_dir )
{
        // -------------------------------------------------
        // status var
        // -------------------------------------------------
        int32_t l_s;
        // -------------------------------------------------
        // get location of lmdb or tmp location to create it
        // -------------------------------------------------
        std::string l_lmdb_dir = (a_dir.empty()) ? "/tmp/test_lmdb" : a_dir;
        // -------------------------------------------------
        // file location
        // -------------------------------------------------
        std::string data_file = l_lmdb_dir + "/data.mdb";
        std::string lock_file = l_lmdb_dir + "/lock.mdb";
        // -------------------------------------------------
        // check if folder location exists
        // -------------------------------------------------
        struct stat l_stat;
        l_s = stat(l_lmdb_dir.c_str(), &l_stat);
        bool dir_exists = l_s == 0;
        // -------------------------------------------------
        // remove db from location if it exists
        // -------------------------------------------------
        if (dir_exists)
        {
                unlink(data_file.c_str());
                unlink(lock_file.c_str());
                l_s = rmdir(l_lmdb_dir.c_str());
                if (l_s != 0)
                {
                        std::cout << "failed to remove dir: " << l_lmdb_dir << std::endl;
                        return nullptr;
                }
        }
        // -------------------------------------------------
        // create directory
        // -------------------------------------------------
        l_s = mkdir(l_lmdb_dir.c_str(), 0700);
        if (l_s != 0)
        {
                std::cout << "failed to make dir: " << l_lmdb_dir << std::endl;
                return nullptr;
        }
        // -------------------------------------------------
        // lmdb pointer
        // -------------------------------------------------
        ns_waflz::kv_db* l_db = NULL;
        l_db = reinterpret_cast<ns_waflz::kv_db *>(new ns_waflz::lm_db());
        // -------------------------------------------------
        // options
        // -------------------------------------------------
        l_db->set_opt(ns_waflz::lm_db::OPT_LMDB_DIR_PATH, l_lmdb_dir.c_str(), l_lmdb_dir.length());
        l_db->set_opt(ns_waflz::lm_db::OPT_LMDB_READERS, NULL, 6);
        l_db->set_opt(ns_waflz::lm_db::OPT_LMDB_MMAP_SIZE, NULL, 10485760);
        // -------------------------------------------------
        // init db
        // -------------------------------------------------
        l_s = l_db->init();
        if (l_s != WAFLZ_STATUS_OK)
        {
                NDBG_PRINT("error performing db init: Reason: %s\n", l_db->get_err_msg());
                if (l_db) { delete l_db; l_db = NULL; }
                return nullptr;
        }
        // -------------------------------------------------
        // done
        // -------------------------------------------------
        return l_db;
}
//! ----------------------------------------------------------------------------
//! instances tests
//! ----------------------------------------------------------------------------
TEST_CASE( "scopes test", "[scopes]" ) {
        // -------------------------------------------------
        // create the callbacks for rqst_ctx
        // -------------------------------------------------
        static ns_waflz::rqst_ctx_callbacks s_callbacks = {
                get_rqst_src_addr_cb,
                get_rqst_host_cb,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                get_rqst_uri_cb,
                NULL,
                NULL,
                NULL,
                NULL, //get_rqst_header_w_key_cb,
                NULL,
                NULL,
                NULL, //get_rqst_local_addr_cb,
                NULL, //get_rqst_canonical_port_cb,
                NULL, //get_rqst_apparent_cache_status_cb,
                NULL, //get_rqst_bytes_out_cb,
                NULL, //get_rqst_bytes_in_cb,
                NULL, //get_rqst_uuid_cb,
                NULL, //get_cust_id_cb
                NULL,
                NULL,
                NULL,
                NULL,
                NULL  //m_get_backend_port_cb
        };
        // -------------------------------------------------
        // status vars
        // -------------------------------------------------
        int32_t l_s;
        // -------------------------------------------------
        // get current working directory
        // -------------------------------------------------
        char l_cwd[1024];
        getcwd(l_cwd, sizeof(l_cwd));
        // -------------------------------------------------
        // get ruleset dir
        // -------------------------------------------------
        std::string l_rule_dir = std::string(l_cwd) + "/../../../../tests/data/waf/ruleset/";
        // -------------------------------------------------
        // get scope file
        // -------------------------------------------------
        std::string l_scope_file = std::string(l_cwd) + "/../../../../tests/data/waf/conf/scopes/0100.scopes.json";
        // -------------------------------------------------
        // get conf path
        // -------------------------------------------------
        std::string l_conf_path = std::string(l_cwd) + "/../../../../tests/data/waf/conf/";
        // -------------------------------------------------
        // get captcha file
        // -------------------------------------------------
        std::string l_captcha_file = std::string(l_cwd) + "/../../../../tests/data/bot/bot-captcha.b64";
        // -------------------------------------------------
        // geo ip dbs
        // -------------------------------------------------
        std::string l_geoip2_city_file = std::string(l_cwd) + "/../../../../tests/data/waf/db/GeoLite2-City.mmdb";
        std::string l_geoip2_asn_file = std::string(l_cwd) + "/../../../../tests/data/waf/db/GeoLite2-ASN.mmdb";
        // -------------------------------------------------
        // init engine
        // -------------------------------------------------
        ns_waflz::engine *l_engine = new ns_waflz::engine();
        l_engine->set_ruleset_dir(l_rule_dir);
        l_engine->set_geoip2_dbs(l_geoip2_city_file, l_geoip2_asn_file);
        l_s = l_engine->init();
        REQUIRE(l_s == WAFLZ_STATUS_OK);
        // -------------------------------------------------
        // create RL db
        // -------------------------------------------------
        ns_waflz::kv_db* l_lmdb = create_lmdb("");
        REQUIRE(l_lmdb != nullptr);
        // -------------------------------------------------
        // create scope object
        // -------------------------------------------------
        ns_waflz::kv_db* l_ja3_db = reinterpret_cast<ns_waflz::kv_db *>(new ns_waflz::lm_db());
        ns_waflz::challenge* l_challenge = new ns_waflz::challenge();
        ns_waflz::captcha* l_captcha = new ns_waflz::captcha();
        ns_waflz::scopes* l_scope = new ns_waflz::scopes(*l_engine,
                                                        *l_lmdb,
                                                        *l_ja3_db,
                                                        *l_challenge,
                                                        *l_captcha);
        // -------------------------------------------------
        // load scope file content
        // -------------------------------------------------
        char* l_scope_content = NULL;
        uint32_t l_scope_content_length = 0;
        l_s = ns_waflz::read_file(l_scope_file.c_str(), &l_scope_content, l_scope_content_length);
        if (l_s != WAFLZ_STATUS_OK)
        {
                std::cout << ":read_file[" << l_scope_file << "]: " << ns_waflz::get_err_msg() << std::endl;
                if (l_scope_content) {
                        free(l_scope_content);
                        l_scope_content = NULL;
                        l_scope_content_length = 0;
                }
        }
        REQUIRE( l_s == WAFLZ_STATUS_OK );
        // -------------------------------------------------
        // parse scope file
        // -------------------------------------------------
        rapidjson::Document* l_js = new rapidjson::Document();
        rapidjson::ParseResult l_ok;
        l_ok = l_js->Parse(l_scope_content, l_scope_content_length);
        if (!l_ok)
        {
                std::cout << "JSON Parse error: " 
                        << rapidjson::GetParseError_En(l_ok.Code())
                        << (int)l_ok.Offset() << std::endl;

        }
        REQUIRE( l_ok );
        // -------------------------------------------------
        // load scope file into scope object
        // -------------------------------------------------
        l_s = l_scope->load( (void *)l_js, l_conf_path );
        REQUIRE(l_s == WAFLZ_STATUS_OK);
        // -------------------------------------------------
        // THIS TEST DOES THE FOLLOWING:
        // fires off audit_1 limit (after 4 rqst)
        // fires off both audit_1 and prod_1 limit (after 7)
        // waits to remove both limits
        // fires off audit_2 limit (after 9)
        // firest off audit_2 limit and prod_1 limit (after 14)
        // -------------------------------------------------
        SECTION("verify load") {
                //! ----------------------------------------
                //! SETUP COMPLETE, now we can test RL.
                //! ----------------------------------------
                // -----------------------------------------
                // variables that will be passed from scope
                // -----------------------------------------
                const waflz_pb::enforcement* l_enforcement = NULL;
                waflz_pb::event* l_audit_event = NULL;
                waflz_pb::event* l_prod_event = NULL;
                waflz_pb::event* l_bot_event = NULL;
                ns_waflz::rqst_ctx* l_ctx = NULL;
                // -----------------------------------------
                // run through three request - there should
                // be no events or enforcements
                // -----------------------------------------
                for (uint32_t i_run_number = 0; i_run_number < 3; i_run_number++)
                {
                        // ---------------------------------
                        // run the scope
                        // ---------------------------------
                        l_s = l_scope->process(
                                &l_enforcement,
                                &l_audit_event,
                                &l_prod_event,
                                &l_bot_event,
                                NULL,
                                ns_waflz::PART_MK_LIMITS,
                                &s_callbacks,
                                &l_ctx,
                                NULL,
                                (int32_t)0
                        );
                        // ---------------------------------
                        // everything should be ok - no bad
                        // stuff
                        // ---------------------------------
                        REQUIRE(l_s == WAFLZ_STATUS_OK);
                        REQUIRE(l_ctx != nullptr);
                        REQUIRE(l_ctx->m_audit_limit == NULL);
                        REQUIRE(l_ctx->m_limit == nullptr);
                        REQUIRE(l_audit_event == nullptr);
                        REQUIRE(l_prod_event == nullptr);
                        REQUIRE(l_bot_event == nullptr);
                        // ---------------------------------
                        // reset context for next run
                        // ---------------------------------
                        l_ctx->reset_phase_1();
                }
                // -----------------------------------------
                // run scope again - it should get hit with
                // an audit limit
                // -----------------------------------------
                l_s = l_scope->process(
                        &l_enforcement,
                        &l_audit_event,
                        &l_prod_event,
                        &l_bot_event,
                        NULL,
                        ns_waflz::PART_MK_LIMITS,
                        &s_callbacks,
                        &l_ctx,
                        NULL,
                        (int32_t)0
                );
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                // -----------------------------------------
                // audit limit is audit_1
                // -----------------------------------------
                REQUIRE(l_ctx->m_audit_limit != nullptr);
                REQUIRE(l_ctx->m_audit_limit->id() == "audit_1");
                // -----------------------------------------
                // nothing stopped the rest of the run
                // (ie: no events)
                // -----------------------------------------
                REQUIRE(l_ctx->m_limit == nullptr);
                REQUIRE(l_audit_event == nullptr);
                REQUIRE(l_prod_event == nullptr);
                REQUIRE(l_bot_event == nullptr);
                // -----------------------------------------
                // remove audit limit from the rqst to keep
                // counting
                // -----------------------------------------
                l_ctx->m_audit_limit = NULL;
                // -----------------------------------------
                // run through two request - this will get
                // us to the limit of the prod limit
                // -----------------------------------------
                for (uint32_t i_run_number = 5; i_run_number < 7; i_run_number++)
                {
                        l_s = l_scope->process(
                                &l_enforcement,
                                &l_audit_event,
                                &l_prod_event,
                                &l_bot_event,
                                NULL,
                                ns_waflz::PART_MK_LIMITS,
                                &s_callbacks,
                                &l_ctx,
                                NULL,
                                (int32_t)0
                        );
                        REQUIRE(l_s == WAFLZ_STATUS_OK);
                        // ---------------------------------
                        // reset context for next run
                        // ---------------------------------
                        l_ctx->reset_phase_1();
                        l_ctx->m_audit_limit = NULL;
                }
                // -----------------------------------------
                // run scope again - it should get hit both
                // an audit limit and a prod limit
                // -----------------------------------------
                l_s = l_scope->process(
                        &l_enforcement,
                        &l_audit_event,
                        &l_prod_event,
                        &l_bot_event,
                        NULL,
                        ns_waflz::PART_MK_LIMITS,
                        &s_callbacks,
                        &l_ctx,
                        NULL,
                        (int32_t)0
                );
                REQUIRE(l_s == WAFLZ_STATUS_OK);
                // -----------------------------------------
                // audit limit is audit_1
                // -----------------------------------------
                REQUIRE(l_ctx->m_audit_limit != nullptr);
                REQUIRE(l_ctx->m_audit_limit->id() == "audit_1");
                // -----------------------------------------
                // prod limit is prod_1
                // -----------------------------------------
                REQUIRE(l_ctx->m_limit != nullptr);
                REQUIRE(l_ctx->m_limit->id() == "prod_1");
                // -----------------------------------------
                // nothing stopped the rest of the run
                // (ie: no events)
                // -----------------------------------------
                REQUIRE(l_audit_event == nullptr);
                REQUIRE(l_prod_event == nullptr);
                REQUIRE(l_bot_event == nullptr);
                // -----------------------------------------
                // wait for 2 seconds - this should remove
                // audit event on next attempt
                // -----------------------------------------
                sleep(2);
                // -----------------------------------------
                // reset context for next run
                // -----------------------------------------
                l_ctx->reset_phase_1();
                l_ctx->m_audit_limit = NULL;
                l_ctx->m_limit = NULL;
                // -----------------------------------------
                // run through two request - this will get
                // us to the second audit limit
                // -----------------------------------------
                for (uint32_t i_run_number = 7; i_run_number < 9; i_run_number++)
                {
                        l_s = l_scope->process(
                                &l_enforcement,
                                &l_audit_event,
                                &l_prod_event,
                                &l_bot_event,
                                NULL,
                                ns_waflz::PART_MK_LIMITS,
                                &s_callbacks,
                                &l_ctx,
                                NULL,
                                (int32_t)0
                        );
                        REQUIRE(l_s == WAFLZ_STATUS_OK);
                        // ---------------------------------
                        // reset context for next run
                        // ---------------------------------
                        l_ctx->reset_phase_1();
                }
                // -----------------------------------------
                // audit limit is audit_2
                // -----------------------------------------
                REQUIRE(l_ctx->m_audit_limit != nullptr);
                REQUIRE(l_ctx->m_audit_limit->id() == "audit_2");
                // -----------------------------------------
                // nothing stopped the rest of the run
                // (ie: no events)
                // -----------------------------------------
                REQUIRE(l_ctx->m_limit == nullptr);
                REQUIRE(l_audit_event == nullptr);
                REQUIRE(l_prod_event == nullptr);
                REQUIRE(l_bot_event == nullptr);
                // -----------------------------------------
                // run through five request - this will get
                // us to the second audit limit and the prod
                // again
                // -----------------------------------------
                for (uint32_t i_run_number = 9; i_run_number < 14; i_run_number++)
                {
                        // -----------------------------------------
                        // reset context for next run
                        // -----------------------------------------
                        l_ctx->reset_phase_1();
                        l_ctx->m_audit_limit = NULL;
                        l_ctx->m_limit = NULL;
                        // -----------------------------------------
                        // run scope
                        // -----------------------------------------
                        l_s = l_scope->process(
                                &l_enforcement,
                                &l_audit_event,
                                &l_prod_event,
                                &l_bot_event,
                                NULL,
                                ns_waflz::PART_MK_LIMITS,
                                &s_callbacks,
                                &l_ctx,
                                NULL,
                                (int32_t)0
                        );
                        REQUIRE(l_s == WAFLZ_STATUS_OK);
                }
                // -----------------------------------------
                // audit limit should still be audit_2
                // even though audit_1 would have tripped.
                // -----------------------------------------
                REQUIRE(l_ctx->m_audit_limit != nullptr);
                REQUIRE(l_ctx->m_audit_limit->id() == "audit_2");
                // -----------------------------------------
                // prod limit is prod_1
                // -----------------------------------------
                REQUIRE(l_ctx->m_limit != nullptr);
                REQUIRE(l_ctx->m_limit->id() == "prod_1");
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                if(l_ctx){delete l_ctx;l_ctx = NULL;}
        }
        // -------------------------------------------------
        // delete all pointers (there is a lot :P)
        // -------------------------------------------------
        if(l_engine){delete l_engine;l_engine = NULL;}
        if(l_lmdb){delete l_lmdb;l_lmdb = NULL;}
        if(l_scope_content){free(l_scope_content); l_scope_content = NULL;}
        if(l_ja3_db){delete l_ja3_db;l_ja3_db = NULL;}
        if(l_challenge){delete l_challenge;l_challenge = NULL;}
        if(l_captcha){delete l_captcha;l_captcha = NULL;}
        if(l_scope){delete l_scope;l_scope = NULL;}
        if(l_js){delete l_js;l_js = NULL;}
}
