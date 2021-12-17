//! ----------------------------------------------------------------------------
//! Copyright Edgecast Inc.
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
// ---------------------------------------------------------
// waflz_server
// ---------------------------------------------------------
#include "cb.h"
#include "sx.h"
#include "sx_profile.h"
#include "sx_acl.h"
#include "sx_rules.h"
#include "sx_scopes.h"
#include "sx_modsecurity.h"
#include "sx_limit.h"
// ---------------------------------------------------------
// waflz
// ---------------------------------------------------------
#include "waflz/rqst_ctx.h"
#include "waflz/profile.h"
#include "waflz/render.h"
#include "waflz/engine.h"
#include "waflz/lm_db.h"
#ifdef WAFLZ_KV_DB_REDIS
#include "waflz/redis_db.h"
#endif
#include "waflz/trace.h"
#include "support/ndebug.h"
#include "support/base64.h"
// ---------------------------------------------------------
// protocol buffers
// ---------------------------------------------------------
#include "event.pb.h"
#include "action.pb.h"
// ---------------------------------------------------------
// is2
// ---------------------------------------------------------
#include "is2/support/trace.h"
#include "is2/nconn/scheme.h"
#include "is2/nconn/nconn.h"
#include "is2/srvr/srvr.h"
#include "is2/srvr/lsnr.h"
#include "is2/srvr/session.h"
#include "is2/srvr/rqst.h"
#include "is2/srvr/resp.h"
#include "is2/srvr/api_resp.h"
#include "is2/srvr/default_rqst_h.h"
#include "is2/handler/proxy_h.h"
#include "is2/handler/file_h.h"
#include "is2/handler/stat_h.h"
// ---------------------------------------------------------
// stdlibs
// ---------------------------------------------------------
#include <errno.h>
#include <string>
#include <getopt.h>
#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef ENABLE_PROFILER
#include <gperftools/profiler.h>
#include <gperftools/heap-profiler.h>
#endif
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#ifndef STATUS_OK
  #define STATUS_OK 0
#endif
#ifndef STATUS_ERROR
  #define STATUS_ERROR -1
#endif
#define _DEFAULT_RESP_BODY_B64 "PCFET0NUWVBFIGh0bWw+PGh0bWw+PGhlYWQ+IDxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4gPHRpdGxlPjwvdGl0bGU+PC9oZWFkPjxib2R5PiA8c3R5bGU+Knstd2Via2l0LWJveC1zaXppbmc6IGJvcmRlci1ib3g7IC1tb3otYm94LXNpemluZzogYm9yZGVyLWJveDsgYm94LXNpemluZzogYm9yZGVyLWJveDt9ZGl2e2Rpc3BsYXk6IGJsb2NrO31ib2R5e2ZvbnQtZmFtaWx5OiAiSGVsdmV0aWNhIE5ldWUiLCBIZWx2ZXRpY2EsIEFyaWFsLCBzYW5zLXNlcmlmOyBmb250LXNpemU6IDE0cHg7IGxpbmUtaGVpZ2h0OiAxLjQyODU3MTQzOyBjb2xvcjogIzMzMzsgYmFja2dyb3VuZC1jb2xvcjogI2ZmZjt9aHRtbHtmb250LXNpemU6IDEwcHg7IC13ZWJraXQtdGFwLWhpZ2hsaWdodC1jb2xvcjogcmdiYSgwLCAwLCAwLCAwKTsgZm9udC1mYW1pbHk6IHNhbnMtc2VyaWY7IC13ZWJraXQtdGV4dC1zaXplLWFkanVzdDogMTAwJTsgLW1zLXRleHQtc2l6ZS1hZGp1c3Q6IDEwMCU7fTpiZWZvcmUsIDphZnRlcnstd2Via2l0LWJveC1zaXppbmc6IGJvcmRlci1ib3g7IC1tb3otYm94LXNpemluZzogYm9yZGVyLWJveDsgYm94LXNpemluZzogYm9yZGVyLWJveDt9LmNvbnRhaW5lcntwYWRkaW5nLXJpZ2h0OiAxNXB4OyBwYWRkaW5nLWxlZnQ6IDE1cHg7IG1hcmdpbi1yaWdodDogYXV0bzsgbWFyZ2luLWxlZnQ6IGF1dG87fUBtZWRpYSAobWluLXdpZHRoOiA3NjhweCl7LmNvbnRhaW5lcnt3aWR0aDogNzUwcHg7fX0uY2FsbG91dCsuY2FsbG91dHttYXJnaW4tdG9wOiAtNXB4O30uY2FsbG91dHtwYWRkaW5nOiAyMHB4OyBtYXJnaW46IDIwcHggMDsgYm9yZGVyOiAxcHggc29saWQgI2VlZTsgYm9yZGVyLWxlZnQtd2lkdGg6IDVweDsgYm9yZGVyLXJhZGl1czogM3B4O30uY2FsbG91dC1kYW5nZXJ7Ym9yZGVyLWxlZnQtY29sb3I6ICNmYTBlMWM7fS5jYWxsb3V0LWRhbmdlciBoNHtjb2xvcjogI2ZhMGUxYzt9LmNhbGxvdXQgaDR7bWFyZ2luLXRvcDogMDsgbWFyZ2luLWJvdHRvbTogNXB4O31oNCwgLmg0e2ZvbnQtc2l6ZTogMThweDt9aDQsIC5oNCwgaDUsIC5oNSwgaDYsIC5oNnttYXJnaW4tdG9wOiAxMHB4OyBtYXJnaW4tYm90dG9tOiAxMHB4O31oMSwgaDIsIGgzLCBoNCwgaDUsIGg2LCAuaDEsIC5oMiwgLmgzLCAuaDQsIC5oNSwgLmg2e2ZvbnQtZmFtaWx5OiBBcGV4LCAiSGVsdmV0aWNhIE5ldWUiLCBIZWx2ZXRpY2EsIEFyaWFsLCBzYW5zLXNlcmlmOyBmb250LXdlaWdodDogNDAwOyBsaW5lLWhlaWdodDogMS4xOyBjb2xvcjogaW5oZXJpdDt9aDR7ZGlzcGxheTogYmxvY2s7IC13ZWJraXQtbWFyZ2luLWJlZm9yZTogMS4zM2VtOyAtd2Via2l0LW1hcmdpbi1hZnRlcjogMS4zM2VtOyAtd2Via2l0LW1hcmdpbi1zdGFydDogMHB4OyAtd2Via2l0LW1hcmdpbi1lbmQ6IDBweDsgZm9udC13ZWlnaHQ6IGJvbGQ7fWxhYmVse2Rpc3BsYXk6IGlubGluZS1ibG9jazsgbWF4LXdpZHRoOiAxMDAlOyBtYXJnaW4tYm90dG9tOiA1cHg7IGZvbnQtd2VpZ2h0OiA3MDA7fWRse21hcmdpbi10b3A6IDA7IG1hcmdpbi1ib3R0b206IDIwcHg7IGRpc3BsYXk6IGJsb2NrOyAtd2Via2l0LW1hcmdpbi1iZWZvcmU6IDFlbTsgLXdlYmtpdC1tYXJnaW4tYWZ0ZXI6IDFlbTsgLXdlYmtpdC1tYXJnaW4tc3RhcnQ6IDBweDsgLXdlYmtpdC1tYXJnaW4tZW5kOiAwcHg7fWRke2Rpc3BsYXk6IGJsb2NrOyAtd2Via2l0LW1hcmdpbi1zdGFydDogNDBweDsgbWFyZ2luLWxlZnQ6IDA7IHdvcmQtd3JhcDogYnJlYWstd29yZDt9ZHR7Zm9udC13ZWlnaHQ6IDcwMDsgZGlzcGxheTogYmxvY2s7fWR0LCBkZHtsaW5lLWhlaWdodDogMS40Mjg1NzE0Mzt9LmRsLWhvcml6b250YWwgZHR7ZmxvYXQ6IGxlZnQ7IHdpZHRoOiAxNjBweDsgb3ZlcmZsb3c6IGhpZGRlbjsgY2xlYXI6IGxlZnQ7IHRleHQtYWxpZ246IHJpZ2h0OyB0ZXh0LW92ZXJmbG93OiBlbGxpcHNpczsgd2hpdGUtc3BhY2U6IG5vd3JhcDt9LmRsLWhvcml6b250YWwgZGR7bWFyZ2luLWxlZnQ6IDE4MHB4O308L3N0eWxlPiA8ZGl2IGNsYXNzPSJjb250YWluZXIiPiA8ZGl2IGNsYXNzPSJjYWxsb3V0IGNhbGxvdXQtZGFuZ2VyIj4gPGg0IGNsYXNzPSJsYWJlbCI+Rm9yYmlkZGVuPC9oND4gPGRsIGNsYXNzPSJkbC1ob3Jpem9udGFsIj4gPGR0PkNsaWVudCBJUDwvZHQ+IDxkZD57e0NMSUVOVF9JUH19PC9kZD4gPGR0PlVzZXItQWdlbnQ8L2R0PiA8ZGQ+e3tVU0VSX0FHRU5UfX08L2RkPiA8ZHQ+UmVxdWVzdCBVUkw8L2R0PiA8ZGQ+e3tSRVFVRVNUX1VSTH19PC9kZD4gPGR0PlJlYXNvbjwvZHQ+IDxkZD57e1JVTEVfTVNHfX08L2RkPiA8ZHQ+RGF0ZTwvZHQ+IDxkZD57e1RJTUVTVEFNUH19PC9kZD4gPC9kbD4gPC9kaXY+PC9kaXY+PC9ib2R5PjwvaHRtbD4="
#define BOGUS_GEO_DATABASE "/tmp/BOGUS_GEO_DATABASE.db"
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef enum {
        SERVER_MODE_DEFAULT = 0,
        SERVER_MODE_PROXY,
        SERVER_MODE_FILE,
        SERVER_MODE_NONE
} server_mode_t;
typedef enum {
        CONFIG_MODE_PROFILE = 0,
        CONFIG_MODE_ACL,
        CONFIG_MODE_RULES,
        CONFIG_MODE_MODSECURITY,
        CONFIG_MODE_LIMIT,
        CONFIG_MODE_SCOPES,
        CONFIG_MODE_NONE
} config_mode_t;
//! ----------------------------------------------------------------------------
//! globals
//! ----------------------------------------------------------------------------
ns_is2::srvr *g_srvr = NULL;
ns_waflz_server::sx *g_sx = NULL;
ns_waflz::challenge *g_challenge = NULL;
FILE *g_out_file_ptr = NULL;
config_mode_t g_config_mode = CONFIG_MODE_NONE;
bool g_action_flag = false;
//! ----------------------------------------------------------------------------
//! \details: remove lmdb dir
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int remove_dir(const std::string& a_db_dir)
{
        int32_t l_s;
        struct stat l_stat;
        l_s = stat(a_db_dir.c_str(), &l_stat);
        if(l_s != 0)
        {
                return 0;
        }
        std::string l_file1(a_db_dir), l_file2(a_db_dir);
        l_file1.append("/data.mdb");
        l_file2.append("/lock.mdb");
        unlink(l_file1.c_str());
        unlink(l_file2.c_str());
        l_s = rmdir(a_db_dir.c_str());
        if(l_s != 0)
        {
                return -1;
        }
        return 0;
}
//! ----------------------------------------------------------------------------
//! \details: create_dir for lmdb
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int create_dir(const std::string& a_db_dir)
{
        int32_t l_s;
        l_s = remove_dir(a_db_dir);
        if(l_s != 0)
        {
                return -1;
        }
        l_s = mkdir(a_db_dir.c_str(), 0700);
        return l_s;
}
//! ----------------------------------------------------------------------------
//! \details: create_dir only once for lmdb
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int create_dir_once(const std::string& a_db_dir)
{
        int32_t l_s;
        struct stat l_stat;
        l_s = stat(a_db_dir.c_str(), &l_stat);
        if(l_s == 0)
        {
                return 0;
        }
        l_s = create_dir(a_db_dir);
        return l_s;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int32_t init_kv_db(ns_waflz::kv_db** ao_db,
#ifdef WAFLZ_KV_DB_REDIS
                          const std::string& a_redis_host,
#endif
                          bool a_lmdb,
                          bool a_lmdb_ip)
{
        if(!ao_db)
        {
                return STATUS_ERROR;
        }
        *ao_db = NULL;
        // -------------------------------------------------
        // redis db
        // -------------------------------------------------
#ifdef WAFLZ_KV_DB_REDIS
        if(!a_redis_host.empty())
        {
                ns_waflz::kv_db* l_db = NULL;
                l_db = reinterpret_cast<ns_waflz::kv_db *>(new ns_waflz::redis_db());
                // -----------------------------------------
                // parse host
                // -----------------------------------------
                std::string l_host;
                uint16_t l_port;
                size_t l_last = 0;
                size_t l_next = 0;
                while((l_next = a_redis_host.find(":", l_last)) != std::string::npos)
                {
                        l_host = a_redis_host.substr(l_last, l_next-l_last);
                        l_last = l_next + 1;
                        break;
                }
                std::string l_port_str;
                l_port_str = a_redis_host.substr(l_last);
                if(l_port_str.empty() ||
                   l_host.empty())
                {
                        NDBG_OUTPUT("error parsing redis host: %s -expected <host>:<port>\n", a_redis_host.c_str());
                        if(l_db) { delete l_db; l_db = NULL; }
                        return STATUS_ERROR;
                }
                // TODO -error checking
                l_port = (uint16_t)strtoul(l_port_str.c_str(), NULL, 10);
                // TODO -check status
                // -----------------------------------------
                // options
                // -----------------------------------------
                l_db->set_opt(ns_waflz::redis_db::OPT_REDIS_HOST, l_host.c_str(), l_host.length());
                l_db->set_opt(ns_waflz::redis_db::OPT_REDIS_PORT, NULL, l_port);
                // -----------------------------------------
                // init db
                // -----------------------------------------
                int32_t l_s;
                l_s = l_db->init();
                if(l_s != STATUS_OK)
                {
                        NDBG_PRINT("error performing db init: Reason: %s\n", l_db->get_err_msg());
                        if(l_db) { delete l_db; l_db = NULL; }
                        return STATUS_ERROR;
                }
                // -----------------------------------------
                // done
                // -----------------------------------------
                //NDBG_PRINT("USING REDIS\n");
                *ao_db = l_db;
                return STATUS_OK;
        }
#endif
        // -------------------------------------------------
        // lmdb
        // -------------------------------------------------
        int32_t l_s;
        ns_waflz::kv_db* l_db = NULL;
        l_db = reinterpret_cast<ns_waflz::kv_db *>(new ns_waflz::lm_db());
        // -----------------------------------------
        // setup disk
        // -----------------------------------------
        std::string l_db_dir("/tmp/test_lmdb");
        if(a_lmdb_ip)
        {
                l_s = create_dir_once(l_db_dir);
                if(l_s != STATUS_OK)
                {
                        NDBG_PRINT("error creating dir -%s\n", l_db_dir.c_str());
                        if(l_db) { delete l_db; l_db = NULL; }
                        return STATUS_ERROR;
                }
        }
        else
        {
                l_s = create_dir(l_db_dir);
                if(l_s != STATUS_OK)
                {
                        NDBG_PRINT("error creating dir - %s\n", l_db_dir.c_str());
                        if(l_db) { delete l_db; l_db = NULL; }
                        return STATUS_ERROR;
                }
        }
        if(l_s != STATUS_OK)
        {
                NDBG_PRINT("error creating dir for lmdb\n");
                if(l_db) { delete l_db; l_db = NULL; }
                return STATUS_ERROR;
        }
        // -----------------------------------------
        // options
        // -----------------------------------------
        l_db->set_opt(ns_waflz::lm_db::OPT_LMDB_DIR_PATH, l_db_dir.c_str(), l_db_dir.length());
        l_db->set_opt(ns_waflz::lm_db::OPT_LMDB_READERS, NULL, 6);
        l_db->set_opt(ns_waflz::lm_db::OPT_LMDB_MMAP_SIZE, NULL, 10485760);
        // -----------------------------------------
        // init db
        // -----------------------------------------
        l_s = l_db->init();
        if(l_s != STATUS_OK)
        {
                NDBG_PRINT("error performing db init: Reason: %s\n", l_db->get_err_msg());
                if(l_db) { delete l_db; l_db = NULL; }
                return STATUS_ERROR;
        }
        // -----------------------------------------
        // done
        // -----------------------------------------
        //NDBG_PRINT("USING LMDB\n");
        *ao_db = l_db;
        return STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int32_t init_engine(ns_waflz::engine** ao_engine,
                           const std::string& a_ruleset_dir,
                           const std::string& a_geoip2_db,
                           const std::string& a_geoip2_isp_db)
{
        if(!ao_engine)
        {
                return STATUS_ERROR;
        }
        *ao_engine = NULL;
        // -------------------------------------------------
        // engine
        // -------------------------------------------------
        ns_waflz::engine* l_engine = new ns_waflz::engine();
        if(!a_ruleset_dir.empty())
        {
                l_engine->set_ruleset_dir(a_ruleset_dir);
        }
        if(!a_geoip2_db.empty() ||
           !a_geoip2_isp_db.empty())
        {
                l_engine->set_geoip2_dbs(a_geoip2_db, a_geoip2_isp_db);
        }
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        int32_t l_s;
        l_s = l_engine->init();
        if(l_s != WAFLZ_STATUS_OK)
        {
                NDBG_PRINT("error initializing engine\n");
                if(l_engine) { delete l_engine; l_engine = NULL; }
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // done
        // -------------------------------------------------
        *ao_engine = l_engine;
        return STATUS_OK;
}
//! ****************************************************************************
//! ----------------------------------------------------------------------------
//!                           request handler
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static ns_is2::h_resp_t handle_enf(ns_waflz::rqst_ctx* a_ctx,
                                   ns_is2::session& a_session,
                                   ns_is2::rqst& a_rqst,
                                   const waflz_pb::enforcement& a_enf,
                                   bool a_bot_enf=false)
{
        if(!a_ctx)
        {
                return ns_is2::H_RESP_NONE;
        }
        // -------------------------------------------------
        // write out if output...
        // -------------------------------------------------
        if(g_out_file_ptr)
        {
                size_t l_fw_s;
                l_fw_s = fwrite(g_sx->m_resp.c_str(), 1, g_sx->m_resp.length(), g_out_file_ptr);
                if(l_fw_s != g_sx->m_resp.length())
                {
                        NDBG_PRINT("error performing fwrite.\n");
                }
                fwrite("\n", 1, 1, g_out_file_ptr);
        }
        ns_is2::h_resp_t l_resp_code = ns_is2::H_RESP_NONE;
        int32_t l_s;
        // -------------------------------------------------
        // no enf
        // -------------------------------------------------
        if(!a_enf.has_enf_type())
        {
                return ns_is2::H_RESP_NONE;
        }
        //NDBG_PRINT("l_enfcmnt: %s\n", a_enf.ShortDebugString().c_str());
#define STR_CMP(_a,_b) (strncasecmp(_a,_b,strlen(_b)) == 0)
        // -------------------------------------------------
        // switch on type
        // -------------------------------------------------
        switch(a_enf.enf_type())
        {
        // -------------------------------------------------
        // ALERT
        // -------------------------------------------------
        case waflz_pb::enforcement_type_t_ALERT:
        {
                //NDBG_PRINT("ALERT\n");
                std::string l_resp_str;
                if(a_bot_enf)
                {
                        // send whole event for logging testing
                        l_resp_str = g_sx->m_resp;
                }
                else
                {
                        ns_is2::create_json_resp_str(ns_is2::HTTP_STATUS_OK, l_resp_str);
                }
                ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
                l_api_resp.add_std_headers(ns_is2::HTTP_STATUS_OK,
                                           "application/json",
                                           l_resp_str.length(),
                                           a_rqst.m_supports_keep_alives,
                                           a_session.get_server_name());
                if(a_enf.has_url())
                {
                        l_api_resp.set_header("Location", a_enf.url().c_str());
                }
                l_api_resp.set_body_data(l_resp_str.c_str(), l_resp_str.length());
                ns_is2::queue_api_resp(a_session, l_api_resp);
                // TODO check status
                UNUSED(l_s);
                l_resp_code = ns_is2::H_RESP_DONE;
                break;
        }
        // -------------------------------------------------
        // NOP
        // -------------------------------------------------
        case waflz_pb::enforcement_type_t_NOP:
        {
                //NDBG_PRINT("NOP\n");
                std::string l_resp_str;
                ns_is2::create_json_resp_str(ns_is2::HTTP_STATUS_OK, l_resp_str);
                ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
                l_api_resp.add_std_headers(ns_is2::HTTP_STATUS_OK,
                                           "application/json",
                                           l_resp_str.length(),
                                           a_rqst.m_supports_keep_alives,
                                           a_session.get_server_name());
                if(a_enf.has_url())
                {
                        l_api_resp.set_header("Location", a_enf.url().c_str());
                }
                l_api_resp.set_body_data(l_resp_str.c_str(), l_resp_str.length());
                ns_is2::queue_api_resp(a_session, l_api_resp);
                // TODO check status
                UNUSED(l_s);
                l_resp_code = ns_is2::H_RESP_DONE;
                break;
        }
        // -------------------------------------------------
        // REDIRECT_302
        // -------------------------------------------------
        case waflz_pb::enforcement_type_t_REDIRECT_302:
        {
                //NDBG_PRINT("REDIRECT_302\n");
                std::string l_resp_str;
                ns_is2::create_json_resp_str(ns_is2::HTTP_STATUS_FOUND, l_resp_str);
                ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
                l_api_resp.add_std_headers(ns_is2::HTTP_STATUS_FOUND,
                                           "application/json",
                                           l_resp_str.length(),
                                           a_rqst.m_supports_keep_alives,
                                           a_session.get_server_name());
                if(a_enf.has_url())
                {
                        l_api_resp.set_header("Location", a_enf.url().c_str());
                }
                l_api_resp.set_body_data(l_resp_str.c_str(), l_resp_str.length());
                ns_is2::queue_api_resp(a_session, l_api_resp);
                // TODO check status
                UNUSED(l_s);
                l_resp_code = ns_is2::H_RESP_DONE;
                break;
        }
        // -------------------------------------------------
        // BLOCK_REQUEST
        // -------------------------------------------------
        case waflz_pb::enforcement_type_t_BLOCK_REQUEST:
        {
                // -----------------------------------------
                // decode
                // -----------------------------------------
                char *l_resp_data = NULL;
                size_t l_resp_len = 0;
                int32_t l_s;
                char *l_dcd = NULL;
                size_t l_dcd_len = 0;
                if(a_enf.has_response_body())
                {
                        l_dcd = (char *)a_enf.response_body().c_str();
                        l_dcd_len = a_enf.response_body().length();
                }
                else
                {
                        l_s = ns_waflz::b64_decode(&l_dcd, l_dcd_len, _DEFAULT_RESP_BODY_B64, strlen(_DEFAULT_RESP_BODY_B64));
                        if(l_s != STATUS_OK)
                        {
                                // error???
                                if(l_dcd) { free(l_dcd); l_dcd = NULL; }
                                l_resp_code = ns_is2::H_RESP_SERVER_ERROR;
                                break;
                        }
                }
                // -----------------------------------------
                // render
                // -----------------------------------------
                l_s = ns_waflz::render(&l_resp_data, l_resp_len, l_dcd, l_dcd_len, a_ctx);
                if(l_s != STATUS_OK)
                {
                        // error???
                        if(l_dcd) { free(l_dcd); l_dcd = NULL; }
                        if(l_resp_data) { free(l_resp_data); l_resp_data = NULL; }
                        l_resp_code = ns_is2::H_RESP_SERVER_ERROR;
                        break;
                }
                if(l_dcd) { free(l_dcd); l_dcd = NULL; }
                ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
                if(a_bot_enf)
                {
                        l_api_resp.add_std_headers(ns_is2::HTTP_STATUS_FORBIDDEN,
                                           "application/json",
                                           g_sx->m_resp.length(),
                                           a_rqst.m_supports_keep_alives,
                                           a_session.get_server_name());
                        l_api_resp.set_body_data(g_sx->m_resp.c_str(), g_sx->m_resp.length());
                }
                else
                {
                        l_api_resp.add_std_headers(ns_is2::HTTP_STATUS_FORBIDDEN,
                                           "text/html",
                                           l_resp_len,
                                           a_rqst.m_supports_keep_alives,
                                           a_session.get_server_name());
                        l_api_resp.set_body_data(l_resp_data, l_resp_len);
                }
                ns_is2::queue_api_resp(a_session, l_api_resp);
                if(l_resp_data) { free(l_resp_data); l_resp_data = NULL; }
                l_resp_code = ns_is2::H_RESP_DONE;
                break;
        }
        // -------------------------------------------------
        // REDIRECT_JS
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        // HASHCASH
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        // CUSTOM RESPONSE
        // -------------------------------------------------
        case waflz_pb::enforcement_type_t_CUSTOM_RESPONSE:
        {
                uint32_t l_status = ns_is2::HTTP_STATUS_OK;
                if(a_enf.has_status())
                {
                        l_status = a_enf.status();
                }
                if(!a_enf.has_response_body_base64())
                {
                        // Custom response can have empty response body
                        break;
                }
                const std::string *l_b64 = &(a_enf.response_body_base64());
                if(l_b64->empty())
                {
                        break;
                }
                // -----------------------------------------
                // decode
                // -----------------------------------------
                int32_t l_s;
                char *l_dcd = NULL;
                size_t l_dcd_len = 0;
                bool l_dcd_allocd = false;
                if(a_enf.has_response_body())
                {
                        l_dcd = (char *)a_enf.response_body().c_str();
                        l_dcd_len = a_enf.response_body().length();
                }
                else
                {
                        l_s = ns_waflz::b64_decode(&l_dcd, l_dcd_len, l_b64->c_str(), l_b64->length());
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                // error???
                                if(l_dcd) { free(l_dcd); l_dcd = NULL; }
                                break;
                        }
                        l_dcd_allocd = true;
                }
                // -----------------------------------------
                // render
                // -----------------------------------------
                char *l_rndr = NULL;
                size_t l_rndr_len = 0;
                l_s = ns_waflz::render(&l_rndr, l_rndr_len, l_dcd, l_dcd_len, a_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // error???
                        if(l_dcd_allocd && l_dcd) { free(l_dcd); l_dcd = NULL; }
                        if(l_rndr) { free(l_rndr); l_rndr = NULL; }
                        break;
                }
                // -----------------------------------------
                // set/cleanup
                // -----------------------------------------
                if(l_dcd_allocd && l_dcd) { free(l_dcd); l_dcd = NULL; }
                // -----------------------------------------
                // response
                // -----------------------------------------
                // TODO -fix content type if resp header...
                ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
                l_api_resp.add_std_headers((ns_is2::http_status_t)l_status,
                                           "text/html",
                                           (uint64_t)l_rndr_len,
                                           a_rqst.m_supports_keep_alives,
                                           a_session.get_server_name());
                l_api_resp.set_body_data(l_rndr, l_rndr_len);
                l_s = ns_is2::queue_api_resp(a_session, l_api_resp);
                // TODO check status
                UNUSED(l_s);
                if(l_rndr) { free(l_rndr); l_rndr = NULL; }
                l_resp_code = ns_is2::H_RESP_DONE;
                break;
        }
        // -------------------------------------------------
        // BROWSER_CHALLENGE
        // -------------------------------------------------
        case waflz_pb::enforcement_type_t_BROWSER_CHALLENGE:
        {
                uint32_t l_status = ns_is2::HTTP_STATUS_OK;
                if(a_enf.has_status())
                {
                        l_status = a_enf.status();
                }
                const std::string *l_b64 = NULL;
                int32_t l_s;
                l_s = g_challenge->get_challenge(&l_b64, a_ctx);
                if((l_s != WAFLZ_STATUS_OK) ||
                    !l_b64)
                {
                        break;
                }
                if(l_b64->empty())
                {
                        break;
                }
                // -----------------------------------------
                // decode
                // -----------------------------------------
                char *l_dcd = NULL;
                size_t l_dcd_len = 0;
                l_s = ns_waflz::b64_decode(&l_dcd, l_dcd_len, l_b64->c_str(), l_b64->length());
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // error???
                        if(l_dcd) { free(l_dcd); l_dcd = NULL; }
                        break;
                }
                //NDBG_PRINT("DECODED: \n*************\n%.*s\n*************\n", (int)l_dcd_len, l_dcd);
                // -----------------------------------------
                // render
                // -----------------------------------------
                char *l_rndr = NULL;
                size_t l_rndr_len = 0;
                l_s =  ns_waflz::render(&l_rndr, l_rndr_len, l_dcd, l_dcd_len, a_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // error???
                        if(l_dcd) { free(l_dcd); l_dcd = NULL; }
                        if(l_rndr) { free(l_rndr); l_rndr = NULL; }
                        break;
                }
                // -----------------------------------------
                // set/cleanup
                // -----------------------------------------
                if(l_dcd) { free(l_dcd); l_dcd = NULL; }
                // -----------------------------------------
                // response
                // -----------------------------------------
                // TODO -fix content type if resp header...
                ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
                l_api_resp.add_std_headers((ns_is2::http_status_t)l_status,
                                           "text/html",
                                           (uint64_t)l_rndr_len,
                                           a_rqst.m_supports_keep_alives,
                                           a_session.get_server_name());
                l_api_resp.set_body_data(l_rndr, l_rndr_len);
                l_s = ns_is2::queue_api_resp(a_session, l_api_resp);
                // TODO check status
                UNUSED(l_s);
                if(l_rndr) { free(l_rndr); l_rndr = NULL; }
                l_resp_code = ns_is2::H_RESP_DONE;
                break;
        }
        // -------------------------------------------------
        // DROP_REQUEST
        // -------------------------------------------------
        case waflz_pb::enforcement_type_t_DROP_REQUEST:
        {
                l_resp_code = ns_is2::H_RESP_DONE;
                break;
        }
        // -------------------------------------------------
        // DROP_CONNECTION
        // -------------------------------------------------
        case waflz_pb::enforcement_type_t_DROP_CONNECTION:
        {
                // -----------------------------------------
                // TODO -yank connection -by signalling no
                // keep-alive support???
                // -----------------------------------------
                l_resp_code = ns_is2::H_RESP_DONE;
                break;
        }
        // -------------------------------------------------
        // default
        // -------------------------------------------------
        default:
        {
                break;
        }
        }
        return l_resp_code;
}
//! ----------------------------------------------------------------------------
//! default
//! ----------------------------------------------------------------------------
class waflz_h: public ns_is2::default_rqst_h
{
public:
        waflz_h(): default_rqst_h() {}
        ~waflz_h() {}
        // -------------------------------------------------
        // default rqst handler...
        // -------------------------------------------------
        ns_is2::h_resp_t do_default(ns_is2::session &a_session,
                                    ns_is2::rqst &a_rqst,
                                    const ns_is2::url_pmap_t &a_url_pmap)
        {
                waflz_pb::enforcement *l_enf = NULL;
                ns_is2::h_resp_t l_resp_t = ns_is2::H_RESP_NONE;
                // -----------------------------------------
                // handle request
                // -----------------------------------------
                ns_waflz::rqst_ctx *l_ctx = NULL;
                l_resp_t = ns_is2::H_RESP_NONE;
                l_resp_t = ns_waflz_server::sx::s_handle_rqst(*g_sx, &l_enf, &l_ctx, a_session, a_rqst, a_url_pmap);
                if(l_resp_t != ns_is2::H_RESP_DONE)
                {
                        if(l_ctx && l_ctx->m_event) { delete l_ctx->m_event; l_ctx->m_event = NULL; }
                        if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                        return l_resp_t;
                }
                // -----------------------------------------
                // no enforcement -nothing to do
                // -----------------------------------------
                if(!l_enf)
                {
                        if(g_action_flag)
                        {
                                std::string l_resp_str;
                                ns_is2::create_json_resp_str(ns_is2::HTTP_STATUS_OK, l_resp_str);
                                ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
                                l_api_resp.add_std_headers(ns_is2::HTTP_STATUS_OK,
                                                           "application/json",
                                                            l_resp_str.length(),
                                                            a_rqst.m_supports_keep_alives,
                                                            a_session.get_server_name());
                                l_api_resp.set_body_data(l_resp_str.c_str(), l_resp_str.length());
                                ns_is2::queue_api_resp(a_session, l_api_resp);
                                if(l_ctx) { delete l_ctx; l_ctx = NULL;}
                                return ns_is2::H_RESP_DONE;
                        }
                        else
                        {
                                ns_is2::api_resp& l_api_resp = ns_is2::create_api_resp(a_session);
                                l_api_resp.add_std_headers(ns_is2::HTTP_STATUS_OK,
                                                           "application/json",
                                                           g_sx->m_resp.length(),
                                                           a_rqst.m_supports_keep_alives,
                                                           a_session.get_server_name());
                                l_api_resp.set_body_data(g_sx->m_resp.c_str(), g_sx->m_resp.length());
                                l_api_resp.set_status(ns_is2::HTTP_STATUS_OK);
                                ns_is2::queue_api_resp(a_session, l_api_resp);
                                if(l_ctx) { delete l_ctx; l_ctx = NULL;}
                                return ns_is2::H_RESP_DONE;
                        }
                }
                // -----------------------------------------
                // handle action
                // -----------------------------------------
                l_resp_t = ns_is2::H_RESP_NONE;
                if(g_action_flag ||
                   (g_config_mode == CONFIG_MODE_LIMIT))
                {
                        l_resp_t = handle_enf(l_ctx, a_session, a_rqst, *l_enf, g_action_flag);
                }
                if(l_enf) { delete l_enf; l_enf = NULL; }
                if(l_ctx && l_ctx->m_event) { delete l_ctx->m_event; l_ctx->m_event = NULL; }
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                // -----------------------------------------
                // if != NONE -return response
                // -----------------------------------------
                if(l_resp_t != ns_is2::H_RESP_NONE)
                {
                        return l_resp_t;
                }
                // -----------------------------------------
                // generate response
                // -----------------------------------------
                ns_is2::api_resp& l_api_resp = ns_is2::create_api_resp(a_session);
                l_api_resp.add_std_headers(ns_is2::HTTP_STATUS_OK,
                                           "application/json",
                                           g_sx->m_resp.length(),
                                           a_rqst.m_supports_keep_alives,
                                           a_session.get_server_name());
                l_api_resp.set_body_data(g_sx->m_resp.c_str(), g_sx->m_resp.length());
                l_api_resp.set_status(ns_is2::HTTP_STATUS_OK);
                ns_is2::queue_api_resp(a_session, l_api_resp);
                return ns_is2::H_RESP_DONE;
        }
};
//! ----------------------------------------------------------------------------
//! file
//! ----------------------------------------------------------------------------
class waflz_file_h: public ns_is2::file_h
{
public:
        waflz_file_h(): file_h() {}
        ~waflz_file_h() {}
        // -------------------------------------------------
        // default rqst handler...
        // -------------------------------------------------
        ns_is2::h_resp_t do_default(ns_is2::session &a_session,
                                    ns_is2::rqst &a_rqst,
                                    const ns_is2::url_pmap_t &a_url_pmap)
        {
                waflz_pb::enforcement *l_enf = NULL;
                ns_is2::h_resp_t l_resp_t = ns_is2::H_RESP_NONE;
                // -----------------------------------------
                // handle request
                // -----------------------------------------
                ns_waflz::rqst_ctx *l_ctx = NULL;
                l_resp_t = ns_is2::H_RESP_NONE;
                l_resp_t = ns_waflz_server::sx::s_handle_rqst(*g_sx, &l_enf, &l_ctx, a_session, a_rqst, a_url_pmap);
                if(l_resp_t != ns_is2::H_RESP_DONE)
                {
                        if(l_ctx && l_ctx->m_event) { delete l_ctx->m_event; l_ctx->m_event = NULL; }
                        if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                        return l_resp_t;
                }
                // -----------------------------------------
                // handle action
                // -----------------------------------------
                l_resp_t = ns_is2::H_RESP_NONE;
                if(l_enf)
                {
                        l_resp_t = handle_enf(l_ctx, a_session, a_rqst, *l_enf);
                }
                if(l_enf) { delete l_enf; l_enf = NULL; }
                if(l_ctx && l_ctx->m_event) { delete l_ctx->m_event; l_ctx->m_event = NULL; }
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                // -----------------------------------------
                // default
                // -----------------------------------------
                if(l_resp_t == ns_is2::H_RESP_NONE)
                {
                        l_resp_t = file_h::do_get(a_session, a_rqst, a_url_pmap);
                }
                return l_resp_t;
        }
};
//! ----------------------------------------------------------------------------
//! proxy
//! ----------------------------------------------------------------------------
class waflz_proxy_h: public ns_is2::proxy_h
{
public:
        waflz_proxy_h(const std::string &a_proxy_host):
                proxy_h(a_proxy_host, ""){}
        ~waflz_proxy_h() {}
        // -------------------------------------------------
        // default rqst handler...
        // -------------------------------------------------
        ns_is2::h_resp_t do_default(ns_is2::session &a_session,
                                    ns_is2::rqst &a_rqst,
                                    const ns_is2::url_pmap_t &a_url_pmap)
        {
                waflz_pb::enforcement *l_enf = NULL;
                ns_is2::h_resp_t l_resp_t = ns_is2::H_RESP_NONE;
                // -----------------------------------------
                // handle request
                // -----------------------------------------
                ns_waflz::rqst_ctx *l_ctx = NULL;
                l_resp_t = ns_is2::H_RESP_NONE;
                l_resp_t = ns_waflz_server::sx::s_handle_rqst(*g_sx, &l_enf, &l_ctx, a_session, a_rqst, a_url_pmap);
                if(l_resp_t != ns_is2::H_RESP_DONE)
                {
                        return l_resp_t;
                }
                // -----------------------------------------
                // handle action
                // -----------------------------------------
                l_resp_t = ns_is2::H_RESP_NONE;
                if(l_enf)
                {
                        l_resp_t = handle_enf(l_ctx, a_session, a_rqst, *l_enf);
                }
                if(l_enf) { delete l_enf; l_enf = NULL; }
                if(l_ctx && l_ctx->m_event) { delete l_ctx->m_event; l_ctx->m_event = NULL; }
                if(l_ctx) { delete l_ctx; l_ctx = NULL; }
                // -----------------------------------------
                // default
                // -----------------------------------------
                if(l_resp_t == ns_is2::H_RESP_NONE)
                {
                        l_resp_t = ns_is2::proxy_h::do_default(a_session, a_rqst, a_url_pmap);
                }
                return l_resp_t;
        }
};
//! ----------------------------------------------------------------------------
//! \details: sighandler
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void sig_handler(int signo)
{
        if(!g_srvr)
        {
                return;
        }
        if(signo == SIGINT)
        {
                // Kill program
                g_srvr->stop();
        }
}
//! ----------------------------------------------------------------------------
//! \details: Print the version.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void print_version(FILE* a_stream, int a_exit_code)
{
        // print out the version information
        fprintf(a_stream, "waflz_server\n");
        fprintf(a_stream, "Copyright (C) Edgecast Inc.\n");
        fprintf(a_stream, "  Version: %s\n", WAFLZ_VERSION);
        exit(a_exit_code);
}
//! ----------------------------------------------------------------------------
//! \details: Print the command line help.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void print_usage(FILE* a_stream, int a_exit_code)
{
        fprintf(a_stream, "Usage: waflz_server [options]\n");
        fprintf(a_stream, "Options:\n");
        fprintf(a_stream, "  -h, --help          display this help and exit.\n");
        fprintf(a_stream, "  -v, --version       display the version number and exit.\n");
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "Config Modes: -specify only one\n");
        fprintf(a_stream, "  -f, --profile       waf profile\n");
        fprintf(a_stream, "  -a, --acl           access control list (acl)\n");
        fprintf(a_stream, "  -e, --rules         rules\n");
        fprintf(a_stream, "  -m, --modsecurity   modsecurity rules\n");
        fprintf(a_stream, "  -l, --limit         limit.\n");
        fprintf(a_stream, "  -b, --scopes        scopes (file or directory)\n");
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "Engine Configuration:\n");
        fprintf(a_stream, "  -r, --ruleset-dir   waf ruleset directory\n");
        fprintf(a_stream, "  -g, --geoip-db      geoip-db\n");
        fprintf(a_stream, "  -s, --geoip-isp-db  geoip-isp-db\n");
        fprintf(a_stream, "  -d  --config-dir    configuration directory (REQUIRED for scopes)\n");
        fprintf(a_stream, "  -x, --random-ips    randomly generate ips\n");
        fprintf(a_stream, "  -c, --challenge     json containing browser challenges\n");
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "KV DB Configuration:\n");
#ifdef WAFLZ_KV_DB_REDIS
        fprintf(a_stream, "  -R, --redis-host    redis host:port -used for counting backend\n");
#endif
        fprintf(a_stream, "  -L, --lmdb          lmdb for rl counting\n");
        fprintf(a_stream, "  -I, --interprocess  lmdb across multiple process (if --lmdb)\n");
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "Server Configuration:\n");
        fprintf(a_stream, "  -p, --port          port (default: 12345)\n");
        fprintf(a_stream, "  -j, --action        apply actions instead of reporting\n");
        fprintf(a_stream, "  -z, --bg            load configs in background thread\n");
        fprintf(a_stream, "  -o, --output        write json alerts to file\n");
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "Server Mode: choose one or none\n");
        fprintf(a_stream, "  -w, --static        static file path (for serving)\n");
        fprintf(a_stream, "  -y, --proxy         run server in proxy mode\n");
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "Debug Options:\n");
        fprintf(a_stream, "  -t, --trace         tracing (error/rule/match/all)\n");
        fprintf(a_stream, "  -T, --server-trace  server tracing  (error/warn/debug/verbose/all)\n");
        fprintf(a_stream, "  -A, --audit-mode    load and exit\n");
        fprintf(a_stream, "  \n");
#ifdef ENABLE_PROFILER
        fprintf(a_stream, "Profile Options:\n");
        fprintf(a_stream, "  -H, --hprofile      Google heap profiler output file\n");
        fprintf(a_stream, "  -C, --cprofile      Google cpu profiler output file\n");
        fprintf(a_stream, "  \n");
#endif
        exit(a_exit_code);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int main(int argc, char** argv)
{
        // -------------------------------------------------
        // defaults
        // -------------------------------------------------
        char l_opt;
        std::string l_arg;
        int l_option_index = 0;
        ns_waflz::trc_level_set(ns_waflz::WFLZ_TRC_LEVEL_ERROR);
        ns_is2::trc_log_level_set(ns_is2::TRC_LOG_LEVEL_NONE);
        // modes
        server_mode_t l_server_mode = SERVER_MODE_NONE;
        std::string l_geoip_db;
        std::string l_geoip_isp_db;
        std::string l_ruleset_dir;
        std::string l_config_file;
        std::string l_config_dir;
        std::string l_server_spec;
        bool l_bg_load = false;
        bool l_audit_mode = false;
        // server settings
        std::string l_out_file;
        uint16_t l_port = 12345;
#ifdef WAFLZ_KV_DB_REDIS
        std::string l_redis_host = "";
#endif
        bool l_lmdb = false;
        bool l_lmdb_ip = false;
        std::string l_challenge_file;
        ns_waflz::engine* l_engine = NULL;
        ns_waflz::kv_db* l_kv_db = NULL;
#ifdef ENABLE_PROFILER
        std::string l_hprof_file;
        std::string l_cprof_file;
#endif
        // -------------------------------------------------
        // options
        // -------------------------------------------------
        struct option l_long_options[] =
                {
                // -----------------------------------------
                // options
                // -----------------------------------------
                { "help",         0, 0, 'h' },
                { "version",      0, 0, 'v' },
                // -----------------------------------------
                // config modes
                // -----------------------------------------
                { "profile",      1, 0, 'f' },
                { "acl",          1, 0, 'a' },
                { "rules",        1, 0, 'e' },
                { "modsecurity",  1, 0, 'm' },
                { "limit",        1, 0, 'l' },
                { "scopes",       1, 0, 'b' },
                // -----------------------------------------
                // engine config
                // -----------------------------------------
                { "ruleset-dir",  1, 0, 'r' },
                { "geoip-db",     1, 0, 'g' },
                { "geoip-isp-db", 1, 0, 's' },
                { "config-dir",   1, 0, 'd' },
                { "random-ips",   0, 0, 'x' },
                { "challenge",    1, 0, 'c' },
                // -----------------------------------------
                // kv db config
                // -----------------------------------------
#ifdef WAFLZ_KV_DB_REDIS
                { "redis",        1, 0, 'R' },
#endif
                { "lmdb",         0, 0, 'L' },
                { "interprocess", 0, 0, 'I' },
                // -----------------------------------------
                // server config
                // -----------------------------------------
                { "port",         1, 0, 'p' },
                { "action",       0, 0, 'j' },
                { "bg",           0, 0, 'z' },
                { "output",       1, 0, 'o' },
                // -----------------------------------------
                // server mode
                // -----------------------------------------
                { "static",       1, 0, 'w' },
                { "proxy",        1, 0, 'y' },
                // -----------------------------------------
                // debug options
                // -----------------------------------------
                { "trace",        1, 0, 't' },
                { "server-trace", 1, 0, 'T' },
                { "audit-mode",   0, 0, 'A' },
                // -----------------------------------------
                // profile options
                // -----------------------------------------
#ifdef ENABLE_PROFILER
                { "cprofile",     1, 0, 'H' },
                { "hprofile",     1, 0, 'C' },
#endif
                // list sentinel
                { 0, 0, 0, 0 }
        };
        // -------------------------------------------------
        // Args...
        // -------------------------------------------------
#ifdef ENABLE_PROFILER
        char l_short_arg_list[] = "hvf:a:e:m:l:b:r:g:s:d:xc:R:LIp:jzo:w:y:t:T:AH:C:";
#else
        char l_short_arg_list[] = "hvf:a:e:m:l:b:r:g:s:d:xc:R:LIp:jzo:w:y:t:T:A";
#endif
        while ((l_opt = getopt_long_only(argc, argv, l_short_arg_list, l_long_options, &l_option_index)) != -1)
        {
                if (optarg)
                {
                        l_arg = std::string(optarg);
                }
                else
                {
                        l_arg.clear();
                }
                //NDBG_PRINT("arg[%c=%d]: %s\n", l_opt, l_option_index, l_arg.c_str());
                switch (l_opt)
                {
                // -----------------------------------------
                // *****************************************
                // options
                // *****************************************
                // -----------------------------------------
                // -----------------------------------------
                // Help
                // -----------------------------------------
                case 'h':
                {
                        print_usage(stdout, STATUS_OK);
                        break;
                }
                // -----------------------------------------
                // Version
                // -----------------------------------------
                case 'v':
                {
                        print_version(stdout, STATUS_OK);
                        break;
                }
                // -----------------------------------------
                // *****************************************
                // config modes
                // *****************************************
                // -----------------------------------------
#define _TEST_SET_CONFIG_MODE(_type) do { \
                if(g_config_mode != CONFIG_MODE_NONE) { \
                        NDBG_OUTPUT("error multiple config modes specified.\n"); \
                        return STATUS_ERROR; \
                } \
                g_config_mode = CONFIG_MODE_##_type; \
                l_config_file = l_arg; \
} while(0)
                // -----------------------------------------
                // profile
                // -----------------------------------------
                case 'f':
                {
                        _TEST_SET_CONFIG_MODE(PROFILE);
                        break;
                }
                // -----------------------------------------
                // acl
                // -----------------------------------------
                case 'a':
                {
                        _TEST_SET_CONFIG_MODE(ACL);
                        break;
                }
                // -----------------------------------------
                // rules
                // -----------------------------------------
                case 'e':
                {
                        _TEST_SET_CONFIG_MODE(RULES);
                        break;
                }
                // -----------------------------------------
                // modsecurity
                // -----------------------------------------
                case 'm':
                {
                        _TEST_SET_CONFIG_MODE(MODSECURITY);
                        break;
                }
                // -----------------------------------------
                // limit
                // -----------------------------------------
                case 'l':
                {
                        _TEST_SET_CONFIG_MODE(LIMIT);
                        break;
                }
                // -----------------------------------------
                // scopes
                // -----------------------------------------
                case 'b':
                {
                        _TEST_SET_CONFIG_MODE(SCOPES);
                        break;
                }
                // -----------------------------------------
                // *****************************************
                // engine config
                // *****************************************
                // -----------------------------------------
                // -----------------------------------------
                // ruleset dir
                // -----------------------------------------
                case 'r':
                {
                        l_ruleset_dir = l_arg;
                        break;
                }
                // -----------------------------------------
                // geoip db
                // -----------------------------------------
                case 'g':
                {
                        l_geoip_db = optarg;
                        break;
                }
                // -----------------------------------------
                // geoip isp db
                // -----------------------------------------
                case 's':
                {
                        l_geoip_isp_db = optarg;
                        break;
                }
                // -----------------------------------------
                // config-dir
                // -----------------------------------------
                case 'd':
                {
                        l_config_dir = optarg;
                        break;
                }
                // -----------------------------------------
                // random ip's
                // -----------------------------------------
                case 'x':
                {
                        ns_waflz_server::g_random_ips = true;
                        break;
                }
                // -----------------------------------------
                // challenge
                // -----------------------------------------
                case 'c':
                {
                        l_challenge_file = l_arg;
                        break;
                }
                // -----------------------------------------
                // *****************************************
                // kv db config
                // *****************************************
                // -----------------------------------------
#ifdef WAFLZ_KV_DB_REDIS
                // -----------------------------------------
                // redis host
                // -----------------------------------------
                case 'R':
                {
                        l_redis_host = l_arg;
                        break;
                }
#endif
                // -----------------------------------------
                // lmdb
                // -----------------------------------------
                case 'L':
                {
                        l_lmdb = true;
                        break;
                }
                // -----------------------------------------
                // interprocess
                // -----------------------------------------
                case 'I':
                {
                        l_lmdb_ip = true;
                        break;
                }
                // -----------------------------------------
                // *****************************************
                // server config
                // *****************************************
                // -----------------------------------------
                // -----------------------------------------
                // port
                // -----------------------------------------
                case 'p':
                {
                        int l_port_val;
                        l_port_val = atoi(optarg);
                        if((l_port_val < 1) ||
                           (l_port_val > 65535))
                        {
                                NDBG_OUTPUT("Error bad port value: %d.\n", l_port_val);
                                print_usage(stdout, STATUS_ERROR);
                        }
                        l_port = (uint16_t)l_port_val;
                        break;
                }
                // -----------------------------------------
                // action
                // -----------------------------------------
                case 'j':
                {
                        g_action_flag = true;
                        break;
                }
                // -----------------------------------------
                // background loading
                // -----------------------------------------
                case 'z':
                {
                        l_bg_load = true;
                        break;
                }
                // -----------------------------------------
                // output
                // -----------------------------------------
                case 'o':
                {
                        l_out_file = l_arg;
                        break;
                }
                // -----------------------------------------
                // *****************************************
                // server mode
                // *****************************************
                // -----------------------------------------
#define _TEST_SET_SERVER_MODE(_type) do { \
                if(l_server_mode != SERVER_MODE_NONE) { \
                        NDBG_OUTPUT("error multiple server modes specified.\n"); \
                        return STATUS_ERROR; \
                } \
                l_server_mode = SERVER_MODE_##_type; \
                l_server_spec = l_arg; \
} while(0)
                // -----------------------------------------
                // static
                // -----------------------------------------
                case 'w':
                {
                        _TEST_SET_SERVER_MODE(FILE);
                        break;
                }
                // -----------------------------------------
                // proxy
                // -----------------------------------------
                case 'y':
                {
                        _TEST_SET_SERVER_MODE(PROXY);
                        break;
                }
                // -----------------------------------------
                // *****************************************
                // debug options
                // *****************************************
                // -----------------------------------------
                // -----------------------------------------
                // tracing
                // -----------------------------------------
#define ELIF_TRACE_STR(_level) else if(strncasecmp(_level, l_arg.c_str(), sizeof(_level)) == 0)
                case 't':
                {
                        bool l_trace = false;
                        if(0) {}
                        ELIF_TRACE_STR("error") { ns_waflz::trc_level_set(ns_waflz::WFLZ_TRC_LEVEL_ERROR);   l_trace = true; }
                        ELIF_TRACE_STR("rule")  { ns_waflz::trc_level_set(ns_waflz::WFLZ_TRC_LEVEL_RULE);    l_trace = true; }
                        ELIF_TRACE_STR("match") { ns_waflz::trc_level_set(ns_waflz::WFLZ_TRC_LEVEL_MATCH);   l_trace = true; }
                        ELIF_TRACE_STR("all")   { ns_waflz::trc_level_set(ns_waflz::WFLZ_TRC_LEVEL_ALL);     l_trace = true; }
                        else
                        {
                                ns_waflz::trc_level_set(ns_waflz::WFLZ_TRC_LEVEL_NONE);
                        }
                        if(l_trace)
                        {
                                ns_waflz::trc_file_open("/dev/stdout");
                        }
                        break;
                }
                // -----------------------------------------
                // server trace
                // -----------------------------------------
                case 'T':
                {
                        bool l_trace = false;
                        if(0) {}
                        ELIF_TRACE_STR("error") { ns_is2::trc_log_level_set(ns_is2::TRC_LOG_LEVEL_ERROR); l_trace = true; }
                        ELIF_TRACE_STR("warn") { ns_is2::trc_log_level_set(ns_is2::TRC_LOG_LEVEL_WARN); l_trace = true; }
                        ELIF_TRACE_STR("debug") { ns_is2::trc_log_level_set(ns_is2::TRC_LOG_LEVEL_DEBUG); l_trace = true; }
                        ELIF_TRACE_STR("verbose") { ns_is2::trc_log_level_set(ns_is2::TRC_LOG_LEVEL_VERBOSE); l_trace = true; }
                        ELIF_TRACE_STR("all") { ns_is2::trc_log_level_set(ns_is2::TRC_LOG_LEVEL_ALL); l_trace = true; }
                        else
                        {
                                ns_is2::trc_log_level_set(ns_is2::TRC_LOG_LEVEL_NONE);
                        }
                        if(l_trace)
                        {
                                ns_is2::trc_log_file_open("/dev/stdout");
                        }
                        break;
                }
                // -----------------------------------------
                // audit mode
                // -----------------------------------------
                case 'A':
                {
                        l_audit_mode = true;
                        break;
                }
                // -----------------------------------------
                // *****************************************
                // profile options
                // *****************************************
                // -----------------------------------------
#ifdef ENABLE_PROFILER
                // -----------------------------------------
                // profiler file
                // -----------------------------------------
                case 'H':
                {
                        l_hprof_file = l_arg;
                        break;
                }
                // -----------------------------------------
                // profiler file
                // -----------------------------------------
                case 'C':
                {
                        l_cprof_file = l_arg;
                        break;
                }
#endif
                // -----------------------------------------
                // What???
                // -----------------------------------------
                case '?':
                {
                        // ---------------------------------
                        // Required argument was missing:
                        // '?' is provided when the 3rd arg
                        // to getopt_long does not begin
                        // with a ':', and is preceeded by
                        // automatic error message.
                        // ---------------------------------
                        NDBG_OUTPUT("  Exiting.\n");
                        print_usage(stdout, STATUS_ERROR);
                        break;
                }
                // -----------------------------------------
                // Huh???
                // -----------------------------------------
                default:
                {
                        NDBG_OUTPUT("Unrecognized option.\n");
                        print_usage(stdout, STATUS_ERROR);
                        break;
                }
                }
        }
        // -------------------------------------------------
        // callbacks request context
        // -------------------------------------------------
        static ns_waflz::rqst_ctx_callbacks s_callbacks = {
                ns_waflz_server::get_rqst_ip_cb,
                ns_waflz_server::get_rqst_host_cb,
                ns_waflz_server::get_rqst_port_cb,
                ns_waflz_server::get_rqst_scheme_cb,
                ns_waflz_server::get_rqst_protocol_cb,
                ns_waflz_server::get_rqst_line_cb,
                ns_waflz_server::get_rqst_method_cb,
                ns_waflz_server::get_rqst_url_cb,
                ns_waflz_server::get_rqst_uri_cb,
                ns_waflz_server::get_rqst_path_cb,
                ns_waflz_server::get_rqst_query_str_cb,
                ns_waflz_server::get_rqst_header_size_cb,
                NULL, //get_rqst_header_w_key_cb,
                ns_waflz_server::get_rqst_header_w_idx_cb,
                ns_waflz_server::get_rqst_body_str_cb,
                NULL, //get_rqst_local_addr_cb,
                NULL, //get_rqst_canonical_port_cb,
                NULL, //get_rqst_apparent_cache_status_cb,
                NULL, //get_rqst_bytes_out_cb,
                NULL, //get_rqst_bytes_in_cb,
                ns_waflz_server::get_rqst_uuid_cb, //get_rqst_req_id_cb,
                ns_waflz_server::get_cust_id_cb, //get_cust_id_cb
        };
#ifdef ENABLE_PROFILER
        // -------------------------------------------------
        // start profiler(s)
        // -------------------------------------------------
        if(!l_hprof_file.empty())
        {
                HeapProfilerStart(l_hprof_file.c_str());
        }
        if(!l_cprof_file.empty())
        {
                ProfilerStart(l_cprof_file.c_str());
        }
#endif
        // -------------------------------------------------
        // open out
        // -------------------------------------------------
        if(!l_out_file.empty())
        {
                g_out_file_ptr = fopen(l_out_file.c_str(), "a");
                if(!g_out_file_ptr)
                {
                        NDBG_PRINT("error opening output file: %s. Reason: %s\n",
                                        l_out_file.c_str(),
                                   strerror(errno));
                        return STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // server
        // -------------------------------------------------
        ns_is2::lsnr *l_lsnr = new ns_is2::lsnr(l_port, ns_is2::SCHEME_TCP);
        g_srvr = new ns_is2::srvr();
        g_srvr->register_lsnr(l_lsnr);
        g_srvr->set_num_threads(0);
        // -------------------------------------------------
        // add stat endpoint
        // -------------------------------------------------
        ns_is2::stat_h *l_stat_h = new ns_is2::stat_h();
        l_stat_h->set_route("/stat/*");
        l_lsnr->add_route("/stat/*", l_stat_h);
        // -------------------------------------------------
        // seed random
        // -------------------------------------------------
        srand(time(NULL));
        // -------------------------------------------------
        // Force directory string to end with '/'
        // -------------------------------------------------
        if(!l_ruleset_dir.empty() &&
           ('/' != l_ruleset_dir[l_ruleset_dir.length() - 1]))
        {
                // Append
                l_ruleset_dir += "/";
        }
        int32_t l_s = 0;
        // -------------------------------------------------
        // Validate is directory
        // Stat file to see if is directory or file
        // -------------------------------------------------
        if(!l_ruleset_dir.empty())
        {
                struct stat l_stat;
                l_s = stat(l_ruleset_dir.c_str(), &l_stat);
                if(l_s != 0)
                {
                        NDBG_OUTPUT("error performing stat on directory: %s.  Reason: %s\n", l_ruleset_dir.c_str(), strerror(errno));
                        exit(STATUS_ERROR);
                }
                // -----------------------------------------
                // Check if is directory
                // -----------------------------------------
                if((l_stat.st_mode & S_IFDIR) == 0)
                {
                        NDBG_OUTPUT("error %s does not appear to be a directory\n", l_ruleset_dir.c_str());
                        exit(STATUS_ERROR);
                }
        }
        // -------------------------------------------------
        // *************************************************
        // challenge
        // -------------------------------------------------
        // *************************************************
        g_challenge = new ns_waflz::challenge();
        if(!l_challenge_file.empty())
        {
                l_s = g_challenge->load_file(l_challenge_file.c_str(), l_challenge_file.length());
                if(l_s != STATUS_OK)
                {
                        NDBG_OUTPUT("error performing challenge load file: %s: reason: %s",
                                    l_challenge_file.c_str(),
                                    g_challenge->get_err_msg());
                        exit(STATUS_ERROR);
                }
        }
        // -------------------------------------------------
        // callbacks render bot challenge
        // -------------------------------------------------
        ns_waflz::rqst_ctx::s_get_bot_ch_prob = ns_waflz_server::get_bot_ch_prob;
        // -------------------------------------------------
        // *************************************************
        // server setup
        // *************************************************
        // -------------------------------------------------
        ns_is2::default_rqst_h *l_h = NULL;
        switch(l_server_mode)
        {
        // -------------------------------------------------
        // proxy
        // -------------------------------------------------
        case(SERVER_MODE_PROXY):
        {
                waflz_proxy_h *l_waflz_proxy_h = new waflz_proxy_h(l_server_spec);
                l_h = l_waflz_proxy_h;
                break;
        }
        // -------------------------------------------------
        // proxy
        // -------------------------------------------------
        case(SERVER_MODE_FILE):
        {
                waflz_file_h *l_waflz_file_h = new waflz_file_h();
                l_waflz_file_h->set_root(l_server_spec);
                l_h = l_waflz_file_h;
                break;
        }
        // -------------------------------------------------
        // default
        // -------------------------------------------------
        default:
        {
                waflz_h *l_waflz = new waflz_h();
                l_h = l_waflz;
                break;
        }
        }
        // -------------------------------------------------
        // default route...
        // -------------------------------------------------
        l_lsnr->set_default_route(l_h);
        // -------------------------------------------------
        // setup engine
        // -------------------------------------------------
        if((g_config_mode == CONFIG_MODE_PROFILE) ||
           (g_config_mode == CONFIG_MODE_ACL) ||
           (g_config_mode == CONFIG_MODE_RULES) ||
           (g_config_mode == CONFIG_MODE_MODSECURITY) ||
           (g_config_mode == CONFIG_MODE_SCOPES))
        {
                l_s = init_engine(&l_engine, l_ruleset_dir, l_geoip_db, l_geoip_isp_db);
                if((l_s != STATUS_OK) ||
                   (l_engine == NULL))
                {
                        NDBG_OUTPUT("error performing init_engine\n");
                        goto cleanup;
                }
        }
        // -------------------------------------------------
        // setup db
        // -------------------------------------------------
        if((g_config_mode == CONFIG_MODE_LIMIT) ||
           (g_config_mode == CONFIG_MODE_SCOPES))
        {
                l_s = init_kv_db(&l_kv_db,
#ifdef WAFLZ_KV_DB_REDIS
                                 l_redis_host,
#endif
                                 l_lmdb, l_lmdb_ip);
                if((l_s != STATUS_OK) ||
                   (l_kv_db == NULL))
                {
                        NDBG_OUTPUT("error performing init_kv_db\n");
                        goto cleanup;
                }
        }
        // -------------------------------------------------
        // *************************************************
        // mode setup
        // *************************************************
        // -------------------------------------------------
        switch(g_config_mode)
        {
        // -------------------------------------------------
        // profile
        // -------------------------------------------------
        case(CONFIG_MODE_PROFILE):
        {
                ns_waflz_server::sx_profile *l_sx_profile = new ns_waflz_server::sx_profile(*l_engine);
                l_sx_profile->m_lsnr = l_lsnr;
                l_sx_profile->m_config = l_config_file;
                l_sx_profile->m_callbacks = &s_callbacks;
                g_sx = l_sx_profile;
                break;
        }
        // -------------------------------------------------
        // acl
        // -------------------------------------------------
        case(CONFIG_MODE_ACL):
        {
                ns_waflz_server::sx_acl *l_sx_acl = new ns_waflz_server::sx_acl(*l_engine);
                l_sx_acl->m_lsnr = l_lsnr;
                l_sx_acl->m_config = l_config_file;
                l_sx_acl->m_callbacks = &s_callbacks;
                g_sx = l_sx_acl;
                break;
        }
        // -------------------------------------------------
        // rules
        // -------------------------------------------------
        case(CONFIG_MODE_RULES):
        {
                ns_waflz_server::sx_rules *l_sx_rules = new ns_waflz_server::sx_rules(*l_engine);
                l_sx_rules->m_lsnr = l_lsnr;
                l_sx_rules->m_config = l_config_file;
                l_sx_rules->m_callbacks = &s_callbacks;
                g_sx = l_sx_rules;
                break;
        }
        // -------------------------------------------------
        // modsecurity
        // -------------------------------------------------
        case(CONFIG_MODE_MODSECURITY):
        {
                ns_waflz_server::sx_modsecurity *l_sx_msx = new ns_waflz_server::sx_modsecurity(*l_engine);
                l_sx_msx->m_lsnr = l_lsnr;
                l_sx_msx->m_config = l_config_file;
                l_sx_msx->m_callbacks = &s_callbacks;
                g_sx = l_sx_msx;
                break;
        }
        // -------------------------------------------------
        // limit
        // -------------------------------------------------
        case(CONFIG_MODE_LIMIT):
        {
                ns_waflz_server::sx_limit *l_sx_limit = new ns_waflz_server::sx_limit(*l_kv_db);
                l_sx_limit->m_lsnr = l_lsnr;
                l_sx_limit->m_config = l_config_file;
                l_sx_limit->m_callbacks = &s_callbacks;
                g_sx = l_sx_limit;
                break;
        }
        // -------------------------------------------------
        //  single scope
        // -------------------------------------------------
        case(CONFIG_MODE_SCOPES):
        {
                ns_waflz_server::sx_scopes *l_sx_scopes = new ns_waflz_server::sx_scopes(*l_engine, *l_kv_db, *g_challenge);
                l_sx_scopes->m_lsnr = l_lsnr;
                l_sx_scopes->m_config = l_config_file;
                l_sx_scopes->m_bg_load = l_bg_load;
                l_sx_scopes->m_callbacks = &s_callbacks;
                l_sx_scopes->m_conf_dir = l_config_dir;
                g_sx = l_sx_scopes;
                break;
        }
        // -------------------------------------------------
        // default
        // -------------------------------------------------
        default:
        {
                NDBG_OUTPUT("error no mode specified.\n");
                return STATUS_ERROR;
        }
        }
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        l_s = g_sx->init();
        if(l_s != STATUS_OK)
        {
                NDBG_OUTPUT("performing initialization\n");
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // Sigint handler
        // -------------------------------------------------
        if (signal(SIGINT, sig_handler) == SIG_ERR)
        {
                printf("Error: can't catch SIGINT\n");
                return STATUS_ERROR;
        }
        // -------------------------------------------------
        // audit mode
        // -------------------------------------------------
        if(l_audit_mode)
        {
                goto cleanup;
        }
        // -------------------------------------------------
        // run
        // -------------------------------------------------
        //NDBG_PRINT("running...\n");
        if(g_srvr)
        {
                g_srvr->run();
        }
        //g_srvr->wait_till_stopped();
#ifdef ENABLE_PROFILER
        // -------------------------------------------------
        // stop profiler(s)
        // -------------------------------------------------
        if (!l_hprof_file.empty())
        {
                HeapProfilerStop();
        }
        if (!l_cprof_file.empty())
        {
                ProfilerStop();
        }
#endif
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
cleanup:
        if(g_out_file_ptr) { fclose(g_out_file_ptr); g_out_file_ptr = NULL; }
        if(g_srvr) { delete g_srvr; g_srvr = NULL; }
        if(l_h) { delete l_h; l_h = NULL; }
        if(g_sx) { delete g_sx; g_sx = NULL; }
        if(g_challenge) { delete g_challenge; g_challenge = NULL; }
        if(l_engine) { delete l_engine; l_engine = NULL; }
        if(l_kv_db) { delete l_kv_db; l_kv_db = NULL; }
        if(l_stat_h) {delete l_stat_h; l_stat_h = NULL; }
        return STATUS_OK;
}
