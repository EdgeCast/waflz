//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _SCOPES_CONFIGS_H
#define _SCOPES_CONFIGS_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "waflz/def.h"
#include "waflz/limit.h"
#include "waflz/challenge.h"
#include "waflz/captcha.h"
#include "waflz/rqst_ctx.h"
#include "waflz/resp_ctx.h"
#include "waflz/client_waf.h"
#include <pthread.h>
#include <string>
#include <set>
#if defined(__APPLE__) || defined(__darwin__)
    #include <unordered_map>
#else
    #include <tr1/unordered_map>
#endif
//! ----------------------------------------------------------------------------
//! fwd Decl's
//! ----------------------------------------------------------------------------
namespace waflz_pb {
        class alert;
}
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! fwd Decl's
//! ----------------------------------------------------------------------------
class scopes;
class kv_db;
//! ----------------------------------------------------------------------------
//! scopes_configs
//! ----------------------------------------------------------------------------
class scopes_configs
{
public:
        // -------------------------------------------------
        // public types
        // -------------------------------------------------
#if defined(__APPLE__) || defined(__darwin__)
        typedef std::unordered_map<uint64_t, scopes*> cust_id_scopes_map_t;
        typedef std::unordered_map<std::string, scopes*> team_id_scopes_map_t;
#else
        typedef std::tr1::unordered_map<uint64_t, scopes*> cust_id_scopes_map_t;
        typedef std::tr1::unordered_map<std::string, scopes*> team_id_scopes_map_t;
#endif
        
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        int32_t load_dir(const char *a_dir_path, uint32_t a_dir_path_len);
        int32_t load_file(const char *a_file_path, uint32_t a_file_path_len);
        int32_t load(const char *a_buf, uint32_t a_buf_len, bool a_update = false);
        int32_t load_acl(const char* a_buf, uint32_t a_buf_len);
        int32_t load_limit(const char* a_buf, uint32_t a_buf_len);
        int32_t load_rules(const char* a_buf, uint32_t a_buf_len);
        int32_t load_bot_manager(const char* a_buf, uint32_t a_buf_len);
        int32_t load_bots(const char* a_buf, uint32_t a_buf_len);
        int32_t load_profile(const char* a_buf, uint32_t a_buf_len);
        int32_t load_api_gw(const char* a_buf, uint32_t a_buf_len);
        int32_t load_schema(const char* a_buf, uint32_t a_buf_len);
        int32_t load_client_waf(const char* a_buf, uint32_t a_buf_len);
        int32_t process(waflz_pb::enforcement **ao_enf,
                        waflz_pb::event **ao_audit_event,
                        waflz_pb::event **ao_prod_event,
                        waflz_pb::event **ao_bot_event,
                        void *a_ctx,
                        uint64_t a_id,
                        std::string& a_team_id,
                        part_mk_t a_part_mk,
                        const rqst_ctx_callbacks *a_callbacks,
                        rqst_ctx **ao_rqst_ctx,
                        void* a_srv,
                        int32_t a_module_id);
        int32_t process_response(waflz_pb::enforcement **ao_enf,
                        waflz_pb::event **ao_audit_event,
                        waflz_pb::event **ao_prod_event,
                        void *a_ctx,
                        uint64_t a_id,
                        std::string& a_team_id,
                        part_mk_t a_part_mk,
                        const resp_ctx_callbacks *a_callbacks,
                        resp_ctx **ao_resp_ctx,
                        void* a_srv,
                        int32_t a_content_length);
        int32_t process_response_phase_3(waflz_pb::enforcement **ao_enf,
                        waflz_pb::event **ao_audit_event,
                        waflz_pb::event **ao_prod_event,
                        void *a_ctx,
                        uint64_t a_id,
                        std::string& a_team_id,
                        part_mk_t a_part_mk,
                        const resp_ctx_callbacks *a_callbacks,
                        resp_ctx **ao_resp_ctx,
                        void* a_srv);
        ns_waflz::header_map_t* get_client_waf_headers(uint64_t a_id,
                                                       std::string& a_team_id,
                                                       const char* a_host,
                                                       uint32_t a_host_len,
                                                       const char* a_path,
                                                       uint32_t a_path_len);
        bool check_id(uint64_t a_cust_id);
        bool check_team_id(std::string& a_team_id);
        const char *get_err_msg(void) { return m_err_msg; }
        int32_t generate_alert(waflz_pb::alert** ao_alert,
                                     rqst_ctx* a_ctx,
                                     uint64_t a_cust_id,
                                     std::string& a_team_id,
                                     bool a_is_audit);
        int32_t generate_alert_for_response(waflz_pb::alert** ao_alert,
                                             resp_ctx* a_ctx,
                                             uint64_t a_cust_id,
                                             std::string& a_team_id,
                                             bool a_is_audit);
        void set_locking(bool a_enable_locking) { m_enable_locking = a_enable_locking; }
        void set_conf_dir(const std::string& a_conf_dir) { m_conf_dir = a_conf_dir; }
        void get_first_id(uint64_t &ao_id);
        void get_rand_id(uint64_t &ao_id);
        scopes_configs(engine& a_engine,
                       kv_db& a_db,
                       kv_db& a_bot_db,
                       challenge& a_challenge,
                       captcha& a_captcha,
                       bool a_enable_locking);
        ~scopes_configs();
private:
        // -------------------------------------------------
        // Private methods
        // -------------------------------------------------
        // disallow copy/assign
        scopes_configs(const scopes_configs &);
        scopes_configs& operator=(const scopes_configs &);
        int32_t load(void *a_js, bool a_update = false);
        scopes* get_scopes(uint64_t a_id);
        scopes* get_teamid_scopes(std::string& a_id);
        int32_t load_acl(void* a_js);
        int32_t load_limit(void* a_js);
        int32_t load_rules(void* a_js);
        int32_t load_bots(void* a_js);
        int32_t load_bot_manager(void* a_js);
        int32_t load_profile(void* a_js);
        int32_t load_schema(void* a_js);
        int32_t load_client_waf(void* a_js);
        int32_t load_api_gw(void* a_js);
        // -------------------------------------------------
        // Private members
        // -------------------------------------------------
        cust_id_scopes_map_t m_cust_id_scopes_map;
        team_id_scopes_map_t m_team_id_scopes_map;
        char m_err_msg[WAFLZ_ERR_LEN];
        engine& m_engine;
        kv_db& m_db;
        kv_db& m_bot_db;
        pthread_mutex_t m_mutex;
        bool m_enable_locking;
        std::string m_conf_dir;
        // -------------------------------------------------
        // bot challenge
        // -------------------------------------------------
        challenge& m_challenge;
        // -------------------------------------------------
        // captcha
        // -------------------------------------------------
        captcha& m_captcha;
};
}
#endif
