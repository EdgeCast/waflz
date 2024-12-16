//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _SCOPES_H_
#define _SCOPES_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#ifdef __cplusplus
#include "waflz/def.h"
#include "waflz/city.h"
#include "waflz/rqst_ctx.h"
#include "waflz/resp_ctx.h"
#include "waflz/client_waf.h"
#include <string>
#include <inttypes.h>
#include <list>
#include <unordered_set>
#if defined(__APPLE__) || defined(__darwin__)
    #include <unordered_map>
#else
    #include <tr1/unordered_map>
#endif
#endif
#ifndef __cplusplus
#include "waflz/rqst_ctx.h"
typedef struct engine_t engine;
typedef struct scopes_t scopes;
typedef struct kv_db_t kv_db;
typedef struct rqst_ctx_t rqst_ctx;
#endif
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
#ifdef __cplusplus
namespace waflz_pb {
        class enforcement;
        class scope_config;
        class event;
        class scope;
        class op_t;
        class config;
        class limit;
        class condition_group;
}
#endif
#ifdef __cplusplus
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
class engine;
class rqst_ctx;
class acl;
class rules;
class bots;
class bot_manager;
class api_gw;
class schema;
class profile;
class limit;
class kv_db;
class enforcer;
class challenge;
class captcha;
class regex;
class client_waf;
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
class scopes
{
public:
        // -------------------------------------------------
        // str hash
        // -------------------------------------------------
        struct str_hash
        {
                inline std::size_t operator()(const std::string& a_key) const
                {
                        return CityHash64(a_key.c_str(), a_key.length());
                }
        };
        // ----------------------------------------------------------------------------
        // types
        // ----------------------------------------------------------------------------
        typedef std::unordered_set<data_t, data_t_hash, data_comp_unordered> data_set_t;
        typedef std::unordered_set<data_t, data_t_case_hash, data_case_i_comp_unordered> data_case_i_set_t;
        // ----------------------------------------------------------------------------
        // compiled operators
        // ----------------------------------------------------------------------------
        typedef std::list<regex *> regex_list_t;
        typedef std::list<data_set_t *> data_set_list_t;
        typedef std::list<data_case_i_set_t *> data_case_i_set_list_t;
#if defined(__APPLE__) || defined(__darwin__)
        typedef std::unordered_map<std::string, acl*, str_hash> id_acl_map_t;
        typedef std::unordered_map<std::string, rules*, str_hash> id_rules_map_t;
        typedef std::unordered_map<std::string, profile*, str_hash> id_profile_map_t;
        typedef std::unordered_map<std::string, limit*, str_hash> id_limit_map_t;
        typedef std::unordered_map<std::string, bot_manager*, str_hash> id_bot_manager_map_t;
        typedef std::unordered_map<std::string, api_gw*, str_hash> id_api_gw_map_t;
        typedef std::unordered_map<std::string, client_waf*, str_hash> id_client_waf_map_t;
#else
        typedef std::tr1::unordered_map<std::string, acl*, str_hash> id_acl_map_t;
        typedef std::tr1::unordered_map<std::string, rules*, str_hash> id_rules_map_t;
        typedef std::tr1::unordered_map<std::string, profile*, str_hash> id_profile_map_t;
        typedef std::tr1::unordered_map<std::string, limit*, str_hash> id_limit_map_t;
        typedef std::tr1::unordered_map<std::string, bot_manager*, str_hash> id_bot_manager_map_t;
        typedef std::tr1::unordered_map<std::string, api_gw*, str_hash> id_api_gw_map_t;
        typedef std::tr1::unordered_map<std::string, client_waf*, str_hash> id_client_waf_map_t;
#endif
        // -------------------------------------------------
        // Public methods
        // -------------------------------------------------
        scopes(engine& a_engine,
               kv_db& a_kv_db,
               kv_db& a_bot_db,
               challenge& a_challenge,
               captcha& a_captcha);
        ~scopes();
        const char* get_err_msg(void) { return m_err_msg; }
        const waflz_pb::scope_config* get_pb(void) { return m_pb; }
        std::string& get_id(void) { return m_id; }
        std::string& get_cust_id(void) { return m_cust_id; }
        bool is_team_config(void) { return m_team_config; }
        std::string& get_account_type(void) { return m_account_type; }
        std::string& get_partner_id(void) { return m_partner_id; }
        std::string& get_name(void) { return m_name; }
        int32_t load(const char* a_buf, uint32_t a_buf_len, const std::string& a_conf_dir_path);
        int32_t load(void* a_js, const std::string& a_conf_dir_path);
        int32_t load_acl(ns_waflz::acl* a_acl);
        int32_t load_rules(ns_waflz::rules* a_rules);
        int32_t load_bots(void* a_js);
        int32_t load_bot_manager(ns_waflz::bot_manager* a_bot_manager);
        int32_t load_profile(ns_waflz::profile* a_profile);
        int32_t load_limit(ns_waflz::limit* a_limit);
        int32_t load_api_gw(ns_waflz::api_gw* a_api_gw);
        int32_t load_schema(ns_waflz::schema* a_schema);
        int32_t load_client_waf(ns_waflz::client_waf* a_client_waf);
        int32_t process(const waflz_pb::enforcement** ao_enf,
                        waflz_pb::event** ao_audit_event,
                        waflz_pb::event** ao_prod_event,
                        waflz_pb::event** ao_bot_event,
                        void* a_ctx,
                        part_mk_t a_part_mk,
                        const rqst_ctx_callbacks *a_callbacks,
                        rqst_ctx **ao_rqst_ctx,
                        void* a_srv,
                        int32_t a_module_id);
        int32_t process_request_plugin(void **ao_enf, size_t *ao_enf_len,
                                       void **ao_audit_event, size_t *ao_audit_event_len,
                                       void **ao_prod_event, size_t *ao_prod_event_len,
                                       void *a_ctx, const rqst_ctx_callbacks *a_callbacks,
                                       rqst_ctx **ao_rqst_ctx);
        ns_waflz::header_map_t* get_client_waf_headers(const char* a_host, uint32_t a_host_len,
                                                       const char* a_path, uint32_t a_path_len);
        int32_t process_response(const waflz_pb::enforcement **ao_enf,
                        waflz_pb::event **ao_audit_event,
                        waflz_pb::event **ao_prod_event,
                        void *a_ctx,
                        part_mk_t a_part_mk,
                        const resp_ctx_callbacks *a_cb,
                        resp_ctx **ao_resp_ctx,
                        void* a_srv,
                        int32_t a_content_length);
        int32_t process_response_phase_3(const waflz_pb::enforcement **ao_enf,
                        waflz_pb::event **ao_audit_event,
                        waflz_pb::event **ao_prod_event,
                        void *a_ctx,
                        part_mk_t a_part_mk,
                        const resp_ctx_callbacks *a_cb,
                        resp_ctx **ao_resp_ctx,
                        void* a_srv);
        void populate_event(waflz_pb::event** ao_event,
                            const waflz_pb::scope& a_scope);
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // -------------------------------------------------
        // DISALLOW_DEFAULT_CTOR(scopes);
        // disallow copy/assign
        // -------------------------------------------------
        scopes(const scopes &);
        scopes& operator=(const scopes &);
        int32_t load_parts(waflz_pb::scope& a_scope, const std::string& a_conf_dir_path);
        int32_t compile(const std::string& a_conf_dir_path);
        int32_t compile_op(::waflz_pb::op_t& ao_op);
        int32_t add_exceed_limit(waflz_pb::config** ao_cfg,
                                 const waflz_pb::limit& a_limit,
                                 const waflz_pb::condition_group* a_condition_group,
                                 const waflz_pb::enforcement& a_action,
                                 const ::waflz_pb::scope& a_scope,
                                 rqst_ctx* a_ctx);
        int32_t add_exceed_limit_for_response(waflz_pb::config** ao_cfg,
                                 const waflz_pb::limit& a_limit,
                                 const waflz_pb::condition_group* a_condition_group,
                                 const waflz_pb::enforcement& a_action,
                                 const ::waflz_pb::scope& a_scope,
                                 resp_ctx* a_ctx);
        int32_t process(const waflz_pb::enforcement** ao_enf,
                        waflz_pb::event** ao_audit_event,
                        waflz_pb::event** ao_prod_event,
                        waflz_pb::event** ao_bot_event,
                        const ::waflz_pb::scope& a_scope,
                        void* a_ctx,
                        part_mk_t a_part_mk,
                        rqst_ctx **ao_rqst_ctx);
        int32_t process_response(const waflz_pb::enforcement** ao_enf,
                        waflz_pb::event** ao_audit_event,
                        waflz_pb::event** ao_prod_event,
                        const ::waflz_pb::scope& a_scope,
                        void *a_ctx,
                        part_mk_t a_part_mk,
                        resp_ctx **ao_resp_ctx,
                        int32_t a_content_length);
        int32_t process_response_phase_3(const waflz_pb::enforcement** ao_enf,
                                         waflz_pb::event** ao_audit_event,
                                         waflz_pb::event** ao_prod_event,
                                         const ::waflz_pb::scope& a_scope,
                                         void *a_ctx,
                                         part_mk_t a_part_mk,
                                         resp_ctx **ao_resp_ctx);
        bool compare_dates(const char* a_loaded_date, const char* a_new_date);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        bool m_init;
        waflz_pb::scope_config* m_pb;
        char m_err_msg[WAFLZ_ERR_LEN];
        engine& m_engine;
        kv_db& m_db;
        kv_db& m_bot_db;
        regex_list_t m_regex_list;
        data_set_list_t m_data_set_list;
        data_case_i_set_list_t m_data_case_i_set_list;
        // properties
        std::string m_id;
        std::string m_cust_id;
        bool m_team_config;
        bool m_use_spoof_ip_header;
        std::string m_spoof_ip_header;
        std::string m_account_type;
        std::string m_bot_tier;
        std::string m_partner_id;
        std::string m_name;
        bool use_team_id_config;
        // -------------------------------------------------
        // parts...
        // -------------------------------------------------
        id_acl_map_t m_id_acl_map;
        id_rules_map_t m_id_rules_map;
        id_profile_map_t m_id_profile_map;
        id_limit_map_t m_id_limit_map;
        id_bot_manager_map_t m_id_bot_manager_map;
        id_api_gw_map_t m_id_api_gw_map;
        id_client_waf_map_t m_id_client_waf_map;
        // -------------------------------------------------
        // enforcements
        // -------------------------------------------------
        enforcer* m_enfx;
        enforcer* m_audit_enfx;
        // -------------------------------------------------
        // bot challenge
        // -------------------------------------------------
        challenge& m_challenge;
        // -------------------------------------------------
        // captcha
        // -------------------------------------------------
        captcha& m_captcha;
};
//! ----------------------------------------------------------------------------
//! run operation
//! ----------------------------------------------------------------------------
int32_t rl_run_op(bool& ao_matched,
                  const waflz_pb::op_t& a_op,
                  const char* a_data,
                  uint32_t a_data_len,
                  bool a_case_insensitive);
//! ----------------------------------------------------------------------------
//! check scope
//! ----------------------------------------------------------------------------
int32_t in_scope(bool& ao_match,
                 const waflz_pb::scope& a_scope,
                 rqst_ctx* a_ctx);
//! ----------------------------------------------------------------------------
//! check response scope
//! ----------------------------------------------------------------------------
int32_t in_scope_response_with_cstr(bool &ao_match, const waflz_pb::scope& a_scope,
                                   const char* a_host, uint32_t a_host_len,
                                   const char* a_path, uint32_t a_path_len);
int32_t in_scope_response(bool &ao_match,
                 const waflz_pb::scope &a_scope,
                 resp_ctx *a_ctx);
//! ----------------------------------------------------------------------------
//! limit with key
//! ----------------------------------------------------------------------------
int32_t add_limit_with_key(waflz_pb::limit& ao_limit,
                                  const std::string a_key,
                                  rqst_ctx* a_ctx);
//! ----------------------------------------------------------------------------
//! get/convert enforcement
//! ----------------------------------------------------------------------------
int32_t compile_action(waflz_pb::enforcement& ao_axn, char* ao_err_msg);
#endif
#ifdef __cplusplus
extern "C" {
#endif
scopes* create_scopes(engine* a_engine, kv_db* a_db, kv_db* a_bot_db);
int32_t load_config(scopes* a_scope, const char* a_buf,
                    uint32_t a_len, const char* a_conf_dir);
int32_t process_waflz(void** ao_enf, size_t* ao_enf_len,
                      void** ao_audit_event, size_t* ao_audit_event_len,
                      void** ao_prod_event, size_t* ao_prod_event_len,
                      scopes* a_scope, void* a_ctx,
                      const rqst_ctx_callbacks* a_callbacks, rqst_ctx** a_rqst_ctx);
int32_t cleanup_scopes(scopes* a_scopes);
const char* get_waflz_error_msg(scopes* a_scopes);
#ifdef __cplusplus
}
} // namespace waflz
#endif
#endif
