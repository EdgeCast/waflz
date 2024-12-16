//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _RQST_CTX_H
#define _RQST_CTX_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <waflz/def.h>
#ifdef __cplusplus
#include <waflz/arg.h>
#include <waflz/parser.h>
#include <waflz/profile.h>
#include <waflz/kv_db.h>
#include <list>
#include <map>
#include <strings.h>
#include <string_view>
#endif

#if defined(__APPLE__) || defined(__darwin__)
    #include <unordered_map>
#else
    #include <tr1/unordered_map>
#endif

//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
#ifndef __cplusplus
typedef struct rqst_ctx_t rqst_ctx;
#endif
#ifdef __cplusplus
namespace waflz_pb {
class event;
}
namespace waflz_pb {
class limit;
class condition_group;
}
namespace ns_waflz {
#endif
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
        get_rqst_data_cb_t m_get_rqst_src_addr_cb;
        get_rqst_data_cb_t m_get_rqst_host_cb;
        get_rqst_data_size_cb_t m_get_rqst_port_cb;
        get_rqst_data_cb_t m_get_rqst_scheme_cb;
        get_rqst_data_cb_t m_get_rqst_protocol_cb;
        get_rqst_data_cb_t m_get_rqst_line_cb;
        get_rqst_data_cb_t m_get_rqst_method_cb;
        get_rqst_data_cb_t m_get_rqst_url_cb;
        get_rqst_data_cb_t m_get_rqst_uri_cb;
        get_rqst_data_cb_t m_get_rqst_path_cb;
        get_rqst_data_cb_t m_get_rqst_query_str_cb;
        get_rqst_data_size_cb_t m_get_rqst_header_size_cb;
        get_rqst_data_w_key_cb_t m_get_rqst_header_w_key_cb;
        get_rqst_kv_w_idx_cb_t m_get_rqst_header_w_idx_cb;
        get_rqst_body_data_cb_t m_get_rqst_body_str_cb;
        get_rqst_data_cb_t m_get_rqst_local_addr_cb;
        get_rqst_data_size_cb_t m_get_rqst_canonical_port_cb;
        get_rqst_data_size_cb_t m_get_rqst_apparent_cache_status_cb;
        get_rqst_data_size_cb_t m_get_rqst_bytes_out_cb;
        get_rqst_data_size_cb_t m_get_rqst_bytes_in_cb;
        get_rqst_data_cb_t m_get_rqst_uuid_cb;
        get_rqst_data_size_cb_t m_get_cust_id_cb;
        get_rqst_data_cb_t m_get_virt_ssl_client_ja3_md5;
        get_data_subr_t m_get_subr_cb;
        get_rqst_data_str_cb_t m_get_team_id_cb;
        get_rqst_data_str_cb_t m_get_env_id_cb;
        get_rqst_data_size_cb_t m_get_backend_port_cb;
        get_rqst_data_cb_t m_get_virt_ssl_client_ja4;
        get_rqst_data_cb_t m_get_virt_ssl_client_ja4_a;
        get_rqst_data_cb_t m_get_virt_ssl_client_ja4_b;
        get_rqst_data_cb_t m_get_virt_ssl_client_ja4_c;
}rqst_ctx_callbacks;

#ifdef __cplusplus
}
#endif
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
#ifdef __cplusplus
class waf;
class geoip2_mmdb;
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef std::map<std::string, std::string, cx_case_i_comp> cx_map_t;
typedef std::map <data_t, data_t, data_case_i_comp> data_map_t;
typedef std::list<data_t> data_list_t;
#if defined(__APPLE__) || defined(__darwin__)
    typedef std::unordered_map<data_t, data_t, data_t_case_hash,data_case_i_comp_unordered> data_unordered_map_t;
#else
    typedef std::tr1::unordered_map<data_t, data_t,data_t_case_hash,data_case_i_comp_unordered> data_unordered_map_t;
#endif
typedef std::tr1::unordered_map<int32_t, std::string> origin_header_map_t;
//! ----------------------------------------------------------------------------
//! xpath optimization
//! ----------------------------------------------------------------------------
typedef std::list <const_arg_t> xpath_arg_list_t;
typedef std::map <std::string, xpath_arg_list_t> xpath_cache_map_t;
//! ----------------------------------------------------------------------------
//! rqst_ctx
//! ----------------------------------------------------------------------------
class rqst_ctx
{
public:
        // -------------------------------------------------
        // callbacks
        // -------------------------------------------------
        static get_data_cb_t s_get_bot_ch_prob;
        // -------------------------------------------------
        // static members
        // -------------------------------------------------
        static uint32_t s_body_arg_len_cap;
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        rqst_ctx(void *a_ctx,
                 uint32_t a_body_len_max,
                 uint32_t m_body_api_sec_len_max,
                 const rqst_ctx_callbacks *a_callbacks,
                 bool a_parse_xml = false,
                 bool a_parse_json = false,
                 void* a_srv = NULL,
                 int32_t a_module_id = -1);
        ~rqst_ctx();
        int32_t init_phase_1(engine& a_engine,
                             const pcre_list_t *a_il_query = NULL,
                             const pcre_list_t *a_il_header = NULL,
                             const pcre_list_t *a_il_cookie = NULL);

        int32_t get_bot_score(kv_db& a_bot_db, bool a_new_db = false);
        int32_t get_score_from_key(kv_db& a_bot_db, const std::string_view& a_db_key, bool a_new_db = false);
        int32_t get_score_for_level(kv_db& a_bot_db,
                                    const std::string& a_level_string,
                                    const std::string& a_user_agent,
                                    bool a_new_db = false);

        int32_t init_phase_2(const ctype_parser_map_t &a_ctype_parser_map);
        int32_t reset_phase_1();
        int32_t get_geo_data_from_mmdb(geoip2_mmdb &a_geoip2_mmdb);
        const data_t* get_header(const std::string_view& header_name);
        const data_t* get_header(const std::string& header_name);
        int32_t append_rqst_info(waflz_pb::event &ao_event, geoip2_mmdb &a_geoip2_mmdb);
        int32_t do_subrequest(const std::string& a_url,
                              const std::string& a_secret,
                              const std::string& a_token);
        void show(void);
        // -------------------------------------------------
        // setters
        // -------------------------------------------------
        // -------------------------------------------------
        // ja4h calculation
        // -------------------------------------------------
        void set_ja4h_a(std::string &a_ja4h_a);
        void set_ja4h_b(const std::string &a_header_str, char* a_ja4h_b);
        void set_ja4h_c_d(char* a_ja4h_c, char* a_ja4h_d);
        void to_lower_case(std::string &str);
        std::string get_substr(const std::string &input, char delimiter);
        void remove_char(std::string &str, char ch);
        // -------------------------------------------------
        //
        // -------------------------------------------------
        void set_body_max_len(uint32_t a_body_len_max) { m_body_len_max = a_body_len_max; }
        void set_src_addr(data_t a_src_addr) { m_src_addr = a_src_addr; }
        int32_t set_src_ip_from_spoof_header(const std::string&);
        void set_recaptcha_fields(const std::string& a_site_key,
                                  const std::string& a_secret_key,
                                  const std::string& a_recaptcha_action);
        // -------------------------------------------------
        // getters
        // -------------------------------------------------
        const char *get_err_msg(void) { return m_err_msg; }
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        uint32_t m_an;
        std::string m_team_id;
        data_t m_src_addr;
        data_t m_local_addr;
        data_t m_host;
        uint32_t m_port;
        uint32_t m_backend_port;
        data_t m_scheme;
        data_t m_protocol;
        data_t m_line;
        data_t m_method;
        data_t m_url;
        data_t m_uri;
        data_t m_path;
        data_t m_base;
        data_t m_query_str;
        data_t m_file_ext;
        arg_list_t m_query_arg_list;
        data_unordered_map_t m_query_arg_map;
        arg_list_t m_body_arg_list;
        data_unordered_map_t m_body_arg_map;
        data_unordered_map_t m_header_map;
        const_arg_list_t m_header_list;
        const_arg_list_t m_cookie_list;
        data_map_t m_cookie_map;
        uint32_t m_apparent_cache_status;
        data_list_t m_content_type_list;
        uint32_t m_uri_path_len;
        uint32_t m_body_len_max;
        uint32_t m_body_api_sec_len_max;
        char *m_body_data;
        uint32_t m_body_len;
        uint64_t m_content_length;
        std::string m_cookie_mutated;
        data_t m_req_uuid;
        uint32_t m_bytes_out;
        uint32_t m_bytes_in;
        mutable_data_t m_token;
        uint32_t m_resp_status;
        bool m_signal_enf;
        uint32_t m_bot_score;
        uint32_t m_cust_id;
        std::string m_bot_tags;
        data_t m_virt_ssl_client_ja3_md5;
        data_t m_virt_ssl_client_ja4;
        data_t m_virt_ssl_client_ja4_a;
        data_t m_virt_ssl_client_ja4_b;
        data_t m_virt_ssl_client_ja4_c;
        std::string m_virt_ssl_client_ja4h;
        bool m_use_spoof_ip;
        uint32_t m_hot_servers;
        uint32_t m_actual_hot_servers;
        std::string m_bot_score_key;
        bool m_falafel;
        bool m_felafel;
        bool m_known_bot;
        uint32_t m_waf_anomaly_score;
        origin_header_map_t m_origin_signal_map;
        // -------------------------------------------------
        // TODO FIX!!! -not thread safe...
        // -------------------------------------------------
        const waflz_pb::limit* m_limit;
        const waflz_pb::limit* m_audit_limit;
        // -------------------------------------------------
        // body parser
        // -------------------------------------------------
        parser *m_body_parser;
        // -------------------------------------------------
        // collections...
        // -------------------------------------------------
        std::string m_cx_matched_var;
        std::string m_cx_matched_var_name;
        data_map_t m_cx_rule_map;
        cx_map_t m_cx_tx_map;
        // -------------------------------------------------
        // state
        // -------------------------------------------------
        bool m_init_phase_1;
        bool m_init_phase_2;
        bool m_intercepted;
        bool m_wl_audit;
        bool m_wl_prod;
        bool m_inspect_body;
        bool m_json_body;
        bool m_xml_body;
        bool m_url_enc_body;
        uint32_t m_skip;
        const char * m_skip_after;
        waflz_pb::event *m_event;
        bool m_inspect_response;
        bool m_inject_client_waf;
        bool m_inspect_response_headers;
        bool m_gather_bot_score;
        // -------------------------------------------------
        // fields for ja4h calculation
        // -------------------------------------------------
        data_t m_client_protocol;
        bool m_has_cookie;
        bool m_has_referer;
        uint32_t m_header_count;
        bool m_has_accept_lang;
        std::string m_accept_lang;
        // -------------------------------------------------
        // xpath optimization
        // -------------------------------------------------
        xpath_cache_map_t *m_xpath_cache_map;
        // -------------------------------------------------
        // request ctx callbacks struct
        // -------------------------------------------------
        const rqst_ctx_callbacks *m_callbacks;
        // -------------------------------------------------
        // extensions
        // -------------------------------------------------
        // TODO use uint32???
        mutable_data_t m_src_asn_str;
        std::string m_geo_cc_sd;
        geoip_data m_geo_data;
        bool m_xml_capture_xxe;
        // -------------------------------------------------
        // bot challenge
        // -------------------------------------------------
        std::string m_bot_ch;
        std::string m_bot_js;
        uint32_t m_challenge_difficulty;
        uint32_t m_ans;
        // -------------------------------------------------
        // recaptcha
        // -------------------------------------------------
        std::string m_recaptcha_site_key;
        std::string m_recaptcha_secret_key;
        std::string m_recaptcha_action_name;
        std::string m_ec_resp_token;
        bool m_resp_token;
        bool m_tp_subr_fail;
        void *m_captcha_enf;
        std::string m_subr_resp;
        uint64_t m_rqst_ts_s;
        uint64_t m_rqst_ts_ms;
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // disallow copy/assign
        rqst_ctx(const rqst_ctx &);
        rqst_ctx& operator=(const rqst_ctx &);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        void *m_ctx;
        void* m_srv;
        int32_t m_module_id;
        char m_err_msg[WAFLZ_ERR_LEN];
};
#endif
#ifdef __cplusplus
extern "C" {
#endif
rqst_ctx *init_rqst_ctx(void *a_ctx, const uint32_t a_max_body_len, const rqst_ctx_callbacks *a_callbacks, bool a_parse_json);
int32_t rqst_ctx_cleanup(rqst_ctx *a_rqst_ctx);
#ifdef __cplusplus
}
}
#endif
#endif
