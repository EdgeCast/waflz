//! ----------------------------------------------------------------------------
//! Copyright Edgecast Inc.
//!
//! \file:    resp_ctx.h
//! \author:  Kanishk Modi
//! \details: Header file for class responsible for processing response headers and body and evaluating them
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _RESP_CTX_H
#define _RESP_CTX_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <waflz/def.h>
#ifdef __cplusplus
#include <waflz/arg.h>
#include <waflz/parser.h>
#include <waflz/rqst_ctx.h>
#include <list>
#include <map>
#include <strings.h>
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
typedef struct resp_ctx_t resp_ctx;
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
        get_resp_data_cb_t m_get_resp_local_addr_cb;
        get_resp_data_cb_t m_get_resp_host_cb;
        get_rqst_data_size_cb_t m_get_rqst_port_cb;
        get_rqst_data_cb_t m_get_rqst_method_cb;
        get_rqst_data_cb_t m_get_rqst_url_cb;
        get_resp_data_cb_t m_get_resp_uri_cb;
        get_resp_data_size_cb_t m_get_resp_status_cb;
        get_resp_data_cb_t m_get_resp_content_type_list_cb;
        get_resp_data_size_cb_t m_get_resp_content_length_cb;
        get_resp_data_size_cb_t m_get_resp_header_size_cb;
        get_resp_data_w_key_cb_t m_get_resp_header_w_key_cb;
        get_resp_kv_w_idx_cb_t m_get_resp_header_w_idx_cb;
        get_resp_body_data_cb_t m_get_resp_body_str_cb;
        get_resp_data_size_cb_t m_get_resp_cust_id_cb;
        get_rqst_data_cb_t m_get_rqst_src_addr_cb;
        get_rqst_data_cb_t m_get_rqst_uuid_cb;
        get_rqst_data_size_cb_t m_get_rqst_header_size_cb;
        get_rqst_kv_w_idx_cb_t m_get_rqst_header_w_idx_cb;
        get_rqst_data_str_cb_t m_get_team_id_cb;
        get_rqst_data_size_cb_t m_get_backend_port_cb;
}resp_ctx_callbacks;
#ifdef __cplusplus
}
#endif
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
#ifdef __cplusplus
class waf;
class geoip2_mmdb;

typedef std::map<std::string, std::string, cx_case_i_comp> cx_map_t;
typedef std::map <data_t, data_t, data_case_i_comp> data_map_t;
typedef std::list<data_t> data_list_t;
#if defined(__APPLE__) || defined(__darwin__)
    typedef std::unordered_map<data_t, data_t, data_t_case_hash,data_case_i_comp_unordered> data_unordered_map_t;
#else
    typedef std::tr1::unordered_map<data_t, data_t,data_t_case_hash,data_case_i_comp_unordered> data_unordered_map_t;
#endif
//! ----------------------------------------------------------------------------
//! resp_ctx
//! ----------------------------------------------------------------------------
class resp_ctx
{
public:
        // -------------------------------------------------
        // callbacks
        // -------------------------------------------------
        // -------------------------------------------------
        // static members
        // -------------------------------------------------
        static uint32_t s_body_arg_len_cap;
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        resp_ctx(void *a_ctx,
                 uint32_t a_body_len_max,
                 uint32_t a_body_api_sec_len_max,
                 const resp_ctx_callbacks *a_callbacks,
                 int32_t a_content_length,
                 void* a_srv);
        ~resp_ctx();
        // -------------------------------------------------
        // response header evaluation
        // -------------------------------------------------
        int32_t init_phase_3(geoip2_mmdb &a_geoip2_mmdb);
        const data_t* get_header(const std::string_view& header_name);
        int32_t get_geo_data_from_mmdb(geoip2_mmdb &a_geoip2_mmdb);
        // -------------------------------------------------
        // response body evaluation
        // -------------------------------------------------
        int32_t init_phase_4();
        int32_t reset_phase_3();
        int32_t append_resp_info(waflz_pb::event &ao_event);
        void show(void);
        // -------------------------------------------------
        // setters
        // -------------------------------------------------
        void set_body_max_len(uint32_t a_body_len_max) { m_body_len_max = a_body_len_max; }
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        data_t m_src_addr;
        uint32_t m_an;
        std::string m_team_id;
        data_t m_host;
        uint32_t m_port;
        uint32_t m_backend_port;
        data_t m_method;
        data_t m_url;
        data_t m_uri;
        uint32_t m_uri_path_len;
        int64_t m_content_length;
        data_list_t m_content_type_list;
        data_unordered_map_t m_header_map;
        const_arg_list_t m_header_list;
        uint32_t m_body_len_max;
        uint32_t m_body_api_sec_len_max;
        char *m_body_data;
        uint32_t m_body_len;
        uint32_t m_resp_status;
        std::string m_resp_status_str;
        bool m_intercepted;
        data_t m_req_uuid;
        mutable_data_t m_src_asn_str;
        std::string m_geo_cc_sd;
        geoip_data m_geo_data;
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
        bool m_init_phase_3;
        bool m_init_phase_4;
        uint32_t m_skip;
        const char * m_skip_after;
        waflz_pb::event *m_event;
        // -------------------------------------------------
        // response ctx callbacks struct
        // -------------------------------------------------
        const resp_ctx_callbacks *m_callbacks;
        // -------------------------------------------------
        // TODO FIX!!! -not thread safe...
        // -------------------------------------------------
        uint32_t m_set_response_status;
        bool m_signal_enf;
        const waflz_pb::limit* m_limit;
        const waflz_pb::limit* m_audit_limit;
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // disallow copy/assign
        resp_ctx(const resp_ctx &);
        resp_ctx& operator=(const resp_ctx &);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        void *m_ctx;
        void *m_srv;
};
#endif
#ifdef __cplusplus
extern "C" {
#endif
resp_ctx *init_resp_ctx(void *a_ctx, const uint32_t a_max_body_len, uint32_t a_body_api_sec_len_max, const resp_ctx_callbacks *a_callbacks, bool a_parse_json);
int32_t resp_ctx_cleanup(resp_ctx *a_resp_ctx);
#ifdef __cplusplus
}
}
#endif
#endif
