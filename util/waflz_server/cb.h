//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _WAFLZ_SERVER_CB_H_
#define _WAFLZ_SERVER_CB_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include <stdint.h>
#include <string>
#include "is2/srvr/resp.h"
#include "is2/srvr/session.h"

namespace ns_waflz_server {
//: ----------------------------------------------------------------------------
//: struct for resp handling
//: ----------------------------------------------------------------------------
typedef struct _waf_resp_pkg {
    ns_is2::resp& m_resp;
    ns_is2::session& m_session;

    _waf_resp_pkg( ns_is2::resp& a_resp, ns_is2::session& a_session ):
        m_resp(a_resp),
        m_session(a_session) {};
} waf_resp_pkg;
//: ----------------------------------------------------------------------------
//: extern...
//: ----------------------------------------------------------------------------
extern bool g_random_ips;
//: ----------------------------------------------------------------------------
//: callbacks
//: ----------------------------------------------------------------------------
int32_t get_rqst_ip_cb(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_rqst_line_cb(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_rqst_method_cb(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_rqst_protocol_cb(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_rqst_scheme_cb(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_rqst_port_cb(uint32_t *a_val, void *a_ctx);
int32_t get_rqst_host_cb(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_rqst_url_cb(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_rqst_uri_cb(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_rqst_path_cb(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_rqst_query_str_cb(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_rqst_uuid_cb(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_rqst_header_size_cb(uint32_t *a_val, void *a_ctx);
int32_t get_rqst_header_w_idx_cb(const char **ao_key, uint32_t *ao_key_len, const char **ao_val, uint32_t *ao_val_len, void *a_ctx, uint32_t a_idx);
int32_t get_rqst_body_str_cb(char *ao_data, uint32_t *ao_data_len, bool *ao_is_eos, void *a_ctx, uint32_t a_to_read);
int32_t get_bot_ch_prob(std::string &ao_challenge, uint32_t *ao_ans);
int32_t get_cust_id_cb(uint32_t *a_val, void *a_ctx);
int32_t get_team_id_cb(std::string&, void* a_ctx);
int32_t get_rqst_ja3_md5(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_rqst_ja4(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_rqst_ja4_a(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_rqst_ja4_b(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_rqst_ja4_c(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_recaptcha_subr_cb(const std::string& a_url,
                              const std::string& a_post_params,
                              std::string& ao_resp,
                              void*,
                              void*,
                              int);
int32_t get_rqst_backend_port_cb(uint32_t *a_val, void *a_srv);
//: ----------------------------------------------------------------------------
//: resp callbacks
//: ----------------------------------------------------------------------------
int32_t get_resp_host_cb(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_resp_uri_cb(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_resp_status_cb(uint32_t* a_data, void *a_ctx);
int32_t get_resp_content_type_list_cb(const char **ao_data, uint32_t *ao_data_len, void *a_ctx);
int32_t get_resp_content_length_cb(uint32_t *ao_val, void *a_ctx);
int32_t get_resp_header_size_cb(uint32_t *ao_size, void *a_ctx);
int32_t get_resp_header_w_idx_cb(const char **ao_key, uint32_t *ao_key_len,
                                const char **ao_val, uint32_t *ao_val_len,
                                void *a_ctx, uint32_t a_idx);
int32_t get_rqst_src_addr_cb(const char **a_data, uint32_t *a_len, void *a_ctx);
int32_t get_resp_body_str_cb(char **ao_data,
                             uint32_t *ao_data_len,
                             bool *ao_is_eos,
                             void *a_ctx,
                             uint32_t a_to_read);
}
#endif
