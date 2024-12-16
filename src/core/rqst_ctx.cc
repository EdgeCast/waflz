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
#include <algorithm>
#include "event.pb.h"
#include "waflz/def.h"
#include "waflz/rqst_ctx.h"
#include "waflz/engine.h"
#include "waflz/geoip2_mmdb.h"
#include "waflz/string_util.h"
#include "core/decode.h"
#include "op/regex.h"
#include "support/ndebug.h"
#include "support/time_util.h"
#include "parser/parser_url_encoded.h"
#include "parser/parser_xml.h"
#include "parser/parser_json.h"
#include <stdlib.h>
#include <string.h>
#include <vector>
// ---------------------------------------------------------
// openssl
// ---------------------------------------------------------
#include <openssl/sha.h>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define _DEFAULT_BODY_ARG_LEN_CAP 4096
#define _JA4H_SHA256_HASH_LEN 32
#define _JA4H_IND_SIZE 13
#define _JA4H_SIZE 53
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
#define GET_RQST_DATA(_cb) do { \
        l_buf = NULL; \
        l_buf_len = 0; \
        if (_cb) { \
                l_s = _cb(&l_buf, &l_buf_len, m_ctx); \
                if (l_s != 0) { \
                        return WAFLZ_STATUS_ERROR; \
                } \
        } \
} while (0)
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! static
//! ----------------------------------------------------------------------------
uint32_t rqst_ctx::s_body_arg_len_cap = _DEFAULT_BODY_ARG_LEN_CAP;
get_data_cb_t rqst_ctx::s_get_bot_ch_prob = NULL;
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
static bool key_in_ignore_list(const pcre_list_t &a_pcre_list,
                               const char *a_data,
                               uint32_t a_data_len)
{
        bool l_match = false;
        for (pcre_list_t::const_iterator i_c = a_pcre_list.begin();
            i_c != a_pcre_list.end();
            ++i_c)
        {
                regex *l_regex = *i_c;
                if (!l_regex)
                {
                        continue;
                }
                int32_t l_s;
                // -----------------------------------------
                // match?
                // -----------------------------------------
                l_s = l_regex->compare(a_data, a_data_len);
                // -----------------------------------------
                // We have a match
                // -----------------------------------------
                if (l_s >= 0)
                {
                       l_match = true;
                       return l_match;
                }
        }
        return l_match;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
static int32_t remove_ignored(arg_list_t &ao_arg_list,
                              const pcre_list_t &a_pcre_list)
{
        // -------------------------------------------------
        // strip ignored cookies
        // -------------------------------------------------
        for (arg_list_t::iterator i_a = ao_arg_list.begin();
            i_a != ao_arg_list.end();)
        {
                bool l_m = false;
                l_m = key_in_ignore_list(a_pcre_list,
                                         i_a->m_key,
                                         i_a->m_key_len);
                if (l_m)
                {
                        // ---------------------------------
                        // free alloc'd buffers
                        // ---------------------------------
                        if (i_a->m_key) { free(i_a->m_key); i_a->m_key = NULL; i_a->m_key_len = 0; }
                        if (i_a->m_val) { free(i_a->m_val); i_a->m_val = NULL; i_a->m_val_len = 0; }
                        // ---------------------------------
                        // remove from list
                        // ---------------------------------
                        ao_arg_list.erase(i_a++);
                        continue;
                }
                ++i_a;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
static int32_t remove_ignored_const(const_arg_list_t &ao_arg_list,
                                    const pcre_list_t &a_pcre_list)
{
        // -------------------------------------------------
        // strip ignored cookies
        // -------------------------------------------------
        for (const_arg_list_t::iterator i_a = ao_arg_list.begin();
            i_a != ao_arg_list.end();)
        {
                bool l_m = false;
                l_m = key_in_ignore_list(a_pcre_list,
                                         i_a->m_key,
                                         i_a->m_key_len);
                if (l_m)
                {
                        ao_arg_list.erase(i_a++);
                        continue;
                }
                ++i_a;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details Check whether the text in the buf begins with JSON structure
//! \return  true: on finding json structure in the begining
//!          false: on not finding json structure in the begining
//! \param   a_buf: Input buffer
//!          a_len: length of buffer
//! ----------------------------------------------------------------------------
static bool infer_is_json(const char *a_buf, uint32_t a_len)
{
        // -------------------------------------------------
        // shortest json string is []
        // -------------------------------------------------
        if (!a_buf ||
           a_len <=2)
        {
                return false;
        }
        // -------------------------------------------------
        // We will only inspect first 16 characters
        // -------------------------------------------------
        uint32_t l_max_check = (a_len < 16) ? a_len : 16;
        uint32_t i_i = 0;
        while (i_i < (l_max_check -1))
        {
                // -----------------------------------------
                // skip all whitespace and newline before we
                // look ahead for json structure
                // -----------------------------------------
                if (isspace(a_buf[i_i]))
                {
                        ++i_i;
                }
                else
                {
                        if ((a_buf[i_i] == '{'))
                        {
                                // -------------------------
                                // check for next char
                                // -------------------------
                                ++i_i;
                                if ((isspace(a_buf[i_i])) ||
                                   (a_buf[i_i] == '"'))
                                   {
                                        return true;
                                   }
                        }
                        else if ((a_buf[i_i] == '['))
                        {
                                // -------------------------
                                // check for next char
                                // ", {, true, false, null
                                // numbers 0-9
                                // -------------------------
                                ++i_i;
                                if ((isspace(a_buf[i_i])) ||
                                   (a_buf[i_i] == '"')   ||
                                   (a_buf[i_i] == '{')   ||
                                   (a_buf[i_i] == '[')   ||
                                   (a_buf[i_i] == 't')   ||
                                   (a_buf[i_i] == 'f')   ||
                                   (a_buf[i_i] == 'n')   ||
                                   (uint32_t(a_buf[i_i]) >= 48 && uint32_t(a_buf[i_i]) <= 57))
                                   {
                                        return true;
                                   }
                        }
                        return false;
                }
        }
        return false;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
rqst_ctx::rqst_ctx(void *a_ctx,
                   uint32_t a_body_len_max,
                   uint32_t a_body_api_sec_len_max,
                   const rqst_ctx_callbacks *a_callbacks,
                   bool a_parse_xml,
                   bool a_parse_json,
                   void* a_srv,
                   int a_module_id):
        m_an(),
        m_team_id(),
        m_src_addr(),
        m_local_addr(),
        m_host(),
        m_port(0),
        m_backend_port(0),
        m_scheme(),
        m_protocol(),
        m_line(),
        m_method(),
        m_url(),
        m_uri(),
        m_path(),
        m_base(),
        m_query_str(),
        m_file_ext(),
        m_query_arg_list(),
        m_query_arg_map(),
        m_body_arg_list(),
        m_body_arg_map(),
        m_header_map(),
        m_header_list(),
        m_cookie_list(),
        m_cookie_map(),
        m_apparent_cache_status(),
        m_content_type_list(),
        m_uri_path_len(0),
        m_body_len_max(a_body_len_max),
        m_body_api_sec_len_max(a_body_api_sec_len_max),
        m_body_data(NULL),
        m_body_len(0),
        m_content_length(0),
        m_cookie_mutated(),
        m_req_uuid(),
        m_bytes_out(0),
        m_bytes_in(0),
        m_token(),
        m_resp_status(0),
        m_signal_enf(0),
        m_bot_score(0),
        m_cust_id(0),
        m_bot_tags(),
        m_virt_ssl_client_ja3_md5(),
        m_virt_ssl_client_ja4(),
        m_virt_ssl_client_ja4_a(),
        m_virt_ssl_client_ja4_b(),
        m_virt_ssl_client_ja4_c(),
        m_virt_ssl_client_ja4h(),
        m_use_spoof_ip(false),
        m_hot_servers(0),
        m_actual_hot_servers(0),
        m_bot_score_key(),
        m_falafel(false),
        m_felafel(false),
        m_known_bot(false),
        m_waf_anomaly_score(0),
        m_origin_signal_map(),
        m_limit(NULL),
        m_audit_limit(NULL),
        m_body_parser(),
        // -------------------------------------------------
        // collections
        // -------------------------------------------------
        m_cx_matched_var(),
        m_cx_matched_var_name(),
        m_cx_rule_map(),
        m_cx_tx_map(),
        // -------------------------------------------------
        // state
        // -------------------------------------------------
        m_init_phase_1(false),
        m_init_phase_2(false),
        m_intercepted(false),
        m_wl_audit(false),
        m_wl_prod(false),
        m_inspect_body(true),
        m_json_body(false),
        m_xml_body(false),
        m_url_enc_body(false),
        m_skip(0),
        m_skip_after(NULL),
        m_event(NULL),
        m_inspect_response(false),
        m_inject_client_waf(false),
        m_inspect_response_headers(false),
        m_gather_bot_score(false),
        m_client_protocol(),
        m_has_cookie(false),
        m_has_referer(false),
        m_header_count(0),
	m_has_accept_lang(false),
	m_accept_lang(),
        // -------------------------------------------------
        // *************************************************
        // xml optimization
        // *************************************************
        // -------------------------------------------------
        m_xpath_cache_map(NULL),
        m_callbacks(a_callbacks),
        // -------------------------------------------------
        // *************************************************
        // extensions
        // *************************************************
        // -------------------------------------------------
        m_src_asn_str(),
        m_geo_cc_sd(),
        m_geo_data(),
        m_xml_capture_xxe(true),
        m_bot_ch(),
        m_bot_js(),
        m_challenge_difficulty(0),
        m_ans(0),
        m_recaptcha_site_key(),
        m_recaptcha_secret_key(),
        m_recaptcha_action_name(),
        m_ec_resp_token(),
        m_resp_token(false),
        m_tp_subr_fail(false),
        m_captcha_enf(NULL),
        m_subr_resp(),
        m_rqst_ts_s(0),
        m_rqst_ts_ms(0),
        m_ctx(a_ctx),
        m_srv(a_srv),
        m_module_id(a_module_id),
        m_err_msg()

{
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
rqst_ctx::~rqst_ctx()
{
        // -------------------------------------------------
        // delete query args
        // -------------------------------------------------
        for (arg_list_t::iterator i_q = m_query_arg_list.begin();
            i_q != m_query_arg_list.end();
            ++i_q)
        {
                if (i_q->m_key) { free(i_q->m_key); i_q->m_key = NULL; }
                if (i_q->m_val) { free(i_q->m_val); i_q->m_val = NULL; }
        }
        // -------------------------------------------------
        // delete body args
        // -------------------------------------------------
        for (arg_list_t::iterator i_q = m_body_arg_list.begin();
            i_q != m_body_arg_list.end();
            ++i_q)
        {
                if (i_q->m_key) { free(i_q->m_key); i_q->m_key = NULL; }
                if (i_q->m_val) { free(i_q->m_val); i_q->m_val = NULL; }
        }
        // -------------------------------------------------
        // delete body
        // -------------------------------------------------
        if (m_body_data)
        {
                free(m_body_data);
                m_body_data = NULL;
                m_body_len = 0;
        }
        // -------------------------------------------------
        // *************************************************
        // xml optimization
        // *************************************************
        // -------------------------------------------------
        if (m_xpath_cache_map)
        {
                for (xpath_cache_map_t::iterator i_p = m_xpath_cache_map->begin();
                    i_p != m_xpath_cache_map->end();
                    ++i_p)
                {
                        for (xpath_arg_list_t::iterator i_s = i_p->second.begin();
                            i_s != i_p->second.end();
                            ++i_s)
                        {
                                if (i_s->m_val)
                                {
                                        free((char *)i_s->m_val);
                                        i_s->m_val = NULL;
                                        i_s->m_val_len = 0;
                                }
                        }
                }
                delete m_xpath_cache_map;
        }
        // -------------------------------------------------
        // delete parser
        // -------------------------------------------------
        if (m_body_parser) { delete m_body_parser; m_body_parser = NULL;}
        // -------------------------------------------------
        // delete any tokens
        // -------------------------------------------------
        if (m_token.m_data) { free(m_token.m_data); m_token.m_data = NULL; m_token.m_len = 0; }
        // -------------------------------------------------
        // delete any extensions
        // -------------------------------------------------
        if (m_src_asn_str.m_data) { free(m_src_asn_str.m_data); m_src_asn_str.m_data = NULL; m_src_asn_str.m_len = 0; }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t rqst_ctx::reset_phase_1()
{
        // -------------------------------------------------
        // delete query args
        // -------------------------------------------------
        if (!m_query_arg_list.empty())
        {
                for (arg_list_t::iterator i_q = m_query_arg_list.begin();
                    i_q != m_query_arg_list.end();
                    ++i_q)
                {
                        if (i_q->m_key) { free(i_q->m_key); i_q->m_key = NULL; }
                        if (i_q->m_val) { free(i_q->m_val); i_q->m_val = NULL; }
                }
                m_query_arg_list.clear();
        }
        m_query_arg_map.clear();
        // -------------------------------------------------
        // clear cookies
        // -------------------------------------------------
        m_cookie_list.clear();
        m_cookie_map.clear();
        // -------------------------------------------------
        // clear headers
        // -------------------------------------------------
        m_header_list.clear();
        // -------------------------------------------------
        // clear tx map
        // -------------------------------------------------
        m_cx_tx_map.clear();
        // -------------------------------------------------
        // clear header map
        // -------------------------------------------------
        m_header_map.clear();
        // -------------------------------------------------
        // clear rule map
        // -------------------------------------------------
        m_cx_rule_map.clear();
        // -------------------------------------------------
        // clear vars
        // -------------------------------------------------
        m_cx_matched_var.clear();
        m_cx_matched_var_name.clear();
        m_cookie_mutated.clear();
        m_init_phase_1 = false;
        m_intercepted = false;
        m_has_cookie = false;
        m_has_referer = false;
        m_header_count = 0;
        m_has_accept_lang = false;
        m_accept_lang.clear();
        m_virt_ssl_client_ja4h.clear();
	return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t rqst_ctx::do_subrequest(const std::string& a_url,
                                const std::string& a_secret,
                                const std::string& a_token)
{
        int32_t l_s = WAFLZ_STATUS_ERROR;
        if (m_callbacks && m_callbacks->m_get_subr_cb)
        {
                std::string l_post_params;
                l_post_params.append("secret=");
                l_post_params.append(a_secret);
                l_post_params.append("&response=");
                l_post_params.append(a_token);
                l_s = m_callbacks->m_get_subr_cb(a_url,
                                                 l_post_params,
                                                 m_subr_resp,
                                                 m_ctx,
                                                 m_srv,
                                                 m_module_id);
                return l_s;
        }
        return l_s;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void rqst_ctx::set_recaptcha_fields(const std::string& a_site_key,
                                    const std::string& a_secret_key,
                                    const std::string& a_action_name)
{
        m_recaptcha_site_key = a_site_key;
        m_recaptcha_secret_key = a_secret_key;
        m_recaptcha_action_name = a_action_name;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t rqst_ctx::init_phase_1(engine& a_engine,
                               const pcre_list_t *a_il_query,
                               const pcre_list_t *a_il_header,
                               const pcre_list_t *a_il_cookie)
{
        if (m_init_phase_1)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // set AN
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_cust_id_cb)
        {
                int32_t l_s;
                l_s = m_callbacks->m_get_cust_id_cb(&m_an, m_ctx);
                if (l_s != 0)
                {
                        WAFLZ_PERROR(m_err_msg, "error in m_get_cust_id_cb callback");
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // set team id
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_team_id_cb)
        {
                int32_t l_s;
                l_s = m_callbacks->m_get_team_id_cb(m_team_id, m_ctx);
                if (l_s != 0)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // src addr
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_rqst_src_addr_cb && !m_use_spoof_ip)
        {
                int32_t l_s;
                // -----------------------------------------
                // get src address
                // -----------------------------------------
                l_s = m_callbacks->m_get_rqst_src_addr_cb(&m_src_addr.m_data,
                                             &m_src_addr.m_len,
                                             m_ctx);
                if (l_s != 0)
                {
                        WAFLZ_PERROR(m_err_msg, "error in m_get_rqst_src_addr_cb callback");
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // Gather country code, sd1, sd2, is_anonymous_proxy
        // for mmdb
        //
        // NOTE: subdiv iso = m_geo_cn2 + "-" + get_sd_iso
        // -------------------------------------------------
        if DATA_T_EXIST(m_src_addr)
        {
                int32_t l_s;
                geoip2_mmdb& l_geoip_db = a_engine.get_geoip2_mmdb();
                l_s = get_geo_data_from_mmdb(l_geoip_db);
                if (l_s != WAFLZ_STATUS_OK)
                {

                }
        }
        // -------------------------------------------------
        // local addr
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_rqst_local_addr_cb)
        {
                int32_t l_s;
                // -----------------------------------------
                // get src address
                // -----------------------------------------
                l_s = m_callbacks->m_get_rqst_local_addr_cb(&m_local_addr.m_data,
                                               &m_local_addr.m_len,
                                               m_ctx);
                if (l_s != 0)
                {
                        WAFLZ_PERROR(m_err_msg, "error in m_get_rqst_local_addr_cb callback");
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // host
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_rqst_host_cb)
        {
                int32_t l_s;
                // -----------------------------------------
                // get src address
                // -----------------------------------------
                l_s = m_callbacks->m_get_rqst_host_cb(&m_host.m_data,
                                         &m_host.m_len,
                                         m_ctx);
                if (l_s != 0)
                {
                        WAFLZ_PERROR(m_err_msg, "error in m_get_rqst_host_cb callback");
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // port
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_rqst_port_cb)
        {
                int32_t l_s;
                // -----------------------------------------
                // get request port
                // -----------------------------------------
                l_s = m_callbacks->m_get_rqst_port_cb(&m_port,
                                         m_ctx);
                if (l_s != 0)
                {
                        WAFLZ_PERROR(m_err_msg, "error in m_get_rqst_port_cb callback");
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // scheme (http/https)
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_rqst_scheme_cb)
        {
                int32_t l_s;
                // -----------------------------------------
                // get request scheme
                // -----------------------------------------
                l_s = m_callbacks->m_get_rqst_scheme_cb(&m_scheme.m_data,
                                           &m_scheme.m_len,
                                           m_ctx);
                if (l_s != 0)
                {
                        
                        WAFLZ_PERROR(m_err_msg, "error in m_get_rqst_port_cb callback");
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // request uuid
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_rqst_uuid_cb)
        {
                int32_t l_s;
                l_s = m_callbacks->m_get_rqst_uuid_cb(&m_req_uuid.m_data,
                                                      &m_req_uuid.m_len,
                                                      m_ctx);
                if (l_s != 0)
                {
                        // ---------------------------------
                        // TODO log reason???
                        // ---------------------------------
                        //return STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // hardcode protocol to http/1.1
        // -------------------------------------------------
        m_protocol.m_data = "HTTP/1.1";
        m_protocol.m_len = strlen(m_protocol.m_data);
        // -------------------------------------------------
        // line
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_rqst_line_cb)
        {
                int32_t l_s;
                // -----------------------------------------
                // get request line
                // -----------------------------------------
                l_s = m_callbacks->m_get_rqst_line_cb(&m_line.m_data,
                                         &m_line.m_len,
                                         m_ctx);
                if (l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // method
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_rqst_method_cb)
        {
                int32_t l_s;
                // -----------------------------------------
                // get method
                // -----------------------------------------
                l_s = m_callbacks->m_get_rqst_method_cb(&m_method.m_data,
                                           &m_method.m_len,
                                           m_ctx);
                if (l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // get uri, url and quert string
        // According to modsecurity:
        //
        // (REQUEST_URI) : holds the full request URL
        // including the query string data
        // (e.g., /index.php?p=X). However, it will never
        // contain a domain name, even if it was provided on
        // the request line.
        //
        // (REQUEST_URI_RAW): will contain the domain
        // name if it was provided on the request line
        // (e.g., http://www.example.com/index.php?p=X
        // The domain name depends on request line.
        // The most common form is origin-form according to
        // https://tools.ietf.org/html/rfc7230#section-5.3.1
        // waflz only supports origin form at this time,
        // meaning uri=uri
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_rqst_uri_cb)
        {
                int32_t l_s;
                // -----------------------------------------
                // get uri
                // -----------------------------------------
                l_s = m_callbacks->m_get_rqst_uri_cb(&m_uri.m_data,
                                                     &m_uri.m_len,
                                                     m_ctx);
                if (l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // get path length w/o q string
                // -----------------------------------------
                m_uri_path_len = m_uri.m_len;
                const char *l_q = NULL;
                l_q = (const char *)memchr(m_uri.m_data, '?', m_uri.m_len);
                if (l_q)
                {
                        m_uri_path_len = l_q - m_uri.m_data;
                        // ---------------------------------
                        // get query string
                        // ---------------------------------
                        m_query_str.m_data = l_q + 1;
                        m_query_str.m_len = m_uri.m_len - m_uri_path_len - 1;
                }
                // -----------------------------------------
                // get path
                // -----------------------------------------
                m_path.m_data = m_uri.m_data;
                m_path.m_len = m_uri_path_len;
                // -----------------------------------------
                // get base
                // -----------------------------------------
                if (m_path.m_data &&
                   m_path.m_len)
                {
                        const void *l_ptr = NULL;
                        l_ptr = memrchr(m_path.m_data, '/', (int)m_path.m_len);
                        if (l_ptr)
                        {
                                m_base.m_data = ((const char *)(l_ptr) + 1);
                                m_base.m_len = m_path.m_len - ((uint32_t)((const char *)l_ptr - m_path.m_data)) - 1;
                        }
                }
                // -----------------------------------------
                // get file_ext
                // -----------------------------------------
                if (m_base.m_data &&
                   m_base.m_len)
                {
                        const void *l_ptr = NULL;
                        l_ptr = memrchr(m_base.m_data, '.', (int)m_base.m_len);
                        if (l_ptr)
                        {
                                m_file_ext.m_data = ((const char *)(l_ptr));
                                m_file_ext.m_len = m_base.m_len - ((uint32_t)((const char *)l_ptr - m_base.m_data));
                        }
                }
                // -----------------------------------------
                // parse query args
                // -----------------------------------------
                if (m_query_str.m_data &&
                   m_query_str.m_len)
                {
                        // ---------------------------------
                        // parse args
                        // ---------------------------------
                        uint32_t l_invalid_cnt = 0;
                        l_s = parse_args(m_query_arg_list,
                                         m_query_arg_map,
                                         l_invalid_cnt,
                                         m_query_str.m_data,
                                         m_query_str.m_len,
                                         '&');
                        if (l_s != WAFLZ_STATUS_OK)
                        {
                                // TODO log reason???
                                return WAFLZ_STATUS_ERROR;
                        }
                        // -----------------------------------------
                        // remove ignored
                        // -----------------------------------------
                        if (a_il_query)
                        {
                                l_s = remove_ignored(m_query_arg_list, *a_il_query);
                                if (l_s != WAFLZ_STATUS_OK)
                                {
                                        // TODO log reason???
                                        return WAFLZ_STATUS_ERROR;
                                }
                        }
                }
        }
        // -------------------------------------------------
        // Url
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_rqst_url_cb)
        {
                int32_t l_s;
                // -----------------------------------------
                // get uri
                // -----------------------------------------
                l_s = m_callbacks->m_get_rqst_url_cb(&m_url.m_data,
                                        &m_url.m_len,
                                        m_ctx);
                if (l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // headers
        // -------------------------------------------------
        uint32_t l_hdr_size = 0;
        if (m_callbacks && m_callbacks->m_get_rqst_header_size_cb)
        {
                int32_t l_s;
                l_s = m_callbacks->m_get_rqst_header_size_cb(&l_hdr_size, m_ctx);
                if (l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_rqst_header_size_cb");
                }
                m_header_count = l_hdr_size;
        }
        // -------------------------------------------------
        // ja4h vars
        // -------------------------------------------------
        // ref: https://blog.foxio.io/ja4+-network-fingerprinting
        // -------------------------------------------------
        std::string l_header_fields_str;
        bool l_is_internal_header;
        char l_ja4h_c[_JA4H_IND_SIZE] = {0};
	char l_ja4h_d[_JA4H_IND_SIZE] = {0};
        for (uint32_t i_h = 0; i_h < l_hdr_size; ++i_h)
        {
                l_is_internal_header = false;
                const_arg_t l_hdr;
                if (!m_callbacks || !m_callbacks->m_get_rqst_header_w_idx_cb)
                {
                        continue;
                }
                int32_t l_s;
                l_s = m_callbacks->m_get_rqst_header_w_idx_cb(&l_hdr.m_key, &l_hdr.m_key_len,
                                                 &l_hdr.m_val, &l_hdr.m_val_len,
                                                 m_ctx,
                                                 i_h);
                if (l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_rqst_header_w_idx_cb: idx: %u", i_h);
                        continue;
                }
                if (!l_hdr.m_key)
                {
                        continue;
                }
                // -------------------------------------------------
                // Check if referer is present for ja4h
                // -------------------------------------------------
                bool l_is_referer_hdr = false;
                if (strncasecmp(l_hdr.m_key, "Referer", sizeof("Referer")) == 0)
                {
                        l_is_referer_hdr = true;
                        m_has_referer = true;
                        m_header_count = m_header_count - 1; // ja4h - referer header removed from calculation
                }
                // -------------------------------------------------
                // Check if Accept-Language header is present for ja4h
                // -------------------------------------------------
                if (strncasecmp(l_hdr.m_key, "Accept-Language", sizeof("Accept-Language")) == 0)
                {
                        m_has_accept_lang = true;
                        m_accept_lang.append(l_hdr.m_val, l_hdr.m_val_len);
                }
                // -------------------------------------------------
                // parse cookie header...
                // -------------------------------------------------
                bool l_is_cookie_hdr = false;
                if (strncasecmp(l_hdr.m_key, "Cookie", sizeof("Cookie")) == 0)
                {
                        l_is_cookie_hdr = true;
                        m_header_count = m_header_count - 1; // ja4h - cookie header removed from calculation
                        int32_t l_s;
                        // ---------------------------------
                        // parse...
                        // ---------------------------------
                        l_s = parse_cookies(m_cookie_list,
                                            l_hdr.m_val,
                                            l_hdr.m_val_len);
                        if (l_s != WAFLZ_STATUS_OK)
                        {
                                // TODO -log error???
                                continue;
                        }
                        if (m_cookie_list.size() > 0)
                        {
                                m_has_cookie = true;
                                // -------------------------------------------------
                                // compute JA4H_C and JA4H_D
                                // NOTE: this needs to be done on raw cookie list, 
                                // before any cookie processing
                                // -------------------------------------------------
                                set_ja4h_c_d(l_ja4h_c, l_ja4h_d);
                        }
                        // ---------------------------------
                        // remove ignored
                        // ---------------------------------
                        if (a_il_cookie)
                        {
                                l_s = remove_ignored_const(m_cookie_list, *a_il_cookie);
                                if (l_s != WAFLZ_STATUS_OK)
                                {
                                        // TODO log reason???
                                        return WAFLZ_STATUS_ERROR;
                                }
                        }
                        // ---------------------------------
                        // regenerate mutated cookie
                        // ---------------------------------
                        m_cookie_mutated.clear();
                        uint32_t i_c_idx = 0;
                        uint32_t l_c_len = m_cookie_list.size();
                        for (const_arg_list_t::const_iterator i_c = m_cookie_list.begin();
                            i_c != m_cookie_list.end();
                            ++i_c, ++i_c_idx)
                        {
                                m_cookie_mutated.append(i_c->m_key, i_c->m_key_len);
                                m_cookie_mutated += "=";
                                m_cookie_mutated.append(i_c->m_val, i_c->m_val_len);
                                if (i_c_idx < (l_c_len - 1))
                                {
                                        m_cookie_mutated += ";";
                                }
                                // -------------------------
                                // add to map
                                // -------------------------
                                data_t l_key;
                                l_key.m_data = i_c->m_key;
                                l_key.m_len = i_c->m_key_len;
                                data_t l_val;
                                l_val.m_data = i_c->m_val;
                                l_val.m_len = i_c->m_val_len;
                                m_cookie_map[l_key] = l_val;

                        }
                        const_arg_t l_arg;
                        l_arg.m_key = "Cookie";
                        l_arg.m_key_len = sizeof("Cookie") - 1;
                        l_arg.m_val = m_cookie_mutated.c_str();
                        l_arg.m_val_len = m_cookie_mutated.length();
                        m_header_list.push_back(l_arg);
                        // ---------------------------------
                        // map
                        // ---------------------------------
                        data_t l_key;
                        l_key.m_data = l_arg.m_key;
                        l_key.m_len = l_arg.m_key_len;
                        data_t l_val;
                        l_val.m_data = l_arg.m_val;
                        l_val.m_len = l_arg.m_val_len;
                        m_header_map[l_key] = l_val;
                }
                // -----------------------------------------
                // else just add header...
                // -----------------------------------------
                else
                {
                        m_header_list.push_back(l_hdr);
                        // ---------------------------------
                        // map
                        // ---------------------------------
                        data_t l_key;
                        l_key.m_data = l_hdr.m_key;
                        l_key.m_len = l_hdr.m_key_len;
                        data_t l_val;
                        l_val.m_data = l_hdr.m_val;
                        l_val.m_len = l_hdr.m_val_len;
                        m_header_map[l_key] = l_val;
                }
                // -----------------------------------------
                // parse content-type header...
                // e.g: Content-type:multipart/form-data; 
                // application/xml(asdhbc)  ;   
                // aasdhhhasd;asdajj-asdad    ;; ;;"
                // -----------------------------------------
                if (strncasecmp(l_hdr.m_key, "Content-Type", sizeof("Content-Type") - 1) == 0)
                {
                        parse_content_type(m_content_type_list, &l_hdr);
                }
                // -----------------------------------------
                // Get content-length, to be verified 
                // in phase 2
                // -----------------------------------------
                if (strncasecmp(l_hdr.m_key, "Content-Length", sizeof("Content-Length") - 1) == 0)
                {
                        m_content_length = strntoul(l_hdr.m_val , l_hdr.m_val_len, NULL, 10);
                }
                // -----------------------------------------
                // For RL, get hot server count to adjust the
                // threshold if needed
                // -----------------------------------------
                if (strncasecmp(l_hdr.m_key, "X-EC-Hot-Servers", sizeof("X-EC-Hot-Servers") -1) == 0)
                {
                        m_hot_servers = strntoull(l_hdr.m_val , l_hdr.m_val_len, NULL, 10);
                        l_is_internal_header = true;
                }
                // -----------------------------------------
                // For RL, get actual hot server count to adjust the
                // threshold if needed
                // -----------------------------------------
                if (strncasecmp(l_hdr.m_key, "X-EC-Actual-Hot-Servers", sizeof("X-EC-Actual-Hot-Servers") -1) == 0)
                {
                        m_actual_hot_servers = strntoull(l_hdr.m_val , l_hdr.m_val_len, NULL, 10);
                        l_is_internal_header = true;
                }
                // -------------------------------------------------
                // Exclude internal headers for ja4h calculation
                // (ja4h_b)
                // -------------------------------------------------
                std::string l_internal_header_check;
                l_internal_header_check.append(l_hdr.m_key, l_hdr.m_key_len);
                to_lower_case(l_internal_header_check);
                if (l_internal_header_check.find("x-ec") != std::string::npos  || l_internal_header_check.find("via") != std::string::npos
                || l_internal_header_check.find("x-") != std::string::npos || l_internal_header_check.find("forwarded") != std::string::npos)
                {
                        l_is_internal_header = true;
                        m_header_count = m_header_count - 1;
                }
                if (!l_is_cookie_hdr && !l_is_referer_hdr && !l_is_internal_header)
                {
                        l_header_fields_str.append(l_hdr.m_key, l_hdr.m_key_len);
                        l_header_fields_str.append(",");
                }
        }
        if (l_header_fields_str.back() == ',') l_header_fields_str.pop_back();
        // -------------------------------------------------
        // Set Cookie fields to 0's if Cookie header is 
        // missing
        // -------------------------------------------------
        if (!m_has_cookie)
        {
                strcat(l_ja4h_c, "000000000000");
                strcat(l_ja4h_d, "000000000000");
        }
        // -------------------------------------------------
        // compute JA4H_A and JA4H_B
        // NOTE: JA4H_B is a hash of header fields(not values) 
        // excluding Referer and Cookie
        // -------------------------------------------------
        std::string l_ja4h_a;
        set_ja4h_a(l_ja4h_a);
        char l_ja4h_b[_JA4H_IND_SIZE] = {0};
        set_ja4h_b(l_header_fields_str, l_ja4h_b);
        // -------------------------------------------------
        // create the overall JA4H string
        // -------------------------------------------------
        std::string l_ja4h;
        l_ja4h.reserve(_JA4H_SIZE);
        snprintf(l_ja4h.data(), _JA4H_SIZE, "%.12s_%.12s_%.12s_%.12s",
                l_ja4h_a.c_str(),
                l_ja4h_b,
                l_ja4h_c,
                l_ja4h_d);
        m_virt_ssl_client_ja4h.append(l_ja4h.c_str());
        // -------------------------------------------------
        // remove ignored
        // -------------------------------------------------
        if (a_il_header)
        {
                int32_t l_s;
                l_s = remove_ignored_const(m_header_list, *a_il_header);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // APPARENT_CACHE_STATUS
        // TODO: check again
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_rqst_apparent_cache_status_cb)
        {
                int32_t l_s;
                uint32_t l_v;
                l_s = m_callbacks->m_get_rqst_apparent_cache_status_cb(&l_v,
                                                                       m_ctx);
                if (l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
                m_apparent_cache_status = l_v;
        }
        // -------------------------------------------------
        // ja3 fingerprint
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_virt_ssl_client_ja3_md5)
        {
                int32_t l_s;
                l_s = m_callbacks->m_get_virt_ssl_client_ja3_md5(&m_virt_ssl_client_ja3_md5.m_data,
                                                      &m_virt_ssl_client_ja3_md5.m_len,
                                                      m_ctx);
                if (l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing m_get_virt_ssl_client_ja3_md5");
                }
                if ( m_virt_ssl_client_ja3_md5.m_len == 0 )
                {
                        m_virt_ssl_client_ja3_md5.m_data = "__na__";
                        m_virt_ssl_client_ja3_md5.m_len = strlen(m_virt_ssl_client_ja3_md5.m_data);
                }
        }
        // -------------------------------------------------
        // ja4 fingerprint
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_virt_ssl_client_ja4)
        {
                int32_t l_s;
                l_s = m_callbacks->m_get_virt_ssl_client_ja4(&m_virt_ssl_client_ja4.m_data,
                                                      &m_virt_ssl_client_ja4.m_len,
                                                      m_ctx);
                if (l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing m_get_virt_ssl_client_ja4");
                }
                if ( m_virt_ssl_client_ja4.m_len == 0 )
                {
                        m_virt_ssl_client_ja4.m_data = "__na__";
                        m_virt_ssl_client_ja4.m_len = strlen(m_virt_ssl_client_ja4.m_data);
                }
        }
        // -------------------------------------------------
        // ja4_a fingerprint
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_virt_ssl_client_ja4_a)
        {
                int32_t l_s;
                l_s = m_callbacks->m_get_virt_ssl_client_ja4_a(&m_virt_ssl_client_ja4_a.m_data,
                                                      &m_virt_ssl_client_ja4_a.m_len,
                                                      m_ctx);
                if (l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing m_get_virt_ssl_client_ja4_a");
                }
                if ( m_virt_ssl_client_ja4_a.m_len == 0 )
                {
                        m_virt_ssl_client_ja4_a.m_data = "__na__";
                        m_virt_ssl_client_ja4_a.m_len = strlen(m_virt_ssl_client_ja4_a.m_data);
                }
        }
        // -------------------------------------------------
        // ja4_b fingerprint
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_virt_ssl_client_ja4_b)
        {
                int32_t l_s;
                l_s = m_callbacks->m_get_virt_ssl_client_ja4_b(&m_virt_ssl_client_ja4_b.m_data,
                                                      &m_virt_ssl_client_ja4_b.m_len,
                                                      m_ctx);
                if (l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing m_get_virt_ssl_client_ja4_b");
                }
                if ( m_virt_ssl_client_ja4_b.m_len == 0 )
                {
                        m_virt_ssl_client_ja4_b.m_data = "__na__";
                        m_virt_ssl_client_ja4_b.m_len = strlen(m_virt_ssl_client_ja4_b.m_data);
                }
        }
        // -------------------------------------------------
        // ja4_c fingerprint
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_virt_ssl_client_ja4_c)
        {
                int32_t l_s;
                l_s = m_callbacks->m_get_virt_ssl_client_ja4_c(&m_virt_ssl_client_ja4_c.m_data,
                                                      &m_virt_ssl_client_ja4_c.m_len,
                                                      m_ctx);
                if (l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing m_get_virt_ssl_client_ja4_c");
                }
                if ( m_virt_ssl_client_ja4_c.m_len == 0 )
                {
                        m_virt_ssl_client_ja4_c.m_data = "__na__";
                        m_virt_ssl_client_ja4_c.m_len = strlen(m_virt_ssl_client_ja4_c.m_data);
                }
        }
        // -------------------------------------------------
        // sf backend port
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_backend_port_cb)
        {
                int32_t l_s;
                l_s = m_callbacks->m_get_backend_port_cb(&m_backend_port, m_srv);
                if (l_s != 0)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // get bot score
        // -------------------------------------------------
        if (a_engine.get_use_bot_lmdb() && this->m_gather_bot_score)
        {
                if ( this->get_bot_score(a_engine.get_bot_lmdb()) != WAFLZ_STATUS_OK )
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        else if (a_engine.get_use_bot_lmdb_new())
        {
                if ( this->get_bot_score(a_engine.get_bot_lmdb(), true) != WAFLZ_STATUS_OK )
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        m_init_phase_1 = true;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
std::string rqst_ctx::get_substr(const std::string &input, char delimiter)
{
        size_t pos = input.find(delimiter);
        if (pos == std::string::npos)
        {
                return ""; // Return an empty string if the delimiter is not found
        }
        return input.substr(pos + 1);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void rqst_ctx::remove_char(std::string &str, char ch)
{
        size_t pos = str.find(ch);
        if (pos != std::string::npos)
        {
                str.erase(pos, 1);
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void rqst_ctx::to_lower_case(std::string &str) 
{
        std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c) 
        {
                return std::tolower(c);
        });
}
//! ----------------------------------------------------------------------------
//! \details: set ja4h_a for ja4h calculation
//! \return:  none
//! \param:   ja4h_a string
//! ----------------------------------------------------------------------------
void rqst_ctx::set_ja4h_a(std::string &a_ja4h_a)
{
        // -------------------------------------------------
        // HTTP method bytes - GET = 'ge', PUT = 'pu' etc
        // -------------------------------------------------
        if(m_method.m_len > 0)
        {
                std::string l_method;
                l_method.append(m_method.m_data, m_method.m_len);
                to_lower_case(l_method);
                a_ja4h_a.append(l_method.substr(0,2));
        }
        // -------------------------------------------------
        // get client protocol via callback
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_rqst_protocol_cb)
        {
                int32_t l_s;
                l_s = m_callbacks->m_get_rqst_protocol_cb(&m_client_protocol.m_data,
                                                      &m_client_protocol.m_len,
                                                      m_ctx);
                if (l_s != 0)
                {
                        WAFLZ_PERROR(m_err_msg, "error in m_get_rqst_protocol_cb, default to 1.1");
                }
        }
        std::string l_version;
        l_version.append(m_client_protocol.m_data, m_client_protocol.m_len);
        uint8_t l_version_length = l_version.length();
        // -------------------------------------------------
        // HTTP protocol bytes, HTTP/1.1 = 11, HTTP/2.0 = 20
        // HTTP/2 = 20, HTTP/3.0 = 30, default to 1.1
        // -------------------------------------------------
        if (l_version_length  < 1)
        {
                l_version = "11";
        }
        else if (l_version_length  == 1)
        {
                l_version += "0";
        }
        else
        {
                remove_char(l_version, '.');
                if (l_version_length > 2)
                {
                        l_version = l_version.substr(0,2);
                }
        }
        a_ja4h_a.append(l_version);
        // -------------------------------------------------
        // HTTP Cookie header present, if Cookie present - 
        // 'c' else 'n'
        // -------------------------------------------------
        if (m_has_cookie)
        {
                a_ja4h_a += "c";
        }
        else
        {
                a_ja4h_a += "n";
        }
        // -------------------------------------------------
        // HTTP referer, if referer present - 'r' else 'n'
        // -------------------------------------------------
        if (m_has_referer)
        {
                a_ja4h_a += "r";
        }
        else
        {
                a_ja4h_a += "n";
        }
        // -------------------------------------------------
        // HTTP header count - minus Cookie and Referer 
        // headers if present
        // -------------------------------------------------
        std::string l_header_count;
        if(m_header_count < 10)
        {
                l_header_count += "0";
        }
        l_header_count += std::to_string(m_header_count);
        a_ja4h_a.append(l_header_count);
        // -------------------------------------------------
        // HTTP check for Accept-Language - append first 4 
        // chars or 0000 if not present, remove '-' if present
        // -------------------------------------------------
        if (m_has_accept_lang)
        {
                std::string l_accept_lang(m_accept_lang);
                // -------------------------------------------------
                // separate by comma, get the first language
                // if contains * we include it
                // -------------------------------------------------
                size_t pos = l_accept_lang.find(',');
                std::string l_first_lang = (pos == std::string::npos) ? l_accept_lang : l_accept_lang.substr(0, pos);
                to_lower_case(l_first_lang);
                // -------------------------------------------------
                // trim leading and trailing whitespaces
                // -------------------------------------------------
                size_t l_lang_start = l_first_lang.find_first_not_of(' ');
                size_t l_lang_end = l_first_lang.find_last_not_of(' ');
                if (l_lang_start != std::string::npos && l_lang_end != std::string::npos)
                {
                        l_first_lang = l_first_lang.substr(l_lang_start, l_lang_end - l_lang_start + 1);
                }
                remove_char(l_first_lang, '-');
                l_first_lang = l_first_lang.substr(0,4);
                while (l_first_lang.length() < 4) 
                {
                        l_first_lang += '0';
                }
                a_ja4h_a.append(l_first_lang);
        }
        else
        {
                a_ja4h_a.append("0000");
        }
}
//! ----------------------------------------------------------------------------
//! \details: sets ja4h_b
//! \return:  none
//! \param:   header string, result string 
//! ----------------------------------------------------------------------------
void rqst_ctx::set_ja4h_b(const std::string &a_header_str, char* a_ja4h_b)
{
        unsigned char l_ja4h_b[_JA4H_SHA256_HASH_LEN] = {0};
	if (a_header_str.length() > 0)
        {
                SHA256(reinterpret_cast <const unsigned char*>(a_header_str.c_str()), a_header_str.length(), l_ja4h_b);
        }
        for(auto i = 0; i < 6; ++i)
	{
		snprintf(&(a_ja4h_b[(i*2)]), 3, "%02x", l_ja4h_b[i]); // appends a null terminating char at the end
	}
}
//! ----------------------------------------------------------------------------
//! \details: sets ja4h_c and ja4h_d for ja4h calculation
//! \return:  none
//! \param:   result strings
//! ----------------------------------------------------------------------------
void rqst_ctx::set_ja4h_c_d(char* a_ja4h_c, char* a_ja4h_d)
{
        // -------------------------------------------------
        // if cookie fields are empty set to 0's and return
        // -------------------------------------------------
        uint32_t l_c_len = m_cookie_list.size();
        if (l_c_len == 0)
        {
                return;
        }
        std::vector<std::string> l_cookie_fields_sorted;
        std::vector<std::string> l_cookie_fields_values_sorted;
        // -------------------------------------------------
        // sort the cookie fields and values
        // -------------------------------------------------
        for (const auto& l_cookie : m_cookie_list)
        {
                // -------------------------------------------------
                // Create the cookie field string for ja4h_c
                // -------------------------------------------------
                std::string l_cookie_fields;
                l_cookie_fields.append(l_cookie.m_key, l_cookie.m_key_len);
                l_cookie_fields_sorted.push_back(std::move(l_cookie_fields));
                std::sort(l_cookie_fields_sorted.begin(), l_cookie_fields_sorted.end());
                // -----------------------------------------------------
                // Create the cookie field and values string for ja4h_d
                // ------------------------------------------------------
                std::string l_cookie_fields_values;
                l_cookie_fields_values.append(l_cookie.m_key, l_cookie.m_key_len);
                l_cookie_fields_values += "=";
                l_cookie_fields_values.append(l_cookie.m_val, l_cookie.m_val_len);
                l_cookie_fields_values_sorted.push_back(std::move(l_cookie_fields_values));
                std::sort(l_cookie_fields_values_sorted.begin(), l_cookie_fields_values_sorted.end());
        }
        std::string l_cookie_fields_conc;
        std::string l_cookie_values_conc;
        for (const auto& str : l_cookie_fields_sorted) 
        {
                l_cookie_fields_conc += str;
                l_cookie_fields_conc += ",";
        }
        if (l_cookie_fields_conc.back() == ',') l_cookie_fields_conc.pop_back();
        for (const auto& str : l_cookie_fields_values_sorted)
        {
                l_cookie_values_conc += str;
                l_cookie_values_conc += ",";
        }
        if (l_cookie_values_conc.back() == ',') l_cookie_values_conc.pop_back();
        unsigned char l_ja4h_c[_JA4H_SHA256_HASH_LEN] = {0};
        unsigned char l_ja4h_d[_JA4H_SHA256_HASH_LEN] = {0};
        if (l_cookie_fields_conc.length() > 0)
        {
                SHA256(reinterpret_cast <const unsigned char*>(l_cookie_fields_conc.c_str()), l_cookie_fields_conc.length(), l_ja4h_c);
        }
        if (l_cookie_values_conc.length() > 0)
        {
                SHA256(reinterpret_cast <const unsigned char*>(l_cookie_values_conc.c_str()), l_cookie_values_conc.length(), l_ja4h_d);
        }
        for(auto i = 0; i < 6; ++i)
	{
                snprintf(&(a_ja4h_c[(i*2)]), 3, "%02x", l_ja4h_c[i]); // appends a null terminating char at the end
                snprintf(&(a_ja4h_d[(i*2)]), 3, "%02x", l_ja4h_d[i]); // appends a null terminating char at the end
	}
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t rqst_ctx::init_phase_2(const ctype_parser_map_t &a_ctype_parser_map)
{
        if (m_init_phase_2)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // request body data
        // -------------------------------------------------
        int32_t l_s;
        // -------------------------------------------------
        // get content length
        // -------------------------------------------------
        if (m_content_length == ULONG_MAX)
        {
                // TODO -return reason...
                m_init_phase_2 = true;
                return WAFLZ_STATUS_OK;
        }
        if (m_content_length <= 0)
        {
                m_init_phase_2 = true;
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // calculate body size
        // -------------------------------------------------
        uint32_t l_body_len;
        l_body_len = m_content_length > m_body_len_max ? m_body_len_max : m_content_length;
        // NDBG_PRINT("body len %d\n", l_body_len);
        // -------------------------------------------------
        // TODO -413 on > max???
        // -------------------------------------------------
        // TODO -should respond here and 413 the request???
        // -------------------------------------------------
        // get content type
        // -------------------------------------------------
        if (!m_content_type_list.size())
        {
                m_init_phase_2 = true;
                return WAFLZ_STATUS_OK;
        }
        if (!m_content_type_list.size())
        {
                m_init_phase_2 = true;
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // check for callback. Exit early
        // -------------------------------------------------
        if (!m_callbacks->m_get_rqst_body_str_cb)
        {
                m_init_phase_2 = true;
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // Get the first one from list
        // TODO: may be check through the list?
        // -------------------------------------------------
        data_t l_type = m_content_type_list.front();
        std::string l_ct;
        l_ct.assign(l_type.m_data, l_type.m_len);
        ctype_parser_map_t::const_iterator i_p = a_ctype_parser_map.find(l_ct);
        if (i_p == a_ctype_parser_map.end())
        {
                m_init_phase_2 = true;
                return WAFLZ_STATUS_OK;
        }
        if (m_body_parser)
        {
                delete m_body_parser;
                m_body_parser = NULL;
        }
        bool l_is_url_encoded = false;
        bool l_is_multipart = false;
        // -------------------------------------------------
        // init parser...
        // -------------------------------------------------
        switch (i_p->second)
        {
        // -------------------------------------------------
        // PARSER_NONE
        // -------------------------------------------------
        case PARSER_NONE:
        {
                // -----------------------------------------
                // do nothing...
                // -----------------------------------------
                m_init_phase_2 = true;
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // PARSER_URL_ENCODED
        // -------------------------------------------------
        case PARSER_URL_ENCODED:
        {
                m_body_parser = new parser_url_encoded(this);
                l_is_url_encoded = true;
                m_url_enc_body = true;
                break;
        }
        // -------------------------------------------------
        // PARSER_XML
        // -------------------------------------------------
        case PARSER_XML:
        {
                parser_xml* l_parser_xml = new parser_xml(this);
                // -----------------------------------------
                // optional set capture xxe
                // -----------------------------------------
                l_parser_xml->set_capture_xxe(m_xml_capture_xxe);
                m_body_parser = l_parser_xml;
                m_xml_body = true;
                break;
        }
        // -------------------------------------------------
        // PARSER_JSON
        // -------------------------------------------------
        case PARSER_JSON:
        {
                m_body_parser = new parser_json(this);
                m_json_body = true;
                break;
        }
        // -------------------------------------------------
        // PARSER_MULTIPART
        // -------------------------------------------------
        case PARSER_MULTIPART:
        {
                // -----------------------------------------
                // We buffer raw body without any parsing
                // -----------------------------------------
                l_is_multipart = true;
                break;
        }
        // -------------------------------------------------
        // default
        // -------------------------------------------------
        default:
        {
                // -----------------------------------------
                // do nothing...
                // -----------------------------------------
                m_init_phase_2 = true;
                return WAFLZ_STATUS_OK;
        }
        }
        if (!m_body_parser &&
            !l_is_multipart)
        {
                // -----------------------------------------
                // do nothing...
                // -----------------------------------------
                m_init_phase_2 = true;
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // If json, pull up to m_body_api_sec_len_max worth
        // of data since schema processes more
        // Do not pull truncated body, since validation 
        // fails for truncated json anyways
        // -------------------------------------------------
        if(m_json_body && m_content_length <= m_body_api_sec_len_max) 
        {
                l_body_len = m_content_length;
        }
        // -------------------------------------------------
        // init parser if not multipart
        // -------------------------------------------------
        if (!l_is_multipart)
        {
                l_s = m_body_parser->init();
                if (l_s != WAFLZ_STATUS_OK)
                {
                        // -----------------------------------------
                        // do nothing...
                        // -----------------------------------------
                        //NDBG_PRINT("error m_body_parser->init()\n");
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // allocate max body size
        // -------------------------------------------------
        if (m_body_data)
        {
                free(m_body_data);
                m_body_data = NULL;
                m_body_len = 0;
        }
        m_body_data = (char *)malloc(sizeof(char)*l_body_len);
        bool l_is_eos = false;
        uint32_t l_rd_count = 0;
        uint32_t l_rd_count_total = 0;
        // -------------------------------------------------
        // while body data...
        // -------------------------------------------------
        while (!l_is_eos &&
              (l_rd_count_total < l_body_len))
        {
                l_rd_count = 0;
                char *l_buf = m_body_data+l_rd_count_total;
                uint32_t l_to_read = l_body_len-l_rd_count_total;
                l_s = m_callbacks->m_get_rqst_body_str_cb(l_buf,
                                             &l_rd_count,
                                             &l_is_eos,
                                             m_ctx,
                                             l_to_read);
                if (l_s != 0)
                {
                        m_init_phase_2 = true;
                        return WAFLZ_STATUS_OK;
                }
                if (!l_rd_count)
                {
                        continue;
                }
                // -------------------------------------------------
                // check for mismatch between content-type and actual
                // content. We only check for json structure. Can
                // extend it to xml if this fixes some false positives
                // -------------------------------------------------
                if (l_is_url_encoded &&
                    !l_is_multipart)
                {
                        if (infer_is_json(l_buf, l_rd_count))
                        {
                                delete m_body_parser;
                                m_body_parser = NULL;
                                // -------------------------
                                // Change parser to json
                                // -------------------------
                                m_body_parser = new parser_json(this);
                                l_s = m_body_parser->init();
                                if (l_s != WAFLZ_STATUS_OK)
                                {
                                        // -----------------
                                        // do nothing...
                                        // -----------------
                                        return WAFLZ_STATUS_ERROR;
                                }
                        }
                        // ---------------------------------
                        // check only once in while loop
                        // ---------------------------------
                        l_is_url_encoded = false;
                }
                // -----------------------------------------
                // If processing is not done...
                // Note: If body len < body len max, 
                // outer for-loop exits before this
                // -----------------------------------------
                if( l_rd_count_total < m_body_len_max &&
                    !l_is_multipart)
                {
                        // ---------------------------------
                        // If adding next chunk puts you out
                        // of body len max, process diff
                        // ---------------------------------
                        if(l_rd_count_total + l_rd_count > m_body_len_max) 
                        {
                                l_s = m_body_parser->process_chunk(l_buf, m_body_len_max - l_rd_count_total);
                        }
                        // ---------------------------------
                        // otherwise, process next chunk
                        // as usual
                        // ---------------------------------
                        else
                        {
                                l_s = m_body_parser->process_chunk(l_buf,l_rd_count);
                        }
                        if (l_s != WAFLZ_STATUS_OK)
                        {
                                // ---------------------------------
                                // Set request body error var in
                                // tx map and return
                                // ---------------------------------
                                //NDBG_PRINT("error m_body_parser->process_chunk()\n");
                                m_cx_tx_map["REQBODY_ERROR"] = "1";
                                m_init_phase_2 = true;
                                return WAFLZ_STATUS_OK;
                        }
                }
                l_rd_count_total += l_rd_count;
                // NDBG_PRINT("read: %6d / %6d\n", (int)l_rd_count, l_rd_count_total);
        }
        m_body_len = l_rd_count_total;
        // -------------------------------------------------
        // finish if parser was invoked
        // -------------------------------------------------
        if (!l_is_multipart)
        {
                l_s = m_body_parser->finish();
                if (l_s != WAFLZ_STATUS_OK)
                {
                        // -----------------------------------------
                        // Set request body error var in
                        // tx map and return
                        // -----------------------------------------
                        m_cx_tx_map["REQBODY_ERROR"] = "1";
                        m_init_phase_2 = true;
                        return WAFLZ_STATUS_OK;
                }
        }
        // -------------------------------------------------
        // cap the arg list size
        // -------------------------------------------------
        for (arg_list_t::iterator i_k = m_body_arg_list.begin();
            i_k != m_body_arg_list.end();
            ++i_k)
        {
                if (i_k->m_key_len > s_body_arg_len_cap)
                {
                        i_k->m_key_len = s_body_arg_len_cap;
                }
                if (i_k->m_val_len > s_body_arg_len_cap)
                {
                        i_k->m_val_len = s_body_arg_len_cap;
                }
        }
        m_init_phase_2 = true;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details gets geo data from mmdb, updates m_geo_data
//! \return  waflz status
//! \param   a_geoip2_mmdb: mmdb database
//! ----------------------------------------------------------------------------
int32_t rqst_ctx::get_geo_data_from_mmdb(geoip2_mmdb &a_geoip2_mmdb)
{
        // -------------------------------------------------
        // if no ip - no data to get
        // -------------------------------------------------
        if (!DATA_T_EXIST(m_src_addr))
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // get geo data
        // -------------------------------------------------
        int32_t l_s;
        l_s = a_geoip2_mmdb.get_geo_data(&m_geo_data,
                                         &m_src_addr);
        if ( l_s != WAFLZ_STATUS_OK )
        {
                // debug here?
        }
        // -------------------------------------------------
        // setting up full m_geo_cc_sd string
        // -------------------------------------------------
        if (DATA_T_EXIST(m_geo_data.m_geo_cn2) &&
                DATA_T_EXIST(m_geo_data.m_src_sd1_iso))
        {
                m_geo_cc_sd = std::string(
                        m_geo_data.m_geo_cn2.m_data,
                        m_geo_data.m_geo_cn2.m_len);
                m_geo_cc_sd += "-" + std::string(
                        m_geo_data.m_src_sd1_iso.m_data,
                        m_geo_data.m_src_sd1_iso.m_len);
        }
        else if (DATA_T_EXIST(m_geo_data.m_geo_cn2) 
                && DATA_T_EXIST(m_geo_data.m_src_sd2_iso))
        {
                m_geo_cc_sd = std::string(
                        m_geo_data.m_geo_cn2.m_data,
                        m_geo_data.m_geo_cn2.m_len);
                m_geo_cc_sd += "-" + std::string(
                        m_geo_data.m_src_sd2_iso.m_data,
                        m_geo_data.m_src_sd2_iso.m_len);
        }
        // -------------------------------------------------
        // converting to str temporarily for str
        // comparisons...
        // -------------------------------------------------
        if (m_geo_data.m_src_asn)
        {
                m_src_asn_str.m_len = asprintf(
                                &(m_src_asn_str.m_data),
                                "%d",
                                m_geo_data.m_src_asn);
        }
        // -------------------------------------------------
        // return ok
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details gets the bot score from the bot db
//! \return  waflz status
//! \param
//! -----------------------------------------------------------------------------
int32_t rqst_ctx::get_score_from_key(kv_db& a_bot_db, const std::string_view& a_db_key, bool a_new_db)
{
        // -------------------------------------------------
        // hash string 
        // -------------------------------------------------
        uint64_t l_db_hash = CityHash64(a_db_key.data(), a_db_key.length());
        // -------------------------------------------------
        // DEBUG: used to see key being sent
        // -------------------------------------------------
        // NDBG_PRINT("looking for '%s' -> '%lu'\n", a_db_key.data(),
        //            l_db_hash);
        // -------------------------------------------------
        // get result from db
        // -------------------------------------------------
        int32_t l_s;
        if (a_new_db)
        {
                this->m_bot_tags.clear();
                lm_bot_val_t l_bot_val = {0,0,nullptr};
                uint32_t l_dummy_val = 0;
                l_s = a_bot_db.get_key(&l_db_hash, sizeof(l_db_hash),
                                       l_dummy_val, &l_bot_val, true);
                if (l_s == WAFLZ_STATUS_ERROR)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", a_bot_db.get_err_msg());
                }
                else
                {
                        this->m_bot_score = l_bot_val.m_score;
                        this->m_cust_id = l_bot_val.m_cust_id;
                        if (l_bot_val.m_tags && l_bot_val.m_tags[0] !='\0')
                        {
                                // -------------------------------------------------
                                // NOTE: assign deletes the underlying memory
                                // -------------------------------------------------
                                this->m_bot_tags.assign(l_bot_val.m_tags);
                                if (l_bot_val.m_tags)
                                {
                                        delete []l_bot_val.m_tags;
                                        l_bot_val.m_tags = nullptr;
                                }
                        }
                        // -----------------------------------------
                        // DEBUG: used to see key that matched
                        // -----------------------------------------
                        // NDBG_PRINT("found entry {%u,%u,%s} with key %s\n",
                        //         this->m_bot_score,
                        //         this->m_cust_id,
                        //         this->m_bot_tags.c_str(),
                        //         this->m_bot_score_key.c_str());

                }
        }
        else
        {
                l_s = a_bot_db.get_key(&l_db_hash, sizeof(l_db_hash),
                                       this->m_bot_score);
        }
        // -------------------------------------------------
        // if we get a match in the database
        // -------------------------------------------------
        if (this->m_bot_score > 0)
        {
                // -----------------------------------------
                // set bot_score_key to the key found
                // -----------------------------------------
                this->m_bot_score_key = a_db_key;
                // -----------------------------------------
                // DEBUG: used to see key that matched
                // -----------------------------------------
                // NDBG_PRINT("found score %u with key %s\n",
                //            this->m_bot_score,
                //            this->m_bot_score_key.c_str());
        }
        // -------------------------------------------------
        // set error if found
        // -------------------------------------------------
        if (l_s == WAFLZ_STATUS_ERROR)
        {
                WAFLZ_PERROR(m_err_msg, "%s", a_bot_db.get_err_msg());
        }
        // -------------------------------------------------
        // return status from get_key
        // -------------------------------------------------
        return l_s;
}
//! ----------------------------------------------------------------------------
//! \details gets the bot score for a level (ie: Ja4/Asn/ip) from the bot db
//! \return  waflz status
//! \param
//! -----------------------------------------------------------------------------
int32_t rqst_ctx::get_score_for_level(kv_db& a_bot_db,
                                      const std::string& a_level_string,
                                      const std::string& a_user_agent,
                                      bool a_new_db)
{
        // -------------------------------------------------
        // quick return if no level string
        // -------------------------------------------------
        if (a_level_string.length() == 0)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // status variable
        // -------------------------------------------------
        int32_t l_s;
        // -------------------------------------------------
        // try level + user agent for most specific key
        // -------------------------------------------------
        if (!a_user_agent.empty())
        {
                // -----------------------------------------
                // construct db key + get value
                // -----------------------------------------
                l_s = this->get_score_from_key(a_bot_db, a_level_string + ":" + a_user_agent, a_new_db);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        // NDBG_PRINT("error performing get_key: Reason: %s\n", a_bot_db.get_err_msg());
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // return value in db if found
        // -------------------------------------------------
        if (this->m_bot_score > 0)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // try just getting the level
        // -------------------------------------------------
        l_s = this->get_score_from_key(a_bot_db, a_level_string, a_new_db);
        if (l_s != WAFLZ_STATUS_OK)
        {
                // NDBG_PRINT("error performing get_key: Reason: %s\n", a_bot_db.get_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // return status ok regardless of score found
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details set bot score
//! \return  waflz status
//! \param
//! -----------------------------------------------------------------------------
int32_t rqst_ctx::get_bot_score(kv_db& a_bot_db, bool a_new_db)
{
        // -------------------------------------------------
        // clear out any existing bot score
        // -------------------------------------------------
        this->m_bot_score = 0;
        // -------------------------------------------------
        // result vars
        // -------------------------------------------------
        int32_t l_s;
        // -------------------------------------------------
        // get user-agent from request
        // -------------------------------------------------
        const data_t* l_user_agent_data = this->get_header(std::string_view("User-Agent"));
        std::string l_user_agent = (l_user_agent_data != nullptr) ?
                std::string(l_user_agent_data->m_data, l_user_agent_data->m_len)
                : std::string();
        // -------------------------------------------------
        // check for IP level in bot db
        // -------------------------------------------------
        std::string l_ip(this->m_src_addr.m_data, this->m_src_addr.m_len);
        l_s = this->get_score_for_level(a_bot_db, l_ip, l_user_agent, a_new_db);
        if (l_s != WAFLZ_STATUS_OK)
        {
                // NDBG_PRINT("error performing get_key: Reason: %s\n", a_bot_db.get_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // return value in db if found
        // -------------------------------------------------
        if (this->m_bot_score > 0)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // check for Ja4 in bot db
        // -------------------------------------------------
        std::string l_ja4(this->m_virt_ssl_client_ja4.m_data,
                          this->m_virt_ssl_client_ja4.m_len);
        l_s = this->get_score_for_level(a_bot_db, l_ja4, l_user_agent, a_new_db);
        if (l_s != WAFLZ_STATUS_OK)
        {
                // NDBG_PRINT("error performing get_key: Reason: %s\n", a_bot_db.get_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // return regardless if a score was found
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
const data_t* rqst_ctx::get_header(const std::string_view& header_name)
{
        // -------------------------------------------------
        // construct search data_t
        // -------------------------------------------------
        data_t l_search_data;
        l_search_data.m_data = header_name.data();
        l_search_data.m_len = header_name.length();
        // -------------------------------------------------
        // search for header
        // -------------------------------------------------
        data_unordered_map_t::const_iterator i_search_results = m_header_map.find(l_search_data);
        // -------------------------------------------------
        // return results or NULL
        // -------------------------------------------------
        if (i_search_results == m_header_map.end())
        {
                return NULL;
        }
        return &(i_search_results->second);
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
const data_t* rqst_ctx::get_header(const std::string& header_name)
{
        // -------------------------------------------------
        // construct search data_t
        // -------------------------------------------------
        data_t l_search_data;
        l_search_data.m_data = header_name.c_str();
        l_search_data.m_len = header_name.length();
        // -------------------------------------------------
        // search for header
        // -------------------------------------------------
        data_unordered_map_t::const_iterator i_search_results = m_header_map.find(l_search_data);
        // -------------------------------------------------
        // return results or NULL
        // -------------------------------------------------
        if (i_search_results == m_header_map.end())
        {
                return NULL;
        }
        return &(i_search_results->second);
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t rqst_ctx::append_rqst_info(waflz_pb::event &ao_event, geoip2_mmdb &a_geoip2_mmdb)
{
        const char *l_buf = NULL;
        uint32_t l_buf_len = 0;
        int32_t l_s;
        waflz_pb::request_info *l_request_info = ao_event.mutable_req_info();
        // -------------------------------------------------
        // Epoch time
        // -------------------------------------------------
        uint32_t l_now_s = get_time_s();
        uint32_t l_now_us = get_time_us();
        waflz_pb::request_info_timespec_t *l_epoch = l_request_info->mutable_epoch_time();
        l_epoch->set_sec(l_now_s);
        l_epoch->set_nsec(l_now_us * 1000);
        // -------------------------------------------------
        // set headers...
        // -------------------------------------------------
#define _SET_HEADER(_header, _val) do { \
        l_d.m_data = _header; \
        l_d.m_len = sizeof(_header) - 1; \
        data_unordered_map_t::const_iterator i_h = l_hm.find(l_d); \
        if (i_h != l_hm.end()) \
        { \
                l_headers->set_##_val(i_h->second.m_data, i_h->second.m_len); \
        } \
} while (0)
#define _SET_IF_EXIST_STR(_field, _proto) do { \
        if (_field.m_data && \
           _field.m_len) { \
                l_request_info->set_##_proto(_field.m_data, _field.m_len); \
        } } while (0)
#define _SET_IF_EXIST_INT(_field, _proto) do { \
                l_request_info->set_##_proto(_field); \
        } while (0)
#define _SET_IF_EXIST_STD_STR(_field, _proto) do { \
        if (!_field.empty()) { \
                l_request_info->set_##_proto(_field.c_str(), _field.length()); \
        } } while (0)
        // -------------------------------------------------
        // headers...
        // -------------------------------------------------
        waflz_pb::request_info::common_header_t* l_headers = l_request_info->mutable_common_header();
        const data_unordered_map_t &l_hm = m_header_map;
        data_t l_d;
        _SET_HEADER("Referer", referer);
        _SET_HEADER("User-Agent", user_agent);
        _SET_HEADER("Host", host);
        _SET_HEADER("X-Forwarded-For", x_forwarded_for);
        _SET_HEADER("Content-Type", content_type);
        // -------------------------------------------------
        // others...
        // -------------------------------------------------
        _SET_IF_EXIST_STR(m_src_addr, virt_remote_host);
        _SET_IF_EXIST_INT(m_port, server_canonical_port);
        _SET_IF_EXIST_INT(m_backend_port, backend_server_port);
        _SET_IF_EXIST_STR(m_uri, orig_url);
        _SET_IF_EXIST_STR(m_url, url);
        _SET_IF_EXIST_STR(m_query_str, query_string);
        _SET_IF_EXIST_STR(m_method, request_method);
        _SET_IF_EXIST_STR(m_virt_ssl_client_ja3_md5, virt_ssl_client_ja3_md5);
        _SET_IF_EXIST_STR(m_virt_ssl_client_ja4, virt_ssl_client_ja4);
        _SET_IF_EXIST_STR(m_virt_ssl_client_ja4_a, virt_ssl_client_ja4_a);
        _SET_IF_EXIST_STR(m_virt_ssl_client_ja4_b, virt_ssl_client_ja4_b);
        _SET_IF_EXIST_STR(m_virt_ssl_client_ja4_c, virt_ssl_client_ja4_c);
	_SET_IF_EXIST_STD_STR(m_virt_ssl_client_ja4h, virt_ssl_client_ja4h);
        // -------------------------------------------------
        // Local address
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_rqst_local_addr_cb)
        {
                GET_RQST_DATA(m_callbacks->m_get_rqst_local_addr_cb);
                if (l_buf_len > 0)
                {
                        l_request_info->set_local_addr(l_buf, l_buf_len);
                }
        }
        // -------------------------------------------------
        // apparent cache status
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_rqst_apparent_cache_status_cb)
        {
                uint32_t l_log_status = 0;
                l_s = m_callbacks->m_get_rqst_apparent_cache_status_cb(&l_log_status, m_ctx);
                if (l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_rqst_apparent_cache_status_cb");
                }
                l_request_info->set_apparent_cache_log_status(static_cast <waflz_pb::request_info::log_status_t>(l_log_status));
        }
        // -------------------------------------------------
        // Bytes out
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_rqst_bytes_out_cb)
        {
                uint32_t l_bytes_out;
                l_s =  m_callbacks->m_get_rqst_bytes_out_cb(&l_bytes_out, m_ctx);
                if (l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_rqst_bytes_out_cb");
                }
                l_request_info->set_bytes_out(l_bytes_out);
        }
        // -------------------------------------------------
        // Bytes in
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_rqst_bytes_in_cb)
        {
                uint32_t l_bytes_in;
                l_s =  m_callbacks->m_get_rqst_bytes_in_cb(&l_bytes_in, m_ctx);
                if (l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_rqst_bytes_in_cb");
                }
                l_request_info->set_bytes_in(l_bytes_in);
        }
        // -------------------------------------------------
        // REQ_UUID
        // -------------------------------------------------
        if (m_req_uuid.m_len > 0)
        {
                l_request_info->set_req_uuid(m_req_uuid.m_data, m_req_uuid.m_len);
        }
        // -------------------------------------------------
        // Customer ID
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_cust_id_cb &&
            !m_falafel && !m_felafel)
        {
                uint32_t l_cust_id;
                l_s =  m_callbacks->m_get_cust_id_cb(&l_cust_id, m_ctx);
                if (l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_cust_id_cb");
                }
                l_request_info->set_customer_id(l_cust_id);
        }
        // -------------------------------------------------
        // team ID
        // -------------------------------------------------
        if (!m_team_id.empty() && !m_falafel & !m_felafel)
        {
                l_request_info->set_team_id(m_team_id);
                // -----------------------------------------
                // if we are dealing with team id, throw in
                // env id as well
                // -----------------------------------------
                if (m_callbacks && m_callbacks->m_get_env_id_cb)
                {
                        std::string l_env_id;
                        l_s =  m_callbacks->m_get_env_id_cb(l_env_id, m_ctx);
                        if (l_s != 0)
                        {
                                //WAFLZ_PERROR(m_err_msg, "performing get_env_id_cb");
                        }
                        l_request_info->set_env_id(l_env_id);
                }
        }
        // -------------------------------------------------
        // if falafel set custom id for logging
        // -------------------------------------------------
        if(m_falafel)
        {
                l_request_info->set_customer_id(4196072978);
        }
        // -------------------------------------------------
        // if falafel set custom id for logging
        // -------------------------------------------------
        if(m_felafel)
        {
                l_request_info->set_customer_id(4263181842);
        }
        // -------------------------------------------------
        // GEOIP info
        // -------------------------------------------------
        if DATA_T_EXIST(m_geo_data.m_cn_name)
        {
                ao_event.set_geoip_country_name(
                                m_geo_data.m_cn_name.m_data,
                                m_geo_data.m_cn_name.m_len);
        }
        if DATA_T_EXIST(m_geo_data.m_city_name) 
        {
                ao_event.set_geoip_city_name(
                              m_geo_data.m_city_name.m_data,
                              m_geo_data.m_city_name.m_len);
        }
        ao_event.set_is_anonymous_proxy(
                           m_geo_data.m_is_anonymous_proxy);
        if DATA_T_EXIST(m_geo_data.m_geo_cn2)
        {
                ao_event.set_geoip_country_code2(
                                m_geo_data.m_geo_cn2.m_data,
                                m_geo_data.m_geo_cn2.m_len);
        }
        if DATA_T_EXIST(m_geo_data.m_geo_rcc)
        {
                ao_event.set_geoip_registered_country_code(
                                m_geo_data.m_geo_rcc.m_data,
                                m_geo_data.m_geo_rcc.m_len);
        }
        ao_event.set_geoip_latitude(m_geo_data.m_lat);
        ao_event.set_geoip_longitude(m_geo_data.m_long);
        if DATA_T_EXIST(m_geo_data.m_src_sd1_iso)
        {
                ao_event.set_geoip_sd1_iso(
                            m_geo_data.m_src_sd1_iso.m_data,
                            m_geo_data.m_src_sd1_iso.m_len);
        }
        if DATA_T_EXIST(m_geo_data.m_src_sd2_iso)
        {
                ao_event.set_geoip_sd2_iso(
                            m_geo_data.m_src_sd2_iso.m_data,
                            m_geo_data.m_src_sd2_iso.m_len);
        }
         if (!m_geo_cc_sd.empty())
        {
                ao_event.set_geoip_cc_sd(
                                      m_geo_cc_sd.c_str(),
                                      m_geo_cc_sd.length());
        }
        ao_event.set_geoip_asn(m_geo_data.m_src_asn);
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details sets the m_scr_addr to spoof header if found
//! \return  waflz_status 
//! \param   a_header: the request header to get the ip from
//! ----------------------------------------------------------------------------
int32_t rqst_ctx::set_src_ip_from_spoof_header(const std::string& a_header)
{
        // -------------------------------------------------
        // create search data_t
        // -------------------------------------------------
        data_t l_search_header;
        l_search_header.m_data = a_header.c_str();
        l_search_header.m_len = a_header.length();
        // -------------------------------------------------
        // search map for spoof header
        // -------------------------------------------------
        auto i_header = m_header_map.find(l_search_header);
        // -------------------------------------------------
        // if found, set ip to spoof
        // -------------------------------------------------
        if (i_header != m_header_map.end())
        {
            nms l_checker;
            if (strncasecmp(i_header->first.m_data, "X-Forwarded-For", i_header->first.m_len) == 0)
            {
                // ---------------------------------
                // store the header in string, nms
                // add_ipv4 doesnt check for len of buffer
                // as a result string_view always fails
                // ---------------------------------
                std::string l_xff_ip = i_header->second.m_data;
                data_t l_header_val = i_header->second;
                // ---------------------------------
                // parse the X-Forwarded-For header
                // if it has multiple ips, use the leftmost
                // ---------------------------------
                std::string_view l_xff_header(i_header->second.m_data, i_header->second.m_len);
                size_t l_end = l_xff_header.find(',');
                if (l_end != std::string::npos)
                {
                    std::string_view l_ip = l_xff_header.substr(0, l_end);
                    // -------------------------
                    // trim leading and trailing
                    // whitespaces
                    // -------------------------
                    size_t l_ip_start = l_ip.find_first_not_of(' ');
                    size_t l_ip_end = l_ip.find_last_not_of(' ');
                    if (l_ip_start != std::string::npos && l_ip_end != std::string::npos)
                    {
                        l_ip = l_ip.substr(l_ip_start, l_ip_end - l_ip_start + 1);
                    }
                    // ---------------------------------
                    // set src addr for the leftmost IP address
                    // ---------------------------------
                    l_header_val.m_data = l_ip.data();
                    l_header_val.m_len = l_ip.length();
                    // -----------------------------------------
                    // store the leftmost ip address for validation
                    // -----------------------------------------
                    l_xff_ip = l_ip;
                }
                // -----------------------------------------
                // validate ip
                // -----------------------------------------
                int32_t l_s = l_checker.add(l_xff_ip.c_str(), l_xff_ip.length());
                // -----------------------------------------
                // if not valid, using true src ip
                // -----------------------------------------
                if (l_s == WAFLZ_STATUS_ERROR)
                {
                    return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // we reached here so we have a valid ip
                // -----------------------------------------
                set_src_addr(l_header_val);
                m_use_spoof_ip = true;
                return WAFLZ_STATUS_OK;
            }
            else
            {
                // -----------------------------------------
                // validate ip
                // -----------------------------------------
                int32_t l_s = l_checker.add(i_header->second.m_data, i_header->second.m_len);
                // -----------------------------------------
                // if not valid, using true src ip
                // -----------------------------------------
                if (l_s == WAFLZ_STATUS_ERROR)
                {
                    return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // we reached here so we have a valid ip
                // -----------------------------------------
                set_src_addr(i_header->second);
                m_use_spoof_ip = true;
                return WAFLZ_STATUS_OK;
            }
        }
        // -------------------------------------------------
        // if not found, return error
        // -------------------------------------------------
        return WAFLZ_STATUS_ERROR;
}

//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void rqst_ctx::show(void)
{
        NDBG_OUTPUT("+------------------------------------------------+\n");
        NDBG_OUTPUT("|            %sR E Q U E S T   C T X%s               |\n", ANSI_COLOR_FG_WHITE, ANSI_COLOR_OFF);
        NDBG_OUTPUT("+------------------------------------------------+-----------------------------+\n");
        NDBG_OUTPUT(": %sAN%s:           %d\n",   ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF, (int)m_an);
        NDBG_OUTPUT(": %sSRC_ADDR%s:     %.*s\n", ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF, m_src_addr.m_len, m_src_addr.m_data);
        NDBG_OUTPUT(": %sPORT%s:         %d\n", ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF, (int)m_port);
        NDBG_OUTPUT(": %sSCHEME%s:       %.*s\n", ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF, m_scheme.m_len, m_scheme.m_data);
        NDBG_OUTPUT(": %sPROTOCOL%s:     %.*s\n", ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF, m_protocol.m_len, m_protocol.m_data);
        NDBG_OUTPUT(": %sLINE%s:         %.*s\n", ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF, m_line.m_len, m_line.m_data);
        NDBG_OUTPUT(": %sURI%s:          %.*s\n", ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF, m_uri.m_len, m_uri.m_data);
        NDBG_OUTPUT(": %sMETHOD%s:       %.*s\n", ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF, m_method.m_len, m_method.m_data);
        NDBG_OUTPUT(": %sQUERY_STR%s:    %.*s\n", ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF, m_query_str.m_len, m_query_str.m_data);
        NDBG_OUTPUT(": ------------+ \n");
        NDBG_OUTPUT(": %sQUERY_ARGS%s  :  \n", ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF);
        NDBG_OUTPUT(": ------------+--------------------------------------------+ \n");
        for (arg_list_t::const_iterator i_q = m_query_arg_list.begin();
            i_q != m_query_arg_list.end();
            ++i_q)
        {
                NDBG_OUTPUT(": %s%.*s%s: %.*s\n",
                            ANSI_COLOR_FG_YELLOW, i_q->m_key_len, i_q->m_key, ANSI_COLOR_OFF,
                            i_q->m_val_len, i_q->m_val);
        }
        NDBG_OUTPUT(": ------------+ \n");
        NDBG_OUTPUT(": %sHEADER_LIST%s : \n", ANSI_COLOR_FG_CYAN, ANSI_COLOR_OFF);
        NDBG_OUTPUT(": ------------+--------------------------------------------+ \n");
        for (const_arg_list_t::const_iterator i_q = m_header_list.begin();
            i_q != m_header_list.end();
            ++i_q)
        {
                NDBG_OUTPUT(": %s%.*s%s: %.*s\n",
                            ANSI_COLOR_FG_YELLOW, i_q->m_key_len, i_q->m_key, ANSI_COLOR_OFF,
                            i_q->m_val_len, i_q->m_val);
        }
        NDBG_OUTPUT(": ------------+ \n");
        NDBG_OUTPUT(": %sCOOKIE_LIST%s : \n", ANSI_COLOR_FG_MAGENTA, ANSI_COLOR_OFF);
        NDBG_OUTPUT(": ------------+--------------------------------------------+ \n");
        for (const_arg_list_t::const_iterator i_q = m_cookie_list.begin();
            i_q != m_cookie_list.end();
            ++i_q)
        {
                NDBG_OUTPUT(": %s%.*s%s: %.*s\n",
                            ANSI_COLOR_FG_YELLOW, i_q->m_key_len, i_q->m_key, ANSI_COLOR_OFF,
                            i_q->m_val_len, i_q->m_val);
        }
        NDBG_OUTPUT("+------------------------------------------------------------------------------+\n");
}
//! ----------------------------------------------------------------------------
//! \details C binding for third party lib to cleanup rqst_ctx object after 
//!          every request is processed
//! \return  0: success
//! \param   a_rqst_ctx: rqst_ctx object
//! ----------------------------------------------------------------------------
extern "C" int32_t rqst_ctx_cleanup(rqst_ctx *a_rqst_ctx)
{
        if (a_rqst_ctx)
        {
                delete a_rqst_ctx;
                a_rqst_ctx = NULL;
        }
        return WAFLZ_STATUS_OK;
}
}
