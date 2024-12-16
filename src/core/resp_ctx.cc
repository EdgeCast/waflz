//! ----------------------------------------------------------------------------
//! Copyright Edgecast Inc.
//!
//! \file:    resp_ctx.cc
//! \author:  Kanishk Modi
//! \details: source file for class responsible for processing response headers and body and evaluating them
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "event.pb.h"
#include "waflz/resp_ctx.h"
#include "waflz/geoip2_mmdb.h"
#include "waflz/string_util.h"
#include "waflz/trace.h"
#include "support/ndebug.h"
#include "support/file_util.h"
#include "support/time_util.h"
#include "core/decode.h"
#include <stdlib.h>
#include <string.h>
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------

namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
resp_ctx::resp_ctx(void *a_ctx,
                   uint32_t a_body_len_max,
                   uint32_t a_body_api_sec_len_max,
                   const resp_ctx_callbacks *a_callbacks,
                   int32_t a_content_length,
                   void* a_srv):
        m_src_addr(),
        m_an(),
        m_team_id(),
        m_host(),
        m_port(0),
        m_backend_port(0),
        m_method(),
        m_url(),
        m_uri(),
        m_uri_path_len(0),
        m_content_length(a_content_length),
        m_content_type_list(),
        m_header_map(),
        m_header_list(),
        m_body_len_max(a_body_len_max),
        m_body_api_sec_len_max(a_body_api_sec_len_max),
        m_body_data(NULL),
        m_body_len(0),
        m_resp_status(0),
        m_resp_status_str(),
        m_intercepted(false),
        m_req_uuid(),
        m_src_asn_str(),
        m_geo_cc_sd(),
        m_geo_data(),
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
        m_init_phase_3(false),
        m_init_phase_4(false),
        m_skip(0),
        m_skip_after(NULL),
        m_event(NULL),
        m_callbacks(a_callbacks),
        m_set_response_status(0),
        m_signal_enf(0),
        m_limit(NULL),
        m_audit_limit(NULL),
        m_ctx(a_ctx),
        m_srv(a_srv)
{
    
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
resp_ctx::~resp_ctx()
{
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
        // delete any extensions
        // -------------------------------------------------
        if (m_src_asn_str.m_data) { free(m_src_asn_str.m_data); m_src_asn_str.m_data = NULL; m_src_asn_str.m_len = 0; }
}

//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t resp_ctx::reset_phase_3()
{
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
        m_init_phase_3 = false;
        m_intercepted = false;
        return WAFLZ_STATUS_OK;
}

//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t resp_ctx::init_phase_3(geoip2_mmdb &a_geoip2_mmdb)
{
        if (m_init_phase_3)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // src addr
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_rqst_src_addr_cb)
        {
                int32_t l_s;
                // get src address
                l_s = m_callbacks->m_get_rqst_src_addr_cb(&m_src_addr.m_data,
                                             &m_src_addr.m_len,
                                             m_ctx);
                if (l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // Gather country code, sd1, sd2, is_anonymous_proxy
        // for mmdb
        //
        // NOTE: subdiv iso = m_geo_cn2 + "-" + get_sd_iso
        // -------------------------------------------------
        if ( (m_src_addr.m_len > 0) && m_src_addr.m_data )
        {
                int32_t l_s;
                l_s = get_geo_data_from_mmdb(a_geoip2_mmdb);
                if (l_s != WAFLZ_STATUS_OK)
                {

                }
        }
        // -------------------------------------------------
        // host
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_resp_host_cb)
        {
                int32_t l_s;
                // get src address
                l_s = m_callbacks->m_get_resp_host_cb(&m_host.m_data,
                                         &m_host.m_len,
                                         m_ctx);
                if (l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // port
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_rqst_port_cb)
        {
                int32_t l_s;
                // get request port
                l_s = m_callbacks->m_get_rqst_port_cb(&m_port,
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
                // get method
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
        // -------------------------------------------------
        // Url
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_rqst_url_cb)
        {
                int32_t l_s;
                // get uri
                l_s = m_callbacks->m_get_rqst_url_cb(&m_url.m_data,
                                        &m_url.m_len,
                                        m_ctx);
                if (l_s != 0)
                {
                        // TODO log reason???
                        return WAFLZ_STATUS_ERROR;
                }
        }
        if (m_callbacks && m_callbacks->m_get_resp_uri_cb)
        {
                int32_t l_s;
                // get uri
                l_s = m_callbacks->m_get_resp_uri_cb(&m_uri.m_data,
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
                }
        }
        // -------------------------------------------------
        // headers
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_resp_status_cb)
        {
                int32_t l_s;
                l_s = m_callbacks->m_get_resp_status_cb(&m_resp_status, m_ctx);
                if (l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_resp_header_size_cb");
                }
                m_resp_status_str = std::to_string(m_resp_status);
        }
        uint32_t l_hdr_size = 0;
        if (m_callbacks && m_callbacks->m_get_resp_header_size_cb)
        {
                int32_t l_s;
                l_s = m_callbacks->m_get_resp_header_size_cb(&l_hdr_size, m_ctx);
                if (l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_resp_header_size_cb");
                }
        }
        for(uint32_t i_h = 0; i_h < l_hdr_size; ++i_h)
        {
                const_arg_t l_hdr;
                if (!m_callbacks || !m_callbacks->m_get_resp_header_w_idx_cb)
                {
                        continue;
                }
                int32_t l_s;
                l_s = m_callbacks->m_get_resp_header_w_idx_cb(&l_hdr.m_key, &l_hdr.m_key_len,
                                                 &l_hdr.m_val, &l_hdr.m_val_len,
                                                 m_ctx,
                                                 i_h);
                if (l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_resp_header_w_idx_cb: idx: %u", i_h);
                        continue;
                }
                if (!l_hdr.m_key)
                {
                        continue;
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
                // e.g: Content-type:multipart/form-data; application/xml(asdhbc)  ;   aasdhhhasd;asdajj-asdad    ;; ;;"
                // -----------------------------------------
                if (strncasecmp(l_hdr.m_key, "Content-Type", sizeof("Content-Type") - 1) == 0)
                {
                        parse_content_type(m_content_type_list, &l_hdr);
                }
                if(m_content_length == -1)
                {
                        // Get content-length, to be verified in phase 2
                        if (strncasecmp(l_hdr.m_key, "Content-Length", sizeof("Content-Length") - 1) == 0)
                        {
                                m_content_length = strntoul(l_hdr.m_val , l_hdr.m_val_len, NULL, 10);
                        }
                }
        }
        // -------------------------------------------------
        // request headers - for event logging purposes only
        // -------------------------------------------------
        uint32_t l_rqst_hdr_size = 0;
        if (m_callbacks && m_callbacks->m_get_rqst_header_size_cb)
        {
                int32_t l_s;
                l_s = m_callbacks->m_get_rqst_header_size_cb(&l_rqst_hdr_size, m_ctx);
                if (l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_resp_header_size_cb");
                }
        }
        for(uint32_t i_h = 0; i_h < l_rqst_hdr_size; ++i_h)
        {
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
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_resp_header_w_idx_cb: idx: %u", i_h);
                        continue;
                }
                if (!l_hdr.m_key)
                {
                        continue;
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
                        // TODO log reason???
                        //return STATUS_ERROR;
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
        m_init_phase_3 = true;
        return WAFLZ_STATUS_OK;
}

int32_t resp_ctx::init_phase_4()
{
        if (m_init_phase_4)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // response body data
        // -------------------------------------------------
        int32_t l_s;
        // -------------------------------------------------
        // get content length
        // -------------------------------------------------
        if (m_content_length == LONG_MAX)
        {
                // TODO -return reason...
                m_init_phase_4 = true;
                return WAFLZ_STATUS_OK;
        }
        if (m_content_length <= 0)
        {
                m_init_phase_4 = true;
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // If content len is less than api sec max, pull 
        // full body. If not, don't pull truncated api sec
        // len max since it will fail validation anyways
        // -------------------------------------------------
        uint32_t l_body_len;
        l_body_len = m_content_length <= m_body_api_sec_len_max ? m_content_length : m_body_len_max;
        //NDBG_PRINT("body len %d\n", l_body_len);
        // -------------------------------------------------
        // get content type
        // -------------------------------------------------
        if (!m_content_type_list.size())
        {
                m_init_phase_4 = true;
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // get response body
        // -------------------------------------------------
        if (!m_callbacks->m_get_resp_body_str_cb)
        {
                m_init_phase_4 = true;
                return WAFLZ_STATUS_OK;
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
        while(!l_is_eos &&
              (l_rd_count_total < l_body_len))
        {
                l_rd_count = 0;
                char *l_buf = m_body_data+l_rd_count_total;
                uint32_t l_to_read = l_body_len-l_rd_count_total;
                l_s = m_callbacks->m_get_resp_body_str_cb(&l_buf,
                                             &l_rd_count,
                                             &l_is_eos,
                                             m_ctx,
                                             l_to_read);
                if (l_s != 0)
                {
                        m_init_phase_4 = true;
                        return WAFLZ_STATUS_OK;
                }
                if (!l_rd_count)
                {
                        continue;
                }
                l_rd_count_total += l_rd_count;
                //NDBG_PRINT("read: %6d / %6d\n", (int)l_rd_count, l_rd_count_total);
        }
        m_body_len = l_rd_count_total;
        m_init_phase_4 = true;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details gets geo data from mmdb, updates m_geo_data
//! \return  waflz status
//! \param   a_geoip2_mmdb: mmdb database
//! ----------------------------------------------------------------------------
int32_t resp_ctx::get_geo_data_from_mmdb(geoip2_mmdb &a_geoip2_mmdb)
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
        if ( DATA_T_EXIST(m_geo_data.m_geo_cn2) &&
             DATA_T_EXIST(m_geo_data.m_src_sd1_iso) )
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
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
const data_t* resp_ctx::get_header(const std::string_view& header_name)
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
int32_t resp_ctx::append_resp_info(waflz_pb::event &ao_event)
{
        const char *l_buf = NULL;
        uint32_t l_buf_len = 0;
        int32_t l_s;
        waflz_pb::request_info *l_request_info = ao_event.mutable_req_info();
        // -------------------------------------------------
        // Epoch time
        // -------------------------------------------------
        uint32_t l_now_s = get_time_s();
        uint32_t l_now_ms = get_time_ms();
        waflz_pb::request_info_timespec_t *l_epoch = l_request_info->mutable_epoch_time();
        l_epoch->set_sec(l_now_s);
        l_epoch->set_nsec(l_now_ms);
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
} while(0)
#define _SET_IF_EXIST_STR(_field, _proto) do { \
        if (_field.m_data && \
           _field.m_len) { \
                l_request_info->set_##_proto(_field.m_data, _field.m_len); \
        } } while(0)
#define _SET_IF_EXIST_INT(_field, _proto) do { \
                l_request_info->set_##_proto(_field); \
        } while(0)
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
        _SET_IF_EXIST_STR(m_uri, orig_url);
        // -------------------------------------------------
        // Append all response headers
        // -------------------------------------------------
        for (data_unordered_map_t::const_iterator i_h = m_header_map.begin();
            i_h != m_header_map.end();
            ++i_h)
        {
                waflz_pb::request_info::req_header_t *l_req_header = l_request_info->add_request_headers();
                l_req_header->set_key(i_h->first.m_data, i_h->first.m_len);
                l_req_header->set_value(i_h->second.m_data, i_h->second.m_len);
        }
        // -------------------------------------------------
        // others...
        // -------------------------------------------------
        _SET_IF_EXIST_STR(m_src_addr, virt_remote_host);
        _SET_IF_EXIST_INT(m_port, server_canonical_port);
        _SET_IF_EXIST_STR(m_uri, orig_url);
        _SET_IF_EXIST_STR(m_url, url);
        //_SET_IF_EXIST_STR(m_query_str, query_string);
        _SET_IF_EXIST_STR(m_method, request_method);
        // -------------------------------------------------
        // Local address
        // -------------------------------------------------
        if (m_callbacks && m_callbacks->m_get_resp_local_addr_cb)
        {
                //GET_RQST_DATA(m_callbacks->m_get_resp_local_addr_cb);
                if (l_buf_len > 0)
                {
                        l_request_info->set_local_addr(l_buf, l_buf_len);
                }
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
        if (m_callbacks && m_callbacks->m_get_resp_cust_id_cb)
        {
                uint32_t l_cust_id;
                l_s =  m_callbacks->m_get_resp_cust_id_cb(&l_cust_id, m_ctx);
                if (l_s != 0)
                {
                        //WAFLZ_PERROR(m_err_msg, "performing s_get_cust_id_cb");
                }
                l_request_info->set_customer_id(l_cust_id);
        }
        return WAFLZ_STATUS_OK;
}
}
