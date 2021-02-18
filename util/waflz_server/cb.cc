//! ----------------------------------------------------------------------------
//! Copyright Verizon.
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
#include "cb.h"
#include "is2/srvr/rqst.h"
#include "is2/srvr/session.h"
#include "is2/srvr/lsnr.h"
#include "is2/support/nbq.h"
#include "is2/support/data.h"
#include "support/ndebug.h"
#include "waflz/string_util.h"
#include "support/time_util.h"
#include <errno.h>
#include <string.h>
#include<map>
#include <stdlib.h>
#include <arpa/inet.h>
namespace ns_waflz_server {
//! ----------------------------------------------------------------------------
//! extern...
//! ----------------------------------------------------------------------------
bool g_random_ips = false;
__thread char g_clnt_addr_str[INET6_ADDRSTRLEN];
__thread char g_rqst_line[4096];
//! ----------------------------------------------------------------------------
//! get ip callback
//! ----------------------------------------------------------------------------
int32_t get_rqst_ip_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        // -------------------------------------------------
        // random ips
        // -------------------------------------------------
        if(g_random_ips)
        {
                // -----------------------------------------
                // skip 0.0.0.0/8;
                // ip ranges from 1.0.0.0 to 255.255.255.255
                // -----------------------------------------
#ifdef CPP17
                static std::random_device s_rd;
                static std::uniform_int_distribution<> s_dist(0x01000000, 0xFFFFFFFF);
                uint32_t l_randaddr = htonl(s_dist(s_rd));
                std::string l_randip_str(INET_ADDRSTRLEN, '#');
                inet_ntop(AF_INET, &g_clnt_addr_str, l_randip_str.data(), INET_ADDRSTRLEN);
#else
                // -----------------------------------------
                // four random octets
                // -packed in network order
                // -----------------------------------------
                uint32_t l_randaddr = rand()%255 << 24
                                    | rand()%255 << 16
                                    | rand()%255 << 8
                                    | rand()/((RAND_MAX + 1u)/255);
                char l_randip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &g_clnt_addr_str, l_randip_str, INET_ADDRSTRLEN);
#endif
        }
        // -------------------------------------------------
        // request object
        // -------------------------------------------------
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        // -------------------------------------------------
        // check for header override
        // -------------------------------------------------
#define _HEADER_SRC_IP "x-waflz-ip"
        const ns_is2::mutable_data_map_list_t& l_headers(l_ctx->m_rqst->get_header_map());
        ns_is2::mutable_data_t i_hdr;
        if(ns_is2::find_first(i_hdr, l_headers, _HEADER_SRC_IP, sizeof(_HEADER_SRC_IP)))
        {
                *a_data = i_hdr.m_data;
                *a_len = i_hdr.m_len;
                return 0;
        }
        // -------------------------------------------------
        // get ip from request
        // -------------------------------------------------
        ns_is2::host_info l_host_info = l_ctx->get_host_info();
        g_clnt_addr_str[0] = '\0';
        if(l_host_info.m_sa_len == sizeof(sockaddr_in))
        {
                // a thousand apologies for this monstrosity :(
                errno = 0;
                const char *l_s;
                l_s = inet_ntop(AF_INET,
                                &(((sockaddr_in *)(&(l_host_info.m_sa)))->sin_addr),
                                g_clnt_addr_str,
                                INET_ADDRSTRLEN);
                if(!l_s)
                {
                        NDBG_PRINT("Error performing inet_ntop. Reason: %s\n", strerror(errno));
                        return -1;
                }
        }
        else if(l_host_info.m_sa_len == sizeof(sockaddr_in6))
        {
                // a thousand apologies for this monstrosity :(
                errno = 0;
                const char *l_s;
                l_s = inet_ntop(AF_INET6,
                                &(((sockaddr_in6 *)(&(l_host_info.m_sa)))->sin6_addr),
                                g_clnt_addr_str,
                                INET6_ADDRSTRLEN);
                if(!l_s)
                {
                        NDBG_PRINT("Error performing inet_ntop. Reason: %s\n", strerror(errno));
                        return -1;
                }
        }
        if(strnlen(g_clnt_addr_str, INET6_ADDRSTRLEN) <= 4)
        {
                snprintf(g_clnt_addr_str, INET6_ADDRSTRLEN, "127.0.0.1");
                return -1;
        }
        *a_data = g_clnt_addr_str;
        *a_len = strnlen(g_clnt_addr_str, INET6_ADDRSTRLEN);
        return 0;
}
//! ----------------------------------------------------------------------------
//! get rqst line callback
//! ----------------------------------------------------------------------------
int32_t get_rqst_line_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        snprintf(g_rqst_line, 4096, "%s %.*s HTTP/%d.%d",
                 l_rqst->get_method_str(),
                 l_rqst->get_url().m_len, l_rqst->get_url().m_data,
                 l_rqst->m_http_major,
                 l_rqst->m_http_minor);
        *a_data = g_rqst_line;
        *a_len = strnlen(g_rqst_line, 4096);
        return 0;
}
//! ----------------------------------------------------------------------------
//! get rqst method callback
//! ----------------------------------------------------------------------------
int32_t get_rqst_method_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        *a_data = l_rqst->get_method_str();
        *a_len = strlen(l_rqst->get_method_str());
        return 0;
}
//! ----------------------------------------------------------------------------
//! get_rqst_protocol_cb
//! ----------------------------------------------------------------------------
int32_t get_rqst_protocol_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        char s_protocol[32];
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        snprintf(s_protocol, 32, "HTTP/%d.%d",
                 l_rqst->m_http_major,
                 l_rqst->m_http_minor);
        *a_data = s_protocol;
        *a_len = strlen(s_protocol);
        return 0;
}
//! ----------------------------------------------------------------------------
//! get_rqst_scheme_cb
//! ----------------------------------------------------------------------------
int32_t get_rqst_scheme_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        char s_scheme[32];
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::scheme_t l_scheme = l_ctx->get_scheme();
        if(l_scheme == ns_is2::SCHEME_TCP)
        {
                snprintf(s_scheme,32,"http");
        }
        // -------------------------------------------------
        // disabling until build in support for is2+tls
        // -------------------------------------------------
#if 0
        else if(l_scheme == ns_is2::SCHEME_TLS)
        {
                snprintf(s_scheme,32,"https");
        }
#endif
        *a_data = s_scheme;
        *a_len = strlen(s_scheme);
        return 0;
}
//! ----------------------------------------------------------------------------
//! get_rqst_port_cb
//! ----------------------------------------------------------------------------
int32_t get_rqst_port_cb(uint32_t *a_val, void *a_ctx)
{
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        *a_val = l_ctx->m_lsnr->get_port();
        return 0;
}
//! ----------------------------------------------------------------------------
//! get_rqst_port_cb
//! ----------------------------------------------------------------------------
int32_t get_rqst_host_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        const ns_is2::mutable_data_map_list_t& l_hm = l_rqst->get_header_map();
        const ns_is2::mutable_data_map_list_t& l_headers(l_ctx->m_rqst->get_header_map());
        ns_is2::mutable_data_t i_hdr;
        if(ns_is2::find_first(i_hdr, l_headers, "Host", sizeof("Host")))
        {
                *a_data = i_hdr.m_data;
                *a_len = i_hdr.m_len;
                return 0;
        }
        *a_data = "localhost";
        *a_len = strlen("localhost");
        return 0;
}
//! ----------------------------------------------------------------------------
//! get_rqst_url_cb
//! ----------------------------------------------------------------------------
int32_t get_rqst_url_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        *a_data = l_rqst->get_url().m_data;
        *a_len = l_rqst->get_url().m_len;
        return 0;
}
//! ----------------------------------------------------------------------------
//! get_rqst_uri_cb
//! ----------------------------------------------------------------------------
int32_t get_rqst_uri_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        *a_data = l_rqst->get_url().m_data;
        *a_len = l_rqst->get_url().m_len;
        return 0;
}
//! ----------------------------------------------------------------------------
//! get_rqst_uri_cb
//! ----------------------------------------------------------------------------
int32_t get_rqst_path_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        *a_data = l_rqst->get_url_path().m_data;
        *a_len = l_rqst->get_url_path().m_len;
        return 0;
}
//! ----------------------------------------------------------------------------
//! get_rqst_query_str_cb
//! ----------------------------------------------------------------------------
int32_t get_rqst_query_str_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        *a_data = l_rqst->get_url_query().m_data;
        *a_len = l_rqst->get_url_query().m_len;
        return 0;
}
//! ----------------------------------------------------------------------------
//! get_rqst_id_cb
//! ----------------------------------------------------------------------------
#define _UUID_STR  "aabbccddeeff"
int32_t get_rqst_uuid_cb(const char **a_data, uint32_t *a_len, void *a_ctx)
{
        *a_data = _UUID_STR;
        *a_len = strlen(_UUID_STR);
        return 0;
}
//! ----------------------------------------------------------------------------
//! get_rqst_header_size_cb
//! ----------------------------------------------------------------------------
int32_t get_rqst_header_size_cb(uint32_t *a_val, void *a_ctx)
{
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        *a_val = l_rqst->get_header_list().size();
        return 0;
}
//! ----------------------------------------------------------------------------
//! get_rqst_header_w_idx_cb
//! ----------------------------------------------------------------------------
int32_t get_rqst_header_w_idx_cb(const char **ao_key,
                                        uint32_t *ao_key_len,
                                        const char **ao_val,
                                        uint32_t *ao_val_len,
                                        void *a_ctx,
                                        uint32_t a_idx)
{
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                return -1;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                return -1;
        }
        *ao_key = NULL;
        *ao_key_len = 0;
        *ao_val = NULL;
        *ao_val_len = 0;
        const ns_is2::mutable_arg_list_t &l_h_list = l_rqst->get_header_list();
        ns_is2::mutable_arg_list_t::const_iterator i_h = l_h_list.begin();
        std::advance(i_h, a_idx);
        if(i_h == l_h_list.end())
        {
                return -1;
        }
        *ao_key = i_h->m_key;
        *ao_key_len = i_h->m_key_len;
        *ao_val = i_h->m_val;
        *ao_val_len = i_h->m_val_len;
        return 0;
}
//! ----------------------------------------------------------------------------
//! get_rqst_body_str_cb
//! ----------------------------------------------------------------------------
int32_t get_rqst_body_str_cb(char *ao_data,
                             uint32_t *ao_data_len,
                             bool *ao_is_eos,
                             void *a_ctx,
                             uint32_t a_to_read)
{
        //NDBG_PRINT(": ======================== \n");
        //NDBG_PRINT(": ao_data:     %p\n", ao_data);
        //NDBG_PRINT(": ao_data_len: %u\n", ao_data_len);
        //NDBG_PRINT(": ao_is_eos:   %d\n", ao_is_eos);
        //NDBG_PRINT(": a_ctx:       %p\n", a_ctx);
        //NDBG_PRINT(": a_to_read:   %u\n", a_to_read);
        if (NULL == a_ctx)
        {
                *ao_is_eos = true;
                *ao_data_len = 0;
                return 0;
        }
        ns_is2::session *l_ctx = (ns_is2::session *)a_ctx;
        if(!l_ctx)
        {
                *ao_is_eos = true;
                *ao_data_len = 0;
                return 0;
        }
        ns_is2::rqst *l_rqst = l_ctx->m_rqst;
        if(!l_rqst)
        {
                *ao_is_eos = true;
                *ao_data_len = 0;
                return 0;
        }
        ns_is2::nbq *l_q = l_rqst->get_body_q();
        if(!l_q)
        {
                *ao_is_eos = true;
                *ao_data_len = 0;
                return 0;
        }
        // -------------------------------------------------
        // set not done
        // -------------------------------------------------
        *ao_is_eos = false;
        *ao_data_len = 0;
        // -------------------------------------------------
        // cal how much to read
        // -------------------------------------------------
        uint32_t l_left = a_to_read;
        if(a_to_read > l_q->read_avail())
        {
                l_left = l_q->read_avail();
        }
        // -------------------------------------------------
        // read until not avail or ao_data_len
        // -------------------------------------------------
        char *l_cur_ptr = ao_data;
        while(l_left)
        {
                int64_t l_read = 0;
                l_read = l_q->read(l_cur_ptr, l_left);
                if(l_read < 0)
                {
                        // TODO error
                        *ao_is_eos = true;
                        *ao_data_len = 0;
                        return 0;
                }
                l_cur_ptr += (uint32_t)l_read;
                *ao_data_len += (uint32_t)l_read;
                l_left -= (uint32_t)l_read;
        }
        if(!l_q->read_avail())
        {
                *ao_is_eos = true;
        }
        //ns_is2::mem_display((const uint8_t *)ao_data, ao_data_len);
        //NDBG_PRINT(": ************************ \n");
        //NDBG_PRINT(": ao_data:     %p\n", ao_data);
        //NDBG_PRINT(": ao_data_len: %u\n", ao_data_len);
        //NDBG_PRINT(": ao_is_eos:   %d\n", ao_is_eos);
        //NDBG_PRINT(": a_ctx:       %p\n", a_ctx);
        //NDBG_PRINT(": a_to_read:   %u\n", a_to_read);
        return 0;
}
//! ----------------------------------------------------------------------------
//! get_bot_ch_prob
//! ----------------------------------------------------------------------------
int32_t get_bot_ch_prob(std::string &ao_challenge, uint32_t *ao_ans)
{
        int l_num_one, l_num_two = 0;
        srand (ns_waflz::get_time_ms());
        l_num_one = rand() % 100 + 100;
        l_num_two = rand() % 100 + 100;
        ao_challenge += ns_waflz::to_string(l_num_one);
        ao_challenge += "+";
        ao_challenge += ns_waflz::to_string(l_num_two);
        *ao_ans = l_num_one + l_num_two;
        return 0;
}
}
