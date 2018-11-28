//! ----------------------------------------------------------------------------
//! Copyright (C) 2018 Verizon.  All Rights Reserved.
//! All Rights Reserved
///
//! @file:    render.cc
//! @details: TODO
//! @author:  Revathi Sabanayagam
//! @date:    01/06/2018
///
//!   Licensed under the Apache License, Version 2.0 (the "License");
//!   you may not use this file except in compliance with the License.
//!   You may obtain a copy of the License at
///
//!       http://www.apache.org/licenses/LICENSE-2.0
///
//!   Unless required by applicable law or agreed to in writing, software
//!   distributed under the License is distributed on an "AS IS" BASIS,
//!   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//!   See the License for the specific language governing permissions and
//!   limitations under the License.
///
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "waflz/def.h"
#include "waflz/rqst_ctx.h"
#include "waflz/render.h"
#include "support/ndebug.h"
#include "support/string_util.h"
#include "support/time_util.h"
#include <string.h>
#include <time.h>
#include <string>
#include <map>
#include <list>
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! field types
//! ----------------------------------------------------------------------------
typedef enum {
        FIELD_NULL = 0,
        FIELD_CLIENT_IP,
        FIELD_REQUEST_URL,
        FIELD_TIMESTAMP
} field_t;
//! ----------------------------------------------------------------------------
//! Types
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! support for skipping Content Types with idempotent methods
//! ----------------------------------------------------------------------------
struct case_i_comp
{
        bool operator() (const std::string& lhs, const std::string& rhs) const
        {
                return strcasecmp(lhs.c_str(), rhs.c_str()) < 0;
        }
};
typedef std::map <std::string, field_t, case_i_comp> str_field_map_t;
//! ----------------------------------------------------------------------------
//! Group function mapping
//! Initialize the map statically
//! ----------------------------------------------------------------------------
const str_field_map_t::value_type g_str_field_map_pairs[]= {
        str_field_map_t::value_type("CLIENT_IP", FIELD_CLIENT_IP),
        str_field_map_t::value_type("CLIENT-IP", FIELD_CLIENT_IP),
        str_field_map_t::value_type("REQUEST_URL", FIELD_REQUEST_URL),
        str_field_map_t::value_type("REQUEST-URL", FIELD_REQUEST_URL),
        str_field_map_t::value_type("TIMESTAMP", FIELD_TIMESTAMP)
};
const str_field_map_t g_str_field_map(g_str_field_map_pairs,
                                      g_str_field_map_pairs + (sizeof(g_str_field_map_pairs)/sizeof(g_str_field_map_pairs[0])));
//! ----------------------------------------------------------------------------
//! @details: TODO
//! @return:  TODO
//! @param:   TODO
//! ----------------------------------------------------------------------------
static field_t get_field(const std::string &a_str)
{
        field_t l_f = FIELD_NULL;
        str_field_map_t::const_iterator i_g = g_str_field_map.find(a_str);
        if(i_g != g_str_field_map.end())
        {
                l_f = i_g->second;
        }
        return l_f;
}
//! ----------------------------------------------------------------------------
//! tp_field_t
//! ----------------------------------------------------------------------------
typedef struct _tp_field {
        field_t m_field;
        const char *m_data;
        uint32_t m_len;
        _tp_field():
                m_field(FIELD_NULL),
                m_data(0),
                m_len(0)
        {}
} tp_field_t;
typedef std::list <tp_field_t> tp_fields_list_t;
//! ----------------------------------------------------------------------------
//! @brief   parse a string with {{XXX}} templates
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
static int32_t rr_parse(tp_fields_list_t &ao_fields_list, const char *a_buf, size_t a_len)
{
        const char *l_cur = a_buf;
        size_t l_left = a_len;
        char *l_start = NULL;
        tp_field_t l_tp;
        // -------------------------------------------------
        // search for templated fields
        // -------------------------------------------------
        while((l_start = strnstr(l_cur, "{{", l_left)) != NULL)
        {
                // -----------------------------------------
                // if start > cur
                // -----------------------------------------
                if(l_start > l_cur)
                {
                        l_tp.m_data = l_cur;
                        l_tp.m_len = l_start - l_cur;
                        l_tp.m_field = FIELD_NULL;
                        ao_fields_list.push_back(l_tp);
                }
                // -----------------------------------------
                // find end of template
                // -----------------------------------------
                char *l_end = NULL;
                l_end = strnstr(l_start, "}}", (int)(l_left - (l_start - l_cur)));
                // -----------------------------------------
                // if no end treat as normal string
                // -----------------------------------------
                if(!l_end)
                {
                        break;
                }
                // -----------------------------------------
                // create field
                // -----------------------------------------
                std::string l_t_str;
                l_t_str.assign(l_start+2, (int)(l_end - l_start - 2));
                l_tp.m_data = NULL;
                l_tp.m_len = 0;
                l_tp.m_field = get_field(l_t_str);
                ao_fields_list.push_back(l_tp);
                // -----------------------------------------
                // increment
                // -----------------------------------------
                l_left -= (l_end + 2) - l_cur;
                l_cur = l_end + 2;
        }
        // -------------------------------------------------
        // add trailing
        // -------------------------------------------------
        if(l_left)
        {
                l_tp.m_data = l_cur;
                l_tp.m_len = l_left;
                l_tp.m_field = FIELD_NULL;
                ao_fields_list.push_back(l_tp);
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @brief   parse a string with {{XXX}} templates
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
static int32_t rr_render(char* ao_buf,
                         size_t& ao_len,
                         const tp_fields_list_t& a_tpf_list,
                         rqst_ctx* a_ctx)
{
        ao_len = 0;
        char *l_buf = ao_buf;
        for(tp_fields_list_t::const_iterator i_tp = a_tpf_list.begin();
            i_tp != a_tpf_list.end();
            ++i_tp)
        {
                const tp_field_t &l_tp = *i_tp;
                switch(l_tp.m_field)
                {
                // -----------------------------------------
                // FIELD_CLIENT_IP
                // -----------------------------------------
                case FIELD_CLIENT_IP:
                {
                        if(!a_ctx ||
                          !a_ctx->m_src_addr.m_data ||
                          !a_ctx->m_src_addr.m_len)
                        {
                                break;
                        }
                        ao_len += a_ctx->m_src_addr.m_len;
                        if(ao_buf)
                        {
                                memcpy(l_buf, a_ctx->m_src_addr.m_data, a_ctx->m_src_addr.m_len);
                                l_buf += a_ctx->m_src_addr.m_len;
                        }
                        break;
                }
                // -----------------------------------------
                // FIELD_REQUEST_URL
                // -----------------------------------------
                case FIELD_REQUEST_URL:
                {
                        // ---------------------------------
                        // scheme...
                        // ---------------------------------
                        const char *l_sc = "http://";
                        if(a_ctx->m_port == 443)
                        {
                                l_sc = "https://";
                        }
                        size_t l_sc_len = strlen(l_sc);
                        ao_len += l_sc_len;
                        if(ao_buf)
                        {
                                memcpy(l_buf, l_sc, l_sc_len);
                                l_buf += l_sc_len;
                        }
                        // ---------------------------------
                        // host...
                        // ---------------------------------
                        if(!a_ctx ||
                          !a_ctx->m_host.m_data ||
                          !a_ctx->m_host.m_len)
                        {
                                break;
                        }
                        ao_len += a_ctx->m_host.m_len;
                        if(ao_buf)
                        {
                                memcpy(l_buf, a_ctx->m_host.m_data, a_ctx->m_host.m_len);
                                l_buf += a_ctx->m_host.m_len;
                        }
                        // ---------------------------------
                        // path...
                        // ---------------------------------
                        if(!a_ctx ||
                          !a_ctx->m_uri.m_data ||
                          !a_ctx->m_uri.m_len)
                        {
                                break;
                        }
                        ao_len += a_ctx->m_uri.m_len;
                        if(ao_buf)
                        {
                                memcpy(l_buf, a_ctx->m_uri.m_data, a_ctx->m_uri.m_len);
                                l_buf += a_ctx->m_uri.m_len;
                        }
                        break;
                }
                // -----------------------------------------
                // FIELD_TIMESTAMP
                // -----------------------------------------
                case FIELD_TIMESTAMP:
                {
                        // TODO FIX!!!
                        uint64_t l_t_s = 0;
                        l_t_s = get_time_s();
                        tm l_tm;
                        gmtime_r((const time_t *)&l_t_s, &l_tm);
                        char l_tmp[64];
                        size_t l_tmp_len;
                        l_tmp_len = strftime(l_tmp, sizeof(l_tmp), "%Y-%m-%d %H:%M:%S", &l_tm);
#define _DEFAULT_TIMESTAMP "1970-1-1 00:00:00"
                        if(l_tmp_len == 0)
                        {
                                l_tmp_len = sizeof(_DEFAULT_TIMESTAMP) - 1;
                                ao_len += l_tmp_len;
                                if(ao_buf)
                                {
                                        memcpy(l_buf, _DEFAULT_TIMESTAMP, l_tmp_len);
                                        l_buf += l_tmp_len;
                                }
                        }
                        else
                        {
                                ao_len += l_tmp_len;
                                if(ao_buf)
                                {
                                        memcpy(l_buf, l_tmp, l_tmp_len);
                                        l_buf += l_tmp_len;
                                }
                        }
                        break;
                }
                // -----------------------------------------
                // default
                // -----------------------------------------
                default:
                {
                        ao_len += l_tp.m_len;
                        if(ao_buf)
                        {
                                memcpy(l_buf, l_tp.m_data, l_tp.m_len);
                                l_buf += l_tp.m_len;
                        }
                        break;
                }
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! @details TODO
//! @return  TODO
//! @param   TODO
//! ----------------------------------------------------------------------------
int32_t render(char** ao_buf,
               size_t& ao_len,
               const char *a_buf,
               size_t a_len,
               rqst_ctx *a_ctx)
{
        if(!a_buf ||
           !a_len ||
           !ao_buf)
        {
                return WAFLZ_STATUS_ERROR;
        }
        *ao_buf = NULL;
        ao_len = 0;
        // -------------------------------------------------
        // parse
        // -------------------------------------------------
        int32_t l_s;
        tp_fields_list_t l_tp_fl;
        l_s = rr_parse(l_tp_fl, a_buf, a_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get size
        // -------------------------------------------------
        size_t l_len = 0;
        l_s = rr_render(NULL, l_len, l_tp_fl, a_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // alloc
        // -------------------------------------------------
        char *l_buf = NULL;
        l_buf = (char *)malloc(l_len);
        // TODO check for alloc fail...
        // -------------------------------------------------
        // render
        // -------------------------------------------------
        l_s = rr_render(l_buf, l_len, l_tp_fl, a_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(l_buf) { free(l_buf); l_buf = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        // done...
        *ao_buf = l_buf;
        ao_len = l_len;
        return WAFLZ_STATUS_OK;
}
}
