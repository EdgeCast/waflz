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
#include "event.pb.h"
#include "waflz/def.h"
#include "waflz/rqst_ctx.h"
#include "waflz/render.h"
#include "waflz/string_util.h"
#include "support/ndebug.h"
#include "support/time_util.h"
#include "waflz/trace.h"
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
        FIELD_EVENT_ID,
        FIELD_CLIENT_IP,
        FIELD_REQUEST_URL,
        FIELD_USER_AGENT,
        FIELD_RULE_MSG,
        FIELD_TIMESTAMP,
        FIELD_STATUS_CODE,
        FIELD_EC_TOKEN,
        FIELD_BOT_PROB,
        FIELD_BOT_JS,
        FIELD_AN,
        FIELD_RECAPTCHA_SITE_KEY,
        FIELD_RECAPTCHA_ACTION_NAME,
        FIELD_CHALLENGE_DIFFICULTY
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
        str_field_map_t::value_type("AN", FIELD_AN),
        str_field_map_t::value_type("EVENT_ID", FIELD_EVENT_ID),
        str_field_map_t::value_type("EVENT-ID", FIELD_EVENT_ID),
        str_field_map_t::value_type("CLIENT_IP", FIELD_CLIENT_IP),
        str_field_map_t::value_type("CLIENT-IP", FIELD_CLIENT_IP),
        str_field_map_t::value_type("REQUEST_URL", FIELD_REQUEST_URL),
        str_field_map_t::value_type("REQUEST-URL", FIELD_REQUEST_URL),
        str_field_map_t::value_type("USER_AGENT", FIELD_USER_AGENT),
        str_field_map_t::value_type("USER-AGENT", FIELD_USER_AGENT),
        str_field_map_t::value_type("RULE_MSG", FIELD_RULE_MSG),
        str_field_map_t::value_type("RULE-MSG", FIELD_RULE_MSG),
        str_field_map_t::value_type("TIMESTAMP", FIELD_TIMESTAMP),
        str_field_map_t::value_type("STATUS_CODE", FIELD_STATUS_CODE),
        str_field_map_t::value_type("STATUS-CODE", FIELD_STATUS_CODE),
        str_field_map_t::value_type("EC_TOKEN", FIELD_EC_TOKEN),
        str_field_map_t::value_type("EC-TOKEN", FIELD_EC_TOKEN),
        str_field_map_t::value_type("BOT-PROB", FIELD_BOT_PROB),
        str_field_map_t::value_type("BOT_PROB", FIELD_BOT_PROB),
        str_field_map_t::value_type("BOT-JS", FIELD_BOT_JS),
        str_field_map_t::value_type("BOT_JS", FIELD_BOT_JS),
        str_field_map_t::value_type("RECAPTCHA_SITE_KEY", FIELD_RECAPTCHA_SITE_KEY),
        str_field_map_t::value_type("RECAPTCHA_SITE_KEY", FIELD_RECAPTCHA_SITE_KEY),
        str_field_map_t::value_type("RECAPTCHA_ACTION_NAME", FIELD_RECAPTCHA_ACTION_NAME),
        str_field_map_t::value_type("RECAPTCHA_ACTION_NAME", FIELD_RECAPTCHA_ACTION_NAME),
        str_field_map_t::value_type("CHALLENGE_DIFFICULTY", FIELD_CHALLENGE_DIFFICULTY),
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
                // FIELD_AN
                // -----------------------------------------
                case FIELD_AN:
                {
                        if(!a_ctx || !a_ctx->m_an)
                        {
                                break;
                        }
                        char l_tmp[8];
                        int l_tmp_len;
                        l_tmp_len = snprintf(l_tmp, 8, "%04lX", (unsigned long)a_ctx->m_an);
                        ao_len += l_tmp_len;
                        if(ao_buf)
                        {
                                memcpy(l_buf, l_tmp, l_tmp_len);
                                l_buf += l_tmp_len;
                        }
                        break;
                }
                // -----------------------------------------
                // FIELD_EVENT_ID
                // -----------------------------------------
                case FIELD_EVENT_ID:
                {
                        if(!a_ctx ||
                          !a_ctx->m_req_uuid.m_data ||
                          !a_ctx->m_req_uuid.m_len)
                        {
                                break;
                        }
                        ao_len += a_ctx->m_req_uuid.m_len;
                        if(ao_buf)
                        {
                                memcpy(l_buf, a_ctx->m_req_uuid.m_data, a_ctx->m_req_uuid.m_len);
                                l_buf += a_ctx->m_req_uuid.m_len;
                        }
                        break;
                }
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
                        ao_len += a_ctx->m_uri_path_len;
                        if(ao_buf)
                        {
                                memcpy(l_buf, a_ctx->m_uri.m_data, a_ctx->m_uri_path_len);
                                l_buf += a_ctx->m_uri_path_len;
                        }
                        // ---------------------------------
                        // query...
                        // ---------------------------------
                        if(!a_ctx ||
                          !a_ctx->m_query_str.m_data ||
                          !a_ctx->m_query_str.m_len)
                        {
                                break;
                        }
                        ao_len += 1;
                        ao_len += a_ctx->m_query_str.m_len;
                        if(ao_buf)
                        {
                                memcpy(l_buf, "?", 1);
                                l_buf += 1;
                                memcpy(l_buf, a_ctx->m_query_str.m_data, a_ctx->m_query_str.m_len);
                                l_buf += a_ctx->m_query_str.m_len;
                        }
                        break;
                }
                // -----------------------------------------
                // FIELD_TIMESTAMP
                // -----------------------------------------
                case FIELD_TIMESTAMP:
                {
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
                // FIELD_STATUS_CODE
                // -----------------------------------------
                case FIELD_STATUS_CODE:
                {
                        char l_tmp[8];
                        int l_tmp_len;
                        l_tmp_len = snprintf(l_tmp, 8, "%u", a_ctx->m_resp_status);
                        ao_len += l_tmp_len;
                        if(ao_buf)
                        {
                                memcpy(l_buf, l_tmp, l_tmp_len);
                                l_buf += l_tmp_len;
                        }
                        break;
                }
                // -----------------------------------------
                // FIELD_USER_AGENT
                // -----------------------------------------
                case FIELD_USER_AGENT:
                {
                        if(!a_ctx)
                        {
                                break;
                        }
#define _GET_HEADER(_header) do { \
        l_d.m_data = _header; \
        l_d.m_len = sizeof(_header) - 1; \
        data_unordered_map_t::const_iterator i_h = a_ctx->m_header_map.find(l_d); \
        if(i_h != a_ctx->m_header_map.end()) \
        { \
                l_v.m_data = i_h->second.m_data; \
                l_v.m_len = i_h->second.m_len; \
        } \
} while(0)
                        data_t l_d;
                        data_t l_v;
                        _GET_HEADER("User-Agent");
                        if(!l_v.m_data ||
                           !l_v.m_len)
                        {
                                break;
                        }
                        ao_len += l_v.m_len;
                        if(ao_buf)
                        {
                                memcpy(l_buf, l_v.m_data, l_v.m_len);
                                l_buf += l_v.m_len;
                        }
                        break;
                }
                // -----------------------------------------
                // FIELD_RULE_MSG
                // -----------------------------------------
                case FIELD_RULE_MSG:
                {
                        if(!a_ctx ||
                           !a_ctx->m_event ||
                           !a_ctx->m_event->has_rule_msg())
                        {
                                break;
                        }
                        const std::string &l_msg = a_ctx->m_event->rule_msg();
                        ao_len += l_msg.length();
                        if(ao_buf)
                        {
                                memcpy(l_buf, l_msg.c_str(), l_msg.length());
                                l_buf += l_msg.length();
                        }
                        break;
                }
                // -----------------------------------------
                // FIELD_EC_TOKEN
                // -----------------------------------------
                case FIELD_EC_TOKEN:
                {
                        if(!a_ctx ||
                          !a_ctx->m_token.m_data ||
                          !a_ctx->m_token.m_len)
                        {
                                break;
                        }
                        ao_len += a_ctx->m_token.m_len;
                        if(ao_buf)
                        {
                                memcpy(l_buf, a_ctx->m_token.m_data, a_ctx->m_token.m_len);
                                l_buf += a_ctx->m_token.m_len;
                        }
                        break;
                }
               // ------------------------------------------
                // FIELD_BOT_PROB
                // -----------------------------------------
                case FIELD_BOT_PROB:
                {
                        if(!a_ctx ||
                           a_ctx->m_bot_ch.empty())
                        {
                                break;
                        }
                        ao_len += a_ctx->m_bot_ch.length();
                        if(ao_buf)
                        {
                                memcpy(l_buf, a_ctx->m_bot_ch.c_str(), a_ctx->m_bot_ch.length());
                                l_buf += a_ctx->m_bot_ch.length();
                        }
                        break;
                }
                // -----------------------------------------
                // FIELD_BOT_JS
                // -----------------------------------------
                case FIELD_BOT_JS:
                {
                       if (!a_ctx ||
                           a_ctx->m_bot_js.empty())
                        {
                                break;
                        }
                        ao_len += a_ctx->m_bot_js.length();
                        if (ao_buf)
                        {
                                memcpy(l_buf, a_ctx->m_bot_js.c_str(), a_ctx->m_bot_js.length());
                                l_buf += a_ctx->m_bot_js.length();
                        }
                        break;
                }
                // -----------------------------------------
                // FIELD_RECAPTCHA_SITE_KEY
                // -----------------------------------------
                case FIELD_RECAPTCHA_SITE_KEY:
                {
                        if (!a_ctx ||
                            a_ctx->m_recaptcha_site_key.empty())
                        {
                                break;
                        }
                        ao_len += a_ctx->m_recaptcha_site_key.length();
                        if (ao_buf)
                        {
                                memcpy(l_buf, 
                                       a_ctx->m_recaptcha_site_key.c_str(),
                                       a_ctx->m_recaptcha_site_key.length());
                                l_buf += a_ctx->m_recaptcha_site_key.length();
                        }
                        break;
                }
                // -----------------------------------------
                // FIELD_RECAPTCHA_ACTION_NAME
                // -----------------------------------------
                case FIELD_RECAPTCHA_ACTION_NAME:
                {
                        if (!a_ctx ||
                            a_ctx->m_recaptcha_action_name.empty())
                        {
                                break;
                        }
                        ao_len += a_ctx->m_recaptcha_action_name.length();
                        if (ao_buf)
                        {
                                memcpy(l_buf, 
                                       a_ctx->m_recaptcha_action_name.c_str(),
                                       a_ctx->m_recaptcha_action_name.length());
                                l_buf += a_ctx->m_recaptcha_action_name.length();
                        }
                        break;
                }
                case FIELD_CHALLENGE_DIFFICULTY:
                {
                        std::string l_tmp = std::to_string(a_ctx->m_challenge_difficulty);
                        ao_len += l_tmp.length();
                        if(ao_buf)
                        {
                                memcpy(l_buf, l_tmp.c_str(), l_tmp.length());
                                l_buf += l_tmp.length();
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
//! ----------------------------------------------------------------------------
//! \details C binding for third party lib to render string
//! \return  0: success
//! \param   a_rqst_ctx: rqst_ctx object
//! ----------------------------------------------------------------------------
extern "C" int32_t plugin_render(char** ao_buf,
                                size_t* ao_len,
                                const char *a_buf,
                                size_t a_len,
                                rqst_ctx *a_rqst_ctx)
{
        return render(ao_buf, *ao_len, a_buf, a_len, a_rqst_ctx);
}
}
