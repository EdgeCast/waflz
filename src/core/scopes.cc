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
#include "waflz/scopes.h"
#include "waflz/rqst_ctx.h"
#include "waflz/config_parser.h"
#include "waflz/acl.h"
#include "waflz/rules.h"
#include "waflz/bots.h"
#include "waflz/bot_manager.h"
#include "waflz/schema.h"
#include "waflz/api_gw.h"
#include "waflz/client_waf.h"
#include "waflz/engine.h"
#include "waflz/rl_obj.h"
#include "waflz/lm_db.h"
#include "waflz/limit.h"
#include "waflz/enforcer.h"
#include "waflz/challenge.h"
#include "waflz/captcha.h"
#include "waflz/trace.h"
#include "support/ndebug.h"
#include "support/base64.h"
#include "support/file_util.h"
#include "support/time_util.h"
#include "op/regex.h"
#include "scope.pb.h"
#include "profile.pb.h"
#include "jspb/jspb.h"
#include "event.pb.h"
#include "limit.pb.h"
#include "rule.pb.h"
#include "bot_manager.pb.h"
#include "client_waf.pb.h"
#include "api_gw.pb.h"
#include <fnmatch.h>
#include <time.h>
#include <sys/time.h>
#include <chrono>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define _SCOPES_MAX_SIZE (1024*1024)
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
#define VERIFY_HAS(_pb, _field) do { \
        if (!_pb.has_##_field()) { \
                WAFLZ_PERROR(m_err_msg, "missing %s field", #_field); \
                return WAFLZ_STATUS_ERROR; \
        } \
} while(0)
#define _GET_HEADER(_header) do { \
    l_d.m_data = _header; \
    l_d.m_len = sizeof(_header) - 1; \
    data_unordered_map_t::const_iterator i_h = a_ctx->m_header_map.find(l_d); \
    if (i_h != a_ctx->m_header_map.end()) \
    { \
            l_v.m_data = i_h->second.m_data; \
            l_v.m_len = i_h->second.m_len; \
    } \
    } while(0)
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! utils
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t compile_action(waflz_pb::enforcement& ao_axn, char* ao_err_msg)
{
        // -------------------------------------------------
        // convert type string to enf_type
        // -------------------------------------------------
        if (!ao_axn.has_enf_type() &&
            ao_axn.has_type())
        {
                const std::string& l_type = ao_axn.type();
#define _ELIF_TYPE(_str, _type) else \
if (strncasecmp(l_type.c_str(), _str, sizeof(_str)) == 0) { \
        ao_axn.set_enf_type(waflz_pb::enforcement_type_t_##_type); \
}
            if (0) {}
            _ELIF_TYPE("REDIRECT_302", REDIRECT_302)
            _ELIF_TYPE("REDIRECT-302", REDIRECT_302)
            _ELIF_TYPE("REDIRECT_JS", REDIRECT_JS)
            _ELIF_TYPE("REDIRECT-JS", REDIRECT_JS)
            _ELIF_TYPE("HASHCASH", HASHCASH)
            _ELIF_TYPE("CUSTOM_RESPONSE", CUSTOM_RESPONSE)
            _ELIF_TYPE("CUSTOM-RESPONSE", CUSTOM_RESPONSE)
            _ELIF_TYPE("DROP_REQUEST", DROP_REQUEST)
            _ELIF_TYPE("DROP-REQUEST", DROP_REQUEST)
            _ELIF_TYPE("DROP_CONNECTION", DROP_CONNECTION)
            _ELIF_TYPE("DROP-CONNECTION", DROP_CONNECTION)
            _ELIF_TYPE("NOP", NOP)
            _ELIF_TYPE("ALERT", ALERT)
            _ELIF_TYPE("BLOCK_REQUEST", BLOCK_REQUEST)
            _ELIF_TYPE("BLOCK-REQUEST", BLOCK_REQUEST)
            _ELIF_TYPE("BROWSER_CHALLENGE", BROWSER_CHALLENGE)
            _ELIF_TYPE("BROWSER-CHALLENGE", BROWSER_CHALLENGE)
            _ELIF_TYPE("NULL_ALERT", NULL_ALERT)
            _ELIF_TYPE("NULL-ALERT", NULL_ALERT)
            _ELIF_TYPE("NULL_BLOCK", NULL_BLOCK)
            _ELIF_TYPE("NULL-BLOCK", NULL_BLOCK)
            _ELIF_TYPE("IGNORE_ALERT", IGNORE_ALERT)
            _ELIF_TYPE("IGNORE-ALERT", IGNORE_ALERT)
            _ELIF_TYPE("IGNORE_BLOCK", IGNORE_BLOCK)
            _ELIF_TYPE("IGNORE-BLOCK", IGNORE_BLOCK)
            _ELIF_TYPE("IGNORE-REDIRECT-302", IGNORE_REDIRECT_302)
            _ELIF_TYPE("IGNORE_REDIRECT_302", IGNORE_REDIRECT_302)
            _ELIF_TYPE("IGNORE-CUSTOM_RESPONSE", IGNORE_CUSTOM_RESPONSE)
            _ELIF_TYPE("IGNORE_CUSTOM_RESPONSE", IGNORE_CUSTOM_RESPONSE)
            _ELIF_TYPE("IGNORE-DROP-REQUEST", IGNORE_DROP_REQUEST)
            _ELIF_TYPE("IGNORE_DROP_REQUEST", IGNORE_DROP_REQUEST)
            else
            {
                    WAFLZ_PERROR(ao_err_msg, "unrecognized enforcement type string: %s", l_type.c_str());
                    return WAFLZ_STATUS_ERROR;
            }
        }
        // -------------------------------------------------
        // convert b64 encoded resp
        // -------------------------------------------------
        if (!ao_axn.has_response_body() &&
                        ao_axn.has_response_body_base64() &&
           !ao_axn.response_body_base64().empty())
        {
                const std::string& l_b64 = ao_axn.response_body_base64();
                char* l_body = NULL;
                size_t l_body_len = 0;
                int32_t l_s;
                l_s = b64_decode(&l_body, l_body_len, l_b64.c_str(), l_b64.length());
                if (!l_body ||
                   !l_body_len ||
                   (l_s != WAFLZ_STATUS_OK))
                {
                        WAFLZ_PERROR(ao_err_msg, "decoding response_body_base64 string: %s", l_b64.c_str());
                        return WAFLZ_STATUS_ERROR;
                }
                ao_axn.mutable_response_body()->assign(l_body, l_body_len);
                if (l_body) { free(l_body); l_body = NULL; }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details return short date in form "<mm>/<dd>/<YYYY>"
//! \return  None
//! \param   TODO
//! ----------------------------------------------------------------------------
static const char* get_date_short_str(void)
{
        // -------------------------------------------------
        // TODO thread caching???
        // -------------------------------------------------
        static char s_date_str[128];
        time_t l_time = time(NULL);
        struct tm* l_tm = localtime(&l_time);
        if (0 == strftime(s_date_str, sizeof(s_date_str), "%m/%d/%Y", l_tm))
        {
                return "1/1/1970";
        }
        else
        {
                return s_date_str;
        }
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  None
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t add_limit_with_key(waflz_pb::limit& ao_limit,
                                  const std::string a_key,
                                  rqst_ctx* a_ctx)
{
        if (!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // Set operator to streq for all
        // -------------------------------------------------
        const char* l_data = NULL;
        uint32_t l_len = 0;
        // -------------------------------------------------
        // IP
        // -------------------------------------------------
        if (strcasecmp(a_key.c_str(), "IP") == 0)
        {
                l_data = a_ctx->m_src_addr.m_data;
                l_len = a_ctx->m_src_addr.m_len;
        }
        // -------------------------------------------------
        // user agent
        // -------------------------------------------------
        else if (strcasecmp(a_key.c_str(), "USER_AGENT") == 0)
        {
                const data_t* l_ua = a_ctx->get_header(std::string_view("User-Agent"));
                if ( l_ua && l_ua->m_len && l_ua->m_data )
                {
                        l_data = l_ua->m_data;
                        l_len = l_ua->m_len;
                }
        }
        // -------------------------------------------------
        // ASN
        // -------------------------------------------------
        else if (strcasecmp(a_key.c_str(), "ASN") == 0)
        {
                const ns_waflz::mutable_data_t l_asn = a_ctx->m_src_asn_str;
                if (l_asn.m_len && l_asn.m_data)
                {
                        l_data = l_asn.m_data;
                        l_len = l_asn.m_len;
                }
        }
        // -------------------------------------------------
        // JA3
        // -------------------------------------------------
        else if (strcasecmp(a_key.c_str(), "JA3") == 0)
        {
                const data_t& l_d = a_ctx->m_virt_ssl_client_ja3_md5;
                if (l_d.m_len && l_d.m_data)
                {
                        l_data = l_d.m_data;
                        l_len = l_d.m_len;
                }
        }
        // -------------------------------------------------
        // JA4
        // -------------------------------------------------
        else if (strcasecmp(a_key.c_str(), "JA4") == 0)
        {
                const data_t& l_d = a_ctx->m_virt_ssl_client_ja4;
                if (l_d.m_len && l_d.m_data)
                {
                        l_data = l_d.m_data;
                        l_len = l_d.m_len;
                }
        }
        // -------------------------------------------------
        // special case: header
        // -------------------------------------------------
        else if (strncasecmp(a_key.c_str(), "HEADER:", (sizeof("HEADER:") - 1)) == 0)
        {
                std::string_view l_t(a_key.c_str() + (sizeof("HEADER:") - 1));
                const data_t* l_hv = a_ctx->get_header(l_t);
                if (l_hv && l_hv->m_len && l_hv->m_data)
                {
                        l_data = l_hv->m_data;
                        l_len = l_hv->m_len;
                }
        }
        // -------------------------------------------------
        // special case: cookie
        // -------------------------------------------------
        else if (strncasecmp(a_key.c_str(), "COOKIE:", (sizeof("COOKIE:") - 1)) == 0)
        {
                data_t l_search_val;
                l_search_val.m_data = a_key.c_str() + (sizeof("COOKIE:") - 1);
                l_search_val.m_len = a_key.length() - (sizeof("COOKIE:") - 1);
                const auto l_cookie_val = a_ctx->m_cookie_map.find(l_search_val);
                if (l_cookie_val != a_ctx->m_cookie_map.end())
                {
                        l_data = l_cookie_val->second.m_data;
                        l_len = l_cookie_val->second.m_len;
                }
        }
        // -------------------------------------------------
        // special case: args
        // -------------------------------------------------
        else if (strncasecmp(a_key.c_str(), "ARGS:", (sizeof("ARGS:") - 1)) == 0)
        {
                data_t l_search_val;
                l_search_val.m_data = a_key.c_str() + (sizeof("ARGS:") - 1);
                l_search_val.m_len = a_key.length() - (sizeof("ARGS:") - 1);
                const auto l_arg_val = a_ctx->m_query_arg_map.find(l_search_val);
                if (l_arg_val != a_ctx->m_query_arg_map.end())
                {
                        l_data = l_arg_val->second.m_data;
                        l_len = l_arg_val->second.m_len;
                }
        }
        // -------------------------------------------------
        // special case: status codes
        // -------------------------------------------------
        else if (strncasecmp(a_key.c_str(), "STATUS_CODE:", (sizeof("STATUS_CODE:") - 1)) == 0)
        {
                l_data = a_key.c_str() + sizeof("STATUS_CODE:") - 1;
                l_len = a_key.length() - sizeof("STATUS_CODE:") + 1;
        }
        // -------------------------------------------------
        // error ?
        // -------------------------------------------------
        else
        {
                // WAFLZ_PERROR(m_err_msg, "unrecognized dimension type: %s", a_key.c_str());
                return WAFLZ_STATUS_ERROR;
  
        }
        // -------------------------------------------------
        // if no data -no limit
        // -------------------------------------------------
        if (!l_data ||
           (l_len == 0))
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // add this value to the log key on the limit
        // -------------------------------------------------
        std::string* l_matched_log = ao_limit.mutable__reserved_matched_key_log();
        if (!l_matched_log->empty()){ *l_matched_log += "::"; }
        *l_matched_log += l_data;
        // -------------------------------------------------
        // special check:
        // we only want to add the status code to the log
        // string - not actually check for it in enforcement
        // -------------------------------------------------
        if (strncasecmp(a_key.c_str(), "STATUS_CODE:", (sizeof("STATUS_CODE:") - 1)) == 0)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // Add limit for any data
        // -------------------------------------------------
        waflz_pb::condition* l_c = NULL;
        if (ao_limit.condition_groups_size() > 0)
        {
                l_c = ao_limit.mutable_condition_groups(0)->add_conditions();
        }
        else
        {
                l_c = ao_limit.add_condition_groups()->add_conditions();
        }
        // -------------------------------------------------
        // set operator
        // always STREQ
        // -------------------------------------------------
        waflz_pb::op_t* l_operator = l_c->mutable_op();
        l_operator->set_type(waflz_pb::op_t_type_t_STREQ);
        l_operator->set_value(l_data, l_len);
        // -------------------------------------------------
        // set var
        // -------------------------------------------------
        waflz_pb::condition_target_t* l_var = l_c->mutable_target();
        // -------------------------------------------------
        // IP
        // -------------------------------------------------
        if (strcasecmp(a_key.c_str(), "IP") == 0)
        {
                l_var->set_type(waflz_pb::condition_target_t_type_t_REMOTE_ADDR);
        }
        // -------------------------------------------------
        // user agent
        // -------------------------------------------------
        else if (strcasecmp(a_key.c_str(), "USER_AGENT") == 0)
        {
                l_var->set_type(waflz_pb::condition_target_t_type_t_REQUEST_HEADERS);
                l_var->mutable_value()->assign("User-Agent");
        }
        // -------------------------------------------------
        // ASN
        // -------------------------------------------------
        else if (strcasecmp(a_key.c_str(), "ASN") == 0)
        {
                l_var->set_type(waflz_pb::condition_target_t_type_t_REMOTE_ASN);
        }
        // -------------------------------------------------
        // JA3
        // -------------------------------------------------
        else if (strcasecmp(a_key.c_str(), "JA3") == 0)
        {
                l_var->set_type(waflz_pb::condition_target_t_type_t_REMOTE_JA3);
        }
        // -------------------------------------------------
        // JA4
        // -------------------------------------------------
        else if (strcasecmp(a_key.c_str(), "JA4") == 0)
        {
                l_var->set_type(waflz_pb::condition_target_t_type_t_REMOTE_JA4);
        }
        // -------------------------------------------------
        // special case: header
        // -------------------------------------------------
        else if (strncasecmp(a_key.c_str(), "HEADER:", (sizeof("HEADER:") - 1)) == 0)
        {
                l_var->set_type(waflz_pb::condition_target_t_type_t_REQUEST_HEADERS);
                l_var->mutable_value()->assign(a_key.c_str() + (sizeof("HEADER:") - 1));
        }
        // -------------------------------------------------
        // special case: cookie
        // -------------------------------------------------
        else if (strncasecmp(a_key.c_str(), "COOKIE:", (sizeof("COOKIE:") - 1)) == 0)
        {
                l_var->set_type(waflz_pb::condition_target_t_type_t_REQUEST_COOKIES);
                l_var->mutable_value()->assign(a_key.c_str() + (sizeof("COOKIE:") - 1));
        }
        // -------------------------------------------------
        // special case: args
        // -------------------------------------------------
        else if (strncasecmp(a_key.c_str(), "ARGS:", (sizeof("ARGS:") - 1)) == 0)
        {
                l_var->set_type(waflz_pb::condition_target_t_type_t_QUERY_ARG);
                l_var->mutable_value()->assign(a_key.c_str() + (sizeof("ARGS:") - 1));
        }
        // -------------------------------------------------
        // done :P
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  None
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t add_limit_with_key_for_response(waflz_pb::limit& ao_limit,
                                  const std::string a_key,
                                  resp_ctx* a_ctx)
{
        if (!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // Set operator to streq for all
        // -------------------------------------------------
        const char* l_data = NULL;
        uint32_t l_len = 0;
        // -------------------------------------------------
        // IP
        // -------------------------------------------------
        if (strcasecmp(a_key.c_str(), "IP") == 0)
        {
                l_data = a_ctx->m_src_addr.m_data;
                l_len = a_ctx->m_src_addr.m_len;
        }
        // -------------------------------------------------
        // user agent
        // -------------------------------------------------
        else if (strcasecmp(a_key.c_str(), "USER_AGENT") == 0)
        {
                const data_t* l_ua = a_ctx->get_header(std::string_view("User-Agent"));
                if ( l_ua && l_ua->m_len && l_ua->m_data )
                {
                        l_data = l_ua->m_data;
                        l_len = l_ua->m_len;
                }
        }
        // -------------------------------------------------
        // special case: header
        // -------------------------------------------------
        else if (strncasecmp(a_key.c_str(), "HEADER:", (sizeof("HEADER:") - 1)) == 0)
        {
                std::string_view l_t(a_key.c_str() + (sizeof("HEADER:") - 1));
                const data_t* l_hv = a_ctx->get_header(l_t);
                if (l_hv && l_hv->m_len && l_hv->m_data)
                {
                        l_data = l_hv->m_data;
                        l_len = l_hv->m_len;
                }
        }
        // -------------------------------------------------
        // special case: status codes
        // -------------------------------------------------
        else if (strncasecmp(a_key.c_str(), "STATUS_CODE:", (sizeof("STATUS_CODE:") - 1)) == 0)
        {
                l_data = a_key.c_str() + sizeof("STATUS_CODE:") - 1;
                l_len = a_key.length() - sizeof("STATUS_CODE:") + 1;
        }
        // -------------------------------------------------
        // error ?
        // -------------------------------------------------
        else
        {
                // WAFLZ_PERROR(m_err_msg, "unrecognized dimension type: %s", a_key.c_str());
                return WAFLZ_STATUS_ERROR;
  
        }
        // -------------------------------------------------
        // if no data -no limit
        // -------------------------------------------------
        if (!l_data ||
           (l_len == 0))
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // add this value to the log key on the limit
        // -------------------------------------------------
        std::string* l_matched_log = ao_limit.mutable__reserved_matched_key_log();
        if (!l_matched_log->empty()){ *l_matched_log += "::"; }
        *l_matched_log += l_data;
        // -------------------------------------------------
        // special check:
        // we only want to add the status code to the log
        // string - not actually check for it in enforcement
        // -------------------------------------------------
        if (strncasecmp(a_key.c_str(), "STATUS_CODE:", (sizeof("STATUS_CODE:") - 1)) == 0)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // Add limit for any data
        // -------------------------------------------------
        waflz_pb::condition* l_c = NULL;
        if (ao_limit.condition_groups_size() > 0)
        {
                l_c = ao_limit.mutable_condition_groups(0)->add_conditions();
        }
        else
        {
                l_c = ao_limit.add_condition_groups()->add_conditions();
        }
        // -------------------------------------------------
        // set operator
        // always STREQ
        // -------------------------------------------------
        waflz_pb::op_t* l_operator = l_c->mutable_op();
        l_operator->set_type(waflz_pb::op_t_type_t_STREQ);
        l_operator->set_value(l_data, l_len);
        // -------------------------------------------------
        // set var
        // -------------------------------------------------
        waflz_pb::condition_target_t* l_var = l_c->mutable_target();
        // -------------------------------------------------
        // IP
        // -------------------------------------------------
        if (strcasecmp(a_key.c_str(), "IP") == 0)
        {
                l_var->set_type(waflz_pb::condition_target_t_type_t_REMOTE_ADDR);
        }
        // -------------------------------------------------
        // user agent
        // -------------------------------------------------
        else if (strcasecmp(a_key.c_str(), "USER_AGENT") == 0)
        {
                l_var->set_type(waflz_pb::condition_target_t_type_t_REQUEST_HEADERS);
                l_var->mutable_value()->assign("User-Agent");
        }
        // -------------------------------------------------
        // ASN
        // -------------------------------------------------
        else if (strcasecmp(a_key.c_str(), "ASN") == 0)
        {
                l_var->set_type(waflz_pb::condition_target_t_type_t_REMOTE_ASN);
        }
        // -------------------------------------------------
        // JA3
        // -------------------------------------------------
        else if (strcasecmp(a_key.c_str(), "JA3") == 0)
        {
                l_var->set_type(waflz_pb::condition_target_t_type_t_REMOTE_JA3);
        }
        // -------------------------------------------------
        // special case: header
        // -------------------------------------------------
        else if (strncasecmp(a_key.c_str(), "HEADER:", (sizeof("HEADER:") - 1)) == 0)
        {
                l_var->set_type(waflz_pb::condition_target_t_type_t_REQUEST_HEADERS);
                l_var->mutable_value()->assign(a_key.c_str() + (sizeof("HEADER:") - 1));
        }
        // -------------------------------------------------
        // special case: cookie
        // -------------------------------------------------
        else if (strncasecmp(a_key.c_str(), "COOKIE:", (sizeof("COOKIE:") - 1)) == 0)
        {
                l_var->set_type(waflz_pb::condition_target_t_type_t_REQUEST_COOKIES);
                l_var->mutable_value()->assign(a_key.c_str() + (sizeof("COOKIE:") - 1));
        }
        // -------------------------------------------------
        // special case: args
        // -------------------------------------------------
        else if (strncasecmp(a_key.c_str(), "ARGS:", (sizeof("ARGS:") - 1)) == 0)
        {
                l_var->set_type(waflz_pb::condition_target_t_type_t_QUERY_ARG);
                l_var->mutable_value()->assign(a_key.c_str() + (sizeof("ARGS:") - 1));
        }
        // -------------------------------------------------
        // done :P
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details ctor
//! \return  None
//! \param   TODO
//! ----------------------------------------------------------------------------
scopes::scopes(engine& a_engine, 
               kv_db& a_kv_db,
               kv_db& a_bot_db,
               challenge& a_challenge,
               captcha& a_captcha):
        m_init(false),
        m_pb(NULL),
        m_err_msg(),
        m_engine(a_engine),
        m_db(a_kv_db),
        m_bot_db(a_bot_db),
        m_regex_list(),
        m_data_set_list(),
        m_data_case_i_set_list(),
        m_id(),
        m_cust_id(),
        m_team_config(false),
        m_use_spoof_ip_header(),
        m_spoof_ip_header(),
        m_account_type("__na__"),
        m_bot_tier("__na__"),
        m_partner_id("__na__"),
        m_name(),
        use_team_id_config(false),
        m_id_acl_map(),
        m_id_rules_map(),
        m_id_profile_map(),
        m_id_limit_map(),
        m_id_bot_manager_map(),
        m_id_api_gw_map(),
        m_id_client_waf_map(),
        m_enfx(NULL),
        m_audit_enfx(NULL),
        m_challenge(a_challenge),
        m_captcha(a_captcha)
{
        m_pb = new waflz_pb::scope_config();
        m_enfx = new enforcer(false);
        m_audit_enfx = new enforcer(false);
}
//! ----------------------------------------------------------------------------
//! \brief   dtor
//! \deatils
//! \return  None
//! ----------------------------------------------------------------------------
scopes::~scopes()
{
        if (m_pb) { delete m_pb; m_pb = NULL; }
        if (m_enfx) { delete m_enfx; m_enfx = NULL; }
        if (m_audit_enfx) { delete m_audit_enfx; m_audit_enfx = NULL; }
        // -------------------------------------------------
        // clear parts...
        // -------------------------------------------------
#define _DEL_MAP(_t, _m) do { \
        for (_t::iterator i = _m.begin(); i != _m.end(); ++i) { \
                if (i->second) { delete i->second; i->second = NULL; } \
        } \
} while(0)
        _DEL_MAP(id_acl_map_t, m_id_acl_map);
        _DEL_MAP(id_rules_map_t, m_id_rules_map);
        _DEL_MAP(id_profile_map_t, m_id_profile_map);
        _DEL_MAP(id_limit_map_t, m_id_limit_map);
        _DEL_MAP(id_bot_manager_map_t, m_id_bot_manager_map);
        _DEL_MAP(id_api_gw_map_t, m_id_api_gw_map);
        _DEL_MAP(id_client_waf_map_t, m_id_client_waf_map);
        // -------------------------------------------------
        // destruct m_regex_list
        // -------------------------------------------------
        for (regex_list_t::iterator i_p = m_regex_list.begin();
            i_p != m_regex_list.end();
            ++i_p)
        {
                if (*i_p) { delete *i_p; *i_p = NULL;}
        }
        // -------------------------------------------------
        // destruct str_ptr_set_list
        // -------------------------------------------------
        for (data_set_list_t::iterator i_n = m_data_set_list.begin();
            i_n != m_data_set_list.end();
            ++i_n)
        {
                if (*i_n) { delete *i_n; *i_n = NULL;}
        }
        for (data_case_i_set_list_t::iterator i_n = m_data_case_i_set_list.begin();
            i_n != m_data_case_i_set_list.end();
            ++i_n)
        {
                if (*i_n) { delete *i_n; *i_n = NULL;}
        }
}
//! ----------------------------------------------------------------------------
//! \details compile_op
//! \return  0/-1
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::compile_op(::waflz_pb::op_t& ao_op)
{
        // -------------------------------------------------
        // check if exist...
        // -------------------------------------------------
        if (!ao_op.has_type())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // for type...
        // -------------------------------------------------
        switch(ao_op.type())
        {
        // -------------------------------------------------
        // regex
        // -------------------------------------------------
        case ::waflz_pb::op_t_type_t_RX:
        {
                if (!ao_op.has_value())
                {
                        return WAFLZ_STATUS_ERROR;
                }
                const std::string& l_val = ao_op.value();
                regex* l_rx = new regex();
                int32_t l_s;
                l_s = l_rx->init(l_val.c_str(), l_val.length());
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "failed to compile regex: '%s'.", l_val.c_str());
                        delete l_rx;
                        l_rx = NULL;
                        return WAFLZ_STATUS_ERROR;
                }
                ao_op.set__reserved_1((uint64_t)(l_rx));
                m_regex_list.push_back(l_rx);
                break;
        }
        // -------------------------------------------------
        // exact condition list
        // -------------------------------------------------
        case ::waflz_pb::op_t_type_t_EM:
        {
                if (!ao_op.has_value() &&
                   !ao_op.values_size())
                {
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // case insensitive
                // -----------------------------------------
                if (ao_op.is_case_insensitive())
                {
                        data_case_i_set_t* l_ds = new data_case_i_set_t();
                        // ---------------------------------
                        // prefer values to value
                        // ---------------------------------
                        if (ao_op.values_size())
                        {
                                for (int32_t i_v = 0; i_v < ao_op.values_size(); ++i_v)
                                {
                                        if (ao_op.values(i_v).empty())
                                        {
                                                continue;
                                        }
                                        data_t l_d;
                                        l_d.m_data = ao_op.values(i_v).c_str();
                                        l_d.m_len = ao_op.values(i_v).length();
                                        l_ds->insert(l_d);
                                }
                        }
                        else if (!ao_op.value().empty())
                        {
                                data_t l_d;
                                l_d.m_data = ao_op.value().c_str();
                                l_d.m_len = ao_op.value().length();
                                l_ds->insert(l_d);
                        }
                        ao_op.set__reserved_1((uint64_t)(l_ds));
                        m_data_case_i_set_list.push_back(l_ds);
                }
                // -----------------------------------------
                // case sensitive
                // -----------------------------------------
                else
                {
                        data_set_t* l_ds = new data_set_t();
                        // ---------------------------------
                        // prefer values to value
                        // ---------------------------------
                        if (ao_op.values_size())
                        {
                                for (int32_t i_v = 0; i_v < ao_op.values_size(); ++i_v)
                                {
                                        if (ao_op.values(i_v).empty())
                                        {
                                                continue;
                                        }
                                        data_t l_d;
                                        l_d.m_data = ao_op.values(i_v).c_str();
                                        l_d.m_len = ao_op.values(i_v).length();
                                        l_ds->insert(l_d);
                                }
                        }
                        else if (!ao_op.value().empty())
                        {
                                data_t l_d;
                                l_d.m_data = ao_op.value().c_str();
                                l_d.m_len = ao_op.value().length();
                                l_ds->insert(l_d);
                        }
                        ao_op.set__reserved_1((uint64_t)(l_ds));
                        m_data_set_list.push_back(l_ds);
                }
                break;
        }
        // -------------------------------------------------
        // default
        // -------------------------------------------------
        default:
        {
                break;
        }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  0/-1
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::compile(const std::string& a_conf_dir_path)
{
        if (m_init)
        {
                return WAFLZ_STATUS_OK;
        }
        if (!m_pb)
        {
                WAFLZ_PERROR(m_err_msg, "pb == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        if (!m_pb->has_id())
        {
                WAFLZ_PERROR(m_err_msg, "missing id field");
                return WAFLZ_STATUS_ERROR;
        }
        if (!m_pb->has_customer_id())
        {
                WAFLZ_PERROR(m_err_msg, "missing customer id field");
                return WAFLZ_STATUS_ERROR;
        }
        if (m_pb->has_account_type())
        {
                m_account_type = m_pb->account_type();
        }
        if (m_pb->has_partner_id())
        {
                m_partner_id = m_pb->partner_id();
        }
        if (m_pb->has_bot_tier())
        {
                m_bot_tier = m_pb->bot_tier();
        }
        m_id = m_pb->id();
        m_cust_id = m_pb->customer_id();
        m_name = m_pb->name();
        if (m_pb->has_team_config())
        {
                m_team_config = m_pb->team_config();
        }
        // -------------------------------------------------
        // for each scope - compile op and load parts
        // -------------------------------------------------
        int32_t l_s;
        for (int i_s = 0; i_s < m_pb->scopes_size(); ++i_s)
        {
                ::waflz_pb::scope& l_sc = *(m_pb->mutable_scopes(i_s));
                if (l_sc.has_host())
                {
                        l_s = compile_op(*(l_sc.mutable_host()));
                        if (l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                }
                if (l_sc.has_path())
                {
                        l_s = compile_op(*(l_sc.mutable_path()));
                        if (l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                }
                l_s = load_parts(l_sc, a_conf_dir_path);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::load(const char* a_buf, uint32_t a_buf_len, const std::string& a_conf_dir_path)
{
        if (a_buf_len > _SCOPES_MAX_SIZE)
        {
                WAFLZ_PERROR(m_err_msg, "config file size(%u) > max size(%u)",
                             a_buf_len,
                             _SCOPES_MAX_SIZE);
                return WAFLZ_STATUS_ERROR;
        }
        m_init = false;
        // -------------------------------------------------
        // load from js object
        // -------------------------------------------------
        int32_t l_s;
        l_s = update_from_json(*m_pb, a_buf, a_buf_len);
        //TRC_DEBUG("whole config %s", m_pb->DebugString().c_str());
        if (l_s != JSPB_OK)
        {
                WAFLZ_PERROR(m_err_msg, "parsing json. Reason: %s", get_jspb_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // compile and load parts
        // -------------------------------------------------
        l_s = compile(a_conf_dir_path);
        if (l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        m_init = true;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::load(void* a_js, const std::string& a_conf_dir_path)
{
        m_init = false;
        // -------------------------------------------------
        // load from js object
        // -------------------------------------------------
        const rapidjson::Document& l_js = *((rapidjson::Document *)a_js);
        int32_t l_s;
        l_s = update_from_json(*m_pb, l_js);
        if (l_s != JSPB_OK)
        {
                WAFLZ_PERROR(m_err_msg, "parsing json. Reason: %s", get_jspb_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // compile and load parts
        // -------------------------------------------------
        l_s = compile(a_conf_dir_path);
        if (l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        m_init = true;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::load_parts(waflz_pb::scope& a_scope,
                           const std::string& a_conf_dir_path)
{
        // -------------------------------------------------
        // acl audit
        // -------------------------------------------------
        if (a_scope.has_acl_audit_id())
        {
                // -----------------------------------------
                // check exist
                // -----------------------------------------
                id_acl_map_t::iterator i_acl = m_id_acl_map.find(a_scope.acl_audit_id());
                if (i_acl != m_id_acl_map.end())
                {
                        a_scope.set__acl_audit__reserved((uint64_t)i_acl->second);
                        goto acl_audit_action;
                }
                // -----------------------------------------
                // make acl obj
                // -----------------------------------------
                acl* l_acl = new acl(m_engine);
                std::string l_path;
                l_path = a_conf_dir_path + "/acl/" + m_cust_id + "-" + a_scope.acl_audit_id() +".acl.json"; 
                char* l_buf = NULL;
                uint32_t l_buf_len;
                int32_t l_s;
                l_s = read_file(l_path.c_str(), &l_buf, l_buf_len);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", ns_waflz::get_err_msg());
                        if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        // TODO cleanup...
                        return WAFLZ_STATUS_ERROR;
                }
                l_s = l_acl->load(l_buf, l_buf_len);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", l_acl->get_err_msg());
                        if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        // TODO cleanup...
                        return WAFLZ_STATUS_ERROR;
                }
                if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                // -----------------------------------------
                // add to map
                // -----------------------------------------
                a_scope.set__acl_audit__reserved((uint64_t)l_acl);
                m_id_acl_map[a_scope.acl_audit_id()] = l_acl;
        }
acl_audit_action:
        // -------------------------------------------------
        // acl audit action
        // -------------------------------------------------
        if (a_scope.has_acl_audit_action())
        {
                waflz_pb::enforcement* l_a = a_scope.mutable_acl_audit_action();
                int32_t l_s;
                l_s = compile_action(*l_a, m_err_msg);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // acl audit
        // -------------------------------------------------
        if (a_scope.has_acl_prod_id())
        {
                // -----------------------------------------
                // check exist
                // -----------------------------------------
                id_acl_map_t::iterator i_acl = m_id_acl_map.find(a_scope.acl_prod_id());
                if (i_acl != m_id_acl_map.end())
                {
                        a_scope.set__acl_prod__reserved((uint64_t)i_acl->second);
                        goto acl_prod_action;
                }
                // -----------------------------------------
                // make acl obj
                // -----------------------------------------
                acl* l_acl = new acl(m_engine);
                std::string l_path;
                l_path = a_conf_dir_path + "/acl/" + m_cust_id + "-" + a_scope.acl_prod_id() +".acl.json";
                int32_t l_s;
                char* l_buf = NULL;
                uint32_t l_buf_len;
                l_s = read_file(l_path.c_str(), &l_buf, l_buf_len);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", ns_waflz::get_err_msg());
                        if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        if (l_acl) { delete l_acl; l_acl = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                l_s = l_acl->load(l_buf, l_buf_len);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", l_acl->get_err_msg());
                        if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        if (l_acl) { delete l_acl; l_acl = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                // -----------------------------------------
                // add to map
                // -----------------------------------------
                a_scope.set__acl_prod__reserved((uint64_t)l_acl);
                m_id_acl_map[a_scope.acl_prod_id()] = l_acl;
        }
acl_prod_action:
        // -------------------------------------------------
        // acl prod action
        // -------------------------------------------------
        if (a_scope.has_acl_prod_action())
        {
                waflz_pb::enforcement* l_a = a_scope.mutable_acl_prod_action();
                int32_t l_s;
                l_s = compile_action(*l_a, m_err_msg);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // bots manager
        // -------------------------------------------------
        if (a_scope.has_bot_manager_config_id())
        {
                // -----------------------------------------
                // check exist
                // -----------------------------------------
                id_bot_manager_map_t::iterator i_bot_m = m_id_bot_manager_map.find(a_scope.bot_manager_config_id());
                if (i_bot_m != m_id_bot_manager_map.end())
                {
                        a_scope.set__bot_manager_config__reserved((uint64_t)i_bot_m->second);
                        goto rules_audit;
                }
                // -----------------------------------------
                // load file and make bot manager obj
                // -----------------------------------------
                std::string l_path;
                l_path = a_conf_dir_path + "/bot_manager/" + m_cust_id + "-" + a_scope.bot_manager_config_id() +".bot_manager.json";
                int32_t l_s;
                char* l_buf = NULL;
                uint32_t l_buf_len;
                l_s = read_file(l_path.c_str(), &l_buf, l_buf_len);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", ns_waflz::get_err_msg());
                        if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        return WAFLZ_STATUS_ERROR;
                }
                bot_manager* l_bot_manager = new bot_manager(m_engine,
                                                             m_challenge,
                                                             m_captcha);
                l_s = l_bot_manager->load(l_buf, l_buf_len, a_conf_dir_path);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", l_bot_manager->get_err_msg());
                        if (l_bot_manager) { delete l_bot_manager; l_bot_manager = NULL;}
                        if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        return WAFLZ_STATUS_ERROR;
                }
                if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                // -----------------------------------------
                // add to map
                // -----------------------------------------
                a_scope.set__bot_manager_config__reserved((uint64_t)l_bot_manager);
                m_id_bot_manager_map[a_scope.bot_manager_config_id()] = l_bot_manager;
                goto rules_audit;
        }
rules_audit:
        // -------------------------------------------------
        // rules audit
        // -------------------------------------------------
        if (a_scope.has_rules_audit_id())
        {
                // -----------------------------------------
                // check exist
                // -----------------------------------------
                id_rules_map_t::iterator i_rules = m_id_rules_map.find(a_scope.rules_audit_id());
                if (i_rules != m_id_rules_map.end())
                {
                        a_scope.set__rules_audit__reserved((uint64_t)i_rules->second);
                        goto rules_audit_action;
                }
                // -----------------------------------------
                // make rules obj
                // -----------------------------------------
                std::string l_path;
                l_path = a_conf_dir_path + "/rules/" + m_cust_id + "-" + a_scope.rules_audit_id() +".rules.json";
                rules* l_rules = new rules(m_engine);
                int32_t l_s;
                l_s = l_rules->load_file(l_path.c_str(), l_path.length());
                if (l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error loading rules (audit) conf file: %s. reason: %s\n",
                                   l_path.c_str(),
                                   "__na__");
                        // ---------------------------------
                        // TODO -get reason...
                        //l_wafl->get_err_msg());
                        // ---------------------------------
                        if (l_rules) { delete l_rules; l_rules = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // add to map
                // -----------------------------------------
                a_scope.set__rules_audit__reserved((uint64_t)l_rules);
                m_id_rules_map[a_scope.rules_audit_id()] = l_rules;
        }
rules_audit_action:
        // -------------------------------------------------
        // rules audit action
        // -------------------------------------------------
        if (a_scope.has_rules_audit_action())
        {
                waflz_pb::enforcement* l_a = a_scope.mutable_rules_audit_action();
                int32_t l_s;
                l_s = compile_action(*l_a, m_err_msg);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // rules prod
        // -------------------------------------------------
        if (a_scope.has_rules_prod_id())
        {
                // -----------------------------------------
                // check exist
                // -----------------------------------------
                id_rules_map_t::iterator i_rules = m_id_rules_map.find(a_scope.rules_prod_id());
                if (i_rules != m_id_rules_map.end())
                {
                        a_scope.set__rules_prod__reserved((uint64_t)i_rules->second);
                        goto rules_prod_action;
                }
                // -----------------------------------------
                // make rules obj
                // -----------------------------------------
                std::string l_path;
                l_path = a_conf_dir_path + "/rules/" + m_cust_id + "-" + a_scope.rules_prod_id() +".rules.json";
                rules* l_rules = new rules(m_engine);
                int32_t l_s;
                l_s = l_rules->load_file(l_path.c_str(), l_path.length());
                if (l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error loading rules (prod) conf file: %s. reason: %s\n",
                                   l_path.c_str(),
                                   "__na__");
                        // ---------------------------------
                        // TODO -get reason...
                        //l_wafl->get_err_msg());
                        // ---------------------------------
                        if (l_rules) { delete l_rules; l_rules = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // add to map
                // -----------------------------------------
                a_scope.set__rules_prod__reserved((uint64_t)l_rules);
                m_id_rules_map[a_scope.rules_prod_id()] = l_rules;
        }
rules_prod_action:
        // -------------------------------------------------
        // rules prod action
        // -------------------------------------------------
        if (a_scope.has_rules_prod_action())
        {
                waflz_pb::enforcement* l_a = a_scope.mutable_rules_prod_action();
                int32_t l_s;
                l_s = compile_action(*l_a, m_err_msg);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // profile audit
        // -------------------------------------------------
        if (a_scope.has_profile_audit_id())
        {
                // -----------------------------------------
                // check exist
                // -----------------------------------------
                id_profile_map_t::iterator i_profile = m_id_profile_map.find(a_scope.profile_audit_id());
                if (i_profile != m_id_profile_map.end())
                {
                        a_scope.set__profile_audit__reserved((uint64_t)i_profile->second);
                        goto profile_audit_action;
                }
                // -----------------------------------------
                // make profile obj
                // -----------------------------------------
                std::string l_path;
                l_path = a_conf_dir_path + "/profile/" + m_cust_id + "-" + a_scope.profile_audit_id() +".wafprof.json";
                profile* l_profile = new profile(m_engine);
                int32_t l_s;
                char* l_buf = NULL;
                uint32_t l_buf_len;
                l_s = read_file(l_path.c_str(), &l_buf, l_buf_len);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", ns_waflz::get_err_msg());
                        if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        if (l_profile) { delete l_profile; l_profile = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                l_s = l_profile->load(l_buf, l_buf_len);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", l_profile->get_err_msg());
                        if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                       if (l_profile) { delete l_profile; l_profile = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                // -----------------------------------------
                // add to map
                // -----------------------------------------
                a_scope.set__profile_audit__reserved((uint64_t)l_profile);
                m_id_profile_map[a_scope.profile_audit_id()] = l_profile;
        }
profile_audit_action:
        // -------------------------------------------------
        // profile audit action
        // -------------------------------------------------
        if (a_scope.has_profile_audit_action())
        {
                waflz_pb::enforcement* l_a = a_scope.mutable_profile_audit_action();
                int32_t l_s;
                l_s = compile_action(*l_a, m_err_msg);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // profile prod
        // -------------------------------------------------
        if (a_scope.has_profile_prod_id())
        {
                // -----------------------------------------
                // check exist
                // -----------------------------------------
                id_profile_map_t::iterator i_profile = m_id_profile_map.find(a_scope.profile_prod_id());
                if (i_profile != m_id_profile_map.end())
                {
                        a_scope.set__profile_prod__reserved((uint64_t)i_profile->second);
                        goto profile_prod_action;
                }
                // -----------------------------------------
                // make profile obj
                // -----------------------------------------
                std::string l_path;
                l_path = a_conf_dir_path + "/profile/" + m_cust_id + "-" + a_scope.profile_prod_id() +".wafprof.json";
                profile* l_profile = new profile(m_engine);
                int32_t l_s;
                char* l_buf = NULL;
                uint32_t l_buf_len;
                l_s = read_file(l_path.c_str(), &l_buf, l_buf_len);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", ns_waflz::get_err_msg());
                        if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        if (l_profile) { delete l_profile; l_profile = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                l_s = l_profile->load(l_buf, l_buf_len);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", l_profile->get_err_msg());
                        if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        if (l_profile) { delete l_profile; l_profile = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                // -----------------------------------------
                // add to map
                // -----------------------------------------
                a_scope.set__profile_prod__reserved((uint64_t)l_profile);
                m_id_profile_map[a_scope.profile_prod_id()] = l_profile;
        }
profile_prod_action:
        // -------------------------------------------------
        // profile audit action
        // -------------------------------------------------
        if (a_scope.has_profile_prod_action())
        {
                waflz_pb::enforcement* l_a = a_scope.mutable_profile_prod_action();
                int32_t l_s;
                l_s = compile_action(*l_a, m_err_msg);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // api_gw audit
        // -------------------------------------------------
        if (a_scope.has_api_gw_audit_id())
        {
                // -----------------------------------------
                // check exist
                // -----------------------------------------
                id_api_gw_map_t::iterator i_api_gw = m_id_api_gw_map.find(a_scope.api_gw_audit_id());
                if (i_api_gw != m_id_api_gw_map.end())
                {
                        a_scope.set__api_gw_audit__reserved((uint64_t)i_api_gw->second);
                        goto api_gw_audit_action;
                }
                // -----------------------------------------
                // make api_gw obj
                // -----------------------------------------
                std::string l_path;
                l_path = a_conf_dir_path + "/api_gw/" + m_cust_id + "-" + a_scope.api_gw_audit_id() +".api_gw.json";
                api_gw* l_api_gw = new api_gw(m_engine);
                int32_t l_s;
                char* l_buf = NULL;
                uint32_t l_buf_len;
                l_s = read_file(l_path.c_str(), &l_buf, l_buf_len);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", ns_waflz::get_err_msg());
                        if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        if (l_api_gw) { delete l_api_gw; l_api_gw = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                l_s = l_api_gw->load(l_buf, l_buf_len, a_conf_dir_path);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", l_api_gw->get_err_msg());
                        if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        if (l_api_gw) { delete l_api_gw; l_api_gw = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                // -----------------------------------------
                // add to map
                // -----------------------------------------
                a_scope.set__api_gw_audit__reserved((uint64_t)l_api_gw);
                m_id_api_gw_map[a_scope.api_gw_audit_id()] = l_api_gw;
        }
api_gw_audit_action:
        // -------------------------------------------------
        // api_gw audit action
        // -------------------------------------------------
        if (a_scope.has_api_gw_audit_action())
        {
                waflz_pb::enforcement* l_a = a_scope.mutable_api_gw_audit_action();
                int32_t l_s;
                l_s = compile_action(*l_a, m_err_msg);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // api_gw prod
        // -------------------------------------------------
        if (a_scope.has_api_gw_prod_id())
        {
                // -----------------------------------------
                // check exist
                // -----------------------------------------
                id_api_gw_map_t::iterator i_api_gw = m_id_api_gw_map.find(a_scope.api_gw_prod_id());
                if (i_api_gw != m_id_api_gw_map.end())
                {
                        a_scope.set__api_gw_prod__reserved((uint64_t)i_api_gw->second);
                        goto api_gw_prod_action;
                }
                // -----------------------------------------
                // make api_gw obj
                // -----------------------------------------
                std::string l_path;
                l_path = a_conf_dir_path + "/api_gw/" + m_cust_id + "-" + a_scope.api_gw_prod_id() +".api_gw.json";
                api_gw* l_api_gw = new api_gw(m_engine);
                int32_t l_s;
                char* l_buf = NULL;
                uint32_t l_buf_len;
                l_s = read_file(l_path.c_str(), &l_buf, l_buf_len);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", ns_waflz::get_err_msg());
                        if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        if (l_api_gw) { delete l_api_gw; l_api_gw = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                l_s = l_api_gw->load(
                    l_buf,
                    l_buf_len,
                    a_conf_dir_path);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", l_api_gw->get_err_msg());
                        if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        if (l_api_gw) { delete l_api_gw; l_api_gw = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                // -----------------------------------------
                // add to map
                // -----------------------------------------
                a_scope.set__api_gw_prod__reserved((uint64_t)l_api_gw);
                m_id_api_gw_map[a_scope.api_gw_prod_id()] = l_api_gw;
        }
api_gw_prod_action:
        // -------------------------------------------------
        // api_gw audit action
        // -------------------------------------------------
        if (a_scope.has_api_gw_prod_action())
        {
                waflz_pb::enforcement* l_a = a_scope.mutable_api_gw_prod_action();
                int32_t l_s;
                l_s = compile_action(*l_a, m_err_msg);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // client waf prod
        // -------------------------------------------------
        if (a_scope.has_client_waf_config_id())
        {
                // -----------------------------------------
                // check if client waf config exists
                // -----------------------------------------
                const std::string& l_id = a_scope.client_waf_config_id();
                id_client_waf_map_t::iterator i_cs_config = m_id_client_waf_map.find(l_id);
                if (i_cs_config != m_id_client_waf_map.end())
                {
                        a_scope.set__client_waf_config__reserved((uint64_t)i_cs_config->second);
                        goto limit_configs;
                }
                // -----------------------------------------
                // construct path to client waf file
                // -----------------------------------------
                std::string l_file_name = m_cust_id + "-" + l_id + ".client_waf.json";
                std::string l_path = a_conf_dir_path + "/client_waf/" + l_file_name;
                // -----------------------------------------
                // read file
                // -----------------------------------------
                char* l_buf = NULL;
                uint32_t l_buf_len;
                int32_t l_s = read_file(l_path.c_str(), &l_buf, l_buf_len);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", ns_waflz::get_err_msg());
                        if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // create client waf object
                // -----------------------------------------
                client_waf* l_client_waf = new client_waf(m_engine);
                l_s = l_client_waf->load(l_buf, l_buf_len);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", l_client_waf->get_err_msg());
                        if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        if (l_client_waf) { delete l_client_waf; l_client_waf = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // cleanup & added to map
                // -----------------------------------------
                if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                a_scope.set__client_waf_config__reserved((uint64_t)l_client_waf);
                m_id_client_waf_map[l_id] = l_client_waf;
        }
limit_configs:
        // -------------------------------------------------
        // limits
        // -------------------------------------------------
        for (int i_l = 0; i_l < a_scope.limits_size(); ++i_l)
        {
                if (!a_scope.limits(i_l).has_id())
                {
                        continue;
                }
                const std::string& l_id = a_scope.limits(i_l).id();
                // -----------------------------------------
                // check exist...
                // -----------------------------------------
                id_limit_map_t::iterator i_limit = m_id_limit_map.find(l_id);
                if (i_limit != m_id_limit_map.end())
                {
                        a_scope.mutable_limits(i_l)->set__reserved_1((uint64_t)i_limit->second);
                        goto limit_action;
                }
                {
                // -----------------------------------------
                // make limit obj
                // -----------------------------------------
                std::string l_path;
                l_path = a_conf_dir_path + "/limit/" + m_cust_id + "-" + l_id +".limit.json";
                limit* l_limit = new limit(m_db);
                int32_t l_s;
                char* l_buf = NULL;
                uint32_t l_buf_len;
                l_s = read_file(l_path.c_str(), &l_buf, l_buf_len);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", ns_waflz::get_err_msg());
                        if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        if (l_limit) { delete l_limit; l_limit = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                l_s = l_limit->load(l_buf, l_buf_len);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", l_limit->get_err_msg());
                        if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        if (l_limit) { delete l_limit; l_limit = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                if (l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                // -----------------------------------------
                // add the pop count flag if missing in
                // config
                // -----------------------------------------
                if (!l_limit->get_pb()->has_enable_pop_count())
                {
                        l_limit->set_enable_pop_count(m_engine.get_use_pop_count());
                }
                // -----------------------------------------
                // add to map
                // -----------------------------------------
                a_scope.mutable_limits(i_l)->set__reserved_1((uint64_t)l_limit);
                m_id_limit_map[l_id] = l_limit;
                }
limit_action:
                // -----------------------------------------
                // limit action
                // -----------------------------------------
                if (a_scope.limits(i_l).has_action())
                {
                        waflz_pb::enforcement* l_a = a_scope.mutable_limits(i_l)->mutable_action();
                        int32_t l_s;
                        l_s = compile_action(*l_a, m_err_msg);
                        if (l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        //NDBG_PRINT("%s\n", a_scope.DebugString().c_str());
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details extern function to call process and pass on event info
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::process_request_plugin(void** ao_enf,
                                       size_t* ao_enf_len,
                                       void** ao_audit_event,
                                       size_t* ao_audit_event_len,
                                       void** ao_prod_event,
                                       size_t* ao_prod_event_len,
                                       void* a_ctx,
                                       const rqst_ctx_callbacks* a_cb,
                                       rqst_ctx** ao_rqst_ctx)
{
        waflz_pb::event* l_audit_event = NULL;
        waflz_pb::event* l_prod_event = NULL;
        waflz_pb::event* l_bot_event = NULL;
        const waflz_pb::enforcement* l_enf = NULL;
        int32_t l_s;
        l_s = process(&l_enf,
                      &l_audit_event,
                      &l_prod_event,
                      &l_bot_event,
                      a_ctx,
                      PART_MK_ALL,
                      a_cb,
                      ao_rqst_ctx,
                      NULL,
                      -1);
        if (l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // Serialize all proto msgs
        // -------------------------------------------------
        if (l_enf)
        {
#if GOOGLE_PROTOBUF_VERSION < 3006001
                size_t l_enf_size = l_enf->ByteSize();
#else
                size_t l_enf_size = l_enf->ByteSizeLong();
#endif
                void* l_enf_buffer = malloc(l_enf_size);
                l_enf->SerializeToArray(l_enf_buffer, l_enf_size);
                *ao_enf = l_enf_buffer;
                *ao_enf_len = l_enf_size;
        }
        if (l_audit_event)
        {
#if GOOGLE_PROTOBUF_VERSION < 3006001
                size_t l_event_len = l_audit_event->ByteSize();
#else
                size_t l_event_len = l_audit_event->ByteSizeLong();
#endif
                void* l_event = malloc(l_event_len);
                l_audit_event->SerializeToArray(l_event, l_event_len);
                *ao_audit_event = l_event;
                *ao_audit_event_len = l_event_len;
        }
        if (l_prod_event)
        {
#if GOOGLE_PROTOBUF_VERSION < 3006001
                size_t l_event_len = l_prod_event->ByteSize();
#else
                size_t l_event_len = l_prod_event->ByteSizeLong();
#endif
                void* l_event = malloc(l_event_len);
                l_prod_event->SerializeToArray(l_event, l_event_len);
                *ao_prod_event = l_event;
                *ao_prod_event_len = l_event_len;
        }
        return l_s;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::process(const waflz_pb::enforcement** ao_enf,
                        waflz_pb::event** ao_audit_event,
                        waflz_pb::event** ao_prod_event,
                        waflz_pb::event** ao_bot_event,
                        void* a_ctx,
                        part_mk_t a_part_mk,
                        const rqst_ctx_callbacks* a_cb,
                        rqst_ctx** ao_rqst_ctx,
                        void* a_srv,
                        int32_t a_module_id)
{
        if (!m_pb)
        {
                WAFLZ_PERROR(m_err_msg, "pb == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // create rqst_ctx
        // -------------------------------------------------
        rqst_ctx* l_ctx = NULL;
        if (ao_rqst_ctx)
        {
                // special handling for captcha second process
                // call which carries the ctx created 
                // from first process call.
                if (*ao_rqst_ctx != NULL)
                {
                        l_ctx = *ao_rqst_ctx;
                }
                else
                {
                        l_ctx = new rqst_ctx(a_ctx,
                                             DEFAULT_BODY_SIZE_MAX,
                                             DEFAULT_BODY_API_SEC_SIZE_MAX,
                                             a_cb,
                                             false,
                                             false,
                                             a_srv,
                                             a_module_id);
                        *ao_rqst_ctx = l_ctx;       
                }
        }
        if(m_cust_id == "FA1AFE12")
        {
                l_ctx->m_falafel = true;
        }
        if(m_cust_id == "FE1AFE12")
        {
                l_ctx->m_felafel = true;
        }
        // -------------------------------------------------
        // run phase 1 init
        // -------------------------------------------------
        int32_t l_s;
        m_engine.set_bot_lmdb(m_bot_db);
        l_ctx->m_gather_bot_score = (m_pb->has_bot_tier() &&
                                     (m_pb->bot_tier() == "A" || m_pb->bot_tier() == "P"));
        l_s = l_ctx->init_phase_1(m_engine, NULL, NULL, NULL);
        if (l_s != WAFLZ_STATUS_OK)
        {
                // TODO -log error???
                if (!ao_rqst_ctx && l_ctx) { delete l_ctx; l_ctx = NULL; }
                WAFLZ_PERROR(m_err_msg, "%s", l_ctx->get_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // for each scope...
        // -------------------------------------------------
        for (int i_s = 0; i_s < m_pb->scopes_size(); ++i_s)
        {
                const ::waflz_pb::scope& l_sc = m_pb->scopes(i_s);
                bool l_m;
                l_s = in_scope(l_m, l_sc, l_ctx);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "in_scope error");
                        if (!ao_rqst_ctx && l_ctx) { delete l_ctx; l_ctx = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // no match continue to next check...
                // -----------------------------------------
                if (!l_m)
                {
                        continue;
                }
                // -----------------------------------------
                // spoof ip if setting enabled
                // -----------------------------------------
                if (
                        l_sc.has_use_spoof_ip_header() && 
                        l_sc.use_spoof_ip_header() &&
                        l_sc.has_spoof_ip_header() && 
                        !l_sc.spoof_ip_header().empty()
                )
                {
                        l_s = (*ao_rqst_ctx)->set_src_ip_from_spoof_header(l_sc.spoof_ip_header());
                        if (l_s == WAFLZ_STATUS_OK)
                        {
                                l_s = (*ao_rqst_ctx)->get_geo_data_from_mmdb(m_engine.get_geoip2_mmdb());
                                if (l_s != WAFLZ_STATUS_OK)
                                {
                                        WAFLZ_PERROR(m_err_msg, "get_geo_data_from_mmdb error");
                                }
                                if (m_engine.get_use_bot_lmdb() &&
                                    (*ao_rqst_ctx)->get_bot_score(m_bot_db) != WAFLZ_STATUS_OK)
                                {
                                        WAFLZ_PERROR(m_err_msg, "%s", (*ao_rqst_ctx)->get_err_msg());
                                }
                                else if (m_engine.get_use_bot_lmdb_new() &&
                                    (*ao_rqst_ctx)->get_bot_score(m_bot_db, true) != WAFLZ_STATUS_OK)
                                {
                                        WAFLZ_PERROR(m_err_msg, "%s", (*ao_rqst_ctx)->get_err_msg());
                                }
                        }
                }
                // -----------------------------------------
                // set recaptcha keys in ctx for doing 
                // sub request and rendering
                // -----------------------------------------
                if (l_sc.has_recaptcha_site_key() &&
                    !l_sc.recaptcha_site_key().empty())
                {
                        (*ao_rqst_ctx)->set_recaptcha_fields(l_sc.recaptcha_site_key(),
                                                             l_sc.recaptcha_secret_key(),
                                                             l_sc.recaptcha_action_name());
                }
                // -----------------------------------------
                // process request
                // -----------------------------------------
                l_s = process(ao_enf,
                              ao_audit_event,
                              ao_prod_event,
                              ao_bot_event,
                              l_sc, a_ctx,
                              a_part_mk,
                              ao_rqst_ctx);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        if(l_s == WAFLZ_STATUS_WAIT)
                        {
                                //not deleting ctx, because 
                                // validate call will need it.
                                populate_event(ao_bot_event, l_sc);
                                return WAFLZ_STATUS_WAIT;
                        }
                        if (!ao_rqst_ctx && l_ctx) { delete l_ctx; l_ctx = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // Log scope id, name and account info
                // that generated an event
                // -----------------------------------------
                populate_event(ao_audit_event, l_sc);
                populate_event(ao_prod_event, l_sc);
                populate_event(ao_bot_event, l_sc);
                if (!*ao_prod_event ||
                    !*ao_enf ||
                    (*ao_enf && (*ao_enf)->enf_type() == waflz_pb::enforcement_type_t::enforcement_type_t_ALERT))
                {
                        for (int i = 0; i < l_sc.origin_signal_headers_size(); ++i)
                        {
                                const waflz_pb::enforcement_header_t l_os_hdr = l_sc.origin_signal_headers(i);
                                data_t l_hdr_key;
                                (*ao_rqst_ctx)->m_origin_signal_map[l_os_hdr.type()] = l_os_hdr.key();
                        }
                }
                // -----------------------------------------
                // break out on first scope match
                // -----------------------------------------
                break;
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if (!ao_rqst_ctx && l_ctx) { delete l_ctx; l_ctx = NULL; }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::process_response(const waflz_pb::enforcement **ao_enf,
                        waflz_pb::event **ao_audit_event,
                        waflz_pb::event **ao_prod_event,
                        void *a_ctx,
                        part_mk_t a_part_mk,
                        const resp_ctx_callbacks *a_cb,
                        resp_ctx **ao_resp_ctx,
                        void* a_srv,
                        int32_t a_content_length)
{
        if (!m_pb)
        {
                WAFLZ_PERROR(m_err_msg, "pb == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // create resp_ctx
        // -------------------------------------------------
        resp_ctx *l_ctx = NULL;
        l_ctx = new resp_ctx(a_ctx, DEFAULT_RESP_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, a_cb, a_content_length, a_srv);
        if (ao_resp_ctx)
        {
                *ao_resp_ctx = l_ctx;
        }
        // -------------------------------------------------
        // run phase 3 init
        // -------------------------------------------------
        int32_t l_s;
        l_s = l_ctx->init_phase_3(m_engine.get_geoip2_mmdb());
        if (l_s != WAFLZ_STATUS_OK)
        {
                // TODO -log error???
                if (!ao_resp_ctx && l_ctx) { delete l_ctx; l_ctx = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // for each scope...
        // -------------------------------------------------
        for(int i_s = 0; i_s < m_pb->scopes_size(); ++i_s)
        {
                const ::waflz_pb::scope& l_sc = m_pb->scopes(i_s);       
                bool l_m;
                l_s = in_scope_response(l_m, l_sc, l_ctx);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "in_scope_response error");
                        if (!ao_resp_ctx && l_ctx) { delete l_ctx; l_ctx = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // no match continue to next check...
                // -----------------------------------------
                if (!l_m)
                {
                        continue;
                }
                l_s = process_response(ao_enf,
                              ao_audit_event,
                              ao_prod_event,
                              l_sc, a_ctx,
                              a_part_mk,
                              ao_resp_ctx,
                              a_content_length);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "process_response error");
                        if (!ao_resp_ctx && l_ctx) { delete l_ctx; l_ctx = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // Log scope id, name and account info
                // that generated an event
                // -----------------------------------------
                populate_event(ao_audit_event, l_sc);
                populate_event(ao_prod_event, l_sc);
                // -----------------------------------------
                // -----------------------------------------
                // break out on first scope match
                // -----------------------------------------
                break;
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if (!ao_resp_ctx && l_ctx) { delete l_ctx; l_ctx = NULL; }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::process_response_phase_3(const waflz_pb::enforcement **ao_enf,
                        waflz_pb::event **ao_audit_event,
                        waflz_pb::event **ao_prod_event,
                        void *a_ctx,
                        part_mk_t a_part_mk,
                        const resp_ctx_callbacks *a_cb,
                        resp_ctx **ao_resp_ctx,
                        void* a_srv)
{
        if (!m_pb)
        {
                WAFLZ_PERROR(m_err_msg, "pb == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // create resp_ctx
        // -------------------------------------------------
        resp_ctx *l_ctx = NULL;
        l_ctx = new resp_ctx(a_ctx, DEFAULT_RESP_BODY_SIZE_MAX, DEFAULT_BODY_API_SEC_SIZE_MAX, a_cb, 0, a_srv);
        if (ao_resp_ctx)
        {
                *ao_resp_ctx = l_ctx;
        }
        // -------------------------------------------------
        // run phase 3 init
        // -------------------------------------------------
        int32_t l_s;
        l_s = l_ctx->init_phase_3(m_engine.get_geoip2_mmdb());
        if (l_s != WAFLZ_STATUS_OK)
        {
                // TODO -log error???
                if (!ao_resp_ctx && l_ctx) { delete l_ctx; l_ctx = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // for each scope...
        // -------------------------------------------------
        for(int i_s = 0; i_s < m_pb->scopes_size(); ++i_s)
        {
                const ::waflz_pb::scope& l_sc = m_pb->scopes(i_s);       
                bool l_m;
                l_s = in_scope_response(l_m, l_sc, l_ctx);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "in_scope_response error");
                        if (!ao_resp_ctx && l_ctx) { delete l_ctx; l_ctx = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // no match continue to next check...
                // -----------------------------------------
                if (!l_m)
                {
                        continue;
                }
                l_s = process_response_phase_3(ao_enf,
                              ao_audit_event,
                              ao_prod_event,
                              l_sc, a_ctx,
                              a_part_mk,
                              ao_resp_ctx);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "process_response phase 3 error");
                        if (!ao_resp_ctx && l_ctx) { delete l_ctx; l_ctx = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // Log scope id, name and account info
                // that generated an event
                // -----------------------------------------
                populate_event(ao_audit_event, l_sc);
                populate_event(ao_prod_event, l_sc);
                // -----------------------------------------
                // -----------------------------------------
                // break out on first scope match
                // -----------------------------------------
                break;
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if (!ao_resp_ctx && l_ctx) { delete l_ctx; l_ctx = NULL; }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details if a_loaded_date is >= a_new_Date
//! \return  False
//! \param   TODO
//! ----------------------------------------------------------------------------
bool scopes::compare_dates(const char* a_loaded_date, const char* a_new_date)
{
        if (a_loaded_date == NULL ||
           a_new_date == NULL)
        {
                return false;
        }
        uint64_t l_loaded_epoch = get_epoch_seconds(a_loaded_date, CONFIG_DATE_FORMAT);
        uint64_t l_new_epoch = get_epoch_seconds(a_new_date, CONFIG_DATE_FORMAT);
        if (l_loaded_epoch >= l_new_epoch)
        {
                return false;
        }
        return true;
}

//! ----------------------------------------------------------------------------
//! \details helper function to set account info and scope info in event
//! \return  False
//! \param   TODO
//! ----------------------------------------------------------------------------
void scopes::populate_event(waflz_pb::event** ao_event,
                              const waflz_pb::scope& a_sc)
{
        if (*ao_event)
        {
                (*ao_event)->set_scope_config_id(a_sc.id());
                (*ao_event)->set_scope_config_name(a_sc.name());
                (*ao_event)->set_account_type(m_account_type);
                (*ao_event)->set_partner_id(m_partner_id);
                (*ao_event)->set_bot_tier(m_bot_tier);
        }
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::load_limit(ns_waflz::limit* a_limit)
{
        if (!a_limit)
        {
                return WAFLZ_STATUS_ERROR;
        }
        const std::string& l_id = a_limit->get_id();
        // -------------------------------------------------
        // check id in map
        // -------------------------------------------------
        id_limit_map_t::iterator i_t = m_id_limit_map.find(l_id);
        if (i_t == m_id_limit_map.end())
        {
                if (a_limit) { delete a_limit; a_limit = NULL; }
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // check if limit is latest
        // -------------------------------------------------
        const waflz_pb::limit* l_old_pb = i_t->second->get_pb();
        const waflz_pb::limit* l_new_pb = a_limit->get_pb();
        if ((l_old_pb != NULL) &&
           (l_new_pb != NULL) &&
           (l_old_pb->has_last_modified_date()) &&
           (l_new_pb->has_last_modified_date()))
        {
                if (!compare_dates(l_old_pb->last_modified_date().c_str(),
                                  l_new_pb->last_modified_date().c_str()))
                {
                        if (a_limit) { delete a_limit; a_limit = NULL; }
                        return WAFLZ_STATUS_OK;
                }
        }
        if (i_t->second) { delete i_t->second; i_t->second = NULL;}
        i_t->second = a_limit;
        // -------------------------------------------------
        // update scope's reserved fields
        // -------------------------------------------------
        for (int i_s = 0; i_s < m_pb->scopes_size(); ++i_s)
        {
                ::waflz_pb::scope& l_sc = *(m_pb->mutable_scopes(i_s));
                for (int i_l = 0; i_l < l_sc.limits_size(); ++i_l)
                {       
                        ::waflz_pb::scope_limit_config* l_slc = l_sc.mutable_limits(i_l);
                        if (l_slc->id() == l_id)
                        {
                                l_slc->set__reserved_1((uint64_t)a_limit);
                                break;
                        }
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::load_acl(ns_waflz::acl* a_acl)
{
        if (!a_acl)
        {
                return WAFLZ_STATUS_ERROR;
        }
        const std::string& l_id = a_acl->get_id();
        // -------------------------------------------------
        // check id in map
        // -------------------------------------------------
        id_acl_map_t::iterator i_t = m_id_acl_map.find(l_id);
        if (i_t == m_id_acl_map.end())
        {
                if (a_acl) { delete a_acl; a_acl = NULL; }
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // check if acl is latest
        // -------------------------------------------------
        const waflz_pb::acl* l_old_pb = i_t->second->get_pb();
        const waflz_pb::acl* l_new_pb = a_acl->get_pb();
        if ((l_old_pb != NULL) &&
           (l_new_pb != NULL) &&
           (l_old_pb->has_last_modified_date()) &&
           (l_new_pb->has_last_modified_date()))
        {
                if (!compare_dates(l_old_pb->last_modified_date().c_str(),
                                  l_new_pb->last_modified_date().c_str()))
                {
                        if (a_acl) { delete a_acl; a_acl = NULL; }
                        return WAFLZ_STATUS_OK;
                }
        }
        if (i_t->second) { delete i_t->second; i_t->second = NULL;}
        i_t->second = a_acl;
        // -------------------------------------------------
        // update scope's reserved fields
        // -------------------------------------------------
        for (int i_s = 0; i_s < m_pb->scopes_size(); ++i_s)
        {
                ::waflz_pb::scope& l_sc = *(m_pb->mutable_scopes(i_s));
                if (l_sc.has_acl_audit_id() &&
                   l_sc.acl_audit_id() == l_id)
                {
                        l_sc.set__acl_audit__reserved((uint64_t)a_acl);
                }
                if (l_sc.has_acl_prod_id() &&
                   l_sc.acl_prod_id() == l_id)
                {
                        l_sc.set__acl_prod__reserved((uint64_t)a_acl);
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::load_schema(ns_waflz::schema* a_schema)
{
        if (!a_schema)
        {
                return WAFLZ_STATUS_ERROR;
        }
        const std::string& l_id = a_schema->get_id();
        // -------------------------------------------------
        // get api gateway object
        // -------------------------------------------------
        const std::string& l_api_gw_id = a_schema->get_api_gw_id();
        auto i_t = m_id_api_gw_map.find(l_api_gw_id);
        if(i_t == m_id_api_gw_map.end()) {
                delete a_schema;
                return WAFLZ_STATUS_OK;
        }
        ns_waflz::api_gw* l_api_gw = i_t->second;
        waflz_pb::api_gw* l_api_gw_pb = l_api_gw->m_pb;
        // -----------------------------------------
        // Look in each api gateway entry
        // -----------------------------------------
        bool l_used = false;
        ns_waflz::schema* l_old_schema = nullptr;
        for (int i_s = 0; i_s < l_api_gw_pb->rules_size(); i_s++)
        {
                // ---------------------------------
                // Update reserved schema ptr
                // ---------------------------------
                waflz_pb::api_rule* l_rule_pb =
                    l_api_gw_pb->mutable_rules(i_s);
                if (l_rule_pb->schema_id() == l_id)
                {
                        l_old_schema =
                            (ns_waflz::schema*)l_rule_pb->_schema_reserved();
                        if (!compare_dates(
                                l_old_schema->get_last_modified_date().c_str(),
                                a_schema->get_last_modified_date().c_str()))
                        {
                                WAFLZ_PERROR(m_err_msg, "schema last modified date incorrect");
                                delete a_schema;
                                return WAFLZ_STATUS_OK;
                        }
                        l_rule_pb->set__schema_reserved((uint64_t)a_schema);
                        l_used = true;
                }
        }
        if (!l_used)
        {
                WAFLZ_PERROR(m_err_msg, "schema not used in api gateway config");
                delete a_schema;
                return WAFLZ_STATUS_OK;
        }
        l_api_gw->add_schema_to_map(a_schema);
        delete l_old_schema;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::load_rules(ns_waflz::rules* a_rules)
{
        if (!a_rules)
        {
                return WAFLZ_STATUS_ERROR;
        }
        const std::string& l_id = a_rules->get_id();
        // -------------------------------------------------
        // check id in map
        // -------------------------------------------------
        id_rules_map_t::iterator i_t = m_id_rules_map.find(l_id);
        if (i_t == m_id_rules_map.end())
        {
                if (a_rules) {delete a_rules; a_rules = NULL;}
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // check if rules is latest
        // -------------------------------------------------
        const waflz_pb::sec_config_t* l_old_pb = i_t->second->get_pb();
        const waflz_pb::sec_config_t* l_new_pb = a_rules->get_pb();
        if ((l_old_pb != NULL) &&
           (l_new_pb != NULL) &&
           (l_old_pb->has_last_modified_date()) &&
           (l_new_pb->has_last_modified_date()))
        {
                if (!compare_dates(l_old_pb->last_modified_date().c_str(),
                                  l_new_pb->last_modified_date().c_str()))
                {
                        if (a_rules) { delete a_rules; a_rules = NULL; }
                        return WAFLZ_STATUS_OK;
                }
        }
        if (i_t->second) { delete i_t->second; i_t->second = NULL;}
        i_t->second = a_rules;
        // -------------------------------------------------
        // update scope's reserved fields
        // -------------------------------------------------
        for (int i_s = 0; i_s < m_pb->scopes_size(); ++i_s)
        {
                ::waflz_pb::scope& l_sc = *(m_pb->mutable_scopes(i_s));
                if (l_sc.has_rules_audit_id() &&
                   l_sc.rules_audit_id() == l_id)
                {
                        l_sc.set__rules_audit__reserved((uint64_t)a_rules);
                }
                if (l_sc.has_rules_prod_id() &&
                   l_sc.rules_prod_id() == l_id)
                {
                        l_sc.set__rules_prod__reserved((uint64_t)a_rules);
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::load_bots(void* a_js)
{
        // -------------------------------------------------
        // loop through the bot_managers in the config
        // -------------------------------------------------
        bool l_update = false;
        for(auto i: m_id_bot_manager_map)
        {
                // -----------------------------------------
                // quick exit if bot_manager doesnt exist
                // ???
                // -----------------------------------------
                ns_waflz::bot_manager* l_botm = i.second;
                if(!l_botm)
                {
                        continue;
                }
                // -----------------------------------------
                // give json to bot_manager to update bots
                // config
                // -----------------------------------------
                uint32_t l_s = l_botm->load_bots(a_js, l_update);
                // -----------------------------------------
                // bubble up error message on failed attempt
                // -----------------------------------------
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "reason: %.*s", WAFLZ_ERR_REASON_LEN, l_botm->get_err_msg());
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // l_update is set to true, if the timestamp 
                // is not latest.
                // -----------------------------------------
                if (l_update)
                {
                        break;
                }
        }
        // -------------------------------------------------
        // return status ok
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::load_bot_manager(ns_waflz::bot_manager* a_bot_manager)
{
        if (!a_bot_manager)
        {
                return WAFLZ_STATUS_ERROR;
        }
        const std::string& l_id = a_bot_manager->get_id();
        // -------------------------------------------------
        // check id in map
        // -------------------------------------------------
        id_bot_manager_map_t::iterator i_t = m_id_bot_manager_map.find(l_id);
        if (i_t == m_id_bot_manager_map.end())
        {
                if (a_bot_manager) { delete a_bot_manager; a_bot_manager = NULL; }
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // check if bot manager is latest
        // -------------------------------------------------
        const waflz_pb::bot_manager* l_old_pb = i_t->second->get_pb();
        const waflz_pb::bot_manager* l_new_pb = a_bot_manager->get_pb();
        if ((l_old_pb != NULL) &&
           (l_new_pb != NULL) &&
           (l_old_pb->has_last_modified_date()) &&
           (l_new_pb->has_last_modified_date()))
        {
                if (!compare_dates(l_old_pb->last_modified_date().c_str(),
                                  l_new_pb->last_modified_date().c_str()))
                {
                        if (a_bot_manager) { delete a_bot_manager; a_bot_manager = NULL; }
                        return WAFLZ_STATUS_OK;
                }
        }
        if (i_t->second) { delete i_t->second; i_t->second = NULL;}
        i_t->second = a_bot_manager;
        // -------------------------------------------------
        // update scope's reserved fields
        // -------------------------------------------------
        for (int i_s = 0; i_s < m_pb->scopes_size(); ++i_s)
        {
                ::waflz_pb::scope& l_sc = *(m_pb->mutable_scopes(i_s));
                if (l_sc.has_bot_manager_config_id() &&
                   l_sc.bot_manager_config_id() == l_id)
                {
                        l_sc.set__bot_manager_config__reserved((uint64_t)a_bot_manager);
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::load_api_gw(ns_waflz::api_gw* a_api_gw)
{
        if (!a_api_gw)
        {
                return WAFLZ_STATUS_ERROR;
        }
        const std::string& l_id = a_api_gw->get_id();
        // -------------------------------------------------
        // check id in map
        // -------------------------------------------------
        id_api_gw_map_t::iterator i_t = m_id_api_gw_map.find(l_id);
        if (i_t == m_id_api_gw_map.end())
        {
                if (a_api_gw) { delete a_api_gw; a_api_gw = NULL; }
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // check if api gateway is latest
        // -------------------------------------------------
        const waflz_pb::api_gw* l_old_pb = i_t->second->get_pb();
        const waflz_pb::api_gw* l_new_pb = a_api_gw->get_pb();
        if ((l_old_pb != NULL) &&
           (l_new_pb != NULL) &&
           (l_old_pb->has_last_modified_date()) &&
           (l_new_pb->has_last_modified_date()))
        {
                if (!compare_dates(l_old_pb->last_modified_date().c_str(),
                                  l_new_pb->last_modified_date().c_str()))
                {
                        if (a_api_gw) { delete a_api_gw; a_api_gw = NULL; }
                        return WAFLZ_STATUS_OK;
                }
        }
        if (i_t->second) { delete i_t->second; i_t->second = NULL;}
        i_t->second = a_api_gw;
        // -------------------------------------------------
        // update scope's reserved fields
        // -------------------------------------------------
        for (int i_s = 0; i_s < m_pb->scopes_size(); ++i_s)
        {
                ::waflz_pb::scope& l_sc = *(m_pb->mutable_scopes(i_s));
                if (l_sc.has_api_gw_audit_id() &&
                   l_sc.api_gw_audit_id() == l_id)
                {
                        l_sc.set__api_gw_audit__reserved((uint64_t)a_api_gw);
                }
                if (l_sc.has_api_gw_prod_id() &&
                   l_sc.api_gw_prod_id() == l_id)
                {
                        l_sc.set__api_gw_prod__reserved((uint64_t)a_api_gw);
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::load_profile(ns_waflz::profile* a_profile)
{
        if (!a_profile)
        {
                return WAFLZ_STATUS_ERROR;
        }
        const std::string& l_id = a_profile->get_id();
        // -------------------------------------------------
        // check id in map
        // -------------------------------------------------
        id_profile_map_t::iterator i_t = m_id_profile_map.find(l_id);
        if (i_t == m_id_profile_map.end())
        {
                if (a_profile) { delete a_profile; a_profile = NULL; }
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // check if profile is latest
        // -------------------------------------------------
        const waflz_pb::profile* l_old_pb = i_t->second->get_pb();
        const waflz_pb::profile* l_new_pb = a_profile->get_pb();
        if ((l_old_pb != NULL) &&
           (l_new_pb != NULL) &&
           (l_old_pb->has_last_modified_date()) &&
           (l_new_pb->has_last_modified_date()))
        {
                if (!compare_dates(l_old_pb->last_modified_date().c_str(),
                                  l_new_pb->last_modified_date().c_str()))
                {
                        if (a_profile) { delete a_profile; a_profile = NULL; }
                        return WAFLZ_STATUS_OK;
                }
        }
        if (i_t->second) { delete i_t->second; i_t->second = NULL;}
        i_t->second = a_profile;
        // -------------------------------------------------
        // update scope's reserved fields
        // -------------------------------------------------
        for (int i_s = 0; i_s < m_pb->scopes_size(); ++i_s)
        {
                ::waflz_pb::scope& l_sc = *(m_pb->mutable_scopes(i_s));

                if (l_sc.has_profile_audit_id() &&
                    l_sc.profile_audit_id() == l_id)
                {
                        l_sc.set__profile_audit__reserved((uint64_t)a_profile);
                }       
                if (l_sc.has_profile_prod_id() &&
                    l_sc.profile_prod_id() == l_id)
                {
                        l_sc.set__profile_prod__reserved((uint64_t)a_profile);
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::load_client_waf(ns_waflz::client_waf* a_client_waf)
{
        // -------------------------------------------------
        // quick exit if there was no config passed
        // -------------------------------------------------
        if (!a_client_waf) { return WAFLZ_STATUS_ERROR; }
        // -------------------------------------------------
        // check id in map
        // -------------------------------------------------
        const std::string& l_id = a_client_waf->get_id();
        id_client_waf_map_t::iterator i_t = m_id_client_waf_map.find(l_id);
        if (i_t == m_id_client_waf_map.end())
        {
                if (a_client_waf) { delete a_client_waf; a_client_waf = NULL; }
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // check if client_waf is latest
        // -------------------------------------------------
        const waflz_pb::client_waf* l_old_pb = i_t->second->get_pb();
        const waflz_pb::client_waf* l_new_pb = a_client_waf->get_pb();
        if ((l_old_pb != NULL) &&
            (l_new_pb != NULL) &&
            (l_old_pb->has_last_modified_date()) &&
            (l_new_pb->has_last_modified_date()))
        {
                if (!compare_dates(l_old_pb->last_modified_date().c_str(),
                                  l_new_pb->last_modified_date().c_str()))
                {
                        if (a_client_waf) { delete a_client_waf; a_client_waf = NULL; }
                        return WAFLZ_STATUS_OK;
                }
        }
        if (i_t->second) { delete i_t->second; i_t->second = NULL;}
        i_t->second = a_client_waf;
        // -------------------------------------------------
        // update scope's reserved fields
        // -------------------------------------------------
        for (int i_s = 0; i_s < m_pb->scopes_size(); ++i_s)
        {
                ::waflz_pb::scope& l_sc = *(m_pb->mutable_scopes(i_s));
                if (l_sc.has_client_waf_config_id() &&
                   l_sc.client_waf_config_id() == l_id)
                {
                        l_sc.set__client_waf_config__reserved((uint64_t)a_client_waf);
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::process_response_phase_3(const waflz_pb::enforcement** ao_enf,
                                         waflz_pb::event** ao_audit_event,
                                         waflz_pb::event** ao_prod_event,
                                         const ::waflz_pb::scope& a_scope,
                                         void *a_ctx,
                                         part_mk_t a_part_mk,
                                         resp_ctx **ao_resp_ctx)
{
        // -------------------------------------------------
        // sanity checking
        // -------------------------------------------------
        if (!ao_enf ||
           !ao_audit_event ||
           !ao_prod_event)
        {
                // TODO reason???
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // clear ao_* inputs
        // -------------------------------------------------
        *ao_enf = NULL;
        *ao_audit_event = NULL;
        *ao_prod_event = NULL;
        // -------------------------------------------------
        // limits
        // -------------------------------------------------
        if (a_part_mk & PART_MK_LIMITS)
        {
                for (int i_l = 0; i_l < a_scope.limits_size(); ++i_l)
                {
                        int32_t l_s;
                        const ::waflz_pb::scope_limit_config& l_slc = a_scope.limits(i_l);
                        if ((!l_slc.has__reserved_1()) || (!l_slc.has_action()))
                        {
                                continue;
                        }
                        limit* l_limit = (limit *)l_slc._reserved_1();
                        // ---------------------------------
                        // skip this limit if it is for
                        // requests
                        // ---------------------------------
                        if (!l_limit->is_response_limit()) { continue; }
                        // ---------------------------------
                        // skip this limit if it is in alert
                        // and we already have an alert
                        // limit on the rqst_ctx
                        // ---------------------------------
                        const bool l_already_have_alert = (*ao_resp_ctx)->m_audit_limit;
                        const bool l_is_alert = l_slc.action().enf_type() == waflz_pb::enforcement_type_t_ALERT;
                        if (l_already_have_alert && l_is_alert)
                        {
                                continue;
                        }
                        // ---------------------------------
                        // process limit
                        // ---------------------------------
                        bool l_exceeds = false;
                        const waflz_pb::condition_group* l_cg = NULL;
                        l_s = l_limit->process_response(l_exceeds, &l_cg, a_scope.id(), *ao_resp_ctx);
                        if (l_s != WAFLZ_STATUS_OK)
                        {
                                WAFLZ_PERROR(m_err_msg, "performing limit process response.");
                                return WAFLZ_STATUS_ERROR;
                        }
                        if (!l_exceeds)
                        {
                                continue;
                        }
                        // ---------------------------------
                        // signal new enforcement
                        // ---------------------------------
                        (*ao_resp_ctx)->m_signal_enf = true;
                        // ---------------------------------
                        // add new exceeds
                        // ---------------------------------
                        const waflz_pb::enforcement& l_axn = l_slc.action();
                        waflz_pb::config* l_cfg = NULL;
                        l_s = add_exceed_limit_for_response(&l_cfg,
                                               *(l_limit->get_pb()),
                                               l_cg,
                                               l_axn,
                                               a_scope,
                                               *ao_resp_ctx);
                        if (l_s != WAFLZ_STATUS_OK)
                        {
                                WAFLZ_PERROR(m_err_msg, "performing add_exceed_limit_for_response");
                                return WAFLZ_STATUS_ERROR;
                        }
                        // ---------------------------------
                        // get enforcer to use
                        // ---------------------------------
                        ns_waflz::enforcer* l_enforcer_for_request = (l_is_alert) ? m_audit_enfx : m_enfx;
                        // ---------------------------------
                        // merge enforcement
                        // ---------------------------------
                        //NDBG_OUTPUT("l_enfx: %s\n", l_enfcr->ShortDebugString().c_str());
                        l_s = l_enforcer_for_request->merge(*l_cfg);
                        if (l_s != WAFLZ_STATUS_OK)
                        {
                                WAFLZ_PERROR(m_err_msg, "error merging enforcer: %.*s",
                                             WAFLZ_ERR_REASON_LEN,
                                             l_enforcer_for_request->get_err_msg());
                                return WAFLZ_STATUS_ERROR;
                        }
                        if (l_cfg) { delete l_cfg; l_cfg = NULL; }
                        // ---------------------------------
                        // process enforcer
                        // ---------------------------------
                        l_s = l_enforcer_for_request->process_response(ao_enf, *ao_resp_ctx, !l_is_alert);
                        if (l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                        // ---------------------------------
                        // enforced???
                        // ---------------------------------
                        if (*ao_enf)
                        {
                                if ((*ao_enf)->has_status())
                                {
                                        (*ao_resp_ctx)->m_set_response_status = (*ao_enf)->status();
                                }
                        }
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::process_response(const waflz_pb::enforcement** ao_enf,
                        waflz_pb::event** ao_audit_event,
                        waflz_pb::event** ao_prod_event,
                        const ::waflz_pb::scope& a_scope,
                        void *a_ctx,
                        part_mk_t a_part_mk,
                        resp_ctx **ao_resp_ctx,
                        int32_t a_content_length)
{
        // -------------------------------------------------
        // sanity checking
        // -------------------------------------------------
        if (!ao_enf ||
           !ao_audit_event ||
           !ao_prod_event)
        {
                // TODO reason???
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // clear ao_* inputs
        // -------------------------------------------------
        *ao_enf = NULL;
        *ao_audit_event = NULL;
        *ao_prod_event = NULL;
        // -------------------------------------------------
        // Audit API GW
        // -------------------------------------------------
        if ((a_part_mk & PART_MK_API_GW) &&
            a_scope.has__api_gw_audit__reserved())
        {
                api_gw* l_api_gw = (api_gw*)a_scope._api_gw_audit__reserved();
                waflz_pb::event* l_event = NULL;
                int32_t l_s;
                l_s = l_api_gw->process_response(&l_event, a_ctx, ao_resp_ctx);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        if (l_event) { delete l_event; l_event = NULL; }
                        WAFLZ_PERROR(m_err_msg, "%s", l_api_gw->get_err_msg());
                        return WAFLZ_STATUS_ERROR;
                }
                if (!l_event)
                {
                        goto audit_profile;
                }
                l_s = (*ao_resp_ctx)->append_resp_info(*l_event);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "performing resp_ctx::append_resp_info for api gw");
                        return WAFLZ_STATUS_ERROR;
                }
                l_event->set_waf_profile_action(waflz_pb::enforcement_type_t_ALERT);
                if (a_scope.has_api_gw_audit_action() &&
                    a_scope.api_gw_audit_action().has_enf_type())
                {
                         l_event->set_waf_profile_action(a_scope.api_gw_audit_action().enf_type());
                }
                *ao_audit_event = l_event;
                goto prod;
        }
        // -------------------------------------------------
        // profile
        // -------------------------------------------------
        //audit_profile
audit_profile:
        if ((a_part_mk & PART_MK_WAF) &&
           a_scope.has__profile_audit__reserved())
        {
                int32_t l_s;
                // -----------------------------------------
                // reset phase 3 to handle ignore...
                // -----------------------------------------
                l_s = (*ao_resp_ctx)->reset_phase_3();
                if (l_s != WAFLZ_STATUS_OK)
                {
                        // TODO reason???
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // profile process
                // -----------------------------------------
                profile *l_profile = (profile *)a_scope._profile_audit__reserved();
                waflz_pb::event *l_event = NULL;
                l_s = l_profile->process_response(&l_event, a_ctx, PART_MK_WAF, ao_resp_ctx);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        if (l_event) { delete l_event; l_event = NULL; }
                        WAFLZ_PERROR(m_err_msg,  "%s", l_profile->get_err_msg());
                        return WAFLZ_STATUS_ERROR;
                }
                if (!l_event)
                {
                        goto prod;
                }
                l_event->set_waf_profile_action(waflz_pb::enforcement_type_t_ALERT);
                if (a_scope.has_profile_audit_action() &&
                   a_scope.profile_audit_action().has_enf_type())
                {
                         l_event->set_waf_profile_action(a_scope.profile_audit_action().enf_type());
                }
                *ao_audit_event = l_event;
                goto prod;
        }
        // -------------------------------------------------
        // *************************************************
        //                    P R O D
        // *************************************************
        // -------------------------------------------------
        // -------------------------------------------------
        // api gw
        // -------------------------------------------------
prod:
        if ((a_part_mk & PART_MK_API_GW) &&
            a_scope.has__api_gw_prod__reserved())
        {
                api_gw* l_api_gw = (api_gw*)a_scope._api_gw_prod__reserved();
                waflz_pb::event* l_event = NULL;
                int32_t l_s;
                l_s = l_api_gw->process_response(&l_event, a_ctx, ao_resp_ctx);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        if (l_event) { delete l_event; l_event = NULL; }
                        WAFLZ_PERROR(m_err_msg, "%s", l_api_gw->get_err_msg());
                        return WAFLZ_STATUS_ERROR;
                }
                if (!l_event)
                {
                        goto prod_profile;
                }
                l_s = (*ao_resp_ctx)->append_resp_info(*l_event);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "performing resp_ctx::append_resp_info for api gw");
                        return WAFLZ_STATUS_ERROR;
                }
                *ao_prod_event = l_event;
                if (a_scope.has_api_gw_prod_action())
                {
                        *ao_enf = &(a_scope.api_gw_prod_action());
                        if ((*ao_enf)->has_status())
                        {
                                (*ao_resp_ctx)->m_resp_status = (*ao_enf)->status();
                        }
                }
                goto done;
        }
        // -------------------------------------------------
        // profile
        // -------------------------------------------------
prod_profile:
        if ((a_part_mk & PART_MK_WAF) &&
           a_scope.has__profile_prod__reserved())
        {
                // -----------------------------------------
                // reset phase 3 to handle ignore...
                // -----------------------------------------
                int32_t l_s;
                l_s = (*ao_resp_ctx)->reset_phase_3();
                if (l_s != WAFLZ_STATUS_OK)
                {
                        // TODO reason???
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // profile process
                // -----------------------------------------
                profile *l_profile = (profile *)a_scope._profile_prod__reserved();
                waflz_pb::event *l_event = NULL;
                l_s = l_profile->process_response(&l_event, a_ctx, PART_MK_WAF, ao_resp_ctx);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        if (l_event) { delete l_event; l_event = NULL; }
                        WAFLZ_PERROR(m_err_msg,  "%s", l_profile->get_err_msg());
                        return WAFLZ_STATUS_ERROR;
                }
                if (!l_event)
                {
                        goto done;
                }
                *ao_prod_event = l_event;
                if (a_scope.has_profile_prod_action())
                {
                        *ao_enf = &(a_scope.profile_prod_action());
                        if ((*ao_enf)->has_status())
                        {
                                (*ao_resp_ctx)->m_resp_status = (*ao_enf)->status();
                        }
                }
                goto done;
        }
done:
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details returns the client waf headers for the first scope that matches
//!          the response.
//! \return  headers
//! \param   a_ctx: the sailfish context
//! \param   a_cb: the callbacks for the request
//! \param   a_content_length: the content length of the request
//! ----------------------------------------------------------------------------
ns_waflz::header_map_t* scopes::get_client_waf_headers(const char* a_host, uint32_t a_host_len,
                                                       const char* a_path, uint32_t a_path_len)
{
        // -------------------------------------------------
        // for each scope...
        // -------------------------------------------------
        for(int i_s = 0; i_s < m_pb->scopes_size(); ++i_s)
        {
                // -----------------------------------------
                // check if response in scope
                // -----------------------------------------
                const ::waflz_pb::scope& l_sc = m_pb->scopes(i_s);       
                bool l_m;
                uint32_t l_s = in_scope_response_with_cstr(l_m, l_sc, a_host, a_host_len, a_path, a_path_len);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "in_scope_response_with_str error");
                        return nullptr;
                }
                // -----------------------------------------
                // no match continue to next check...
                // -----------------------------------------
                if (!l_m) { continue; }
                // -----------------------------------------
                // return client waf headers if they exists
                // -----------------------------------------
                if (l_sc.has__client_waf_config__reserved())
                {
                        client_waf* l_cs = (client_waf*) l_sc._client_waf_config__reserved();
                        return l_cs->get_headers();
                }
                // -----------------------------------------
                // break after first match
                // -----------------------------------------
                break;
        }
        // -------------------------------------------------
        // return null for no match
        // -------------------------------------------------
        return nullptr;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::process(const waflz_pb::enforcement** ao_enf,
                        waflz_pb::event** ao_audit_event,
                        waflz_pb::event** ao_prod_event,
                        waflz_pb::event** ao_bot_event,
                        const ::waflz_pb::scope& a_scope,
                        void* a_ctx,
                        part_mk_t a_part_mk,
                        rqst_ctx** ao_rqst_ctx)
{
        // -------------------------------------------------
        // sanity checking
        // -------------------------------------------------
        if (!ao_enf ||
           !ao_audit_event ||
           !ao_prod_event)
        {
                WAFLZ_PERROR(m_err_msg, "nullptr for enf, audit or prod event");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // clear ao_* inputs
        // -------------------------------------------------
        *ao_enf = NULL;
        *ao_audit_event = NULL;
        *ao_prod_event = NULL;
        // -------------------------------------------------
        // *************************************************
        //                   A U D I T
        // *************************************************
        // -------------------------------------------------
        // -------------------------------------------------
        // acl
        // -------------------------------------------------
        if ((a_part_mk & PART_MK_ACL) &&
           a_scope.has__acl_audit__reserved())
        {
                acl* l_acl = (acl *)a_scope._acl_audit__reserved();
                waflz_pb::event* l_event = NULL;
                bool l_wl = false;
                int32_t l_s;
                l_s = l_acl->process(&l_event, l_wl, a_ctx, ao_rqst_ctx);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        if (l_event) { delete l_event; l_event = NULL; }
                        WAFLZ_PERROR(m_err_msg, "error processing acl reason: %.*s",
                                     WAFLZ_ERR_REASON_LEN,
                                     l_acl->get_err_msg());
                        return WAFLZ_STATUS_ERROR;
                }
                if (l_wl)
                {
                        goto prod;
                }
                if (!l_event)
                {
                        goto audit_api_gw;
                }
                l_s = (*ao_rqst_ctx)->append_rqst_info(*l_event, m_engine.get_geoip2_mmdb());
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "performing rqst_ctx::append_rqst_info for acl");
                        return WAFLZ_STATUS_ERROR;
                }
                l_event->set_waf_profile_action(waflz_pb::enforcement_type_t_ALERT);
                if (a_scope.has_acl_audit_action() &&
                   a_scope.acl_audit_action().has_enf_type())
                {
                         l_event->set_waf_profile_action(a_scope.acl_audit_action().enf_type());
                }
                *ao_audit_event = l_event;
                goto prod;
        }
        // -------------------------------------------------
        // api gateway
        // -------------------------------------------------
audit_api_gw:
        if ((a_part_mk & PART_MK_API_GW) &&
            a_scope.has__api_gw_audit__reserved())
        {
                api_gw* l_api_gw = (api_gw*)a_scope._api_gw_audit__reserved();
                waflz_pb::event* l_event = NULL;
                int32_t l_s;
                l_s = l_api_gw->process(&l_event, a_ctx, ao_rqst_ctx);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        if (l_event) { delete l_event; l_event = NULL; }
                         WAFLZ_PERROR(m_err_msg, "error processing api_gw %.*s",
                                      WAFLZ_ERR_REASON_LEN, l_api_gw->get_err_msg());
                        return WAFLZ_STATUS_ERROR;
                }
                if (!l_event)
                {
                        goto audit_rules;
                }
                l_s = (*ao_rqst_ctx)->append_rqst_info(*l_event, m_engine.get_geoip2_mmdb());
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "performing rqst_ctx::append_rqst_info for api gw");
                        return WAFLZ_STATUS_ERROR;
                }
                l_event->set_waf_profile_action(waflz_pb::enforcement_type_t_ALERT);
                if (a_scope.has_api_gw_audit_action() &&
                    a_scope.api_gw_audit_action().has_enf_type())
                {
                         l_event->set_waf_profile_action(a_scope.api_gw_audit_action().enf_type());
                }
                *ao_audit_event = l_event;
                goto prod;
        }
        // -------------------------------------------------
        // rules
        // -------------------------------------------------
audit_rules:
        if ((a_part_mk & PART_MK_RULES) &&
           a_scope.has__rules_audit__reserved())
        {
                rules* l_rules = (rules *)a_scope._rules_audit__reserved();
                waflz_pb::event* l_event = NULL;
                int32_t l_s;
                l_s = l_rules->process(&l_event, a_ctx, ao_rqst_ctx);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        if (l_event) { delete l_event; l_event = NULL; }
                        WAFLZ_PERROR(m_err_msg,  "error processing rules %.*s",
                                     WAFLZ_ERR_REASON_LEN, l_rules->get_err_msg());
                        return WAFLZ_STATUS_ERROR;
                }
                if (!l_event)
                {
                        goto audit_profile;
                }
                l_event->set_rules_config_id(l_rules->get_id());
                l_event->set_rules_config_name(l_rules->get_name());
                l_event->set_waf_profile_action(waflz_pb::enforcement_type_t_ALERT);
                if (a_scope.has_rules_audit_action() &&
                   a_scope.rules_audit_action().has_enf_type())
                {
                         l_event->set_waf_profile_action(a_scope.rules_audit_action().enf_type());
                }
                *ao_audit_event = l_event;
                goto prod;
        }
        // -------------------------------------------------
        // profile
        // -------------------------------------------------
audit_profile:
        if ((a_part_mk & PART_MK_WAF) &&
           a_scope.has__profile_audit__reserved())
        {
                int32_t l_s;
                // -----------------------------------------
                // reset phase 1 to handle ignore...
                // -----------------------------------------
                l_s = (*ao_rqst_ctx)->reset_phase_1();
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "error resetting phase 1");
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // profile process
                // -----------------------------------------
                profile* l_profile = (profile *)a_scope._profile_audit__reserved();
                waflz_pb::event* l_event = NULL;
                // --------------------------------------------------------
                // check if outbound response needs to be handled later on
                // --------------------------------------------------------
                const waflz_pb::profile* l_pb = l_profile->get_pb();
                if (l_pb->has_general_settings() && l_pb->general_settings().has_process_response_body())
                {
                        if (l_pb->general_settings().process_response_body())
                        {
                                (*ao_rqst_ctx)->m_inspect_response = true;
                        }
                }
                l_s = l_profile->process(&l_event, a_ctx, PART_MK_WAF, ao_rqst_ctx);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        if (l_event) { delete l_event; l_event = NULL; }
                        WAFLZ_PERROR(m_err_msg,  "error processing profile: %.*s",
                                     WAFLZ_ERR_REASON_LEN, l_profile->get_err_msg());
                        return WAFLZ_STATUS_ERROR;
                }
                if (!l_event)
                {
                        goto prod;
                }
                l_event->set_waf_profile_action(waflz_pb::enforcement_type_t_ALERT);
                if (a_scope.has_profile_audit_action() &&
                   a_scope.profile_audit_action().has_enf_type())
                {
                         l_event->set_waf_profile_action(a_scope.profile_audit_action().enf_type());
                }
                *ao_audit_event = l_event;
                goto prod;
        }
        // -------------------------------------------------
        // *************************************************
        //                    P R O D
        // *************************************************
        // -------------------------------------------------
prod:
        // -------------------------------------------------
        // acl
        // -------------------------------------------------
        if ((a_part_mk & PART_MK_ACL) &&
           a_scope.has__acl_prod__reserved())
        {
                acl* l_acl = (acl *)a_scope._acl_prod__reserved();
                waflz_pb::event* l_event = NULL;
                bool l_wl = false;
                int32_t l_s;
                l_s = l_acl->process(&l_event, l_wl, a_ctx, ao_rqst_ctx);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        if (l_event) { delete l_event; l_event = NULL; }
                        WAFLZ_PERROR(m_err_msg,  "error processing prod acl: %.*s",
                                     WAFLZ_ERR_REASON_LEN, l_acl->get_err_msg());
                        return WAFLZ_STATUS_ERROR;
                }
                if (l_wl)
                {
                        goto done;
                }
                if (!l_event)
                {
                        goto api_gw;
                }
                l_s = (*ao_rqst_ctx)->append_rqst_info(*l_event, m_engine.get_geoip2_mmdb());
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "performing rqst_ctx::append_rqst_info for acl");
                        return WAFLZ_STATUS_ERROR;
                }
                *ao_prod_event = l_event;
                if (a_scope.has_acl_prod_action())
                {
                        *ao_enf = &(a_scope.acl_prod_action());
                        if ((*ao_enf)->has_status())
                        {
                                (*ao_rqst_ctx)->m_resp_status = (*ao_enf)->status();
                        }
                }
                goto done;
        }
        // -------------------------------------------------
        // api gateway
        // -------------------------------------------------
api_gw:
        if ((a_part_mk & PART_MK_API_GW) &&
            a_scope.has__api_gw_prod__reserved())
        {
                api_gw* l_api_gw = (api_gw*)a_scope._api_gw_prod__reserved();
                waflz_pb::event* l_event = NULL;
                int32_t l_s;
                l_s = l_api_gw->process(&l_event, a_ctx, ao_rqst_ctx);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        if (l_event) { delete l_event; l_event = NULL; }
                        WAFLZ_PERROR(m_err_msg, "%s", l_api_gw->get_err_msg());
                        return WAFLZ_STATUS_ERROR;
                }
                if (!l_event)
                {
                        goto enforcements;
                }
                l_s = (*ao_rqst_ctx)->append_rqst_info(*l_event, m_engine.get_geoip2_mmdb());
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "performing rqst_ctx::append_rqst_info for api gw");
                        return WAFLZ_STATUS_ERROR;
                }
                *ao_prod_event = l_event;
                if (a_scope.has_api_gw_prod_action())
                {
                        *ao_enf = &(a_scope.api_gw_prod_action());
                        if ((*ao_enf)->has_status())
                        {
                                (*ao_rqst_ctx)->m_resp_status = (*ao_enf)->status();
                        }
                }
                goto done;
        }
        // -------------------------------------------------
        // enforcements
        // -------------------------------------------------
enforcements:
{
        // -------------------------------------------------
        // request handling Timestamp calculation (epoch)
        // -------------------------------------------------
        struct timeval tp;
        gettimeofday(&tp, 0);
        uint64_t l_time_cur_s = tp.tv_sec;
        uint64_t l_time_cur_ms = tp.tv_usec * 1000;
        (*ao_rqst_ctx)->m_rqst_ts_s  = l_time_cur_s;
        (*ao_rqst_ctx)->m_rqst_ts_ms = l_time_cur_ms;
        if (!(a_part_mk & PART_MK_LIMITS))
        {
                goto bot_manager;
        }
        if (!m_enfx && !m_audit_enfx)
        {
                goto limits;
        }
        if (m_audit_enfx)
        {
                int32_t l_s;
                l_s = m_audit_enfx->process(*ao_rqst_ctx);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "performing audit enforcer process");
                        return WAFLZ_STATUS_ERROR;
                }
        }
        if (m_enfx)
        {
                int32_t l_s;
                l_s = m_enfx->process(ao_enf, *ao_rqst_ctx);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "performing enforcer process");
                        return WAFLZ_STATUS_ERROR;
                }
                if (*ao_enf)
                {
                        // ---------------------------------
                        // TODO: handle browser 
                        // challenge validation
                        // ---------------------------------
                        if ((*ao_enf)->has_status())
                        {
                                (*ao_rqst_ctx)->m_resp_status = (*ao_enf)->status();
                        }
                        goto done;
                }
        }
}
limits:
        // -------------------------------------------------
        // limits
        // -------------------------------------------------
        if (a_part_mk & PART_MK_LIMITS)
        {
                for (int i_l = 0; i_l < a_scope.limits_size(); ++i_l)
                {
                        int32_t l_s;
                        const ::waflz_pb::scope_limit_config& l_slc = a_scope.limits(i_l);
                        if (!l_slc.has__reserved_1())
                        {
                                continue;
                        }
                        if (!l_slc.has_action())
                        {
                                continue;
                        }
                        limit* l_limit = (limit *)l_slc._reserved_1();
                        // ---------------------------------
                        // skip this limit if it is in alert
                        // and we already have an alert
                        // limit on the rqst_ctx
                        // ---------------------------------
                        const bool l_is_alert = l_slc.action().enf_type() == waflz_pb::enforcement_type_t_ALERT;
                        if ((*ao_rqst_ctx)->m_audit_limit &&
                            l_is_alert)
                        {
                                continue;
                        }
                        // ---------------------------------
                        // mark that the request should get
                        // its response viewed.
                        // ---------------------------------
                        bool l_exceeds = false;
                        const waflz_pb::condition_group* l_cg = NULL;
                        // ---------------------------------
                        // process limit
                        // ---------------------------------
                        if (l_limit->is_response_limit())
                        {
                                (*ao_rqst_ctx)->m_inspect_response_headers = true;
                        }
                        l_s = l_limit->process(l_exceeds,
                                               &l_cg,
                                               a_scope.id(),
                                               *ao_rqst_ctx,
                                               !l_limit->is_response_limit());
                        if (l_s != WAFLZ_STATUS_OK)
                        {
                                WAFLZ_PERROR(m_err_msg, "%s", l_limit->get_err_msg());
                                return WAFLZ_STATUS_ERROR;
                        }
                        if (!l_exceeds)
                        {
                                continue;
                        }
                        // ---------------------------------
                        // signal new enforcement
                        // ---------------------------------
                        (*ao_rqst_ctx)->m_signal_enf = true;
                        // ---------------------------------
                        // add new exceeds
                        // ---------------------------------
                        const waflz_pb::enforcement& l_axn = l_slc.action();
                        waflz_pb::config* l_cfg = NULL;
                        l_s = add_exceed_limit(&l_cfg,
                                               *(l_limit->get_pb()),
                                               l_cg,
                                               l_axn,
                                               a_scope,
                                               *ao_rqst_ctx);
                        if (l_s != WAFLZ_STATUS_OK)
                        {
                                WAFLZ_PERROR(m_err_msg, "performing add_exceed_limit");
                                return WAFLZ_STATUS_ERROR;
                        }
                        // ---------------------------------
                        // get enforcer to use
                        // ---------------------------------
                        ns_waflz::enforcer* l_enforcer_for_request = (l_is_alert) ? m_audit_enfx : m_enfx;
                        // ---------------------------------
                        // merge enforcement
                        // ---------------------------------
                        //NDBG_OUTPUT("l_enfx: %s\n", l_enfcr->ShortDebugString().c_str());
                        l_s = l_enforcer_for_request->merge(*l_cfg);
                        if (l_s != WAFLZ_STATUS_OK)
                        {
                                WAFLZ_PERROR(m_err_msg, "error merging enforcer: %.*s",
                                             WAFLZ_ERR_REASON_LEN,
                                             l_enforcer_for_request->get_err_msg());
                                return WAFLZ_STATUS_ERROR;
                        }
                        if (l_cfg) { delete l_cfg; l_cfg = NULL; }
                        // ---------------------------------
                        // process enforcer
                        // ---------------------------------
                        l_s = l_enforcer_for_request->process(ao_enf, *ao_rqst_ctx, !l_is_alert);
                        if (l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                        // ---------------------------------
                        // enforced???
                        // ---------------------------------
                        if (*ao_enf)
                        {
                                if ((*ao_enf)->has_status())
                                {
                                        (*ao_rqst_ctx)->m_resp_status = (*ao_enf)->status();
                                }
                                goto done;
                        }
                }
        }
bot_manager:
        // -------------------------------------------------
        // bot manager
        // -------------------------------------------------
        if ((a_part_mk & PART_MK_BOTS) &&
            a_scope.has__bot_manager_config__reserved())
        {
                bot_manager* l_bot_manager = (bot_manager*)a_scope._bot_manager_config__reserved();
                waflz_pb::event* l_event = NULL;
                int32_t l_s;
                l_s = l_bot_manager->process(&l_event, ao_enf, a_ctx, ao_rqst_ctx);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        if(l_s == WAFLZ_STATUS_WAIT)
                        {
                                //do not delete event.
                                //Server will delete event
                                (*ao_rqst_ctx)->append_rqst_info(*l_event, m_engine.get_geoip2_mmdb());
                                *ao_bot_event = l_event;
                                return WAFLZ_STATUS_WAIT;
                        }
                        if (l_event) { delete l_event; l_event = NULL; }
                        WAFLZ_PERROR(m_err_msg, "error processing bot manager: %.*s",
                                     WAFLZ_ERR_REASON_LEN,
                                     l_bot_manager->get_err_msg());
                        return WAFLZ_STATUS_ERROR;
                }
                if (!l_event)
                {
                        goto prod_rules;
                }
                l_s = (*ao_rqst_ctx)->append_rqst_info(*l_event, m_engine.get_geoip2_mmdb());
                if (l_s != WAFLZ_STATUS_OK)
                {
                        if (l_event) { delete l_event; l_event = NULL; }
                        WAFLZ_PERROR(m_err_msg, 
                                     "performing rqst_ctx::append_rqst_info for bot_manager");
                        return WAFLZ_STATUS_ERROR;
                }
                if (!(*ao_enf))
                {
                        if (l_event) { delete l_event; l_event = NULL; }
                        WAFLZ_PERROR(m_err_msg, "enforcement is null");
                        return WAFLZ_STATUS_ERROR;

                }
                if ((*ao_enf)->enf_type() == waflz_pb::enforcement_type_t_ALERT ||
                    (*ao_enf)->enf_type() == waflz_pb::enforcement_type_t_IGNORE_ALERT )
                {
                        *ao_bot_event = l_event;
                        goto prod_rules;
                }
                *ao_bot_event = l_event;
                goto done;
        }
prod_rules:
        // -------------------------------------------------
        // rules
        // -------------------------------------------------
        if ((a_part_mk & PART_MK_RULES) &&
           a_scope.has__rules_prod__reserved())
        {
                // -----------------------------------------
                // process
                // -----------------------------------------
                rules* l_rules = (rules *)a_scope._rules_prod__reserved();
                waflz_pb::event* l_event = NULL;
                int32_t l_s;
                l_s = l_rules->process(&l_event, a_ctx, ao_rqst_ctx);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        if (l_event) { delete l_event; l_event = NULL; }
                        WAFLZ_PERROR(m_err_msg,  "error processing prod rules: %.*s",
                                     WAFLZ_ERR_REASON_LEN, l_rules->get_err_msg());
                        return WAFLZ_STATUS_ERROR;
                }
                if (!l_event)
                {
                        goto prod_profile;
                }
                l_event->set_rules_config_id(l_rules->get_id());
                l_event->set_rules_config_name(l_rules->get_name());
                *ao_prod_event = l_event;
                if (a_scope.has_rules_prod_action())
                {
                        *ao_enf = &(a_scope.rules_prod_action());;
                        if ((*ao_enf)->has_status())
                        {
                                (*ao_rqst_ctx)->m_resp_status = (*ao_enf)->status();
                        }
                }
                goto done;
        }
        // -------------------------------------------------
        // profile
        // -------------------------------------------------
prod_profile:
        if ((a_part_mk & PART_MK_WAF) &&
           a_scope.has__profile_prod__reserved())
        {
                // -----------------------------------------
                // reset phase 1 to handle ignore...
                // -----------------------------------------
                int32_t l_s;
                l_s = (*ao_rqst_ctx)->reset_phase_1();
                if (l_s != WAFLZ_STATUS_OK)
                {
                        // TODO reason???
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // profile process
                // -----------------------------------------
                profile* l_profile = (profile *)a_scope._profile_prod__reserved();
                waflz_pb::event* l_event = NULL;
                // --------------------------------------------------------
                // check if outbound response needs to be handled later on
                // --------------------------------------------------------
                const waflz_pb::profile* l_pb = l_profile->get_pb();
                if (l_pb->has_general_settings() && l_pb->general_settings().has_process_response_body())
                {
                        if (l_pb->general_settings().process_response_body())
                        {
                                (*ao_rqst_ctx)->m_inspect_response = true;
                        }
                }
                l_s = l_profile->process(&l_event, a_ctx, PART_MK_WAF, ao_rqst_ctx);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        if (l_event) { delete l_event; l_event = NULL; }
                        WAFLZ_PERROR(m_err_msg,  "error processing prod profile: %.*s",
                                     WAFLZ_ERR_REASON_LEN, l_profile->get_err_msg());
                        return WAFLZ_STATUS_ERROR;
                }
                if (!l_event)
                {
                        goto client_waf;
                }
                *ao_prod_event = l_event;
                if (a_scope.has_profile_prod_action())
                {
                        *ao_enf = &(a_scope.profile_prod_action());
                        if ((*ao_enf)->has_status())
                        {
                                (*ao_rqst_ctx)->m_resp_status = (*ao_enf)->status();
                        }
                }
                goto done;
        }
        // -------------------------------------------------
        // client waf
        // no processing done, but marks for review later
        // -------------------------------------------------
client_waf:
        if ((a_part_mk & PART_MK_CLIENT_WAF) &&
           a_scope.has__client_waf_config__reserved())
        {
                (*ao_rqst_ctx)->m_inject_client_waf = true;
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
done:
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::add_exceed_limit(waflz_pb::config** ao_cfg,
                                 const waflz_pb::limit& a_limit,
                                 const waflz_pb::condition_group* a_condition_group,
                                 const waflz_pb::enforcement& a_action,
                                 const waflz_pb::scope& a_scope,
                                 rqst_ctx* a_ctx)
{
        if (!ao_cfg)
        {
                WAFLZ_PERROR(m_err_msg, "enforcer ptr NULL.");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // create enforcement
        // -------------------------------------------------
        waflz_pb::config* l_cfg = new waflz_pb::config();
        l_cfg->set_id("__na__");
        l_cfg->set_name("__na__");
        l_cfg->set_type(waflz_pb::config_type_t_ENFORCER);
        l_cfg->set_customer_id(m_cust_id);
        l_cfg->set_enabled_date(get_date_short_str());
        // -------------------------------------------------
        // populate limit info
        // -------------------------------------------------
        waflz_pb::limit* l_limit = l_cfg->add_limits();
        l_limit->set_id(a_limit.id());
        l_limit->set_customer_id(m_cust_id);
        l_limit->set__reserved_match(a_limit._reserved_match());
        l_limit->set_num(a_limit.num());
        l_limit->set_duration_sec(a_limit.duration_sec());
        if (a_limit.has_name())
        {
            l_limit->set_name(a_limit.name());
        }
        else
        {
                l_limit->set_name("__na__");
        }
        if (a_limit.has_last_modified_date())
        {
                l_limit->set_last_modified_date(a_limit.last_modified_date());
        }
        l_limit->set_disabled(false);
        // -------------------------------------------------
        // copy "the limit"
        // -------------------------------------------------
        if (a_condition_group)
        {
                waflz_pb::condition_group* l_cg = l_limit->add_condition_groups();
                l_cg->CopyFrom(*a_condition_group);
        }
        waflz_pb::scope* l_sc = l_limit->mutable_scope();
        if (a_scope.has_host())
        {
                l_sc->mutable_host()->CopyFrom(a_scope.host());
        }
        if (a_scope.has_path())
        {
                l_sc->mutable_path()->CopyFrom(a_scope.path());
        }
        if (a_scope.has_id())
        {
                l_sc->set_id(a_scope.id());
        }
        if (a_scope.has_name())
        {
                l_sc->set_name(a_scope.name());
        }
        // -------------------------------------------------
        // create limits for dimensions
        // -------------------------------------------------
        for (int i_k = 0; i_k < a_limit.keys_size(); ++i_k)
        {
                int32_t l_s;
                l_s = add_limit_with_key(*l_limit,
                                         a_limit.keys(i_k),
                                         a_ctx);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        // TODO cleanup
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // copy action(s)
        // -------------------------------------------------
        uint64_t l_cur_time_ms = get_time_ms();
        uint32_t l_e_duration_s = 0;
        waflz_pb::enforcement* l_e = l_limit->mutable_action();
        l_e->CopyFrom(a_action);
        // -------------------------------------------------
        // only id/name/type might be set
        // -------------------------------------------------
        l_e->set_start_time_ms(l_cur_time_ms);
        // -------------------------------------------------
        // TODO set percentage to 100 for now
        // -------------------------------------------------
        l_e->set_percentage(100.0);
        // -------------------------------------------------
        // duration calculation
        // -------------------------------------------------
        if (l_e->has_duration_sec())
        {
                l_e_duration_s = l_e->duration_sec();
        }
        else
        {
                l_e_duration_s = a_limit.duration_sec();
        }
        l_e->set_duration_sec(l_e_duration_s);
        // -------------------------------------------------
        // set duration
        // -------------------------------------------------
        l_limit->set_start_epoch_msec(l_cur_time_ms);
        l_limit->set_end_epoch_msec(l_cur_time_ms + l_e_duration_s*1000);
        // -------------------------------------------------
        // set
        // -------------------------------------------------
        *ao_cfg = l_cfg;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t scopes::add_exceed_limit_for_response(waflz_pb::config** ao_cfg,
                                 const waflz_pb::limit& a_limit,
                                 const waflz_pb::condition_group* a_condition_group,
                                 const waflz_pb::enforcement& a_action,
                                 const waflz_pb::scope& a_scope,
                                 resp_ctx* a_ctx)
{
        if (!ao_cfg)
        {
                WAFLZ_PERROR(m_err_msg, "enforcer ptr NULL.");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // create enforcement
        // -------------------------------------------------
        waflz_pb::config* l_cfg = new waflz_pb::config();
        l_cfg->set_id("__na__");
        l_cfg->set_name("__na__");
        l_cfg->set_type(waflz_pb::config_type_t_ENFORCER);
        l_cfg->set_customer_id(m_cust_id);
        l_cfg->set_enabled_date(get_date_short_str());
        // -------------------------------------------------
        // populate limit info
        // -------------------------------------------------
        waflz_pb::limit* l_limit = l_cfg->add_limits();
        l_limit->set_id(a_limit.id());
        l_limit->set_customer_id(m_cust_id);
        l_limit->set__reserved_match(a_limit._reserved_match());
        l_limit->set_num(a_limit.num());
        l_limit->set_duration_sec(a_limit.duration_sec());
        if (a_limit.has_name())
        {
            l_limit->set_name(a_limit.name());
        }
        else
        {
                l_limit->set_name("__na__");
        }
        if (a_limit.has_last_modified_date())
        {
                l_limit->set_last_modified_date(a_limit.last_modified_date());
        }
        l_limit->set_disabled(false);
        // -------------------------------------------------
        // copy "the limit"
        // -------------------------------------------------
        if (a_condition_group)
        {
                waflz_pb::condition_group* l_cg = l_limit->add_condition_groups();
                l_cg->CopyFrom(*a_condition_group);
        }
        waflz_pb::scope* l_sc = l_limit->mutable_scope();
        if (a_scope.has_host())
        {
                l_sc->mutable_host()->CopyFrom(a_scope.host());
        }
        if (a_scope.has_path())
        {
                l_sc->mutable_path()->CopyFrom(a_scope.path());
        }
        if (a_scope.has_id())
        {
                l_sc->set_id(a_scope.id());
        }
        if (a_scope.has_name())
        {
                l_sc->set_name(a_scope.name());
        }
        // -------------------------------------------------
        // create limits for dimensions
        // -------------------------------------------------
        for (int i_k = 0; i_k < a_limit.keys_size(); ++i_k)
        {
                int32_t l_s;
                l_s = add_limit_with_key_for_response(*l_limit,
                                         a_limit.keys(i_k),
                                         a_ctx);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        // TODO cleanup
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // copy action(s)
        // -------------------------------------------------
        uint64_t l_cur_time_ms = get_time_ms();
        uint32_t l_e_duration_s = 0;
        waflz_pb::enforcement* l_e = l_limit->mutable_action();
        l_e->CopyFrom(a_action);
        // -------------------------------------------------
        // only id/name/type might be set
        // -------------------------------------------------
        l_e->set_start_time_ms(l_cur_time_ms);
        // -------------------------------------------------
        // TODO set percentage to 100 for now
        // -------------------------------------------------
        l_e->set_percentage(100.0);
        // -------------------------------------------------
        // duration calculation
        // -------------------------------------------------
        if (l_e->has_duration_sec())
        {
                l_e_duration_s = l_e->duration_sec();
        }
        else
        {
                l_e_duration_s = a_limit.duration_sec();
        }
        l_e->set_duration_sec(l_e_duration_s);
        // -------------------------------------------------
        // set duration
        // -------------------------------------------------
        l_limit->set_start_epoch_msec(l_cur_time_ms);
        l_limit->set_end_epoch_msec(l_cur_time_ms + l_e_duration_s*1000);
        // -------------------------------------------------
        // set
        // -------------------------------------------------
        *ao_cfg = l_cfg;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details  run a limit operator on some data
//! \l_retval number of entries added to ao_match_list
//!           -1 on failure
//! \param    TODO
//! ----------------------------------------------------------------------------
int32_t rl_run_op(bool& ao_matched,
                  const waflz_pb::op_t& a_op,
                  const char* a_data,
                  uint32_t a_len,
                  bool a_case_insensitive)
{
        // -------------------------------------------------
        // assume operator is STREQ
        // -------------------------------------------------
        ao_matched = false;
        waflz_pb::op_t_type_t l_op_type = waflz_pb::op_t_type_t_STREQ;
        if (a_op.has_type())
        {
                // -----------------------------------------
                // operator type actually provided
                // -----------------------------------------
                l_op_type = a_op.type();
        }
        switch (l_op_type)
        {
        // -------------------------------------------------
        // RX (regex)
        // -------------------------------------------------
        case waflz_pb::op_t_type_t_RX:
        {
                // -----------------------------------------
                // get regex
                // -----------------------------------------
                if (!a_op.has__reserved_1())
                {
                        return WAFLZ_STATUS_ERROR;
                }
                regex* l_rx = (regex *)(a_op._reserved_1());
                if (!l_rx)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // match?
                // -----------------------------------------
                int l_s;
                l_s = l_rx->compare(a_data, a_len);
                // -----------------------------------------
                // if failed to match
                // -----------------------------------------
                if (l_s < 0)
                {
                        break;
                }
                ao_matched = true;
                break;
        }
        // -------------------------------------------------
        // STREQ
        // -------------------------------------------------
        case waflz_pb::op_t_type_t_STREQ:
        {
                const std::string& l_op_match = a_op.value();
                uint32_t l_len = l_op_match.length();
                if (l_len != a_len)
                {
                        break;
                }
                int l_cmp = 0;
                if (a_case_insensitive)
                {
                        l_cmp = strncasecmp(l_op_match.c_str(), a_data, l_len);
                }
                else
                {
                        l_cmp = strncmp(l_op_match.c_str(), a_data, l_len);
                }
                if (l_cmp == 0)
                {
                        // ---------------------------------
                        // matched
                        // ---------------------------------
                        ao_matched = true;
                        break;
                }
                break;
        }
        // -------------------------------------------------
        // GLOB (glob -wildcard match)
        // -------------------------------------------------
        case waflz_pb::op_t_type_t_GLOB:
        {
                int l_flags = FNM_NOESCAPE;
                if (a_case_insensitive)
                {
                        l_flags |= FNM_CASEFOLD;
                }
                int l_cmp;
                const std::string& l_op_match = a_op.value();
                l_cmp = fnmatch(l_op_match.c_str(), a_data, l_flags);
                if (l_cmp == 0)
                {
                        // ---------------------------------
                        // matched
                        // ---------------------------------
                        ao_matched = true;
                }
                break;
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        case waflz_pb::op_t_type_t_IPMATCH:
        {
                // -----------------------------------------
                // get regex
                // -----------------------------------------
                if (!a_op.has__reserved_1())
                {
                        return WAFLZ_STATUS_ERROR;
                }
                nms* l_nms = (nms *)(a_op._reserved_1());
                if (!l_nms)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // match?
                // -----------------------------------------
                int32_t l_s;
                l_s = l_nms->contains(ao_matched, a_data, a_len);
                // -----------------------------------------
                // if failed to match
                // -----------------------------------------
                if (l_s < 0)
                {
                        break;
                }
                break;
        }
        // -------------------------------------------------
        // Exact Match list (EM)
        // -------------------------------------------------
        case waflz_pb::op_t_type_t_EM:
        {
                // -----------------------------------------
                // get str set
                // -----------------------------------------
                if (!a_op.has__reserved_1())
                {
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // case insensitive
                // -----------------------------------------
                if (a_op.is_case_insensitive())
                {
                        data_case_i_set_t *l_ds = (data_case_i_set_t *)(a_op._reserved_1());
                        if (!l_ds)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                        // ---------------------------------
                        // match?
                        // ---------------------------------
                        data_t l_d;
                        l_d.m_data = a_data;
                        l_d.m_len = a_len;
                        data_case_i_set_t::const_iterator i_d = l_ds->find(l_d);
                        if ((i_d != l_ds->end()) &&
                           (i_d->m_len == l_d.m_len))
                        {
                                ao_matched = true;
                        }
                }
                // -----------------------------------------
                // case sensitive
                // -----------------------------------------
                else
                {
                       data_set_t* l_ds = (data_set_t *)(a_op._reserved_1());
                        if (!l_ds)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                        // ---------------------------------
                        // match?
                        // ---------------------------------
                        data_t l_d;
                        l_d.m_data = a_data;
                        l_d.m_len = a_len;
                        data_set_t::const_iterator i_d = l_ds->find(l_d);
                        if ((i_d != l_ds->end()) &&
                           (i_d->m_len == l_d.m_len))
                        {
                                ao_matched = true;
                        }
                }
                break;
        }
        // -------------------------------------------------
        // value equal (EQ)
        // -------------------------------------------------
        case ::waflz_pb::op_t_type_t_EQ:
        {
                ao_matched = (a_len == (uint32_t) a_op._reserved_1());
                break;
        }
        case ::waflz_pb::op_t_type_t_LE:
        {
                ao_matched = (a_len <= (uint32_t) a_op._reserved_1());
                break;
        }
        case ::waflz_pb::op_t_type_t_GE:
        {
                ao_matched = (a_len >= (uint32_t) a_op._reserved_1());
                break;
        }

        case ::waflz_pb::op_t_type_t_LT:
        {
                ao_matched = (a_len < (uint32_t) a_op._reserved_1());
                break;
        }
        case ::waflz_pb::op_t_type_t_GT:
        {
                ao_matched = (a_len > (uint32_t) a_op._reserved_1());
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
                return WAFLZ_STATUS_OK;
        }
        }
        if (a_op.is_negated())
        {
                // -----------------------------------------
                // negate value
                // -----------------------------------------
                ao_matched = !ao_matched;
        }
        // -------------------------------------------------
        // TODO -push matches???
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details check if request "in scope"
//! \return  true if in scope
//!          false if not in scope
//! \param   a_scope TODO
//! \param   a_ctx   TODO
//! ----------------------------------------------------------------------------
int32_t in_scope(bool& ao_match,
                 const waflz_pb::scope& a_scope,
                 rqst_ctx* a_ctx)
{
        ao_match = false;
        if (!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // host
        // -------------------------------------------------
        if (a_scope.has_host() &&
           a_scope.host().has_type() &&
           (a_scope.host().has_value() ||
            a_scope.host().values_size()))
        {
                const data_t &l_d = a_ctx->m_host;
                if (!l_d.m_data ||
                   !l_d.m_len)
                {
                        return WAFLZ_STATUS_OK;
                }
                bool l_matched = false;
                int32_t l_s;
                l_s = rl_run_op(l_matched,
                                a_scope.host(),
                                l_d.m_data,
                                l_d.m_len,
                                true);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                if (!l_matched)
                {
                        return WAFLZ_STATUS_OK;
                }
        }
        // -------------------------------------------------
        // path
        // -------------------------------------------------
        if (a_scope.has_path() &&
           a_scope.path().has_type() &&
           (a_scope.path().has_value() ||
            a_scope.path().values_size()))
        {
                data_t l_d = a_ctx->m_uri;
                if (!l_d.m_data ||
                   !l_d.m_len)
                {
                        return WAFLZ_STATUS_OK;
                }
                // -----------------------------------------
                // use length w/o q string
                // -----------------------------------------
                if (a_ctx->m_uri_path_len)
                {
                        l_d.m_len = a_ctx->m_uri_path_len;
                }
                bool l_matched = false;
                int32_t l_s;
                l_s = rl_run_op(l_matched,
                                a_scope.path(),
                                l_d.m_data,
                                l_d.m_len,
                                true);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                if (!l_matched)
                {
                        return WAFLZ_STATUS_OK;
                }
        }
        ao_match = true;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details check if a host and path are "in scope"
//! \return  true if a host and path are in scope
//!          false if not in scope
//! \param   a_host  TODO
//! \param   a_path  TODO
//! \param   a_ctx   TODO
//! ----------------------------------------------------------------------------
int32_t in_scope_response_with_cstr(bool &ao_match, const waflz_pb::scope& a_scope,
                                   const char* a_host, uint32_t a_host_len,
                                   const char* a_path, uint32_t a_path_len)
{
        // -------------------------------------------------
        // default no match
        // -------------------------------------------------
        ao_match = false;
        // -------------------------------------------------
        // host
        // -------------------------------------------------
        bool l_has_host = ( a_scope.has_host() &&
                            a_scope.host().has_type() &&
                            ( a_scope.host().has_value() ||
                              a_scope.host().values_size() ));
        if ( l_has_host && a_host && a_host_len )
        {
                bool l_matched = false;
                int32_t l_s = rl_run_op(l_matched,
                                a_scope.host(),
                                a_host,
                                a_host_len,
                                true);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                if (!l_matched)
                {
                        return WAFLZ_STATUS_OK;
                }
        }
        // -------------------------------------------------
        // path
        // -------------------------------------------------
        bool l_has_path = ( a_scope.has_path() &&
                            a_scope.path().has_type() &&
                            ( a_scope.path().has_value() ||
                              a_scope.path().values_size() ));
        if ( l_has_path && a_path && a_path_len )
        {
                bool l_matched = false;
                int32_t l_s = rl_run_op(l_matched,
                                a_scope.path(),
                                a_path,
                                a_path_len,
                                true);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                if (!l_matched)
                {
                        return WAFLZ_STATUS_OK;
                }
        }
        // -------------------------------------------------
        // set to true if both host and path passed
        // -------------------------------------------------
        ao_match = true;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details check if response "in scope"
//! \return  true if in scope
//!          false if not in scope
//! \param   a_scope TODO
//! \param   a_ctx   TODO
//! ----------------------------------------------------------------------------
int32_t in_scope_response(bool &ao_match,
                 const waflz_pb::scope &a_scope,
                 resp_ctx *a_ctx)
{
        ao_match = false;
        if (!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // host
        // -------------------------------------------------
        if (a_scope.has_host() &&
           a_scope.host().has_type() &&
           (a_scope.host().has_value() ||
            a_scope.host().values_size()))
        {
                const data_t &l_d = a_ctx->m_host;
                if (!l_d.m_data ||
                   !l_d.m_len)
                {
                        return WAFLZ_STATUS_OK;
                }
                bool l_matched = false;
                int32_t l_s;
                l_s = rl_run_op(l_matched,
                                a_scope.host(),
                                l_d.m_data,
                                l_d.m_len,
                                true);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                if (!l_matched)
                {
                        return WAFLZ_STATUS_OK;
                }
        }
        // -------------------------------------------------
        // path
        // -------------------------------------------------
        if (a_scope.has_path() &&
           a_scope.path().has_type() &&
           (a_scope.path().has_value() ||
            a_scope.path().values_size()))
        {
                data_t l_d = a_ctx->m_uri;
                if (!l_d.m_data ||
                   !l_d.m_len)
                {
                        return WAFLZ_STATUS_OK;
                }
                // use length w/o q string
                // use length w/o q string
                if (a_ctx->m_uri_path_len)
                {
                        l_d.m_len = a_ctx->m_uri_path_len;
                }
                bool l_matched = false;
                int32_t l_s;
                l_s = rl_run_op(l_matched,
                                a_scope.path(),
                                l_d.m_data,
                                l_d.m_len,
                                true);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                if (!l_matched)
                {
                        return WAFLZ_STATUS_OK;
                }
        }
        ao_match = true;
        return WAFLZ_STATUS_OK;
}

//! ----------------------------------------------------------------------------
//! \details C binding for third party lib to create a scopes obj
//! \return  a scopes object
//! \param   a_engine: waflz engine object
//! ----------------------------------------------------------------------------
extern "C" scopes* create_scopes(engine* a_engine,
                                 kv_db* a_db,
                                 kv_db* a_bot_db)
{
        ns_waflz::challenge* l_ch = NULL;
        ns_waflz::captcha* l_ca = NULL;
        return new scopes(*a_engine, *a_db, *a_bot_db, *l_ch, *l_ca);
}
//! ----------------------------------------------------------------------------
//! \details C binding for third party lib to load a scopes config in json frmt
//! \return  0 on success
//!          -1 on failure
//! \param   a_scope: scopes object
//! \param   a_buf: a char pointer to contents of a scopes config file
//! \param   a_len: length of a_buf
//! \param   a_conf_dir: the location of acl, waf, rules config
//!          which are part of a scope config
//! ----------------------------------------------------------------------------
extern "C" int32_t load_config(scopes* a_scope,
                               const char* a_buf,
                               uint32_t a_len,
                               const char* a_conf_dir)
{
        std::string l_conf_dir(a_conf_dir);
        return a_scope->load(a_buf, a_len, l_conf_dir);
}
//! ----------------------------------------------------------------------------
//! \details C binding for third party lib to process a request through waflz
//! \return  0 on success
//!          -1 on failure
//! \param   a_scope: scopes object
//! \param   a_ctx: void pointer of the request ctx of the calling http library
//! \param   a_rqst_ctx: object of waflz rqst_ctx class, which holds all 
//!          the pieces of a http request
//! \param   a_callbacks: callback struct which tells rqst_ctx where to get 
//!          the peices of a http request from the given ao_ctx
//! \param   ao_event: event details, if there was an action taken by waflz
//! ----------------------------------------------------------------------------
extern "C" int32_t process_waflz(void** ao_enf,
                                 size_t* ao_enf_len,
                                 void** ao_audit_event,
                                 size_t* ao_audit_event_len,
                                 void** ao_prod_event,
                                 size_t* ao_prod_event_len,
                                 scopes* a_scope,
                                 void* a_ctx,
                                 const rqst_ctx_callbacks* a_cb,
                                 rqst_ctx** a_rqst_ctx)
{
        if (!a_scope)
        {
                return WAFLZ_STATUS_ERROR;
        }
        int32_t l_s;
        l_s = a_scope->process_request_plugin(ao_enf,
                                              ao_enf_len,
                                              ao_audit_event,
                                              ao_audit_event_len,
                                              ao_prod_event,
                                              ao_prod_event_len,
                                              a_ctx,
                                              a_cb,
                                              a_rqst_ctx);
        return l_s;
}
//! ----------------------------------------------------------------------------
//! \details C binding for third party lib to do a graceful cleanup of scopes
//!          object
//! \return  0: success
//! \param   a_scope: scopes object
//! ----------------------------------------------------------------------------
extern "C" int32_t cleanup_scopes(scopes* a_scopes)
{
        if (a_scopes)
        {
                delete a_scopes;
                a_scopes = NULL;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details get error message string
//! \return  char* err message string
//! \param   a_scope: scopes object
//! ----------------------------------------------------------------------------
extern "C" const char* get_waflz_error_msg(scopes* a_scopes)
{
        if (a_scopes)
        {
                return a_scopes->get_err_msg();
        }
        return NULL;
}
}
