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
#include "profile.pb.h"
#include "action.pb.h"
#include "request_info.pb.h"
#include "acl.pb.h"
#include "event.pb.h"
#include "jspb/jspb.h"
#include "support/ndebug.h"
#include "support/file_util.h"
#include "support/time_util.h"
#include "op/regex.h"
#include "waflz/def.h"
#include "waflz/city.h"
#include "waflz/engine.h"
#include "waflz/limit.h"
#include "waflz/profile.h"
#include "waflz/acl.h"
#include "waflz/waf.h"
#include "waflz/rqst_ctx.h"
#include "waflz/config_parser.h"
#include "waflz/string_util.h"
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "waflz/trace.h"
#include "support/time_util.h"
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define _CONFIG_PROFILE_MAX_SIZE (1<<20)
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
#define VERIFY_HAS(_pb, _field) do { \
        if(!_pb.has_##_field()) { \
                WAFLZ_PERROR(m_err_msg, "missing %s field", #_field); \
                return WAFLZ_STATUS_ERROR; \
        } \
} while(0)
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
static void clear_ignore_list(pcre_list_t &a_pcre_list)
{
        for(pcre_list_t::iterator i_r = a_pcre_list.begin();
            i_r != a_pcre_list.end();
            ++i_r)
        {
                if(*i_r)
                {
                        delete *i_r;
                        *i_r = NULL;
                }
        }
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
profile::profile(engine &a_engine):
        m_init(false),
        m_pb(NULL),
        m_err_msg(),
        m_engine(a_engine),
        m_waf(NULL),
        m_id(),
        m_cust_id(),
        m_team_config(false),
        m_name(),
        m_resp_header_name(),
        m_action(waflz_pb::enforcement_type_t_NOP),
        m_paranoia_level(1),
        m_il_query(),
        m_il_header(),
        m_il_cookie()
{
        m_pb = new waflz_pb::profile();
}
//! ----------------------------------------------------------------------------
//! \details dtor
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
profile::~profile()
{
        if(m_pb) { delete m_pb; m_pb = NULL; }
        if(m_waf) { delete m_waf; m_waf = NULL; }
        clear_ignore_list(m_il_query);
        clear_ignore_list(m_il_header);
        clear_ignore_list(m_il_cookie);
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
void profile::set_pb(waflz_pb::profile *a_pb)
{
        if(m_pb)
        {
                delete m_pb;
                m_pb = NULL;
        }
        m_pb = a_pb;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t profile::load(const char *a_buf, uint32_t a_buf_len)
{
        if(a_buf_len > _CONFIG_PROFILE_MAX_SIZE)
        {
                WAFLZ_PERROR(m_err_msg, "config file size(%u) > max size(%u)",
                             a_buf_len,
                             _CONFIG_PROFILE_MAX_SIZE);
                return WAFLZ_STATUS_ERROR;
        }
        m_init = false;
        // -------------------------------------------------
        // new pb obj
        // -------------------------------------------------
        if(m_pb)
        {
                delete m_pb;
                m_pb = NULL;
        }
        // -------------------------------------------------
        // load from json
        // -------------------------------------------------
        m_pb = new waflz_pb::profile();
        int32_t l_s;
        l_s = update_from_json(*m_pb, a_buf, a_buf_len);
        //NDBG_PRINT("whole config %s", m_pb->DebugString().c_str());
        if(l_s != JSPB_OK)
        {
                WAFLZ_PERROR(m_err_msg, "%s", get_jspb_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        l_s = init();
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t profile::load(void* a_js)
{
        m_init = false;
        const rapidjson::Document &l_js = *((rapidjson::Document *)a_js);
        int32_t l_s;
        if(m_pb)
        {
                delete m_pb;
                m_pb = NULL;
        }
        m_pb = new waflz_pb::profile();
        l_s = update_from_json(*m_pb, l_js);
        if(l_s != JSPB_OK)
        {
                WAFLZ_PERROR(m_err_msg, "parsing json. Reason: %s", get_jspb_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        l_s = init();
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t profile::load(const waflz_pb::profile *a_pb)
{
        if(!a_pb)
        {
                WAFLZ_PERROR(m_err_msg, "pb == NULL (input)");
                return WAFLZ_STATUS_ERROR;
        }
        m_init = false;
        if(m_pb)
        {
                delete m_pb;
                m_pb = NULL;
        }
        // -------------------------------------------------
        // copy from profile pb
        // -------------------------------------------------
        m_pb = new waflz_pb::profile();
        m_pb->CopyFrom(*a_pb);
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        int32_t l_s;
        l_s = init();
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t profile::regex_list_add(const std::string &a_regex,
                                pcre_list_t &a_pcre_list)
{
        int32_t l_s;
        regex *l_regex = new regex();
        l_s = l_regex->init(a_regex.c_str(), a_regex.length());
        if(l_s != WAFLZ_STATUS_OK)
        {
                const char *l_err_ptr;
                int l_err_off;
                l_regex->get_err_info(&l_err_ptr, l_err_off);
                delete l_regex;
                l_regex = NULL;
                WAFLZ_PERROR(m_err_msg, "init failed for regex: '%s' in general_settings ignore list. Reason: %s -offset: %d",
                            a_regex.c_str(),
                            l_err_ptr,
                            l_err_off);
                return WAFLZ_STATUS_ERROR;
        }
        // add to map
        a_pcre_list.push_back(l_regex);
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t profile::init(void)
{
        if(m_init)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // validate/compile/load
        // -------------------------------------------------
        int32_t l_s;
        l_s = validate();
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // create new waf object...
        // -------------------------------------------------
        if(m_waf)
        {
                delete m_waf;
                m_waf = NULL;
        }
        m_waf = new waf(m_engine);
        // -------------------------------------------------
        // copy over properties
        // -------------------------------------------------
        m_waf->set_id(m_id);
        m_waf->set_name(m_name);
        m_waf->set_paranoia_level(m_paranoia_level);
        // -------------------------------------------------
        // json parser
        // -------------------------------------------------
        if(m_pb->general_settings().has_json_parser())
        {
                m_waf->set_parse_json(m_pb->general_settings().json_parser());
        }
        // -------------------------------------------------
        // xml parser
        // -------------------------------------------------
        if(m_pb->general_settings().has_xml_parser())
        {
                m_waf->set_parse_xml(m_pb->general_settings().xml_parser());
        }
        // -------------------------------------------------
        // Don't log matched data
        // -------------------------------------------------
        if(m_pb->general_settings().has_no_log_matched())
        {
                m_waf->set_no_log_matched(m_pb->general_settings().no_log_matched());
        }
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        l_s = m_waf->init(*this);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "%s", m_waf->get_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // *************************************************
        //                  I G N O R E
        // *************************************************
        // -------------------------------------------------
        const ::waflz_pb::profile_general_settings_t& l_gs = m_pb->general_settings();
        // -------------------------------------------------
        // ignore query args
        // -------------------------------------------------
        for(int32_t i_q = 0;
            i_q < l_gs.ignore_query_args_size();
            ++i_q)
        {
                std::string l_query_arg = l_gs.ignore_query_args(i_q);
                l_s = regex_list_add(l_query_arg, m_il_query);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // ignore headers
        // -------------------------------------------------
        for(int32_t i_h = 0;
            i_h < l_gs.ignore_header_size();
            ++i_h)
        {
                std::string l_header = l_gs.ignore_header(i_h);
                l_s = regex_list_add(l_header, m_il_header);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // ignore cookies
        // -------------------------------------------------
        for(int32_t i_c = 0;
            i_c < l_gs.ignore_cookie_size();
            ++i_c)
        {
                std::string l_cookie = l_gs.ignore_cookie(i_c);
                l_s = regex_list_add(l_cookie, m_il_cookie);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // add recaptcha cookie in ignore list for all
        // profiles
        // -------------------------------------------------
        regex_list_add(CAPTCHA_GOOGLE_TOKEN, m_il_cookie);
        m_init = true;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details Validate json for generating modsecurity configuration
//!          For now we do this simply by checking that it has all
//!          the required elements.  We could use a json-schema
//!          implementation in C (http://json-schema.org/implementations.html)
//!          but we have such a nice lightweight json component, it seems
//!          a shame to bring in a huge thing just for this use
//! \return  0 if it is valid, ao_err_msg reset
//!          -1 if it is not and ao_err_msg is populated
//! ----------------------------------------------------------------------------
int32_t profile::validate(void)
{
        if(m_init)
        {
                return WAFLZ_STATUS_OK;
        }
        if(!m_pb)
        {
                WAFLZ_PERROR(m_err_msg, "pb == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        const waflz_pb::profile &l_pb = *m_pb;
        // -------------------------------------------------
        // id/name
        // -------------------------------------------------
        VERIFY_HAS(l_pb, id);
        VERIFY_HAS(l_pb, name);
        m_id = m_pb->id();
        m_name = m_pb->name();
        // -------------------------------------------------
        // ruleset info
        // -------------------------------------------------
        VERIFY_HAS(l_pb, ruleset_id);
        VERIFY_HAS(l_pb, ruleset_version);
        //TODO: Throw waflz error once customer_id
        // field is added to all profiles
        if(m_pb->has_customer_id())
        {
                m_cust_id = m_pb->customer_id();
        }
        if (m_pb->has_team_config())
        {
                m_team_config = m_pb->team_config();
        }
        // -------------------------------------------------
        // general settings
        // -------------------------------------------------
        VERIFY_HAS(l_pb, general_settings);
        const ::waflz_pb::profile_general_settings_t& l_gs = l_pb.general_settings();
        // set paranoia
        if(l_gs.has_paranoia_level())
        {
                m_paranoia_level = l_gs.paranoia_level();
        }
        VERIFY_HAS(l_gs, xml_parser);
        VERIFY_HAS(l_gs, validate_utf8_encoding);
        VERIFY_HAS(l_gs, max_num_args);
        VERIFY_HAS(l_gs, arg_name_length);
        VERIFY_HAS(l_gs, arg_length);
        VERIFY_HAS(l_gs, total_arg_length);
        VERIFY_HAS(l_gs, anomaly_threshold);
        // -------------------------------------------------
        // set resp header name
        // -------------------------------------------------
        if(l_gs.has_response_header_name())
        {
                m_resp_header_name = l_gs.response_header_name();
        }
        // -------------------------------------------------
        // disabled rules
        // -------------------------------------------------
        if(l_pb.disabled_rules_size())
        {
                for(int32_t i_r = 0;
                    i_r < l_pb.disabled_rules_size();
                    ++i_r)
                {
                        const waflz_pb::profile_disabled_rule_t& l_r = l_pb.disabled_rules(i_r);
                        VERIFY_HAS(l_r, rule_id);
                }
        }
        // -------------------------------------------------
        // custom rules
        // -------------------------------------------------
        // TODO ???
        // -------------------------------------------------
        // custom scores --optional
        // -------------------------------------------------
        if (l_pb.custom_scores_size())
        {
                for (int32_t i_r = 0; i_r < l_pb.custom_scores_size(); ++i_r)
                {
                        const waflz_pb::profile_custom_score_t &l_r =
                            l_pb.custom_scores(i_r);
                        // ---------------------------------
                        // check if there is a rule id
                        // or rule_id_list
                        // ---------------------------------
                        if (!l_r.has_rule_id() && l_r.rule_id_list_size() == 0)
                        {
                                WAFLZ_PERROR(
                                    m_err_msg,
                                    "missing rule_id and rule_id_list field");
                                return WAFLZ_STATUS_ERROR;
                        }
                        // ---------------------------------
                        // verify score is over 0
                        // ---------------------------------
                        VERIFY_HAS(l_r, score);
                        if ( l_r.score() <= 0 )
                        {
                                WAFLZ_PERROR(
                                    m_err_msg,
                                    "score must be over 0");
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        // -------------------------------------------------
        // rule target updates --optional
        // -------------------------------------------------
        if (l_pb.rule_target_updates_size())
        {
                for(int32_t i_r = 0;
                    i_r < l_pb.rule_target_updates_size();
                    ++i_r)
                {
                        const waflz_pb::profile_rule_target_update_t& l_r = l_pb.rule_target_updates(i_r);
                        // ---------------------------------
                        // check if there is a rule id
                        // or rule_id_list
                        // ---------------------------------
                        if ( !l_r.has_rule_id() && l_r.rule_id_list_size() == 0 ){
                                WAFLZ_PERROR(m_err_msg, "missing rule_id and rule_id_list field");
                                return WAFLZ_STATUS_ERROR;
                        }
                        VERIFY_HAS(l_r, target);
                        VERIFY_HAS(l_r, target_match);
                        VERIFY_HAS(l_r, is_regex);
                }
        }
        // -------------------------------------------------
        // redacted variables
        // -------------------------------------------------
        if ( l_pb.redacted_variables_size() )
        {
                for (int32_t i_r = 0;
                    i_r < l_pb.redacted_variables_size();
                    ++i_r)
                {
                        // ---------------------------------
                        // get redacted variable
                        // ---------------------------------
                        const waflz_pb::profile_redacted_var_t& l_r = l_pb.redacted_variables(i_r);
                        // ---------------------------------
                        // verify has information
                        // ---------------------------------
                        VERIFY_HAS(l_r, match_on);
                        VERIFY_HAS(l_r, replacement_value);
                        // ---------------------------------
                        // verify regex is correctly formed
                        // ---------------------------------
                        int32_t l_s;
                        regex* l_pcre = new regex();
                        const std::string& l_rx = l_r.match_on();
                        l_s = l_pcre->init(l_rx.c_str(), l_rx.length());
                        if (l_s != WAFLZ_STATUS_OK)
                        {
                                const char* l_err_ptr;
                                int l_err_off;
                                l_pcre->get_err_info(&l_err_ptr, l_err_off);
                                WAFLZ_PERROR(m_err_msg, "Failed to init re from %s. Reason: %s -offset: %d",
                                             l_rx.c_str(),
                                             l_err_ptr,
                                             l_err_off);
                                if (l_pcre) { delete l_pcre; l_pcre = NULL; }
                                return WAFLZ_STATUS_ERROR;
                        }
                        if (l_pcre) { delete l_pcre; l_pcre = NULL; }
                }
        }
        // -------------------------------------------------
        // validated
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}

//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t profile::process_response(waflz_pb::event **ao_event,
                         void *a_ctx,
                         part_mk_t a_part_mk,
                         resp_ctx **ao_resp_ctx)
{
        if(!ao_event)
        {
                WAFLZ_PERROR(m_err_msg, "ao_event == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        *ao_event = NULL;
        int32_t l_s;
        // -------------------------------------------------
        // create new if null
        // -------------------------------------------------
        resp_ctx *l_resp_ctx = NULL;
        if(ao_resp_ctx &&
           *ao_resp_ctx)
        {
                l_resp_ctx = *ao_resp_ctx;
        }
        if(!l_resp_ctx)
        {
                WAFLZ_PERROR(m_err_msg, "ao_resp_ctx == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        if(m_waf->get_request_body_in_memory_limit() > 0)
        {
                l_resp_ctx->set_body_max_len(m_waf->get_request_body_in_memory_limit());
        }
        // -------------------------------------------------
        // run phase 3 init
        // -------------------------------------------------
        l_s = l_resp_ctx->init_phase_3(m_engine.get_geoip2_mmdb());
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "performing resp_ctx::init_phase_3");
                if(!ao_resp_ctx && l_resp_ctx) { delete l_resp_ctx; l_resp_ctx = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        waflz_pb::event *l_event = NULL;
        // -------------------------------------------------
        // process waf...
        // -------------------------------------------------
        if(a_part_mk & PART_MK_WAF)
        {
                l_s = m_waf->process_response(&l_event, a_ctx, &l_resp_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", m_waf->get_err_msg());
                        if(!ao_resp_ctx && l_resp_ctx) { delete l_resp_ctx; l_resp_ctx = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // We got an event
        // -------------------------------------------------
        if(l_event)
        {
                l_s = l_resp_ctx->append_resp_info(*l_event);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "performing resp_ctx::append_rqst_info");
                        if(!ao_resp_ctx && l_resp_ctx) { delete l_resp_ctx; l_resp_ctx = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
                l_event->set_rule_intercept_status(403);
                l_event->set_waf_profile_id(m_pb->id());
                l_event->set_waf_profile_name(m_pb->name());
                if(!m_resp_header_name.empty())
                {
                        l_event->set_response_header_name(get_resp_header_name());
                }
                else
                {
                        // -------------------------------------------------
                        // general settings
                        // -------------------------------------------------
                        if (m_pb->has_general_settings() && m_pb->general_settings().has_response_header_name())
                        {
                                // -------------------------------------------------
                                // set resp header name in event
                                // -------------------------------------------------
                                m_resp_header_name = m_pb->general_settings().response_header_name();
                                l_event->set_response_header_name(m_resp_header_name);
                        }
                }
                if(m_pb->has_last_modified_date())
                {
                        l_event->set_config_last_modified(m_pb->last_modified_date());
                }
                *ao_event = l_event;
        }
        if(!ao_resp_ctx && l_resp_ctx) { delete l_resp_ctx; l_resp_ctx = NULL; }
        return WAFLZ_STATUS_OK;
}

//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t profile::process(waflz_pb::event **ao_event,
                         void *a_ctx,
                         part_mk_t a_part_mk,
                         rqst_ctx **ao_rqst_ctx)
{
        if(!ao_event)
        {
                WAFLZ_PERROR(m_err_msg, "ao_event == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        *ao_event = NULL;
        int32_t l_s;
        // -------------------------------------------------
        // create new if null
        // -------------------------------------------------
        rqst_ctx *l_rqst_ctx = NULL;
        if(ao_rqst_ctx &&
           *ao_rqst_ctx)
        {
                l_rqst_ctx = *ao_rqst_ctx;
        }
        if(!l_rqst_ctx)
        {
                WAFLZ_PERROR(m_err_msg, "ao_rqst_ctx == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        if(m_waf->get_request_body_in_memory_limit() > 0)
        {
                l_rqst_ctx->set_body_max_len(m_waf->get_request_body_in_memory_limit());
        }
        // -------------------------------------------------
        // run phase 1 init
        // -------------------------------------------------
        l_s = l_rqst_ctx->init_phase_1(m_engine, &m_il_query, &m_il_header, &m_il_cookie);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "performing rqst_ctx::init_phase_1");
                if(!ao_rqst_ctx && l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        waflz_pb::event *l_event = NULL;
        // -------------------------------------------------
        // optionally set xml capture xxe
        // TODO remove or move this elsewhere later
        // -------------------------------------------------
        if(m_pb->has_general_settings() &&
           m_pb->general_settings().has_xml_capture_xxe() &&
           m_pb->general_settings().xml_capture_xxe())
        {
                l_rqst_ctx->m_xml_capture_xxe = true;
        }
        // -------------------------------------------------
        // process waf...
        // -------------------------------------------------
        if(a_part_mk & PART_MK_WAF)
        {
                l_s = m_waf->process(&l_event, a_ctx, &l_rqst_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "waf error %.*s", WAFLZ_ERR_REASON_LEN, m_waf->get_err_msg());
                        if(!ao_rqst_ctx && l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // We got an event
        // -------------------------------------------------
        if(l_event)
        {
                l_s = l_rqst_ctx->append_rqst_info(*l_event, m_engine.get_geoip2_mmdb());
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "performing rqst_ctx::append_rqst_info");
                        if(!ao_rqst_ctx && l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
                l_event->set_rule_intercept_status(403);
                l_event->set_waf_profile_id(m_pb->id());
                l_event->set_waf_profile_name(m_pb->name());
                if(!m_resp_header_name.empty())
                {
                        l_event->set_response_header_name(m_resp_header_name);
                }
                if(m_pb->has_last_modified_date())
                {
                        l_event->set_config_last_modified(m_pb->last_modified_date());
                }
                *ao_event = l_event;
        }
        if(!ao_rqst_ctx && l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        return WAFLZ_STATUS_OK;
}
}
