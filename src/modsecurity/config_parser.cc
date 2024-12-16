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
#include "support/ndebug.h"
#include "support/file_util.h"
#include "waflz/engine.h"
#include "waflz/config_parser.h"
#include "waflz/def.h"
#include "waflz/string_util.h"
#include "jspb/jspb.h"
#include "rule.pb.h"
#include <google/protobuf/descriptor.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pcre.h>
#include <regex.h>
#include <set>
#include <algorithm>
//! ----------------------------------------------------------------------------
//! Macros
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! Errors
//! ----------------------------------------------------------------------------
#define WAFLZ_CONFIG_ERROR_MSG(a_msg) \
        do { \
                show_config_error(__FILE__,__FUNCTION__,__LINE__,a_msg); \
        } while (0)
//! ----------------------------------------------------------------------------
//! Scanning
//! ----------------------------------------------------------------------------
#define SCAN_OVER_SPACE(l_line, l_char, l_line_len) \
        do { \
                while (isspace(int(*l_line)) && \
                      (l_char < l_line_len)) \
                {\
                        ++l_char;\
                        ++l_line;\
                }\
        } while (0)
#define SCAN_OVER_NON_SPACE_ESC(l_line, l_char, l_line_len) \
        do { \
                while ((!isspace(int(*l_line)) || (isspace(int(*l_line)) && (*(l_line - 1) == '\\') && (*(l_line - 2) != '\\'))) && \
                     (l_char < l_line_len))\
                {\
                        ++l_char;\
                        ++l_line;\
                }\
        } while (0)
#define SCAN_OVER_SPACE_BKWD(l_line, l_char) \
        do { \
                while (isspace(int(*l_line)) && (l_char > 0))\
                {\
                        --l_char;\
                        --l_line;\
                }\
        } while (0)
#define SCAN_UNTIL_ESC(l_line, l_delimiter, l_char, l_line_len) \
        do { \
                while ((((*l_line) != l_delimiter) || (((*l_line) == l_delimiter) && (*(l_line - 1) == '\\') && (*(l_line - 2) != '\\'))) && \
                     (l_char < l_line_len))\
                {\
                        ++l_char;\
                        ++l_line;\
                }\
        } while (0)
#define SCAN_UNTIL_ESC_QUOTE(l_line, l_delimiter, l_char, l_line_len) \
        do { \
                while ((((*l_line) != l_delimiter) || (((*l_line) == l_delimiter) && (*(l_line - 1) == '\\') && (*(l_line - 2) != '\\'))) && \
                     (l_char < l_line_len))\
                {\
                        if ((*l_line) == '\'') { ++l_char; ++l_line; SCAN_UNTIL_ESC(l_line, '\'', l_char, l_line_len); }\
                        if (l_char >= l_line_len) break; \
                        ++l_char;\
                        ++l_line;\
                }\
        } while (0)
//! ----------------------------------------------------------------------------
//! Caseless compare
//! ----------------------------------------------------------------------------
#define STRCASECMP_KV(_match) (strcasecmp(i_kv->m_key.c_str(), _match) == 0)
#define STRCASECMP(_str, _match) (strcasecmp(_str.c_str(), _match) == 0)
#define BUFCASECMP(_str, _match) (strncasecmp(_str, _match, strlen(_match)) == 0)
//! ----------------------------------------------------------------------------
//! String 2 int
//! ----------------------------------------------------------------------------
#define STR2INT(a_str) strtoul(a_str.data(), NULL, 10)
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int32_t parse_setvar(::waflz_pb::sec_action_t_setvar_t &ao_setvar,
                            const std::string &a_str)
{
        //NDBG_PRINT("setvar: %s\n", a_str.c_str());
        const char *l_sv_buf = a_str.c_str();
        uint32_t l_sv_len = a_str.length();
        uint32_t l_sv_idx = 0;
        SCAN_OVER_SPACE(l_sv_buf, l_sv_idx, l_sv_len);
        // -------------------------------------------------
        // if ! -set op to DELETE
        // -------------------------------------------------
        if (*l_sv_buf == '!')
        {
                ao_setvar.set_op(::waflz_pb::sec_action_t_setvar_t_op_t_DELETE);
                ++l_sv_buf;
                ++l_sv_idx;
        }
        SCAN_OVER_SPACE(l_sv_buf, l_sv_idx, l_sv_len);
        const char *l_scope = l_sv_buf;
        uint32_t l_scope_len = l_sv_idx;
        SCAN_UNTIL_ESC(l_sv_buf, '.', l_sv_idx, l_sv_len);
        l_scope_len = l_sv_idx - l_scope_len;
        // -------------------------------------------------
        // scope
        // -------------------------------------------------
        if (BUFCASECMP(l_scope, "tx"))
        {
                ao_setvar.set_scope(::waflz_pb::sec_action_t_setvar_t_scope_t_TX);
        }
        else if (BUFCASECMP(l_scope, "ip"))
        {
                ao_setvar.set_scope(::waflz_pb::sec_action_t_setvar_t_scope_t_IP);
        }
        else if (BUFCASECMP(l_scope, "global"))
        {
                ao_setvar.set_scope(::waflz_pb::sec_action_t_setvar_t_scope_t_GLOBAL);
        }
        else
        {
                // -------------------------------------------------
                // TODO log error
                // -------------------------------------------------
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // skip past
        // -------------------------------------------------
        if (l_sv_idx >= l_sv_len)
        {
                // -------------------------------------------------
                // TODO log error
                // -------------------------------------------------
                return WAFLZ_STATUS_ERROR;
        }
        ++l_sv_buf;
        ++l_sv_idx;
        if (l_sv_idx >= l_sv_len)
        {
                // -------------------------------------------------
                // TODO log error
                // -------------------------------------------------
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get var
        // -------------------------------------------------
        const char *l_var = l_sv_buf;
        uint32_t l_var_len = l_sv_idx;
        while ((l_sv_idx < l_sv_len) &&
              (*l_sv_buf != '='))
        {
                ++l_sv_buf;
                ++l_sv_idx;
        }
        l_var_len = l_sv_idx - l_var_len;
        if (l_var_len == 0)
        {
                // -------------------------------------------------
                // TODO log error
                // -------------------------------------------------
                return WAFLZ_STATUS_ERROR;
        }
        ao_setvar.set_var(l_var, l_var_len);
        if (ao_setvar.op() == ::waflz_pb::sec_action_t_setvar_t_op_t_DELETE)
        {
                return WAFLZ_STATUS_OK;
        }
        if (l_sv_idx >= l_sv_len)
        {
                ao_setvar.set_op(::waflz_pb::sec_action_t_setvar_t_op_t_ASSIGN);
                ao_setvar.set_val("1");
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // get operator
        // -------------------------------------------------
        if (*l_sv_buf != '=')
        {
                // -------------------------------------------------
                // TODO log error
                // -------------------------------------------------
                return WAFLZ_STATUS_ERROR;
        }
        ++l_sv_buf;
        ++l_sv_idx;
        if (l_sv_idx >= l_sv_len)
        {
                ao_setvar.set_val("");
                ao_setvar.set_op(::waflz_pb::sec_action_t_setvar_t_op_t_ASSIGN);
                return WAFLZ_STATUS_OK;
        }
        if (*l_sv_buf == '-')
        {
                ++l_sv_buf;
                ++l_sv_idx;
                ao_setvar.set_op(::waflz_pb::sec_action_t_setvar_t_op_t_DECREMENT);
        }
        else if (*l_sv_buf == '+')
        {
                ++l_sv_buf;
                ++l_sv_idx;
                ao_setvar.set_op(::waflz_pb::sec_action_t_setvar_t_op_t_INCREMENT);
        }
        else
        {
                ao_setvar.set_op(::waflz_pb::sec_action_t_setvar_t_op_t_ASSIGN);
        }
        // -------------------------------------------------
        // get update value
        // -------------------------------------------------
        ao_setvar.set_val(l_sv_buf, (l_sv_len - l_sv_idx));
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t config_parser::show_config_error(const char *a_file, const char *a_func, uint32_t a_line, const char *a_msg)
{
        NDBG_OUTPUT("%s.%s.%d: Error in file: %s line: %d:%d [%s]. Reason: %s\n",
                        a_file,
                        a_func,
                        a_line,
                        m_cur_file.c_str(),
                        m_cur_line_num,
                        m_cur_line_pos,
                        m_cur_line.c_str(),
                        a_msg
                        );
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t config_parser::add_action(waflz_pb::sec_action_t &ao_action,
                                  const kv_list_t & a_action_list,
                                  bool &ao_is_chained)
{
        for (kv_list_t::const_iterator i_kv = a_action_list.begin();
            i_kv != a_action_list.end();
            ++i_kv)
        {
                // -----------------------------------------
                // id
                // -----------------------------------------
                if (STRCASECMP_KV("id"))
                {
                        // ---------------------------------
                        // Use first
                        // ---------------------------------
                        if (!i_kv->m_list.empty())
                        {
                                ao_action.set_id(*(i_kv->m_list.begin()));
                        }
                }
                // -----------------------------------------
                // msg
                // -----------------------------------------
                else if (STRCASECMP_KV("msg"))
                {
                        // Use first
                        if (!i_kv->m_list.empty())
                        {
                                ao_action.set_msg(*(i_kv->m_list.begin()));
                        }
                }
                // -----------------------------------------
                // accuracy
                // -----------------------------------------
                else if (STRCASECMP_KV("accuracy"))
                {
                        // ---------------------------------
                        // Use first
                        // ---------------------------------
                        if (!i_kv->m_list.empty())
                        {
                                ao_action.set_accuracy(*(i_kv->m_list.begin()));
                        }
                }
                // -----------------------------------------
                // capture
                // -----------------------------------------
                else if (STRCASECMP_KV("capture"))
                {
                        // Use first
                        if (!i_kv->m_list.empty())
                        {
                                ++(m_actions["capture"]);
                                ao_action.set_capture(true);
                        }
                }
                // -----------------------------------------
                // ctl
                // -----------------------------------------
                else if (STRCASECMP_KV("ctl"))
                {
                        for (string_list_t::const_iterator i_ctl = i_kv->m_list.begin();
                            i_ctl != i_kv->m_list.end();
                            ++i_ctl)
                        {
                                if (i_ctl->empty())
                                {
                                        continue;
                                }
                                size_t l_pos;
                                l_pos = i_ctl->find('=');
                                if (l_pos == std::string::npos)
                                {
                                        continue;
                                }
                                // -------------------------
                                // Get the ctl action
                                // -------------------------
                                std::string l_ctl_k = i_ctl->substr(0, l_pos);
                                if (STRCASECMP(l_ctl_k, "auditengine"))
                                {
                                        ao_action.set_audit_engine(i_ctl->substr(l_pos+1));
                                }
                                else if (STRCASECMP(l_ctl_k, "ruleengine"))
                                {
                                        ao_action.set_rule_engine(i_ctl->substr(l_pos+1));
                                }
                                else if (STRCASECMP(l_ctl_k, "forcerequestbodyvariable"))
                                {
                                        ao_action.set_force_request_body_variable(i_ctl->substr(l_pos+1));
                                }
                                else if (STRCASECMP(l_ctl_k, "requestbodyaccess"))
                                {
                                        ao_action.set_request_body_access(i_ctl->substr(l_pos+1));
                                }
                                else if (STRCASECMP(l_ctl_k, "auditlogparts"))
                                {
                                        ao_action.set_audit_log_parts(i_ctl->substr(l_pos+1));
                                }
                                else if (STRCASECMP(l_ctl_k, "requestBodyProcessor"))
                                {
                                        ao_action.set_request_body_processor(i_ctl->substr(l_pos+1));
                                }
                                else if (STRCASECMP(l_ctl_k, "ruleremovebyid"))
                                {
                                        ao_action.mutable_rule_remove_by_id()->assign(i_ctl->substr(l_pos+1));
                                }
                                // -------------------------
                                // TODO -fix!!!
                                // -------------------------
#if 0                                     
                                // -------------------------
                                // ctl:ruleRemoveTargetById=123;ARGS:/^id_/
                                // -------------------------
                                else if (STRCASECMP(l_ctl_k, "ruleremovetargetbyid"))
                                {
                                        // -----------------
                                        // get everything 
                                        // after = 
                                        // '123;ARGS:/^id_/'
                                        // -----------------
                                        std::string l_target = i_ctl->substr(l_pos+1);
                                        size_t l_pos_id;
                                        // -----------------
                                        // get id 123
                                        // -----------------
                                        l_pos_id = l_target.find(";");
                                        waflz_pb::sec_action_t_rule_update_t *l_rm_target_by_id = ao_action.mutable_rule_remove_target_by_id();
                                        // -----------------
                                        // set the id of 
                                        // the rule
                                        // -----------------
                                        l_rm_target_by_id->set_id(l_target.substr(0, l_pos_id));
                                        // -----------------
                                        // get target value 
                                        // 'ARGS:/^id_/'
                                        // -----------------
                                        std::string l_target_val = l_target.substr(l_pos_id+1);
                                        if (l_target_val.at(0) == '!')
                                        {
                                                l_rm_target_by_id->set_is_negated(true);
                                        }
                                        else
                                        {
                                                l_rm_target_by_id->set_is_negated(false);
                                        }
                                        size_t l_pos_target;
                                        l_pos_target = l_target_val.find(":");
                                        // -----------------
                                        // We have a target 
                                        // match ':/^id_/'
                                        // -----------------
                                        if (l_pos_target != std::string::npos)
                                        {
                                                if (l_rm_target_by_id->is_negated())
                                                {
                                                        l_rm_target_by_id->set_target(l_target_val.substr(1, l_pos_target));
                                                }
                                                else
                                                {
                                                        l_rm_target_by_id->set_target(l_target_val.substr(0, l_pos_target));
                                                }
                                                // ---------
                                                // get
                                                // target 
                                                // match 
                                                // which is 
                                                // '/^id_/' 
                                                // ---------
                                                std::string l_target_match = l_target_val.substr(l_pos_target + 1);
                                                // ---------
                                                // Check is 
                                                // its a 
                                                // regex 
                                                // '/^id_/'
                                                // ---------
                                                if ((l_target_match[0] == '/') &&
                                                   (l_target_match[l_target_match.length() - 1] == '/'))
                                                {
                                                        l_rm_target_by_id->set_target_match(l_target_match.substr(1, l_target_match.length() - 2));
                                                        l_rm_target_by_id->set_is_regex(true);
                                                }
                                                else
                                                {
                                                        l_rm_target_by_id->set_target_match(l_target_match);
                                                        l_rm_target_by_id->set_is_regex(false);
                                                }
                                        }
                                        else
                                        {
                                                if (l_rm_target_by_id->is_negated())
                                                {
                                                        l_rm_target_by_id->set_target(l_target_val.substr(1, l_pos_target));
                                                }
                                                else
                                                {
                                                        l_rm_target_by_id->set_target(l_target_val.substr(0, l_pos_target));
                                                }
                                        }
                                }
#endif
                                // -------------------------
                                // TODO -fix!!!
                                // -------------------------
#if 0
                                // -------------------------
                                // ctl:ruleRemoveTargetByTag=OWASP_CRS/(WEB_ATTACK/;ARGS:login[password]
                                // -------------------------
                                else if (STRCASECMP(l_ctl_k, "ruleremovetargetbytag"))
                                {
                                        // -----------------
                                        // get everything 
                                        // after = 
                                        // 'OWASP_CRS/(WEB_ATTACK/;ARGS:login[password]'
                                        // -----------------
                                        std::string l_target = i_ctl->substr(l_pos+1);
                                        size_t l_pos_id;
                                        // -----------------
                                        // get id 123 
                                        // -----------------
                                        l_pos_id = l_target.find(";");
                                        waflz_pb::sec_action_t_rule_update_t *l_rm_target_by_tag = ao_action.mutable_ruleremovetargetbytag();
                                        // -----------------
                                        // set the tag of
                                        // the rule 
                                        // -----------------
                                        l_rm_target_by_tag->set_tag(l_target.substr(0, l_pos_id));
                                        // -----------------
                                        // get target value
                                        // 'ARGS:/^id_/' 
                                        // -----------------
                                        std::string l_target_val = l_target.substr(l_pos_id+1);
                                        if (l_target_val.at(0) == '!')
                                        {
                                                l_rm_target_by_tag->set_is_negated(true);
                                        }
                                        else
                                        {
                                                l_rm_target_by_tag->set_is_negated(false);
                                        }
                                        size_t l_pos_target;
                                        l_pos_target = l_target_val.find(":");
                                        // -----------------
                                        // We have a target 
                                        // match ':/^id_/'
                                        // -----------------
                                        if (l_pos_target != std::string::npos)
                                        {
                                                if (l_rm_target_by_tag->is_negated())
                                                {
                                                        l_rm_target_by_tag->set_target(l_target_val.substr(1, l_pos_target));
                                                }
                                                else
                                                {
                                                        l_rm_target_by_tag->set_target(l_target_val.substr(0, l_pos_target));
                                                }
                                                // ---------
                                                // get target 
                                                // match which 
                                                // is '/^id_/' 
                                                // ---------
                                                std::string l_target_match = l_target_val.substr(l_pos_target + 1);
                                                // ---------
                                                // Check is 
                                                // its a regex 
                                                // '/^id_/' 
                                                // ---------
                                                if ((l_target_match[0] == '/') &&
                                                   (l_target_match[l_target_match.length() - 1] == '/'))
                                                {
                                                        l_rm_target_by_tag->set_target_match(l_target_match.substr(1, l_target_match.length() - 2));
                                                        l_rm_target_by_tag->set_is_regex(true);
                                                }
                                                else
                                                {
                                                        l_rm_target_by_tag->set_target_match(l_target_match);
                                                        l_rm_target_by_tag->set_is_regex(false);
                                                }
                                        }
                                        else
                                        {
                                                if (l_rm_target_by_tag->is_negated())
                                                {
                                                        l_rm_target_by_tag->set_target(l_target_val.substr(1, l_pos_target));
                                                }
                                                else
                                                {
                                                        l_rm_target_by_tag->set_target(l_target_val.substr(0, l_pos_target));
                                                }
                                        }
                                }
#endif
                                else
                                {
                                        ++m_unimplemented_ctls[l_ctl_k.c_str()];
                                }
                                ++(m_ctls[l_ctl_k]);
                        }
                }
                // -----------------------------------------
                // log
                // -----------------------------------------
                else if (STRCASECMP_KV("log"))
                {
                        // ---------------------------------
                        // Use first
                        // ---------------------------------
                        if (!i_kv->m_list.empty())
                        {
                                ao_action.set_log(true);
                        }
                }
                // -----------------------------------------
                // logdata
                // -----------------------------------------
                else if (STRCASECMP_KV("logdata"))
                {
                        // ---------------------------------
                        // Use first
                        // ---------------------------------
                        if (!i_kv->m_list.empty())
                        {
                                ao_action.set_logdata(*(i_kv->m_list.begin()));
                        }
                }
                // -----------------------------------------
                // maturity
                // -----------------------------------------
                else if (STRCASECMP_KV("maturity"))
                {
                        // ---------------------------------
                        // Use first
                        // ---------------------------------
                        if (!i_kv->m_list.empty())
                        {
                                ao_action.set_maturity(*(i_kv->m_list.begin()));
                        }
                }
                // -----------------------------------------
                // multimatch
                // -----------------------------------------
                else if (STRCASECMP_KV("multimatch"))
                {
                        // ---------------------------------
                        // Use first
                        // ---------------------------------
                        if (!i_kv->m_list.empty())
                        {
                                ao_action.set_multimatch(true);
                        }
                }
                // -----------------------------------------
                // noauditlog
                // -----------------------------------------
                else if (STRCASECMP_KV("noauditlog"))
                {
                        // ---------------------------------
                        // Use first
                        // ---------------------------------
                        if (!i_kv->m_list.empty())
                        {
                                ao_action.set_noauditlog(true);
                        }
                }
                // -----------------------------------------
                // auditlog
                // -----------------------------------------
                else if (STRCASECMP_KV("auditlog"))
                {
                        // ---------------------------------
                        // Use first
                        // ---------------------------------
                        if (!i_kv->m_list.empty())
                        {
                                ao_action.set_auditlog(true);
                        }
                }
                // -----------------------------------------
                // sanitisematched
                // -----------------------------------------
                else if (STRCASECMP_KV("sanitisematched"))
                {
                        // ---------------------------------
                        // Use first
                        // ---------------------------------
                        if (!i_kv->m_list.empty())
                        {
                                ao_action.set_sanitisematched(true);
                        }
                }
                // -----------------------------------------
                // initcol
                // -----------------------------------------
                else if (STRCASECMP_KV("initcol"))
                {
                        // ---------------------------------
                        // Use first
                        // ---------------------------------
                        if (!i_kv->m_list.empty())
                        {
                                ao_action.set_initcol(*(i_kv->m_list.begin()));
                        }
                }
                // status
                else if (STRCASECMP_KV("status"))
                {
                        // ---------------------------------
                        // Use first
                        // ---------------------------------
                        if (!i_kv->m_list.empty())
                        {
                                ao_action.set_status(*(i_kv->m_list.begin()));
                        }
                }
                // -----------------------------------------
                // initcol
                // -----------------------------------------
                else if (STRCASECMP_KV("skip"))
                {
                        // ---------------------------------
                        // Use first
                        // ---------------------------------
                        if (!i_kv->m_list.empty())
                        {
                                ++(m_actions["skip"]);
                                ao_action.set_skip(STR2INT((*(i_kv->m_list.begin()))));
                        }
                }
                // -----------------------------------------
                // noauditlog
                // -----------------------------------------
                else if (STRCASECMP_KV("nolog"))
                {
                        // ---------------------------------
                        // Use first
                        // ---------------------------------
                        if (!i_kv->m_list.empty())
                        {
                                ++(m_actions["nolog"]);
                                ao_action.set_nolog(true);
                        }
                }
                // -----------------------------------------
                // phase
                // -----------------------------------------
                else if (STRCASECMP_KV("phase"))
                {
                        // ---------------------------------
                        // Use first
                        // ---------------------------------
                        if (!i_kv->m_list.empty())
                        {
                                // -------------------------
                                // Starting in ModSecurity
                                // version v2.7 there are
                                // aliases for some phase
                                // numbers:
                                // 2 - request
                                // 4 - response
                                // 5 - logging
                                // -------------------------
                                std::string l_phase = *(i_kv->m_list.begin());
                                if (STRCASECMP(l_phase, "request"))
                                {
                                        ao_action.set_phase(MODSECURITY_RULE_PHASE_REQUEST_BODY);
                                }
                                else if (STRCASECMP(l_phase, "response"))
                                {
                                        ao_action.set_phase(MODSECURITY_RULE_PHASE_RESPONSE_BODY);
                                }
                                else if (STRCASECMP(l_phase, "logging"))
                                {
                                        ao_action.set_phase(MODSECURITY_RULE_PHASE_LOGGING);
                                }
                                else
                                {
                                       ao_action.set_phase(STR2INT((*(i_kv->m_list.begin()))));
                                }
                        }
                }
                // -----------------------------------------
                // rev
                // -----------------------------------------
                else if (STRCASECMP_KV("rev"))
                {
                        // ---------------------------------
                        // Use first
                        // ---------------------------------
                        if (!i_kv->m_list.empty())
                        {
                                ao_action.set_rev(*(i_kv->m_list.begin()));
                        }
                }
                // -----------------------------------------
                // severity
                // -----------------------------------------
                else if (STRCASECMP_KV("severity"))
                {
                        // ---------------------------------
                        // Use first
                        // ---------------------------------
                        if (!i_kv->m_list.empty())
                        {
                                ao_action.set_severity((*(i_kv->m_list.begin())));
                        }
                }
                // -----------------------------------------
                // setvar
                // -----------------------------------------
                else if (STRCASECMP_KV("setvar"))
                {
                        // ---------------------------------
                        // Use first
                        // ---------------------------------
                        if (!i_kv->m_list.empty())
                        {
                                for (string_list_t::const_iterator i_t = i_kv->m_list.begin();
                                    i_t != i_kv->m_list.end();
                                    ++i_t)
                                {
                                        int32_t l_s;
                                        ::waflz_pb::sec_action_t_setvar_t l_setvar;
                                        ++(m_actions["setvar"]);
                                        l_s = parse_setvar(l_setvar, *i_t);
                                        if (l_s != WAFLZ_STATUS_OK)
                                        {
                                                NDBG_PRINT("error performing parse_setvar\n");
                                                return WAFLZ_STATUS_ERROR;
                                        }
                                        ::waflz_pb::sec_action_t_setvar_t* l_ptr = ao_action.add_setvar();
                                        //NDBG_PRINT("setvar: %s\n", l_setvar.ShortDebugString().c_str());
                                        l_ptr->CopyFrom(l_setvar);
                                }
                        }
                }
                // -----------------------------------------
                // skipAfter
                // -----------------------------------------
                else if (STRCASECMP_KV("skipafter"))
                {
                        // ---------------------------------
                        // Use first
                        // ---------------------------------
                        if (!i_kv->m_list.empty())
                        {
                                ++(m_actions["skipafter"]);
                                ao_action.set_skipafter(*(i_kv->m_list.begin()));
                        }
                }
                // -----------------------------------------
                // tag
                // -----------------------------------------
                else if (STRCASECMP_KV("tag"))
                {
                        // ---------------------------------
                        // Use first
                        // ---------------------------------
                        if (!i_kv->m_list.empty())
                        {
                                for (string_list_t::const_iterator i_t = i_kv->m_list.begin();
                                    i_t != i_kv->m_list.end();
                                    ++i_t)
                                {
                                        ao_action.add_tag(*i_t);
                                }
                        }
                }
                // -----------------------------------------
                // ver
                // -----------------------------------------
                else if (STRCASECMP_KV("ver"))
                {
                        // ---------------------------------
                        // Use first
                        // ---------------------------------
                        if (!i_kv->m_list.empty())
                        {
                                ao_action.set_ver(*(i_kv->m_list.begin()));
                        }
                }
                // -----------------------------------------
                // actions
                // -----------------------------------------
                else if (STRCASECMP_KV("pass"))
                {
                        ++(m_actions["pass"]);
                        ao_action.set_action_type(waflz_pb::sec_action_t_action_type_t_PASS);
                }
                else if (STRCASECMP_KV("block"))
                {
                        ++(m_actions["block"]);
                        ao_action.set_action_type(waflz_pb::sec_action_t_action_type_t_BLOCK);
                }
                else if (STRCASECMP_KV("deny"))
                {
                        ++(m_actions["deny"]);
                        ao_action.set_action_type(waflz_pb::sec_action_t_action_type_t_DENY);
                }
                else if (STRCASECMP_KV("drop"))
                {
                        ++(m_actions["drop"]);
                        ao_action.set_action_type(waflz_pb::sec_action_t_action_type_t_DROP);
                }
                // -----------------------------------------
                // used???
                // -----------------------------------------
                else if (STRCASECMP_KV("expirevar"))
                {
                        ++(m_actions["expirevar"]);
                        if (!i_kv->m_list.empty())
                        {
                                ao_action.set_expirevar(*(i_kv->m_list.begin()));
                        }
                }
                // -----------------------------------------
                // allow may or may not have a param. eg:
                //  SecAction phase:1,allow:request,id:96
                // and
                //  SecAction phase:1,allow,id:97
                // -----------------------------------------
                else if (STRCASECMP_KV("allow"))
                {
                        ++(m_actions["allow"]);
                        std::string l_tmp;
                        // ---------------------------------
                        // Use first
                        // ---------------------------------
                        if (!i_kv->m_list.empty())
                        {
                                l_tmp += "allow:";
                                l_tmp += *(i_kv->m_list.begin());
                                ao_action.set_allow(l_tmp);
                        }
                        else
                        {
                                ao_action.set_allow("allow");
                        }
                        //ao_action.set_action_type(waflz_pb::sec_action_t_action_type_t_ALLOW);
                }
                // -----------------------------------------
                // transforms
                // -----------------------------------------
                else if (STRCASECMP_KV("t"))
                {
                        // ---------------------------------
                        // Add transforms for list
                        // ---------------------------------
                        for (string_list_t::const_iterator i_t = i_kv->m_list.begin();
                            i_t != i_kv->m_list.end();
                            ++i_t)
                        {
#define _ELIF_TX(_tx) else if (STRCASECMP((*i_t), #_tx)) { \
                ++(m_transformations[#_tx]);\
                ao_action.add_t(waflz_pb::sec_action_t_transformation_type_t_##_tx); \
        }
                                if (0) {}
                                _ELIF_TX(CMDLINE)
                                _ELIF_TX(COMPRESSWHITESPACE)
                                _ELIF_TX(CSSDECODE)
                                _ELIF_TX(HEXENCODE)
                                _ELIF_TX(HEXDECODE)
                                _ELIF_TX(HTMLENTITYDECODE)
                                _ELIF_TX(JSDECODE)
                                _ELIF_TX(LENGTH)
                                _ELIF_TX(LOWERCASE)
                                _ELIF_TX(MD5)
                                _ELIF_TX(NONE)
                                _ELIF_TX(NORMALIZEPATH)
                                _ELIF_TX(NORMALISEPATH)
                                _ELIF_TX(NORMALIZEPATHWIN)
                                _ELIF_TX(REMOVENULLS)
                                _ELIF_TX(REMOVEWHITESPACE)
                                _ELIF_TX(REMOVECOMMENTS)
                                _ELIF_TX(REPLACECOMMENTS)
                                _ELIF_TX(REMOVECOMMENTS)
                                _ELIF_TX(SHA1)
                                _ELIF_TX(URLDECODEUNI)
                                _ELIF_TX(URLDECODE)
                                _ELIF_TX(UTF8TOUNICODE)
                                else
                                {
                                        std::string l_lowercase = *i_t;
                                        std::transform(l_lowercase.begin(), l_lowercase.end(), l_lowercase.begin(), ::tolower);
                                        ++(m_unimplemented_transformations[l_lowercase]);
                                }
                        }
                }
                // -----------------------------------------
                // chain
                // -----------------------------------------
                else if (STRCASECMP_KV("chain"))
                {
                        ao_is_chained = true;
                }
                // -----------------------------------------
                // default
                // -----------------------------------------
                else
                {
                        std::string l_lowercase = i_kv->m_key;
                        std::transform(l_lowercase.begin(), l_lowercase.end(), l_lowercase.begin(), ::tolower);
                        ++(m_unimplemented_actions[l_lowercase]);
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t config_parser::add_rule(waflz_pb::sec_config_t &ao_config,
                                variable_list_t &a_variable_list,
                                const std::string &a_operator_fx,
                                const std::string &a_operator_match,
                                const kv_list_t &a_action_list,
                                bool a_operator_is_negated)
{
        waflz_pb::sec_rule_t *l_rule = NULL;
        bool l_is_chained = false;
        // -------------------------------------------------
        // Add rule to config or to chain
        // -------------------------------------------------
        if (m_cur_parent_rule)
        {
                l_rule = m_cur_parent_rule->add_chained_rule();
        }
        else
        {
                waflz_pb::directive_t *l_directive = ao_config.add_directive();
                l_rule = l_directive->mutable_sec_rule();
                //l_rule->set_order(ao_config.sec_rule_size() - 1);
        }
        // -------------------------------------------------
        // variables...
        // -------------------------------------------------
        for (variable_list_t::iterator i_v = a_variable_list.begin();
            i_v != a_variable_list.end();
            ++i_v)
        {
                if (!*i_v)
                {
                        continue;
                }
                l_rule->add_variable()->CopyFrom(**i_v);
                delete *i_v;
                *i_v = NULL;
        }
        // -----------------------------------------------------------
        // operator...
        // -----------------------------------------------------------
        if (!a_operator_fx.empty() || !a_operator_match.empty())
        {
                waflz_pb::sec_rule_t::operator_t *l_operator = l_rule->mutable_operator_();
                l_operator->set_is_negated(a_operator_is_negated);
                if (!a_operator_fx.empty())
                {
                        l_operator->set_is_regex(false);
                        if (STRCASECMP(a_operator_fx, "RX"))
                        {
                                l_operator->set_is_regex(true);
                        }
                        if (0) {}
#define _SET_OPERATOR_if(_op) \
        else if (STRCASECMP(a_operator_fx, #_op)) { \
                ++(m_operators[#_op]); \
                l_operator->set_type(waflz_pb::sec_rule_t_operator_t_type_t_##_op); }
                        _SET_OPERATOR_if(BEGINSWITH)
                        _SET_OPERATOR_if(CONTAINS)
                        _SET_OPERATOR_if(CONTAINSWORD)
                        _SET_OPERATOR_if(ENDSWITH)
                        _SET_OPERATOR_if(EQ)
                        _SET_OPERATOR_if(GE)
                        _SET_OPERATOR_if(GEOLOOKUP)
                        _SET_OPERATOR_if(GSBLOOKUP)
                        _SET_OPERATOR_if(GT)
                        _SET_OPERATOR_if(INSPECTFILE)
                        _SET_OPERATOR_if(IPMATCH)
                        _SET_OPERATOR_if(IPMATCHF)
                        _SET_OPERATOR_if(IPMATCHFROMFILE)
                        _SET_OPERATOR_if(LE)
                        _SET_OPERATOR_if(LT)
                        _SET_OPERATOR_if(NOMATCH)
                        _SET_OPERATOR_if(PM)
                        _SET_OPERATOR_if(PMF)
                        _SET_OPERATOR_if(PMFROMFILE)
                        _SET_OPERATOR_if(RBL)
                        _SET_OPERATOR_if(RSUB)
                        _SET_OPERATOR_if(RX)
                        _SET_OPERATOR_if(STREQ)
                        _SET_OPERATOR_if(STRMATCH)
                        _SET_OPERATOR_if(UNCONDITIONALMATCH)
                        _SET_OPERATOR_if(VALIDATEDTD)
                        _SET_OPERATOR_if(VALIDATEHASH)
                        _SET_OPERATOR_if(VALIDATESCHEMA)
                        _SET_OPERATOR_if(VALIDATEBYTERANGE)
                        _SET_OPERATOR_if(VALIDATEURLENCODING)
                        _SET_OPERATOR_if(VALIDATEUTF8ENCODING)
                        _SET_OPERATOR_if(VERIFYCC)
                        _SET_OPERATOR_if(DETECTXSS)
                        _SET_OPERATOR_if(VERIFYSSN)
                        _SET_OPERATOR_if(DETECTSQLI)
                        _SET_OPERATOR_if(WITHIN)
                        // ---------------------------------
                        // default
                        // ---------------------------------
                        else
                        {
                                std::string l_lowercase = a_operator_fx;
                                std::transform(l_lowercase.begin(), l_lowercase.end(), l_lowercase.begin(), ::tolower);
                                ++(m_unimplemented_operators[l_lowercase]);
                        }
                }
                else if (!a_operator_match.empty())
                {
                        l_operator->set_is_regex(true);
                }
                if (!a_operator_match.empty())
                {
                        l_operator->set_value(a_operator_match);
#if 0
                        // ---------------------------------
                        // fix path for files
                        // ---------------------------------
                        if (l_operator->has_type() &&
                           ((l_operator->type() == ::waflz_pb::sec_rule_t_operator_t_type_t_PMF) ||
                           (l_operator->type() == ::waflz_pb::sec_rule_t_operator_t_type_t_PMFROMFILE) ||
                           (l_operator->type() == ::waflz_pb::sec_rule_t_operator_t_type_t_IPMATCHF) ||
                           (l_operator->type() == ::waflz_pb::sec_rule_t_operator_t_type_t_IPMATCHFROMFILE)) &&
                           a_operator_match[0] != '/')
                        {
                                std::string l_path;
                                l_path = m_cur_file_dir;
                                l_path += "/";
                                l_path += a_operator_match;
                                l_operator->set_value(l_path);
                        }
                        else
                        {
                                l_operator->set_value(a_operator_match);
                        }
#endif
                }
        }
        // -----------------------------------------------------------
        // actions...
        // Add action
        // -----------------------------------------------------------
        waflz_pb::sec_action_t *l_action = l_rule->mutable_action();
        int32_t l_s;
        l_s = add_action(*l_action, a_action_list, l_is_chained);
        if (l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -----------------------------------------------------------
        // handle chain
        // -----------------------------------------------------------
        if (!l_is_chained)
        {
                m_cur_parent_rule = NULL;
        }
        else if (!m_cur_parent_rule)
        {
                m_cur_parent_rule = l_rule;
        }
        // -----------------------------------------------------------
        // set file
        // -----------------------------------------------------------
        l_action->set_file(m_cur_file_base);
        // -----------------------------------------------------------
        // set hidden to false
        // -----------------------------------------------------------
        l_rule->set_hidden(false);
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t config_parser::tokenize_kv_list(const std::string &a_string,
                                        const char a_delimiter,
                                        kv_list_t &ao_kv_list)
{
        // -----------------------------------------------------------
        // TODO Add arg to specify kv delimiter -hard coded to ':' now
        // Parse list by characters
        // Scan over string copying bits into list until end-of-string
        // -----------------------------------------------------------
        uint32_t i_char = 0;
        const char *l_line = a_string.data();
        uint32_t l_line_len = a_string.length();
        while (i_char < l_line_len)
        {
                const char *l_str_begin = l_line;
                uint32_t l_str_begin_index = i_char;
                SCAN_UNTIL_ESC_QUOTE(l_line, a_delimiter, i_char, l_line_len);
                std::string l_part;
                l_part.assign(l_str_begin, i_char - l_str_begin_index);
                //NDBG_PRINT("PART[%d]: %s\n", 0, l_part.c_str());
                // -----------------------------------------
                // Now we have a string -that is optional 
                // split by colon's
                // -----------------------------------------
                std::string l_key;
                std::string l_val = "";
                const char *l_str_key = l_part.data();
                uint32_t i_char_key = 0;
                SCAN_UNTIL_ESC_QUOTE(l_str_key, ':', i_char_key, l_part.length());
                l_key.assign(l_part.data(), i_char_key);
                if (i_char_key < l_part.length())
                {
                        l_val.assign(l_str_key + 1, l_part.length() - i_char_key);
                }
                // -----------------------------------------
                // Clean quotes
                // -----------------------------------------
                if (!l_val.empty() && l_val.at(0) == '\'' )
                {
                        std::string l_val_tmp = l_val;
                        l_val.assign(l_val_tmp.data() + 1, l_val_tmp.length() - 3);
                }
                std::string l_val_tmp = l_val.c_str();
                l_val = l_val_tmp;
                //NDBG_PRINT("KEY[%s]: %s\n", l_key.c_str(), l_val.c_str());
                //ao_string_list.push_back(l_part);
                // -----------------------------------------
                // find in list
                // -----------------------------------------
                kv_list_t::iterator i_kv;
                for (i_kv = ao_kv_list.begin(); i_kv != ao_kv_list.end(); ++i_kv)
                {
                        if (i_kv->m_key == l_key)
                        {
                                break;
                        }
                }
                l_key.erase( std::remove_if(l_key.begin(), l_key.end(), ::isspace), l_key.end());
                if (i_kv == ao_kv_list.end())
                {
                        kv_t l_kv;
                        l_kv.m_key = l_key;
                        l_kv.m_list.push_back(l_val);
                        ao_kv_list.push_back(l_kv);
                }
                else
                {
                        i_kv->m_list.push_back(l_val);
                }
                if (i_char < l_line_len)
                {
                        ++i_char;
                        ++l_line;
                        // ---------------------------------
                        // chomp whitespace
                        // ---------------------------------
                        SCAN_OVER_SPACE(l_line, i_char, l_line_len);
                        if (i_char >= l_line_len)
                        {
                                break;
                        }
                }
                else
                {
                        break;
                }
        }
        if (m_verbose)
        {
                for (kv_list_t::iterator i_kv = ao_kv_list.begin();
                    i_kv != ao_kv_list.end();
                    ++i_kv)
                {
                        uint32_t i_var = 0;
                        for (string_list_t::iterator i_v = i_kv->m_list.begin();
                            i_v != i_kv->m_list.end();
                            ++i_v, ++i_var)
                        {
                                NDBG_OUTPUT("KEY: %24s[%3d]: %s\n", i_kv->m_key.c_str(), i_var, i_v->c_str());
                        }
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t config_parser::get_next_string(char **ao_line,
                                     uint32_t *ao_char,
                                     uint32_t a_line_len,
                                     std::string &ao_string)
{
        //NDBG_PRINT("%sao_line%s: %.*s\n",  ANSI_COLOR_FG_RED, ANSI_COLOR_OFF, a_line_len, (*ao_line));
        // -------------------------------------------------
        // Scan past whitespace to first quote
        // -------------------------------------------------
        SCAN_OVER_SPACE(*ao_line, *ao_char, a_line_len);
        if (*ao_char == a_line_len)
        {
                return WAFLZ_STATUS_OK;
        }
        bool l_is_quoted = true;
        if ((*(*ao_line)) != '\"')
        {
                if (isgraph(int((*(*ao_line)))) || (int((*(*ao_line))) == '&'))
                {
                        l_is_quoted = false;
                        //NDBG_PRINT("%sNO_QUOTE%s: l_line: %s\n", ANSI_COLOR_BG_RED, ANSI_COLOR_OFF, (*ao_line));
                }
                else
                {
                        WAFLZ_CONFIG_ERROR_MSG("isgraph");
                        return WAFLZ_STATUS_ERROR;
                }
        }
        if (l_is_quoted)
        {
                ++(*ao_char);
                ++(*ao_line);
        }
        const char *l_str_begin = *ao_line;
        uint32_t l_str_begin_index = *ao_char;
        //NDBG_PRINT("START[%d]: %s\n",  l_str_begin_index, *ao_line);
        if (l_is_quoted)
        {
                SCAN_UNTIL_ESC(*ao_line, '"', *ao_char, a_line_len);
                if ((*ao_char) == a_line_len)
                {
                        ao_string.assign(l_str_begin, *ao_char - l_str_begin_index);
                        return WAFLZ_STATUS_OK;
                }
        }
        else
        {
                SCAN_OVER_NON_SPACE_ESC(*ao_line, *ao_char, a_line_len);
        }
        //NDBG_PRINT("STR: %.*s\n",  *ao_char - l_str_begin_index, l_str_begin);
        //NDBG_PRINT("END: %d\n", *ao_char - l_str_begin_index);
        ao_string.assign(l_str_begin, *ao_char - l_str_begin_index);
        if (l_is_quoted)
        {
                ++(*ao_char);
                ++(*ao_line);
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t config_parser::get_strings_from_line(const char *a_line,
                                           uint32_t a_line_len,
                                           string_list_t &ao_str_list)
{
        const char *l_line = a_line;
        uint32_t l_char = 0;
        uint32_t l_line_len = a_line_len;
        int32_t l_s = WAFLZ_STATUS_OK;
        std::string l_str;
        do {
                l_str.clear();
                l_s = get_next_string((char **)&l_line, &l_char, l_line_len, l_str);
                if ((l_s == WAFLZ_STATUS_OK) && !l_str.empty())
                {
                        //NDBG_PRINT("l_s: %d l_str: %s\n", l_s, l_str.c_str());
                        ao_str_list.push_back(l_str);
                }
        } while ((l_s == WAFLZ_STATUS_OK) && !l_str.empty());
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! \notes:
//!   Syntax:        SecRule  VARIABLES  OPERATOR      [ACTIONS]
//!   Example Usage: SecRule  ARGS       "@rx attack"  "phase:1,log,deny,id:1"
//! ----------------------------------------------------------------------------
int32_t config_parser::add_secaction(waflz_pb::sec_config_t &ao_config,
                                      const char *a_line,
                                      uint32_t a_line_len,
                                      bool a_is_default)
{
        uint32_t i_char = 0;
        const char *l_line = a_line;
        uint32_t l_line_len = a_line_len;
        int32_t l_s;
        //NDBG_OUTPUT("------------------------------------------------------------------\n");
        //NDBG_OUTPUT("FILE: %s %sLINE%s[%d] %sDIRECTIVE%s: %s: %s\n",
        //                m_cur_file.c_str(),
        //                ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF, m_cur_line_num,
        //                ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF, "SEC_RULE",
        //                a_line);
        // -------------------------------------------------
        // Scan past whitespace
        // -------------------------------------------------
        SCAN_OVER_SPACE(l_line, i_char, l_line_len);
        if (i_char == l_line_len)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // get ACTIONS [optional]
        // -------------------------------------------------
        std::string l_actions;
        l_s = get_next_string((char **)&l_line, &i_char, l_line_len, l_actions);
        if (l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        //NDBG_PRINT("l_actions: %s\n", l_actions.c_str());
        if (m_verbose)
        {
                if (m_color)
                {
                        NDBG_OUTPUT("%sLINE%s[%d] %s%s%s\n",
                                        ANSI_COLOR_FG_WHITE, ANSI_COLOR_OFF, m_cur_line_num,
                                        ANSI_COLOR_FG_YELLOW, l_actions.c_str(), ANSI_COLOR_OFF);
                }
                else
                {
                        NDBG_OUTPUT("LINE[%d] %s\n",
                                        m_cur_line_num,
                                        l_actions.c_str());
                }
        }
        // -------------------------------------------------
        // Try parse actions
        // -------------------------------------------------
        kv_list_t l_action_list;
        l_s = tokenize_kv_list(l_actions, ',', l_action_list);
        if (l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // Add rule
        // -------------------------------------------------
        waflz_pb::sec_action_t *l_action = NULL;
        if (a_is_default)
        {
                l_action = ao_config.mutable_default_action();
        }
        else
        {
                waflz_pb::directive_t *l_directive = ao_config.add_directive();
                // -----------------------------------------
                // l_directive->
                // -----------------------------------------
                l_action = l_directive->mutable_sec_action();
        }
        bool l_unused;
        l_s = add_action(*l_action, l_action_list, l_unused);
        if (l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t config_parser::parse_vars(variable_list_t &ao_variable_list,
                                  const std::string &a_str,
                                  char a_sep)
{
        // -------------------------------------------------
        // Try parse variables
        // -------------------------------------------------
        kv_list_t l_var_list;
        int32_t l_s;
        l_s = tokenize_kv_list(a_str, a_sep, l_var_list);
        if (l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // variables...
        // -------------------------------------------------
        for (kv_list_t::const_iterator i_kv = l_var_list.begin();
            i_kv != l_var_list.end();
            ++i_kv)
        {
                // -----------------------------------------
                // Loop over list
                // -----------------------------------------
                for (string_list_t::const_iterator i_v = i_kv->m_list.begin();
                    i_v != i_kv->m_list.end();
                    ++i_v)
                {
                        const std::string &i_str = *i_v;
                        bool l_found_key = true;
                        std::string l_var_str;
                        bool l_match_is_negated = false;
                        bool l_is_count = false;
                        // ---------------------------------
                        // negation
                        // ---------------------------------
                        if (i_kv->m_key.at(0) == '!')
                        {
                                l_match_is_negated = true;
                                l_var_str.assign(i_kv->m_key.data() + 1, i_kv->m_key.length() - 1);
                        }
                        // ---------------------------------
                        // count
                        // ---------------------------------
                        else if (i_kv->m_key.at(0) == '&')
                        {
                                l_is_count = true;
                                l_var_str.assign(i_kv->m_key.data() + 1, i_kv->m_key.length() - 1);
                        }
                        // ---------------------------------
                        // assign var
                        // ---------------------------------
                        else
                        {
                                l_var_str = i_kv->m_key;
                        }
                        // ---------------------------------
                        // get type
                        // ---------------------------------
                        waflz_pb::variable_t_type_t l_var_type = waflz_pb::variable_t_type_t_ARGS;
#define VARIABLE_SET_IF_KV(a_key) \
        if (STRCASECMP(l_var_str, #a_key))\
        {\
                if (!i_kv->m_list.empty())\
                {\
                        ++(m_variables[#a_key]); \
                        l_var_type = waflz_pb::variable_t_type_t_##a_key;\
                }\
        }
                        VARIABLE_SET_IF_KV(ARGS)
                        else VARIABLE_SET_IF_KV(ARGS_COMBINED_SIZE)
                        else VARIABLE_SET_IF_KV(ARGS_NAMES)
                        else VARIABLE_SET_IF_KV(FILES)
                        else VARIABLE_SET_IF_KV(FILES_COMBINED_SIZE)
                        else VARIABLE_SET_IF_KV(FILES_NAMES)
                        else VARIABLE_SET_IF_KV(GLOBAL)
                        else VARIABLE_SET_IF_KV(MULTIPART_STRICT_ERROR)
                        else VARIABLE_SET_IF_KV(MULTIPART_UNMATCHED_BOUNDARY)
                        else VARIABLE_SET_IF_KV(QUERY_STRING)
                        else VARIABLE_SET_IF_KV(REMOTE_ADDR)
                        else VARIABLE_SET_IF_KV(REMOTE_ASN)
                        else VARIABLE_SET_IF_KV(REQBODY_ERROR)
                        else VARIABLE_SET_IF_KV(REQUEST_BASENAME)
                        else VARIABLE_SET_IF_KV(REQUEST_BODY)
                        else VARIABLE_SET_IF_KV(REQUEST_COOKIES)
                        else VARIABLE_SET_IF_KV(REQUEST_COOKIES_NAMES)
                        else VARIABLE_SET_IF_KV(REQUEST_FILENAME)
                        else VARIABLE_SET_IF_KV(REQUEST_HEADERS)
                        else VARIABLE_SET_IF_KV(REQUEST_HEADERS_NAMES)
                        else VARIABLE_SET_IF_KV(REQUEST_LINE)
                        else VARIABLE_SET_IF_KV(REQUEST_METHOD)
                        else VARIABLE_SET_IF_KV(REQUEST_PROTOCOL)
                        else VARIABLE_SET_IF_KV(REQUEST_URI)
                        else VARIABLE_SET_IF_KV(RESOURCE)
                        else VARIABLE_SET_IF_KV(RESPONSE_BODY)
                        else VARIABLE_SET_IF_KV(RESPONSE_STATUS)
                        else VARIABLE_SET_IF_KV(TX)
                        else VARIABLE_SET_IF_KV(WEBSERVER_ERROR_LOG)
                        else VARIABLE_SET_IF_KV(XML)
                        else VARIABLE_SET_IF_KV(REQBODY_PROCESSOR)
                        else VARIABLE_SET_IF_KV(ARGS_GET)
                        else VARIABLE_SET_IF_KV(ARGS_GET_NAMES)
                        else VARIABLE_SET_IF_KV(ARGS_POST)
                        else VARIABLE_SET_IF_KV(ARGS_POST_NAMES)
                        else VARIABLE_SET_IF_KV(MATCHED_VAR)
                        else VARIABLE_SET_IF_KV(RESPONSE_HEADERS)
                        else VARIABLE_SET_IF_KV(SESSION)
                        else VARIABLE_SET_IF_KV(GEO)
                        else VARIABLE_SET_IF_KV(REQUEST_URI_RAW)
                        else VARIABLE_SET_IF_KV(DURATION)
                        else VARIABLE_SET_IF_KV(MATCHED_VARS)
                        else VARIABLE_SET_IF_KV(MATCHED_VARS_NAMES)
                        else VARIABLE_SET_IF_KV(UNIQUE_ID)
                        else VARIABLE_SET_IF_KV(IP)
                        else VARIABLE_SET_IF_KV(SD_ISO)
                        // ---------------------------------
                        // default
                        // ---------------------------------
                        else
                        {
                                std::string l_lowercase = l_var_str;
                                std::transform(l_lowercase.begin(), l_lowercase.end(), l_lowercase.begin(), ::tolower);
                                ++(m_unimplemented_variables[l_lowercase]);
                                l_found_key = false;
                        }
                        if (STRCASECMP(l_var_str, "tx"))
                        {
                                //NDBG_PRINT("T: %s\n", i_v->c_str());
                                ++(m_tx_variables[i_str]);
                        }
                        waflz_pb::variable_t::match_t *l_match = NULL;
                        if (l_found_key &&
                           !(i_v->empty()))
                        {
                                l_match = new waflz_pb::variable_t::match_t();
                                l_match->set_is_negated(l_match_is_negated);
                                std::string l_match_str = i_str;
                                // -------------------------
                                // Check if has 
                                // "selection operator" '/'s
                                // -------------------------
                                if ((l_match_str[0] == '/') &&
                                   (l_match_str[l_match_str.length() - 1] == '/'))
                                {
                                        l_match->set_value(l_match_str.substr(1, l_match_str.length() - 2));
                                        l_match->set_is_regex(true);
                                }
                                else
                                {
                                        l_match->set_value(l_match_str);
                                        l_match->set_is_regex(false);
                                }
                        }
                        else if (l_found_key)
                        {
                                l_match = new waflz_pb::variable_t::match_t();
                                l_match->set_is_negated(false);
                                l_match->set_is_regex(false);
                        }
                        // ---------------------------------
                        // Find existing type?
                        // ---------------------------------
                        bool l_found_var = false;
                        variable_list_t::iterator i_var = ao_variable_list.begin();
                        for (;
                            i_var !=  ao_variable_list.end();
                            ++i_var)
                        {
                                if (!*i_var)
                                {
                                        continue;
                                }
                                if ((*i_var)->type()  == l_var_type)
                                {
                                        l_found_var = true;
                                        break;
                                }
                        }
                        // ---------------------------------
                        // not found -create new var...
                        // ---------------------------------
                        if (!l_found_var)
                        {
                                waflz_pb::variable_t *l_var = new waflz_pb::variable_t();
                                l_var->set_type(l_var_type);
                                l_var->set_is_count(l_is_count);
                                if (l_match)
                                {
                                        l_var->add_match()->CopyFrom(*l_match);
                                }
                                ao_variable_list.push_back(l_var);
                        }
                        // ---------------------------------
                        // Add match to existing var
                        // ---------------------------------
                        else if (l_match)
                        {
                                if (i_var == ao_variable_list.end())
                                {
                                        continue;
                                }
                                if (!*i_var)
                                {
                                        continue;
                                }
                                (*i_var)->add_match()->CopyFrom(*l_match);
                        }
                        if (l_match)
                        {
                                delete l_match;
                                l_match = NULL;
                        }
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! \notes:
//!   Syntax:        SecRule  VARIABLES  OPERATOR      [ACTIONS]
//!   Example Usage: SecRule  ARGS       "@rx attack"  "phase:1,log,deny,id:1"
//! ----------------------------------------------------------------------------
int32_t config_parser::add_secrule(waflz_pb::sec_config_t& ao_config,
                                   const char *a_line,
                                   uint32_t a_line_len)
{
        uint32_t i_char = 0;
        const char *l_line = a_line;
        uint32_t l_line_len = a_line_len;
        int32_t l_s;
        //NDBG_OUTPUT("------------------------------------------------------------------\n");
        //NDBG_OUTPUT("FILE: %s %sLINE%s[%d] %sDIRECTIVE%s: %s: %s\n",
        //                m_cur_file.c_str(),
        //                ANSI_COLOR_FG_YELLOW, ANSI_COLOR_OFF, m_cur_line_num,
        //                ANSI_COLOR_FG_GREEN, ANSI_COLOR_OFF, "SEC_RULE",
        //                a_line);
        // -------------------------------------------------
        // Scan past whitespace
        // -------------------------------------------------
        SCAN_OVER_SPACE(l_line, i_char, l_line_len);
        if (i_char == l_line_len)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // get VARIABLES
        // -------------------------------------------------
        std::string l_variables;
        l_s = get_next_string((char **)&l_line, &i_char, l_line_len, l_variables);
        if (l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        //NDBG_PRINT("l_variables: %s\n", l_variables.c_str());
        // -------------------------------------------------
        // get OPERATOR
        // -------------------------------------------------
        std::string l_operator;
        l_s = get_next_string((char **)&l_line, &i_char, l_line_len, l_operator);
        if (l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        //NDBG_PRINT("l_operator: %s\n", l_operator.c_str());
        // -------------------------------------------------
        // get ACTIONS [optional]
        // -------------------------------------------------
        std::string l_actions;
        l_s = get_next_string((char **)&l_line, &i_char, l_line_len, l_actions);
        if (l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        //NDBG_PRINT("l_actions: %s\n", l_actions.c_str());
        // -------------------------------------------------
        // verbose output
        // -------------------------------------------------
        if (m_verbose)
        {
                if (m_color)
                {
                        NDBG_OUTPUT("%sLINE%s[%d] %s%s%s %s%s%s %s%s%s\n",
                                        ANSI_COLOR_FG_WHITE, ANSI_COLOR_OFF, m_cur_line_num,
                                        ANSI_COLOR_FG_GREEN,  l_variables.c_str(), ANSI_COLOR_OFF,
                                        ANSI_COLOR_FG_BLUE,   l_operator.c_str(), ANSI_COLOR_OFF,
                                        ANSI_COLOR_FG_YELLOW, l_actions.c_str(), ANSI_COLOR_OFF);
                }
                else
                {
                        NDBG_OUTPUT("LINE[%d] %s %s %s\n",
                                        m_cur_line_num,
                                        l_variables.c_str(),
                                        l_operator.c_str(),
                                        l_actions.c_str());
                }
        }
        // -------------------------------------------------
        // Try parse variables
        // -------------------------------------------------
        variable_list_t l_var_list;
        l_s = parse_vars(l_var_list, l_variables, '|');
        if (l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // Parse operator
        // -------------------------------------------------
        std::string l_operator_fx;
        std::string l_operator_match;
        bool l_is_negated(false);
        int32_t l_index = 0;
        // -------------------------------------------------
        // Check if operator is negated
        // -------------------------------------------------
        if (l_operator.at(l_index) == '!')
        {
                l_is_negated = true;
                ++l_index;
        }
        // -------------------------------------------------
        // Special checks for @ prefix
        // -------------------------------------------------
        // const std::string &a_operator,
        //NDBG_PRINT("%sOPERATOR%s: %s\n", ANSI_COLOR_FG_BLUE, ANSI_COLOR_OFF, l_operator.c_str());
        if (l_operator.at(l_index) == '@')
        {
                // -----------------------------------------
                // Scan until space
                // -----------------------------------------
                const char *l_fx_line = l_operator.data() + l_index;
                uint32_t l_fx_char = 0;
                uint32_t l_fx_line_len = l_operator.length() - l_index;
                //std::string l_fx;
                SCAN_OVER_NON_SPACE_ESC(l_fx_line, l_fx_char, l_fx_line_len);
                l_operator_fx.assign(l_operator.data() + 1 + l_index, l_fx_char - 1);
                if (l_fx_char < l_fx_line_len)
                {
                        SCAN_OVER_SPACE(l_fx_line, l_fx_char, l_fx_line_len);
                        l_operator_match.assign(l_fx_line, l_fx_line_len - l_fx_char);
                }
                //NDBG_PRINT("OPERATOR[%s]: %s\n", l_operator_fx.c_str(), l_operator_match.c_str());
        }
        // -------------------------------------------------
        // Default operator for mod security is regex
        // https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual#rx
        // -------------------------------------------------
        else
        {
                l_operator_fx = "rx";
                l_operator_match.assign(l_operator, l_index, l_operator.length() - l_index);
        }
        // -------------------------------------------------
        // Try parse actions
        // -------------------------------------------------
        kv_list_t l_action_list;
        l_s = tokenize_kv_list(l_actions, ',', l_action_list);
        if (l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // Add rule
        // -------------------------------------------------
        l_s = add_rule(ao_config,
                       l_var_list,
                       l_operator_fx,
                       l_operator_match,
                       l_action_list,
                       l_is_negated);
        if (l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t config_parser::read_wholeline(waflz_pb::sec_config_t& ao_config,
                                      const char *a_line,
                                      uint32_t a_line_len)
{
        uint32_t i_char = 0;
        const char *l_line = a_line;
        uint32_t l_line_len = a_line_len;
        //NDBG_PRINT("l_line: %.*s\n", (int)l_line_len, l_line);
        // -------------------------------------------------
        // get directive string
        // Space delimited -read until space
        // -------------------------------------------------
        const char *l_directive_str_begin = l_line;
        SCAN_OVER_NON_SPACE_ESC(l_line, i_char, l_line_len);
        if (i_char == l_line_len)
        {
                return WAFLZ_STATUS_OK;
        }
        std::string l_directive;
        l_directive.assign(l_directive_str_begin, l_line);
        // -------------------------------------------------
        // Scan past whitespace
        // -------------------------------------------------
        SCAN_OVER_SPACE(l_line, i_char, l_line_len);
        if (i_char == l_line_len)
        {
                return WAFLZ_STATUS_OK;
        }
        //NDBG_PRINT("DIRECTIVE: %s\n", l_directive.c_str());
        // -------------------------------------------------
        // Include Directive --recurse!!!
        // -------------------------------------------------
        if (strcasecmp(l_directive.c_str(), "include") == 0)
        {
                //NDBG_OUTPUT(": %s\n", l_line);
                // -----------------------------------------
                // Read from quote to quote
                // -----------------------------------------
                if (*l_line != '"')
                {
                        // TODO Make error macro to print file/line/cursor
                        WAFLZ_CONFIG_ERROR_MSG("include file specification malformed");
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // Skip quote
                // -----------------------------------------
                ++i_char;
                ++l_line;
                const char *l_include_file_str_start = l_line;
                SCAN_UNTIL_ESC(l_line, '"', i_char, l_line_len);
                // -----------------------------------------
                // Check bounds
                // -----------------------------------------
                if (i_char == l_line_len)
                {
                        // TODO Make error macro to print file/line/cursor
                        WAFLZ_CONFIG_ERROR_MSG("include file specification malformed");
                        return WAFLZ_STATUS_ERROR;
                }
                std::string l_include_file;
                l_include_file.assign(l_include_file_str_start, l_line);
                //NDBG_OUTPUT("%sINCLUDE%s: %s\n", ANSI_COLOR_FG_MAGENTA, ANSI_COLOR_OFF, l_include_file.c_str());
#if 0
                // -----------------------------------------
                // Recurse
                // TODO -check for exists...
                // -----------------------------------------
                int l_s;
                l_s = read_file_modsec(ao_config, l_include_file.c_str(), false);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
#else
                waflz_pb::directive_t *l_directive = ao_config.add_directive();
                l_directive->set_include(l_include_file);
#endif
                return WAFLZ_STATUS_OK;
        }
        string_list_t l_list;
        // -----------------------------------------
        // secrule
        // -----------------------------------------
#define IF_DIRECTIVE(_a_dir) if (strcasecmp(l_directive.c_str(), _a_dir) == 0)
#define ELIF_DIRECTIVE(_a_dir) else if (strcasecmp(l_directive.c_str(), _a_dir) == 0)
        // -------------------------------------------------
        //
        // -------------------------------------------------
        IF_DIRECTIVE("secrule")
        {
                ++(m_directives["secrule"]);
                int l_s;
                l_s = add_secrule(ao_config, l_line, a_line_len - i_char);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("performing add_secrule: %s\n", l_line);
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        ELIF_DIRECTIVE("secdefaultaction")
        {
                ++(m_directives["secdefaultaction"]);
                int l_s;
                l_s = add_secaction(ao_config, l_line, a_line_len - i_char, true);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("performing add_secaction: %s\n", l_line);
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        ELIF_DIRECTIVE("secaction")
        {
                ++(m_directives["secaction"]);
                int l_s;
                l_s = add_secaction(ao_config, l_line, a_line_len - i_char, false);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("performing add_secaction: %s\n", l_line);
                        return WAFLZ_STATUS_ERROR;
                }
        }
#define GET_STRS(_error_msg) \
        do {\
        int32_t _status = 0;\
        _status = get_strings_from_line(l_line, a_line_len - i_char, l_list);\
        if ((_status != WAFLZ_STATUS_OK) || l_list.empty())\
        {\
                WAFLZ_CONFIG_ERROR_MSG(_error_msg);\
                return WAFLZ_STATUS_ERROR;\
        }\
        } while (0)
        // -------------------------------------------------
        //
        // -------------------------------------------------
        ELIF_DIRECTIVE("secargumentseparator")
        {
                ++(m_directives["secargumentseparator"]);
                GET_STRS("secargumentseparator missing separator");
                ao_config.set_argument_separator((uint32_t)(l_list.begin()->data()[0]));
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        ELIF_DIRECTIVE("seccomponentsignature")
        {
                ++(m_directives["seccomponentsignature"]);
                GET_STRS("seccomponentsignature missing string");
                ao_config.set_component_signature(*(l_list.begin()));
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        ELIF_DIRECTIVE("seccookieformat")
        {
                ++(m_directives["seccookieformat"]);
                GET_STRS("seccookieformat missing format type 0|1");
                if (*(l_list.begin()) == "1")
                {
                        ao_config.set_cookie_format(1);
                }
                else
                {
                        ao_config.set_cookie_format(0);
                }
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        ELIF_DIRECTIVE("secdatadir")
        {
                ++(m_directives["secdatadir"]);
                GET_STRS("secdatadir missing directory string");
                ao_config.set_data_dir(*(l_list.begin()));
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        ELIF_DIRECTIVE("secmarker")
        {
                ++(m_directives["secmarker"]);
                GET_STRS("secmarker missing id|label string");
                waflz_pb::directive_t *l_directive = ao_config.add_directive();
                l_directive->set_marker(*(l_list.begin()));
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        ELIF_DIRECTIVE("secpcrematchlimit")
        {
                ++(m_directives["secpcrematchlimit"]);
                GET_STRS("secpcrematchlimit missing size");
                uint32_t l_limit = STR2INT((*(l_list.begin())));
                ao_config.set_pcre_match_limit(l_limit);
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        ELIF_DIRECTIVE("secpcrematchlimitrecursion")
        {
                ++(m_directives["secpcrematchlimitrecursion"]);
                GET_STRS("secpcrematchlimitrecursion missing size");
                uint32_t l_limit = STR2INT((*(l_list.begin())));
                ao_config.set_pcre_match_limit_recursion(l_limit);
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        ELIF_DIRECTIVE("secrequestbodyaccess")
        {
                ++(m_directives["secrequestbodyaccess"]);
                GET_STRS("secrequestbodyaccess missing specifier on|off");
                if STRCASECMP((*(l_list.begin())), "ON")
                {
                        ao_config.set_request_body_access(true);
                }
                else if STRCASECMP((*(l_list.begin())), "OFF")
                {
                        ao_config.set_request_body_access(false);
                }
                else
                {
                        WAFLZ_CONFIG_ERROR_MSG("secrequestbodyaccess missing specifier on|off");
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        ELIF_DIRECTIVE("secrequestbodyinmemorylimit")
        {
                ++(m_directives["secrequestbodyinmemorylimit"]);
                GET_STRS("secrequestbodyinmemorylimit missing size");
                uint32_t l_limit = STR2INT((*(l_list.begin())));
                ao_config.set_request_body_in_memory_limit(l_limit);
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        ELIF_DIRECTIVE("secrequestbodylimit")
        {
                ++(m_directives["secrequestbodylimit"]);
                GET_STRS("secrequestbodylimit missing size");
                uint32_t l_limit = STR2INT((*(l_list.begin())));
                ao_config.set_request_body_limit(l_limit);
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        ELIF_DIRECTIVE("secrequestbodylimitaction")
        {
                ++(m_directives["secrequestbodylimitaction"]);
                GET_STRS("secrequestbodylimitaction missing specifier Reject|ProcessPartial");
                if STRCASECMP((*(l_list.begin())), "Reject")
                {
                        ao_config.set_request_body_limit_action(waflz_pb::sec_config_t_limit_action_type_t_REJECT);
                }
                else if STRCASECMP((*(l_list.begin())), "ProcessPartial")
                {
                        ao_config.set_request_body_limit_action(waflz_pb::sec_config_t_limit_action_type_t_PROCESS_PARTIAL);
                }
                else
                {
                        WAFLZ_CONFIG_ERROR_MSG("secrequestbodylimitaction missing specifier Reject|ProcessPartial");
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        ELIF_DIRECTIVE("secrequestbodynofileslimit")
        {
                ++(m_directives["secrequestbodynofileslimit"]);
                GET_STRS("secrequestbodynofileslimit missing size");
                uint32_t l_limit = STR2INT((*(l_list.begin())));
                ao_config.set_request_body_no_files_limit(l_limit);
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        ELIF_DIRECTIVE("secresponsebodyaccess")
        {
                ++(m_directives["secresponsebodyaccess"]);
                GET_STRS("secresponsebodyaccess missing specifier on|off");
                if STRCASECMP((*(l_list.begin())), "ON")
                {
                        ao_config.set_response_body_access(true);
                }
                else if STRCASECMP((*(l_list.begin())), "OFF")
                {
                        ao_config.set_response_body_access(false);
                }
                else
                {
                        WAFLZ_CONFIG_ERROR_MSG("secresponsebodyaccess missing specifier on|off");
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        ELIF_DIRECTIVE("secresponsebodylimit")
        {
                ++(m_directives["secresponsebodylimit"]);
                GET_STRS("secresponsebodylimit missing size");
                uint32_t l_limit = STR2INT((*(l_list.begin())));
                ao_config.set_response_body_limit(l_limit);
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        ELIF_DIRECTIVE("secresponsebodylimitaction")
        {
                ++(m_directives["secresponsebodylimitaction"]);
                GET_STRS("secresponsebodylimitaction missing specifier Reject|ProcessPartial");
                if STRCASECMP((*(l_list.begin())), "Reject")
                {
                        ao_config.set_response_body_limit_action(waflz_pb::sec_config_t_limit_action_type_t_REJECT);
                }
                else if STRCASECMP((*(l_list.begin())), "ProcessPartial")
                {
                        ao_config.set_response_body_limit_action(waflz_pb::sec_config_t_limit_action_type_t_PROCESS_PARTIAL);
                }
                else
                {
                        WAFLZ_CONFIG_ERROR_MSG("secresponsebodylimitaction missing specifier Reject|ProcessPartial");
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        ELIF_DIRECTIVE("secresponsebodymimetype")
        {
                ++(m_directives["secresponsebodymimetype"]);
                GET_STRS("secresponsebodymimetype missing type list");
                // -----------------------------------------
                // Add types...
                // -----------------------------------------
                std::string l_mime_type;
                for (string_list_t::iterator i_type = l_list.begin(); i_type != l_list.end(); ++i_type)
                {
                       l_mime_type += *i_type;
                       l_mime_type += " ";
                }
                ao_config.set_response_body_mime_type(l_mime_type);
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        ELIF_DIRECTIVE("secruleengine")
        {
                ++(m_directives["secruleengine"]);
                GET_STRS("secruleengine missing specification (on|off|detectiononly");
                if STRCASECMP((*(l_list.begin())), "ON")
                {
                        ao_config.set_rule_engine(waflz_pb::sec_config_t_engine_type_t_ON);
                }
                else if STRCASECMP((*(l_list.begin())), "OFF")
                {
                        ao_config.set_rule_engine(waflz_pb::sec_config_t_engine_type_t_OFF);
                }
                else if STRCASECMP((*(l_list.begin())), "DETECTIONONLY")
                {
                        ao_config.set_rule_engine(waflz_pb::sec_config_t_engine_type_t_DETECTION_ONLY);
                }
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        ELIF_DIRECTIVE("sectmpdir")
        {
                ++(m_directives["sectmpdir"]);
                GET_STRS("sectmpdir missing directory string");
                ao_config.set_tmp_dir(*(l_list.begin()));
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        ELIF_DIRECTIVE("secdebuglog")
        {
                ++(m_directives["secdebuglog"]);
                GET_STRS("sectmpdir missing debug log file string");
                ao_config.set_debug_log(*(l_list.begin()));
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        ELIF_DIRECTIVE("secdebugloglevel")
        {
                ++(m_directives["secdebugloglevel"]);
                GET_STRS("secdebugloglevel missing size");
                uint32_t l_level = STR2INT((*(l_list.begin())));
                ao_config.set_debug_log_level(l_level);
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        ELIF_DIRECTIVE("secruleremovebyid")
        {
                ++(m_directives["secruleremovebyid"]);
                GET_STRS("secruleremovebyid missing ruleid");
                ao_config.add_rule_remove_by_id((*(l_list.begin())));
        }
        // -------------------------------------------------
        // Syntax: SecRuleUpdateTargetById RULEID TARGET1[,TARGET2,TARGET3] REPLACED_TARGET
        // -------------------------------------------------
        ELIF_DIRECTIVE("secruleupdatetargetbyid")
        {
                ++(m_directives["secruleupdatetargetbyid"]);
                GET_STRS("secruleremovebyid missing ruleid");
                ::waflz_pb::update_target_t* l_rtu = ao_config.add_update_target_by_id();
                int32_t i_idx = 0;
                // -----------------------------------------
                // parse rule target update by id...
                // -----------------------------------------
                for (string_list_t::const_iterator i_f = l_list.begin();
                    i_f != l_list.end();
                    ++i_f,
                    ++i_idx)
                {
                        switch (i_idx) {
                        // ---------------------------------
                        // id
                        // ---------------------------------
                        case 0:
                        {
                                l_rtu->set_id(*i_f);
                                break;
                        }
                        // ---------------------------------
                        // update
                        // ---------------------------------
                        case 1:
                        {
                                // -------------------------
                                // split on comma
                                // -------------------------
                                variable_list_t l_var_list;
                                int32_t l_s;
                                l_s = parse_vars(l_var_list, *i_f, ',');
                                if (l_s != WAFLZ_STATUS_OK)
                                {
                                        return WAFLZ_STATUS_ERROR;
                                }
                                for (variable_list_t::iterator i_v = l_var_list.begin();
                                    i_v != l_var_list.end();
                                    ++i_v)
                                {
                                        if (!*i_v)
                                        {
                                                continue;
                                        }
                                        l_rtu->add_variable()->CopyFrom(**i_v);
                                        delete *i_v;
                                        *i_v = NULL;
                                }
                                break;
                        }
                        // ---------------------------------
                        // replace
                        // ---------------------------------
                        case 2:
                        {
                                l_rtu->set_replace(*i_f);
                                break;
                        }
                        // ---------------------------------
                        // default
                        // ---------------------------------
                        default:
                        {
                                break;
                        }
                        }
                }
        }
        // -------------------------------------------------
        // geo db
        // -------------------------------------------------
        ELIF_DIRECTIVE("secgeolookupdb")
        {
                ++(m_directives["secgeolookupdb"]);
                GET_STRS("secdebugloglevel missing db");
                ao_config.set_geo_lookup_db(*(l_list.begin()));
        }
        // -------------------------------------------------
        // unimplemented
        // -------------------------------------------------
        else
        {
                //NDBG_OUTPUT("XXX: %.*s\n", a_line_len, a_line);
                std::string l_lowercase = l_directive;
                std::transform(l_lowercase.begin(), l_lowercase.end(), l_lowercase.begin(), ::tolower);
                ++(m_unimplemented_directives[l_lowercase]);
        }
        //NDBG_OUTPUT("%s\n", a_line);
        // -------------------------------------------------
        // TOKENIZE line
        // Includes
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t config_parser::read_line(waflz_pb::sec_config_t &ao_config,
                                 std::string &ao_cur_line,
                                 const char *a_line,
                                 uint32_t a_line_len,
                                 uint32_t a_cur_line_num)
{
        // -------------------------------------------------
        // Line index
        // -------------------------------------------------
        uint32_t i_char = 0;
        const char *l_line = a_line;
        // -------------------------------------------------
        // Scan past whitespace
        // -------------------------------------------------
        SCAN_OVER_SPACE(l_line, i_char, a_line_len);
        if (i_char == a_line_len)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // Search for continuation back to front
        // -------------------------------------------------
        const char *l_line_end = a_line + a_line_len - 1;
        int32_t i_char_end = a_line_len;
        SCAN_OVER_SPACE_BKWD(l_line_end, i_char_end);
        if (i_char_end <= 0)
        {
                return WAFLZ_STATUS_OK;
        }
        //NDBG_OUTPUT("last char == %c\n", *l_line_end);
        if (*l_line_end == '\\')
        {
                // -----------------------------------------
                // Continuation -append to current 
                // line and return
                // -----------------------------------------
                //NDBG_OUTPUT("append [%d bytes] \'%.*s\'\n",
                //                i_char_end - i_char - 1,
                //                i_char_end - i_char - 1,
                //                l_line);
                ao_cur_line.append(l_line, i_char_end - i_char - 1);
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // If first non-whitespace is comment
        // -move on
        // -------------------------------------------------
        if (*l_line == '#')
        {
                ao_cur_line.clear();
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // Else we have a complete line
        // -------------------------------------------------
        ao_cur_line.append(l_line, i_char_end - i_char);
        // -------------------------------------------------
        // If first non-whitespace is comment
        // -move on
        // -------------------------------------------------
        if (ao_cur_line.empty() ||
           ao_cur_line[0] == '#')
        {
                ao_cur_line.clear();
                return WAFLZ_STATUS_OK;
        }
        //waflz_pb::sec_config_t_order_t *l_order = ao_config.add_order();
                        //NDBG_PRINT("devtest setting directive");
        //l_order->set_position(a_cur_line_num);
        int32_t l_s;
        l_s = read_wholeline(ao_config, ao_cur_line.c_str(), ao_cur_line.length());
        if (l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        if (!m_unimplemented_transformations.empty())
        {
                //NDBG_OUTPUT("LINE: %.*s\n", a_line_len, a_line);
        }
        //NDBG_PRINT("one line for whole thing %s\n\n", ao_cur_line.c_str());
        // -------------------------------------------------
        // clearline
        // -------------------------------------------------
        ao_cur_line.clear();
        // -------------------------------------------------
        // Done...
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t config_parser::read_file_modsec(waflz_pb::sec_config_t& ao_config,
                                        const std::string &a_file,
                                        bool a_force)
{
        //NDBG_PRINT("FILE: %s\n", a_file.c_str());
        // -------------------------------------------------
        // Check is a file
        // -------------------------------------------------
        struct stat l_stat;
        int32_t l_s = WAFLZ_STATUS_OK;
        l_s = stat(a_file.c_str(), &l_stat);
        if (l_s != 0)
        {
                NDBG_PRINT("error performing stat on file: %s.  Reason: %s\n", a_file.c_str(), strerror(errno));
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // Check if is regular file
        // -------------------------------------------------
        if (!(l_stat.st_mode & S_IFREG))
        {
                NDBG_PRINT("error opening file: %s.  Reason: is NOT a regular file\n", a_file.c_str());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // Check for *.conf
        // TODO -skip files w/o *.conf suffix
        // -------------------------------------------------
        if (!a_force)
        {
                std::string l_file_ext;
                l_file_ext = get_file_ext(a_file);
                if (l_file_ext != "conf")
                {
                        if (m_verbose)
                        {
                                NDBG_PRINT("Skiping file: %s.  Reason: Missing .conf extension.\n", a_file.c_str());
                        }
                        return WAFLZ_STATUS_OK;
                }
        }
        // -------------------------------------------------
        // Open file...
        // -------------------------------------------------
        FILE * l_file;
        l_file = fopen(a_file.c_str(),"r");
        if (NULL == l_file)
        {
                NDBG_PRINT("error opening file: %s.  Reason: %s\n", a_file.c_str(), strerror(errno));
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // set current state
        // -------------------------------------------------
        m_cur_file = a_file;
        m_cur_file_dir = get_file_path(a_file);
        m_cur_file_base = get_file_wo_path(a_file);
        m_cur_line_num = 0;
        m_cur_line_pos = 0;
        std::string l_modsec_line;
        // -------------------------------------------------
        // TODO -might be faster to set max size and fgets
        // instead of realloc'ing and free'ing with getline
        // MAX_READLINE_SIZE will have to be big for modsec
        // rules -test with "wc" for max and double largest?
        // -------------------------------------------------
#if 0
        char l_readline[MAX_READLINE_SIZE];
        while (fgets(l_readline, sizeof(l_readline), a_file_ptr))
        {
#endif
        ssize_t l_file_line_size = 0;
        char *l_file_line = NULL;
        size_t l_unused;
        while ((l_file_line_size = getline(&l_file_line,&l_unused,l_file)) != -1)
        {
                // TODO strnlen -with max line length???
                if (l_file_line_size > 0)
                {
                        // ---------------------------------
                        // For errors
                        // ---------------------------------
                        ++m_cur_line_num;
                        //m_cur_line = l_file_line;
                        //NDBG_PRINT("FILE: %s LINE[%d len:%d]: %s\n", m_cur_file.c_str(), m_cur_line_num, (int)l_file_line_size, m_cur_line.c_str());
                        l_s = read_line(ao_config,
                                        l_modsec_line,
                                        l_file_line,
                                        (uint32_t)l_file_line_size,
                                        m_cur_line_num);
                        if (WAFLZ_STATUS_OK != l_s)
                        {
                                if (l_file_line) { free(l_file_line); l_file_line = NULL;}
                                return WAFLZ_STATUS_ERROR;
                        }
                }
                if (l_file_line) { free(l_file_line); l_file_line = NULL;}
        }
        if (l_file_line) { free(l_file_line); l_file_line = NULL;}
        // -------------------------------------------------
        // Close file...
        // -------------------------------------------------
        l_s = fclose(l_file);
        if (WAFLZ_STATUS_OK != l_s)
        {
                NDBG_PRINT("error performing fclose.  Reason: %s\n", strerror(errno));
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static void show_map(const count_map_t &a_count_map, const char *a_msg, bool a_used)
{
        // -------------------------------------------------
        // Dump unimplemented guys
        // -------------------------------------------------
        if (a_count_map.empty())
        {
                return;
        }
        const char *l_color;
        if (a_used)
        {
                l_color = ANSI_COLOR_FG_BLUE;
        }
        else
        {
                l_color = ANSI_COLOR_FG_RED;
        }
#if 1
        // -------------------------------------------------
        // Sort
        // -------------------------------------------------
        typedef std::map<uint32_t, std::list<std::string> > _sorted_map_t;
        _sorted_map_t l_sorted_map;
        l_sorted_map.clear();
        for (count_map_t::const_iterator i_s = a_count_map.begin(); i_s != a_count_map.end(); ++i_s)
        {
                if (l_sorted_map.find(i_s->second) == l_sorted_map.end())
                {
                        std::list<std::string> l_list;
                        l_list.push_back(i_s->first);
                        l_sorted_map[i_s->second] = l_list;
                }
                else
                {
                        l_sorted_map[i_s->second].push_back(i_s->first);
                }
        }
        NDBG_OUTPUT("+---------------------------------+----------+\n");
        NDBG_OUTPUT("| %s%-32s%s| Count    |\n",
                        l_color, a_msg, ANSI_COLOR_OFF);
        NDBG_OUTPUT("+---------------------------------+----------+\n");
        for (_sorted_map_t::reverse_iterator i_str = l_sorted_map.rbegin();
                        i_str != l_sorted_map.rend();
                        ++i_str)
        {
                for (std::list<std::string>::iterator i_k = i_str->second.begin();
                    i_k !=  i_str->second.end();
                    ++i_k)
                {
                NDBG_OUTPUT("| %s%-32s%s| %8d |\n",
                                ANSI_COLOR_FG_YELLOW, i_k->c_str(), ANSI_COLOR_OFF,
                                i_str->first);
                }
        }
        NDBG_OUTPUT("+---------------------------------+----------+\n");
#else
        NDBG_OUTPUT("+---------------------------------+----------+\n");
        NDBG_OUTPUT("| %s%-32s%s| Count    |\n",
                        l_color, a_msg, ANSI_COLOR_OFF);
        NDBG_OUTPUT("+---------------------------------+----------+\n");
        for (count_map_t::const_iterator i_str = a_count_map.begin();
                        i_str != a_count_map.end();
                        ++i_str)
        {
                NDBG_OUTPUT("| %s%-32s%s| %8d |\n",
                                ANSI_COLOR_FG_YELLOW, i_str->first.c_str(), ANSI_COLOR_OFF,
                                i_str->second);
        }
        NDBG_OUTPUT("+---------------------------------+----------+\n");
#endif
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void config_parser::show_status(void)
{
        // -------------------------------------------------
        // Dump implemented guys
        // -------------------------------------------------
#if 0
        show_map(m_directives,"Directives", true);
        show_map(m_variables,"Variables", true);
        show_map(m_operators,"Operators", true);
        show_map(m_actions,"Actions", true);
        show_map(m_transformations,"Transforms", true);
        show_map(m_ctls,"Controls", true);
#endif
        //show_map(m_tx_variables,"Tx Variables", true);
        // -------------------------------------------------
        // Dump implemented guys
        // -------------------------------------------------
        show_map(m_unimplemented_directives,"Unimplemented Directives", false);
        show_map(m_unimplemented_variables,"Unimplemented Variables", false);
        show_map(m_unimplemented_operators,"Unimplemented Operators", false);
        show_map(m_unimplemented_actions,"Unimplemented Actions", false);
        show_map(m_unimplemented_transformations,"Unimplemented Transforms", false);
        show_map(m_unimplemented_ctls,"Unimplemented Controls", false);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t get_pcre_match_list(const char *a_regex, const char *a_str, match_list_t &ao_match_list)
{
        pcre *l_re;
        const char *l_error;
        int l_erroffset;
        l_re = pcre_compile(a_regex,      // the pattern
                            PCRE_ANCHORED,// options
                            &l_error,     // for error message
                            &l_erroffset, // for error offset
                            0);           // use default character tables
        if (!l_re)
        {
                NDBG_PRINT("pcre_compile failed (offset: %d), %s\n", l_erroffset, l_error);
                return WAFLZ_STATUS_ERROR;
        }
        uint32_t l_offset = 0;
        uint32_t l_len = strlen(a_str);
        int l_rc;
        int l_ovector[100];
        while (l_offset < l_len)
        {
                l_rc = pcre_exec(l_re,                  // Compiled pattern
                                 0,                     // Study
                                 a_str,                 // str
                                 l_len,                 // str len
                                 l_offset,              // str offset
                                 0,                     // options
                                 l_ovector,             // output vector for substr info
                                 sizeof(l_ovector));    // num elements in output vector
                if (l_rc < 0)
                {
                        break;
                }
                for (int i_match = 0; i_match < l_rc; ++i_match)
                {
                        std::string l_match;
                        l_match.assign(a_str + l_ovector[2*i_match], l_ovector[2*i_match+1] - l_ovector[2*i_match]);
                        ao_match_list.push_back(l_match);
                        //NDBG_PRINT("%2d: %.*s\n", i_match, l_ovector[2*i_match+1] - l_ovector[2*i_match], a_str + l_ovector[2*i_match]);
                }
                l_offset = l_ovector[1];
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t config_parser::get_action_string(std::string &ao_str,
                                         const waflz_pb::sec_action_t &a_sec_action)
{
#define ADD_KV_IFE_STR(_a_key) \
        if (a_sec_action.has_##_a_key()) \
        {\
                ao_str += #_a_key;\
                ao_str += ":'";\
                ao_str += a_sec_action._a_key();\
                ao_str += "',";\
        }
#define ADD_KV_IFE_STR_NO_QUOTE(_a_key) \
        if (a_sec_action.has_##_a_key()) \
        {\
                ao_str += #_a_key;\
                ao_str += ":";\
                ao_str += a_sec_action._a_key();\
                ao_str += ",";\
        }
#define ADD_V_IFE_STR(_a_key) \
        if (a_sec_action.has_##_a_key()) \
        {\
                ao_str += a_sec_action._a_key(); \
                ao_str += ","; \
        }
#define ADD_KV_IFE_BOOL(_a_key) \
        if (a_sec_action.has_##_a_key() && a_sec_action._a_key()) \
        {\
                ao_str += #_a_key;\
                ao_str += ",";\
        }
#define ADD_KV_IFE_UINT32(_a_key) \
        if (a_sec_action.has_##_a_key()) \
        {\
                char __buf[64];\
                sprintf(__buf, "%u", a_sec_action._a_key());\
                ao_str += #_a_key;\
                ao_str += ":";\
                ao_str += __buf;\
                ao_str += ",";\
        }
#define ADD_KV_IFE_UINT32_QUOTE(_a_key) \
        if (a_sec_action.has_##_a_key()) \
        {\
                char __buf[64];\
                sprintf(__buf, "%u", a_sec_action._a_key());\
                ao_str += #_a_key;\
                ao_str += ":'";\
                ao_str += __buf;\
                ao_str += "',";\
        }
        ADD_KV_IFE_UINT32(phase);
        // -------------------------------------------------
        // action_type
        // -------------------------------------------------
        if (a_sec_action.has_action_type())
        {
                // -----------------------------------------
                // Reflect Variable name
                // -----------------------------------------
                const google::protobuf::EnumValueDescriptor* l_descriptor =
                                waflz_pb::sec_action_t_action_type_t_descriptor()->FindValueByNumber(a_sec_action.action_type());
                if (l_descriptor != NULL)
                {
                        std::string l_action_type = l_descriptor->name();
                        std::transform(l_action_type.begin(), l_action_type.end(), l_action_type.begin(), ::tolower);
                        ao_str += l_action_type;
                        ao_str += ",";
                }
                else
                {
                        NDBG_PRINT("error getting descriptor for action type\n");
                        return WAFLZ_STATUS_ERROR;
                }
        }
        ADD_KV_IFE_STR(rev);
        ADD_KV_IFE_STR(ver);
        ADD_KV_IFE_STR(maturity);
        ADD_KV_IFE_STR(accuracy);
        if (a_sec_action.has_audit_engine())
        {
                ao_str += "ctl";
                ao_str += ":";
                ao_str += "auditEngine=";
                ao_str += a_sec_action.audit_engine();
                ao_str += ",";
        }
        if (a_sec_action.has_audit_log_parts())
        {
                ao_str += "ctl";
                ao_str += ":";
                ao_str += "auditLogParts=";
                ao_str += a_sec_action.audit_log_parts();
                ao_str += ",";
        }
        if (a_sec_action.has_audit_engine())
        {
                ao_str += "ctl";
                ao_str += ":";
                ao_str += "auditEngine:";
                ao_str += a_sec_action.audit_engine();
                ao_str += ",";
        }
        if (a_sec_action.has_force_request_body_variable())
        {
                ao_str += "ctl";
                ao_str += ":";
                ao_str += "forceRequestBodyVariable=";
                ao_str += a_sec_action.force_request_body_variable();
                ao_str += ",";
        }
        if (a_sec_action.has_audit_engine())
        {
                ao_str += "ctl";
                ao_str += ":";
                ao_str += "auditEngine:";
                ao_str += a_sec_action.audit_engine();
                ao_str += ",";
        }
        if (a_sec_action.has_request_body_access())
        {
                ao_str += "ctl";
                ao_str += ":";
                ao_str += "RequestBodyAccess=";
                ao_str += a_sec_action.request_body_access();
                ao_str += ",";
        }
        if (a_sec_action.has_request_body_processor())
        {
                ao_str += "ctl";
                ao_str += ":";
                ao_str += "requestBodyProcessor=";
                ao_str += a_sec_action.request_body_processor();
                ao_str += ",";
        }
        if (a_sec_action.has_rule_engine())
        {
                ao_str += "ctl";
                ao_str += ":";
                ao_str += "ruleEngine=";
                ao_str += a_sec_action.rule_engine();
                ao_str += ",";
        }
        if (a_sec_action.has_rule_remove_by_id())
        {
                ao_str += "ctl";
                ao_str += ":";
                ao_str += "ruleRemovebyId=";
                ao_str += a_sec_action.rule_remove_by_id();
                ao_str += ",";
        }
        // -------------------------------------------------
        // TODO FIX!!!
        // -------------------------------------------------
#if 0
        if (a_sec_action.has_rule_remove_target_by_id())
        {
                ao_str += "ctl";
                ao_str += ":";
                ao_str += "ruleRemoveTargetById=";
                const waflz_pb::sec_action_t_rule_update_t &l_rule_update = a_sec_action.ruleremovetargetbyid();
                if (l_rule_update.has_id())
                {
                        ao_str += l_rule_update.id();
                }
                if (l_rule_update.has_target())
                {
                        ao_str += ":";
                        if (l_rule_update.is_negated())
                        {
                                ao_str += "!";
                        }
                        ao_str += l_rule_update.target();
                }
                if (l_rule_update.has_target_match())
                {
                        ao_str += ":";
                        if (l_rule_update.is_regex())
                        {
                                ao_str += "/";
                                ao_str += l_rule_update.target_match();
                                ao_str += "/";
                        }
                        else
                        {
                               ao_str += l_rule_update.target_match();
                        }
                }
                ao_str += ",";
        }
#endif
        // -------------------------------------------------
        // TODO FIX!!!
        // -------------------------------------------------
#if 0
        if (a_sec_action.has_rule_remove_target_by_tag())
        {
                ao_str += "ctl";
                ao_str += ":";
                ao_str += "ruleRemoveTargetByTag=";
                const waflz_pb::sec_action_t_rule_update_t &l_rule_update = a_sec_action.ruleremovetargetbytag();
                if (l_rule_update.has_tag())
                {
                        ao_str += l_rule_update.tag();
                }
                if (l_rule_update.has_target())
                {
                        ao_str += ":";
                        if (l_rule_update.is_negated())
                        {
                                ao_str += "!";
                        }
                        ao_str += l_rule_update.target();
                }
                if (l_rule_update.has_target_match())
                {
                        ao_str += ":";
                        if (l_rule_update.is_regex())
                        {
                                ao_str += "/";
                                ao_str += l_rule_update.target_match();
                                ao_str += "/";
                        }
                        else
                        {
                               ao_str += l_rule_update.target_match();
                        }
                }
                ao_str += ",";
        }
#endif
        if (a_sec_action.has_multimatch() && a_sec_action.multimatch())
        {
                ao_str += "multiMatch";
                ao_str += ",";
        }
        for (int32_t i_tx = 0; i_tx < a_sec_action.t_size(); ++i_tx)
        {
                ao_str += "t";
                ao_str += ":";
                // -----------------------------------------
                // Reflect transformation name
                // -----------------------------------------
                const google::protobuf::EnumValueDescriptor* l_descriptor =
                                waflz_pb::sec_action_t_transformation_type_t_descriptor()->FindValueByNumber(a_sec_action.t(i_tx));
                if (l_descriptor != NULL)
                {
                        std::string l_t_type = l_descriptor->name();
                        std::transform(l_t_type.begin(), l_t_type.end(), l_t_type.begin(), ::tolower);
                        // ---------------------------------
                        // Camel case conversion...
                        // ---------------------------------
                        if (l_t_type == "urldecodeuni") l_t_type = "urlDecodeUni";
                        else if (l_t_type == "htmlentitydecode") l_t_type = "htmlEntityDecode";
                        else if (l_t_type == "jsdecode") l_t_type = "jsDecode";
                        else if (l_t_type == "cssdecode") l_t_type = "cssDecode";
                        else if (l_t_type == "htmlentitydecode") l_t_type = "htmlEntityDecode";
                        else if (l_t_type == "normalizepath") l_t_type = "normalisePath";
                        ao_str += l_t_type;
                        ao_str += ",";
                }
                else
                {
                        NDBG_PRINT("error getting descriptor for action type\n");
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // setvar
        // -------------------------------------------------
        for (int32_t i_setvar = 0; i_setvar < a_sec_action.setvar_size(); ++i_setvar)
        {
                const waflz_pb::sec_action_t_setvar_t &l_var = a_sec_action.setvar(i_setvar);
                if (!l_var.has_scope() ||
                   !l_var.has_op() ||
                   !l_var.has_var())
                {
                        continue;
                }
                ao_str += "setvar";
                ao_str += ":'";
                const waflz_pb::sec_action_t_setvar_t_op_t &l_op = l_var.op();
                if (l_op == waflz_pb::sec_action_t_setvar_t_op_t_DELETE)
                {
                        ao_str += "!";
                }
                const waflz_pb::sec_action_t_setvar_t_scope_t &l_scope = l_var.scope();
                switch (l_scope)
                {
                case waflz_pb::sec_action_t_setvar_t_scope_t_TX:
                {
                        ao_str += "tx.";
                        break;
                }
                case waflz_pb::sec_action_t_setvar_t_scope_t_IP:
                {
                        ao_str += "ip.";
                        break;
                }
                case waflz_pb::sec_action_t_setvar_t_scope_t_GLOBAL:
                {
                        ao_str += "global.";
                        break;
                }
                default:
                {
                        NDBG_PRINT("error unknown scope type: %d\n", l_scope);
                        return WAFLZ_STATUS_ERROR;
                }
                }
                ao_str += l_var.var();
                ao_str += "',";
        }
        ADD_KV_IFE_BOOL(capture);
        ADD_KV_IFE_STR(logdata);
        ADD_KV_IFE_STR_NO_QUOTE(severity);
        ADD_KV_IFE_STR_NO_QUOTE(id);
        ADD_KV_IFE_STR(msg);
        ADD_KV_IFE_BOOL(nolog);
        ADD_KV_IFE_BOOL(log);
        ADD_KV_IFE_BOOL(noauditlog);
        ADD_KV_IFE_BOOL(auditlog);
        ADD_KV_IFE_STR(initcol);
        ADD_KV_IFE_STR(status);
        ADD_KV_IFE_UINT32_QUOTE(skip);
        ADD_KV_IFE_BOOL(sanitisematched);
        ADD_V_IFE_STR(allow);
        ADD_KV_IFE_STR(expirevar);
        for (int32_t i_tag = 0; i_tag < a_sec_action.tag_size(); ++i_tag)
        {
                ao_str += "tag";
                ao_str += ":'";
                ao_str += a_sec_action.tag(i_tag);
                ao_str += "',";
        }
        ADD_KV_IFE_STR_NO_QUOTE(skipafter);
        // -------------------------------------------------
        // Chop last comma
        // -------------------------------------------------
        if (ao_str[ao_str.length() - 1] == ',')
        {
                ao_str = ao_str.substr(0, ao_str.size()-1);
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! \notes:
//!   Syntax:        SecRule  VARIABLES  OPERATOR      [ACTIONS]
//!   Example Usage: SecRule  ARGS       "@rx attack"  "phase:1,log,deny,id:1"
//! ----------------------------------------------------------------------------
int32_t config_parser::get_modsec_rule_line(std::string &ao_str,
                                          const waflz_pb::sec_rule_t &a_secrule,
                                          const uint32_t a_indent,
                                          bool a_is_chained)
{
        std::string l_rule = "";
        // -------------------------------------------------
        // TODO -this is stupid
        // -------------------------------------------------
        if (a_indent)
        {
                l_rule += "\t";
        }
        // -----------------------------------------------------------
        // Directive
        // -----------------------------------------------------------
        l_rule += "SecRule";
        l_rule += " ";
        // -----------------------------------------------------------
        // Variables
        // -----------------------------------------------------------
        bool l_bracket_with_quotes = false;
        // -------------------------------------------------
        // Bracket TX with quotes
        // -------------------------------------------------
        if (a_secrule.variable_size() &&
           a_secrule.variable(0).has_type() &&
           (a_secrule.variable(0).type() == waflz_pb::variable_t_type_t_TX))
        {
                l_bracket_with_quotes = true;
        }
        if (l_bracket_with_quotes)
        {
                l_rule += "\"";
        }
        for (int32_t i_var = 0; i_var < a_secrule.variable_size(); ++i_var)
        {
                const waflz_pb::variable_t &l_var = a_secrule.variable(i_var);
                if (l_var.has_type())
                {
                        if (l_var.has_is_count() && l_var.is_count())
                        {
                                l_rule += "&";
                        }
                        if (l_var.match_size() == 0)
                        {
                                // -------------------------
                                // Reflect Variable name
                                // -------------------------
                                const google::protobuf::EnumValueDescriptor* l_descriptor =
                                                waflz_pb::variable_t_type_t_descriptor()->FindValueByNumber(l_var.type());
                                if (l_descriptor != NULL)
                                {
                                        // -----------------
                                        // Reflect Variable 
                                        // name
                                        // -----------------
                                        l_rule += l_descriptor->name();
                                }
                                else
                                {
                                        NDBG_PRINT("error getting descriptor for variable type\n");
                                        return WAFLZ_STATUS_ERROR;
                                }
                        }
                        else
                        {
                                for (int i_match = 0; i_match < l_var.match_size(); ++i_match)
                                {
                                        const waflz_pb::variable_t_match_t &l_match = l_var.match(i_match);
                                        if (l_match.has_is_negated() && l_match.is_negated())
                                        {
                                                l_rule += "!";
                                        }
                                        // -----------------
                                        // Reflect Variable 
                                        // name
                                        // -----------------
                                        const google::protobuf::EnumValueDescriptor* l_descriptor =
                                                        waflz_pb::variable_t_type_t_descriptor()->FindValueByNumber(l_var.type());
                                        if (l_descriptor != NULL)
                                        {
                                                // ---------
                                                // Reflect 
                                                // Variable 
                                                // name
                                                // ---------
                                                l_rule += l_descriptor->name();
                                        }
                                        else
                                        {
                                                NDBG_PRINT("error getting descriptor for variable type\n");
                                                return WAFLZ_STATUS_ERROR;
                                        }
                                        if (l_match.has_value())
                                        {
                                                // ---------
                                                // if pipe 
                                                // in string 
                                                // quote 
                                                // string 
                                                // ---------
                                                if (l_match.value().find('|',0) != std::string::npos)
                                                {
                                                        l_rule += ":'";
                                                        if (l_match.has_is_regex() && l_match.is_regex())
                                                        l_rule += "/";
                                                        l_rule += l_match.value();
                                                        if (l_match.has_is_regex() && l_match.is_regex())
                                                        l_rule += "/";
                                                        l_rule += "'";
                                                }
                                                else
                                                {
                                                        l_rule += ":";
                                                        if (l_match.has_is_regex() && l_match.is_regex())
                                                        {
                                                                if (l_descriptor->name() == "TX")
                                                                {
                                                                        l_rule += "'";
                                                                }
                                                                l_rule += "/";
                                                        }
                                                        l_rule += l_match.value();
                                                        if (l_match.has_is_regex() && l_match.is_regex())
                                                        {
                                                                l_rule += "/";
                                                                if (l_descriptor->name() == "TX")
                                                                {
                                                                        l_rule += "'";
                                                                }
                                                        }
                                                }
                                        }
                                        if (i_match + 1 < l_var.match_size())
                                        {
                                                l_rule += "|";
                                        }
                                }
                        }
                        if ((i_var + 1) < a_secrule.variable_size() && a_secrule.variable(i_var).has_type())
                        {
                                l_rule += "|";
                        }
                }
        }
        if (l_bracket_with_quotes)
        {
                l_rule += "\"";
        }
        l_rule += " ";
        // -----------------------------------------------------------
        // Operator
        // -----------------------------------------------------------
        l_rule += "\"";
        if (a_secrule.has_operator_())
        {
                const waflz_pb::sec_rule_t_operator_t &l_operator = a_secrule.operator_();
                if (l_operator.has_type())
                {
                        if (l_operator.has_is_negated() && l_operator.is_negated())
                        {
                                l_rule += '!';
                        }
                        // ---------------------------------
                        // Reflect Variable name
                        // ---------------------------------
                        const google::protobuf::EnumValueDescriptor* l_descriptor =
                                        waflz_pb::sec_rule_t_operator_t_type_t_descriptor()->FindValueByNumber(l_operator.type());
                        if (l_descriptor != NULL)
                        {
                                std::string l_type = l_descriptor->name();
                                std::transform(l_type.begin(), l_type.end(), l_type.begin(), ::tolower);
                                // -------------------------
                                // Reflect Variable name
                                // -------------------------
                                l_rule += "@";
                                l_rule += l_type;
                                l_rule += " ";
                        }
                        else
                        {
                                NDBG_PRINT("error getting descriptor for variable type\n");
                                return WAFLZ_STATUS_ERROR;
                        }
                }
                if (l_operator.has_value())
                {
                        l_rule += l_operator.value();
                }
        }
        l_rule += "\"";
        l_rule += " ";
        // -----------------------------------------------------------
        // Actions
        // -----------------------------------------------------------
        if (!a_secrule.has_action())
        {
                return WAFLZ_STATUS_OK;
        }
        const waflz_pb::sec_action_t &l_action = a_secrule.action();
        std::string l_action_str;
        if (a_secrule.chained_rule_size() || a_is_chained)
        {
                l_action_str += "chain,";
        }
        get_action_string(l_action_str, l_action);
        if (!l_action_str.empty())
        {
                l_rule += "\"";
                l_rule += l_action_str;
                l_rule += "\"";
        }
        // -----------------------------------------------------------
        // Chop last comma
        // -----------------------------------------------------------
        if (l_rule[l_rule.length() - 1] == ',')
        {
                l_rule = l_rule.substr(0, l_rule.size()-1);
        }
        // -----------------------------------------------------------
        // Assign to output
        // -----------------------------------------------------------
        ao_str = l_rule;
        ao_str += '\n';
        // -----------------------------------------------------------
        // chain....
        // For rule in sec_config_t append
        // -----------------------------------------------------------
        for (int32_t i_chained_rule = 0; i_chained_rule < a_secrule.chained_rule_size(); ++i_chained_rule)
        {
                int32_t l_s;
                bool l_chained = false;
                if (i_chained_rule + 1 < a_secrule.chained_rule_size())
                {
                        l_chained = true;
                }
                l_s = append_modsec_rule(ao_str,
                                              a_secrule.chained_rule(i_chained_rule),
                                              MODSECURITY_RULE_INDENT_SIZE,
                                              l_chained);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        //NDBG_PRINT("%s\n", ao_str.c_str());
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t config_parser::get_modsec_config_str(std::string &ao_str,
                                             const waflz_pb::sec_config_t &a_config)
{
        std::string l_directive;
        // -------------------------------------------------
        // rule engine
        // -------------------------------------------------
        if (a_config.has_rule_engine())
        {
                ao_str += "SecRuleEngine ";
                const waflz_pb::sec_config_t_engine_type_t l_rule_engine = a_config.rule_engine();
                switch (l_rule_engine)
                {
                    case waflz_pb::sec_config_t_engine_type_t_ON:
                    {
                            ao_str += "ON";
                            break;
                    }
                    case waflz_pb::sec_config_t_engine_type_t_OFF:
                    {
                            ao_str += "OFF";
                            break;
                    }
                    case waflz_pb::sec_config_t_engine_type_t_DETECTION_ONLY:
                    {
                            ao_str += "DETECTIONONLY";
                            break;
                    }
                }
                ao_str += '\n';
        }
        // -------------------------------------------------
        // request body access
        // -------------------------------------------------
        if (a_config.has_request_body_access())
        {
                ao_str += "SecRequestBodyAccess ";
                if (a_config.request_body_access())
                {
                        ao_str += "ON";
                }
                else
                {
                        ao_str += "OFF";
                }
                ao_str += '\n';
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        if (a_config.has_request_body_limit())
        {
                ao_str += "SecRequestBodyLimit ";
                ao_str += to_string(a_config.request_body_limit());
                ao_str += "\n";
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        if (a_config.has_request_body_no_files_limit())
        {
                ao_str += "SecRequestBodyNoFilesLimit ";
                ao_str += to_string(a_config.request_body_no_files_limit());
                ao_str += "\n";
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        if (a_config.has_request_body_in_memory_limit())
        {
                ao_str += "SecRequestBodyInMemoryLimit ";
                ao_str += to_string(a_config.request_body_in_memory_limit());
                ao_str += "\n";
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        if (a_config.has_request_body_limit_action())
        {
                ao_str += "SecRequestBodyLimitAction ";
                const waflz_pb::sec_config_t_limit_action_type_t l_limit_action_type = a_config.request_body_limit_action();
                switch (l_limit_action_type)
                {
                        case waflz_pb::sec_config_t_limit_action_type_t_REJECT:
                        {
                                ao_str += "Reject";
                                break;
                        }
                        case waflz_pb::sec_config_t_limit_action_type_t_PROCESS_PARTIAL:
                        {
                                ao_str += "ProcessPartial";
                                break;
                        }
                }
                ao_str += "\n";
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        if (a_config.has_pcre_match_limit())
        {
                ao_str += "SecPcreMatchLimit ";
                ao_str += to_string(a_config.pcre_match_limit());
                ao_str += "\n";
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        if (a_config.has_pcre_match_limit_recursion())
        {
                ao_str += "SecPcreMatchLimitRecursion ";
                ao_str += to_string(a_config.pcre_match_limit_recursion());
                ao_str += "\n";
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        if (a_config.has_response_body_access())
        {
                ao_str += "SecResponseBodyAccess ";
                if (a_config.response_body_access())
                {
                        ao_str += "ON";
                }
                else
                {
                        ao_str += "OFF";
                }
                ao_str += '\n';
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        if (a_config.has_response_body_mime_type())
        {
                ao_str += "SecResponseBodyMimeType ";
                ao_str += a_config.response_body_mime_type();
                ao_str += "\n";
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        if (a_config.has_response_body_limit())
        {
                ao_str += "SecResponseBodyLimit ";
                ao_str += to_string(a_config.response_body_limit());
                ao_str += "\n";
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        if (a_config.has_response_body_limit_action())
        {
                ao_str += "SecResponseBodyLimitAction ";
                const waflz_pb::sec_config_t_limit_action_type_t l_limit_action_type = a_config.response_body_limit_action();
                switch (l_limit_action_type)
                {
                        case waflz_pb::sec_config_t_limit_action_type_t_REJECT:
                        {
                                ao_str += "Reject";
                                break;
                        }
                        case waflz_pb::sec_config_t_limit_action_type_t_PROCESS_PARTIAL:
                        {
                                ao_str += "ProcessPartial";
                                break;
                        }
                }
                ao_str += "\n";
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        if (a_config.has_tmp_dir())
        {
                ao_str += "SecTmpDir ";
                ao_str += a_config.tmp_dir();
                ao_str += "\n";
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        if (a_config.has_data_dir())
        {
                ao_str += "SecDataDir ";
                ao_str += a_config.data_dir();
                ao_str += "\n";
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        if (a_config.has_argument_separator())
        {
                ao_str += "SecArgumentSeparator ";
                ao_str += a_config.argument_separator();
                ao_str += "\n";
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        if (a_config.has_cookie_format())
        {
                ao_str += "SecCookieFormat ";
                ao_str += to_string(a_config.cookie_format());
                ao_str += "\n";
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        if (a_config.has_component_signature())
        {
                ao_str += "SecComponentSignature \"";
                ao_str += a_config.component_signature();
                ao_str += "\"";
                ao_str += "\n";
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        if (a_config.has_default_action())
        {
                const waflz_pb::sec_action_t& l_action = a_config.default_action();
                std::string l_action_str;
                get_action_string(l_action_str, l_action);
                if (!l_action_str.empty())
                {
                        ao_str += "SecDefaultAction";
                        ao_str += " \"";
                        ao_str += l_action_str;
                        ao_str += "\"";
                        ao_str += '\n';
                }
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        if (a_config.has_debug_log())
        {
                ao_str += "SecDebugLog ";
                ao_str += a_config.debug_log();
                ao_str += "\n";
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        if (a_config.has_debug_log_level())
        {
                ao_str += "SecDebugLogLevel ";
                ao_str += to_string(a_config.debug_log_level());
                ao_str += "\n";
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        if (a_config.has_geo_lookup_db())
        {
                ao_str += "SecGeoLookupDb ";
                ao_str += a_config.geo_lookup_db();
                ao_str += "\n";
        }
        // -------------------------------------------------
        //
        // -------------------------------------------------
        for (int i=0; i < a_config.directive_size(); i++)
        {
                const waflz_pb::directive_t &l_directive = a_config.directive(i);
                if (l_directive.has_marker())
                {
                        ao_str += "SecMarker ";
                        ao_str += l_directive.marker();
                        ao_str += "\n";
                }
                if (l_directive.has_sec_rule())
                {
                        append_modsec_rule(ao_str, l_directive.sec_rule(), 0, false);
                }
                if (l_directive.has_sec_action())
                {
                        const waflz_pb::sec_action_t& l_action = l_directive.sec_action();
                        std::string l_action_str;
                        get_action_string(l_action_str, l_action);
                        if (!l_action_str.empty())
                        {
                                ao_str += "SecAction";
                                ao_str += " \"";
                                ao_str += l_action_str;
                                ao_str += "\"";
                                ao_str += '\n';
                        }
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t config_parser::append_modsec_rule(std::string &ao_str,
                                         const waflz_pb::sec_rule_t &a_secrule,
                                         const uint32_t a_indent,
                                         bool a_is_chained)
{
        std::string l_rule;
        int32_t l_s;
        l_s = get_modsec_rule_line(l_rule, a_secrule, a_indent, a_is_chained);
        if (l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        ao_str += l_rule;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t config_parser::read_file_pbuf(waflz_pb::sec_config_t& ao_config,
                                      const std::string &a_file,
                                      bool a_force)
{
        // -------------------------------------------------
        // Check is a file
        // TODO
        // -------------------------------------------------
        struct stat l_stat;
        int32_t l_s = WAFLZ_STATUS_OK;
        l_s = stat(a_file.c_str(), &l_stat);
        if (l_s != 0)
        {
                NDBG_PRINT("error performing stat on file: %s.  Reason: %s\n", a_file.c_str(), strerror(errno));
                return WAFLZ_STATUS_ERROR;
        }
        // -----------------------------------------------------------
        // Check if is regular file
        // -----------------------------------------------------------
        if (!(l_stat.st_mode & S_IFREG))
        {
                NDBG_PRINT("error opening file: %s.  Reason: is NOT a regular file\n", a_file.c_str());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // Check for *.conf
        // TODO -skip files w/o *.pbuf suffix
        // -------------------------------------------------
        if (!a_force)
        {
                std::string l_file_ext;
                l_file_ext = get_file_ext(a_file);
                if (l_file_ext != "pbuf")
                {
                        return WAFLZ_STATUS_OK;
                }
        }
        // -------------------------------------------------
        // Open file...
        // -------------------------------------------------
        FILE * l_file;
        l_file = fopen(a_file.c_str(),"r");
        if (NULL == l_file)
        {
                NDBG_PRINT("error opening file: %s.  Reason: %s\n", a_file.c_str(), strerror(errno));
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // Read in file...
        // -------------------------------------------------
        int32_t l_size = l_stat.st_size;
        int32_t l_read_size;
        char *l_buf = (char *)malloc(sizeof(char)*l_size);
        l_read_size = fread(l_buf, 1, l_size, l_file);
        if (l_read_size != l_size)
        {
                NDBG_PRINT("error performing fread.  Reason: %s [%d:%d]\n", strerror(errno), l_read_size, l_size);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // Parse
        // -------------------------------------------------
        bool l_parse_status;
        ao_config.Clear();
        l_parse_status = ao_config.ParseFromArray(l_buf, l_size);
        if (!l_parse_status)
        {
                NDBG_PRINT("error performing ParseFromArray\n");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // Close file...
        // -------------------------------------------------
        l_s = fclose(l_file);
        if (WAFLZ_STATUS_OK != l_s)
        {
                NDBG_PRINT("error performing fclose.  Reason: %s\n", strerror(errno));
                return WAFLZ_STATUS_ERROR;
        }
        if (l_buf)
        {
                free(l_buf);
                l_buf = NULL;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t config_parser::read_file_json(waflz_pb::sec_config_t& ao_config,
                                      const std::string &a_file,
                                      bool a_force)
{
        // -------------------------------------------------
        // Check is a file
        // TODO
        // -------------------------------------------------
        struct stat l_stat;
        int32_t l_s = WAFLZ_STATUS_OK;
        l_s = stat(a_file.c_str(), &l_stat);
        if (l_s != 0)
        {
                WAFLZ_PERROR(m_err_msg, "error performing stat on file: %s.  Reason: %s\n", a_file.c_str(), strerror(errno));
                return WAFLZ_STATUS_ERROR;
        }
        // -----------------------------------------------------------
        // Check if is regular file
        // -----------------------------------------------------------
        if (!(l_stat.st_mode & S_IFREG))
        {
                WAFLZ_PERROR(m_err_msg, "error opening file: %s.  Reason: is NOT a regular file\n", a_file.c_str());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // Check for *.conf
        // TODO -skip files w/o *.pbuf suffix
        // -------------------------------------------------
        if (!a_force)
        {
                std::string l_file_ext;
                l_file_ext = get_file_ext(a_file);
                if (l_file_ext != "json")
                {
                        return WAFLZ_STATUS_OK;
                }
        }
        // -------------------------------------------------
        // Open file...
        // -------------------------------------------------
        FILE * l_file;
        l_file = fopen(a_file.c_str(),"r");
        if (NULL == l_file)
        {
                WAFLZ_PERROR(m_err_msg, "error opening file: %s.  Reason: %s\n", a_file.c_str(), strerror(errno));
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // Read in file...
        // -------------------------------------------------
        int32_t l_size = l_stat.st_size;
        int32_t l_read_size;
        char *l_buf = (char *)malloc(sizeof(char)*l_size);
        l_read_size = fread(l_buf, 1, l_size, l_file);
        if (l_read_size != l_size)
        {
                WAFLZ_PERROR(m_err_msg, "error performing fread.  Reason: %s [%d:%d]\n", strerror(errno), l_read_size, l_size);
                if (l_buf) { free(l_buf); l_buf = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // Parse
        // -------------------------------------------------
        l_s = update_from_json(ao_config, l_buf, l_size);
        if (l_s != JSPB_OK)
        {
                WAFLZ_PERROR(m_err_msg, "parsing json. Reason: %s", get_jspb_err_msg());
                if (l_buf) { free(l_buf); l_buf = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // Close file...
        // -------------------------------------------------
        l_s = fclose(l_file);
        if (WAFLZ_STATUS_OK != l_s)
        {
                WAFLZ_PERROR(m_err_msg, "error performing fclose.  Reason: %s\n", strerror(errno));
                if (l_buf) { free(l_buf); l_buf = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        if (l_buf)
        {
                free(l_buf);
                l_buf = NULL;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t config_parser::read_buf_json(waflz_pb::sec_config_t& ao_config, const char* a_buf, uint64_t a_buf_len)
{
        // -------------------------------------------------
        // Parse
        // -------------------------------------------------
        int32_t l_s;
        l_s = update_from_json(ao_config, a_buf, a_buf_len);
        if (l_s != JSPB_OK)
        {
                WAFLZ_PERROR(m_err_msg, "parsing json. Reason: %s", get_jspb_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t config_parser::read_directory(waflz_pb::sec_config_t& ao_config,
                                      format_t a_format,
                                      const std::string &a_directory)
{
        // -------------------------------------------------
        // Walk through directory (no recursion)
        // -------------------------------------------------
        typedef std::set<std::string> file_set_t;
        file_set_t l_file_set;
        // -----------------------------------------------------------
        // Scan directory for existing
        // -----------------------------------------------------------
        DIR *l_dir_ptr;
        struct dirent *l_dirent;
        l_dir_ptr = opendir(a_directory.c_str());
        if (l_dir_ptr == NULL)
        {
                NDBG_PRINT("Failed to open directory: %s.  Reason: %s\n", a_directory.c_str(), strerror(errno));
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // dir walk
        // -------------------------------------------------
        while ((l_dirent = readdir(l_dir_ptr)) != NULL)
        {
                std::string l_filename(a_directory);
                l_filename += "/";
                l_filename += l_dirent->d_name;
                // -----------------------------------------
                // Check if is directory
                // -----------------------------------------
                struct stat l_stat;
                int32_t l_s = WAFLZ_STATUS_OK;
                l_s = stat(l_filename.c_str(), &l_stat);
                if (l_s != 0)
                {
                        NDBG_PRINT("error performing stat on file: %s.  Reason: %s\n", l_filename.c_str(), strerror(errno));
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // Skip directories
                // -----------------------------------------
                if (l_stat.st_mode & S_IFDIR)
                {
                        continue;
                }
                l_file_set.insert(l_filename);
        }
        closedir(l_dir_ptr);
        // -------------------------------------------------
        // Read every file
        // -------------------------------------------------
        for (file_set_t::const_iterator i_file = l_file_set.begin(); i_file != l_file_set.end(); ++i_file)
        {
                waflz_pb::sec_config_t* l_sc = new waflz_pb::sec_config_t();
                int32_t l_s;
                l_s = read_file(*l_sc, a_format, *i_file, false);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        // ---------------------------------
                        // Fail or continue???
                        // Continuing for now...
                        // ---------------------------------
                        NDBG_PRINT("error performing read_file: %s\n", i_file->c_str());
                        if (l_sc) { delete l_sc; l_sc = NULL; }
                        //return WAFLZ_STATUS_ERROR;
                }
                ao_config.mutable_directive()->MergeFrom(l_sc->directive());
                if (l_sc) { delete l_sc; l_sc = NULL; }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t config_parser::read_single_line(waflz_pb::sec_config_t& ao_config,
                                        format_t a_format,
                                        std::string a_line)
{
        int32_t l_s = WAFLZ_STATUS_OK;
        m_cur_line_num = 0;
        if (a_line.empty())
        {
                return WAFLZ_STATUS_OK;
        }
        switch (a_format)
        {
        // -------------------------------------------------
        // MODSECURITY
        // -------------------------------------------------
        case MODSECURITY:
        {
                std::string l_modsec_line;
                ++m_cur_line_num;
                l_s = read_line(ao_config,
                                l_modsec_line,
                                a_line.c_str(),
                                a_line.length(),
                                m_cur_line_num);
                if (WAFLZ_STATUS_OK != l_s)
                {
                        NDBG_PRINT("error\n");
                        return WAFLZ_STATUS_ERROR;
                }
                break;
        }
        // -------------------------------------------------
        // JSON
        // -------------------------------------------------
        case JSON:
        {
                l_s = update_from_json(ao_config, a_line.c_str(), a_line.length());
                if (l_s != JSPB_OK)
                {
                        NDBG_PRINT("error performing update_from_json\n");
                        return WAFLZ_STATUS_ERROR;
                }
                break;
        }
        // -------------------------------------------------
        // PROTOBUF
        // -------------------------------------------------
        case PROTOBUF:
        {
                bool l_s;
                ao_config.Clear();
                l_s = ao_config.ParseFromArray(a_line.c_str(), a_line.length());
                if (!l_s)
                {
                        NDBG_PRINT("error performing ParseFromArray\n");
                        return WAFLZ_STATUS_ERROR;
                }
                break;
        }
        // -------------------------------------------------
        // ???
        // -------------------------------------------------
        default:
        {
                NDBG_PRINT("error\n");
                return WAFLZ_STATUS_ERROR;
        }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t config_parser::read_file(waflz_pb::sec_config_t& ao_config,
                                 format_t a_format,
                                 const std::string &a_file,
                                 bool a_force)
{
        int l_s;
        switch (a_format)
        {
        // -------------------------------------------------
        // MODSECURITY
        // -------------------------------------------------
        case MODSECURITY:
        {
                l_s = read_file_modsec(ao_config, a_file, a_force);
                return l_s;
        }
        // -------------------------------------------------
        // JSON
        // -------------------------------------------------
        case JSON:
        {
                // TODO -share data with engine!!!!
                l_s = read_file_json(ao_config, a_file, a_force);
                return l_s;
        }
        // -------------------------------------------------
        // PROTOBUF
        // -------------------------------------------------
        case PROTOBUF:
        {
                // TODO -share data with engine!!!!
                l_s = read_file_pbuf(ao_config, a_file, a_force);
                return l_s;
        }
        // -------------------------------------------------
        // ???
        // -------------------------------------------------
        default:
        {
                // TODO Add message
                return WAFLZ_STATUS_ERROR;
        }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t config_parser::parse_config(waflz_pb::sec_config_t &ao_config,
                                    format_t a_format,
                                    const std::string &a_path)
{
        // -------------------------------------------------
        // Stat file to see if is directory or file
        // -------------------------------------------------
        struct stat l_stat;
        int32_t l_s = WAFLZ_STATUS_OK;
        l_s = stat(a_path.c_str(), &l_stat);
        if (l_s != 0)
        {
                WAFLZ_PERROR(m_err_msg, "error performing stat on file: %s.  Reason: %s\n", a_path.c_str(), strerror(errno));
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // Check if is directory
        // -------------------------------------------------
        if (l_stat.st_mode & S_IFDIR)
        {
                // -----------------------------------------
                // read dir
                // -----------------------------------------
                int32_t l_retval = WAFLZ_STATUS_OK;
                l_retval = read_directory(ao_config, a_format, a_path);
                if (l_retval != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // File
        // -------------------------------------------------
        else if ((l_stat.st_mode & S_IFREG) ||
                (l_stat.st_mode & S_IFLNK))
        {
                int32_t l_retval = WAFLZ_STATUS_OK;
                l_retval = read_file(ao_config, a_format, a_path, true);
                if (l_retval != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t config_parser::parse_config(waflz_pb::sec_config_t &ao_config,
                                    void* a_js)
{
        int32_t l_s;
        const rapidjson::Document &l_js = *((rapidjson::Document *)a_js);
        l_s = update_from_json(ao_config, l_js);
        if (l_s != JSPB_OK)
        {
                WAFLZ_PERROR(m_err_msg, "parsing json. Reason: %s", get_jspb_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t config_parser::parse_line(waflz_pb::sec_config_t &ao_config,
                                  format_t a_format,
                                  const std::string &a_line)
{
        int32_t l_retval = WAFLZ_STATUS_OK;
        l_retval = read_single_line(ao_config, a_format, a_line);
        if (l_retval != WAFLZ_STATUS_OK)
        {
                NDBG_PRINT("error\n");
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
config_parser::config_parser(void):
        m_verbose(false),
        m_color(false),
        m_cur_file(),
        m_cur_file_dir(),
        m_cur_file_base(),
        m_cur_line(),
        m_cur_line_num(0),
        m_cur_line_pos(0),
        m_cur_parent_rule(NULL),
        m_directives(),
        m_variables(),
        m_operators(),
        m_actions(),
        m_transformations(),
        m_tx_variables(),
        m_ctls(),
        m_unimplemented_directives(),
        m_unimplemented_variables(),
        m_unimplemented_operators(),
        m_unimplemented_actions(),
        m_unimplemented_transformations(),
        m_unimplemented_ctls(),
        m_err_msg()
{
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
config_parser::~config_parser()
{
}
}
