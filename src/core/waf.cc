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
#include "rule.pb.h"
#include "event.pb.h"
#include "profile.pb.h"
#include "waflz/def.h"
#include "waflz/waf.h"
#include "waflz/rqst_ctx.h"
#include "waflz/engine.h"
#include "waflz/profile.h"
#include "waflz/trace.h"
#include "waflz/string_util.h"
#include "support/ndebug.h"
#include "support/file_util.h"
#include "support/time_util.h"
#include "support/md5.h"
#include "core/op.h"
#include "core/var.h"
#include "core/tx.h"
#include "core/macro.h"
#include "jspb/jspb.h"
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! \details: Mark the context with the applied tx. This can be used to avoid
//!           performing the same logic more than once. ie: tolower() on a
//!           particular operation that uses the ac when a previous tx already
//!           lowered the string.
//! \param:   A context(output)
//! \param:   A transformation type.
//! \return:  Sets the context with the appropiated applied tx.
//! ----------------------------------------------------------------------------
static void mark_tx_applied(ns_waflz::rqst_ctx *a_ctx,
                waflz_pb::sec_action_t_transformation_type_t const &tx_type)
{
        switch(tx_type)
        {
        case waflz_pb::sec_action_t_transformation_type_t::
                sec_action_t_transformation_type_t_LOWERCASE:
        {
                a_ctx->m_src_asn_str.m_tx_applied |= ns_waflz::TX_APPLIED_TOLOWER;
                break;
        }
        case waflz_pb::sec_action_t_transformation_type_t::
                sec_action_t_transformation_type_t_CMDLINE:
        {
                a_ctx->m_src_asn_str.m_tx_applied |= ns_waflz::TX_APPLIED_CMDLINE;
                break;
        }
        default:;
                // TODO: CMDLINE tx will also apply tolower(), Should it be included?
        }
}
//! ----------------------------------------------------------------------------
//! \details: checks if the given string is a tx score key
//! \return:  true if the given param is a score key - otherwise false
//! \param:   a_var_key: a string to check
//! ----------------------------------------------------------------------------
bool tx_val_is_score( const std::string& a_var_key )
{
        // -------------------------------------------------
        // all score keys
        // -------------------------------------------------
        if (a_var_key == "anomaly_score_pl1" || 
            a_var_key == "anomaly_score_pl2" || 
            a_var_key == "anomaly_score_pl3" || 
            a_var_key == "anomaly_score_pl4" || 
            a_var_key == "inbound_anomaly_score_pl1" || 
            a_var_key == "inbound_anomaly_score_pl2" || 
            a_var_key == "inbound_anomaly_score_pl3" || 
            a_var_key == "inbound_anomaly_score_pl4" || 
            a_var_key == "outbound_anomaly_score_pl1" || 
            a_var_key == "outbound_anomaly_score_pl2" || 
            a_var_key == "outbound_anomaly_score_pl3" || 
            a_var_key == "outbound_anomaly_score_pl4"
        )
        {
                return true;
        }
        // -------------------------------------------------
        // return not found
        // -------------------------------------------------
        return false;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
waf::waf(engine &a_engine):
        // -------------------------------------------------
        // protobuf
        // -------------------------------------------------
        m_pb(NULL),
        // -------------------------------------------------
        // compiled
        // -------------------------------------------------
        m_compiled_config(NULL),
        m_ctype_parser_map(a_engine.get_ctype_parser_map()),
        m_rtu_variable_map(),
        m_custom_score_map(),
        m_redacted_vars(),
        m_mx_rule_list()
#ifdef WAFLZ_NATIVE_ANOMALY_MODE
        ,m_anomaly_score_cur(0),
#endif
        m_is_initd(false),
        m_err_msg(),
        m_engine(a_engine),
        m_id("__na__"),
        m_cust_id("__na__"),
        m_name("__na__"),
        m_ruleset_dir(),
        m_paranoia_level(1),
        m_no_log_matched(false),
        m_parse_xml(true),
        m_parse_json(true),
        m_team_config(false)
{
        m_compiled_config = new compiled_config_t();
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
waf::~waf()
{
        if(m_compiled_config) { delete m_compiled_config; m_compiled_config = NULL; }
        if(m_pb) { delete m_pb; m_pb = NULL; }
        for (directive_list_t::iterator i_d = m_mx_rule_list.begin();
             i_d != m_mx_rule_list.end();
             ++i_d)
        {
                if(!*i_d) { continue; }
                delete *i_d;
                *i_d = NULL;
        }
        // ---------------------------------------
        // removing regex for redacted vars
        // ---------------------------------------
        this->clear_redacted_variables_list();
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
#if 0
void waf::show(void)
{
        std::string l_config = m_pb->DebugString();
        colorize_string(l_config);
        NDBG_OUTPUT("%s\n", l_config.c_str());
}
#endif
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
#if 0
void waf::show_status(void)
{
        m_parser.show_status();
}
#endif
//! ----------------------------------------------------------------------------
//! \details: clears the regexs in the redacted variables list
//! ----------------------------------------------------------------------------
void waf::clear_redacted_variables_list()
{
        for(redacted_var_list_t::iterator i_d = m_redacted_vars.begin();
            i_d != m_redacted_vars.end();
            ++i_d)
        {
                regex* l_rd = std::get<0>(*i_d);
                if(!l_rd) { continue; }
                delete l_rd;
                l_rd = nullptr;
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
uint32_t waf::get_request_body_in_memory_limit(void)
{
        if(m_pb &&
           m_pb->has_request_body_in_memory_limit())
        {
                return m_pb->request_body_in_memory_limit();
        }
        return 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t waf::get_str(std::string &ao_str, config_parser::format_t a_format)
{
        bool l_s;
        switch(a_format)
        {
        // ---------------------------------------
        // Protobuf
        // ---------------------------------------
        case config_parser::PROTOBUF:
        {
                l_s = m_pb->SerializeToString(&ao_str);
                if(!l_s)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                else
                {
                        return WAFLZ_STATUS_OK;
                }
                break;
        }
        // ---------------------------------------
        // json
        // ---------------------------------------
        case config_parser::JSON:
        {
                // convert protobuf message to JsonCpp object
                try
                {
                        ns_waflz::convert_to_json(ao_str, *m_pb);
                }
                catch(int e)
                {
                        NDBG_PRINT("Error -json_protobuf::convert_to_json threw\n");
                        return WAFLZ_STATUS_ERROR;
                }
                return WAFLZ_STATUS_OK;
        }
        // ---------------------------------------
        // modsecurity
        // ---------------------------------------
        case config_parser::MODSECURITY:
        {
                l_s = config_parser::get_modsec_config_str(ao_str, *m_pb);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        //NDBG_PRINT("Error performing get_modsec_config_str\n");
                        return WAFLZ_STATUS_ERROR;
                }
                else
                {
                        return WAFLZ_STATUS_OK;
                }
                break;
        }
        default:
        {
                NDBG_PRINT("Error -unrecognized format specification[%d]\n", a_format);
                return WAFLZ_STATUS_ERROR;
        }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! types for organizing rule modifications
//! ----------------------------------------------------------------------------
typedef std::map <waflz_pb::variable_t_type_t, waflz_pb::variable_t> _type_var_map_t;
typedef std::map <std::string, _type_var_map_t> _id_tv_map_t;
//! ----------------------------------------------------------------------------
//! \details: This function generates modified variable lists based on RTUs.
//!           The RTUs are stored in id to variable map (a_tv_map).
//! \return:  waflz status code
//! \param:   ao_var_map: the map of rule_id to variable list
//            ao_rx_list: list of regexes
//            a_tv_map: map of rtu changes
//            a_rule: the rule that needs modifications
//            a_replace: replace flag
//! ----------------------------------------------------------------------------
static int32_t create_modified_variable_list(update_variable_map_t* ao_var_map,
                                             regex_list_t &ao_rx_list,
                                             const _type_var_map_t& a_tv_map,
                                             const ::waflz_pb::sec_rule_t &a_rule,
                                             bool a_replace = false)
{
        // -------------------------------------------------
        // DEBUG - tells you which rule is being looked at
        // -------------------------------------------------
        // NDBG_PRINT("Creating modified var list for: %s\n", a_rule.action().id().c_str());
        // -------------------------------------------------
        // save rule_id to create keys in ao_var_map
        // -------------------------------------------------
        const std::string l_rule_id = a_rule.action().id();
        // -------------------------------------------------
        // current rule to look at (can be a chained rule)
        // -------------------------------------------------
        int32_t l_cr_idx = -1;
        do
        {
                // -----------------------------------------
                // construct key for ao_var_map
                // -----------------------------------------
                std::string l_var_key = l_rule_id + "_" + std::to_string(l_cr_idx+1);
                // -----------------------------------------
                // current rule to look at 
                // NOTE: can be a chained rule
                // -----------------------------------------
                bool l_in_chain = l_cr_idx >= 0;
                const ::waflz_pb::sec_rule_t* l_rule = (l_in_chain) ? &a_rule.chained_rule(l_cr_idx) : &a_rule;
                // -----------------------------------------
                // create a list ot store the new vars
                // -----------------------------------------
                std::vector<::waflz_pb::variable_t> l_new_vars_for_rule;
                // -----------------------------------------
                // copy and modify any var the rule contains
                // store if it was modified in l_is_modified
                // -----------------------------------------
                bool l_is_modified = false;
                for (int32_t i_v = 0; i_v < l_rule->variable_size(); ++i_v)
                {
                        // ---------------------------------
                        // get current variable from rule
                        // ---------------------------------
                        const ::waflz_pb::variable_t& l_v = l_rule->variable(i_v);
                        // ---------------------------------
                        // skip variables without types 
                        // (ex: ARGS, etc)
                        // ---------------------------------
                        if (!l_v.has_type()) { continue; }
                        // ---------------------------------
                        // copy variable
                        // ---------------------------------
                        ::waflz_pb::variable_t l_new_var = ::waflz_pb::variable_t(l_v);
                        // ---------------------------------
                        // check for rtu on variable type
                        // ---------------------------------
                        ns_waflz::_type_var_map_t::const_iterator l_rtu_matches = a_tv_map.find(l_v.type());
                        if (l_rtu_matches != a_tv_map.end())
                        { 
                                // ---------------------------------
                                // set modified
                                // ---------------------------------
                                l_is_modified = true;
                                // ---------------------------------
                                // get variable from rtu
                                // ---------------------------------
                                const::waflz_pb::variable_t l_rtu_variable = l_rtu_matches->second;
                                // ---------------------------------
                                // if replace -replace whole var
                                // ---------------------------------
                                if (a_replace)
                                {
                                        l_new_var.CopyFrom(l_rtu_variable);
                                        l_new_vars_for_rule.push_back(l_new_var);
                                        continue;
                                }
                                // ---------------------------------
                                // add rtu matches
                                // ---------------------------------
                                for (int32_t i_m = 0; i_m < l_rtu_variable.match_size(); i_m++)
                                {
                                        // -------------------------
                                        // get the current match
                                        // -------------------------
                                        const ::waflz_pb::variable_t_match_t& l_mm = l_rtu_variable.match(i_m);
                                        // -------------------------
                                        // no value = skip
                                        // -------------------------
                                        if (!l_mm.has_value()) { continue; }
                                        // -------------------------
                                        // create a copy of the
                                        // match
                                        // -------------------------
                                        ::waflz_pb::variable_t_match_t* l_new_mx = l_new_var.add_match();
                                        l_new_mx->CopyFrom(l_mm);
                                        // -------------------------
                                        // if its a regex, compile
                                        // -------------------------
                                        if (l_mm.is_regex())
                                        {
                                                regex *l_pcre = NULL;
                                                l_pcre = new regex();
                                                const std::string &l_rx = l_mm.value();
                                                int32_t l_s;
                                                l_s = l_pcre->init(l_rx.c_str(), l_rx.length());
                                                if(l_s != WAFLZ_STATUS_OK)
                                                {
                                                        // TODO -log error reason???
                                                        return WAFLZ_STATUS_ERROR;
                                                }
                                                ao_rx_list.push_back(l_pcre);
                                                l_new_mx->set__reserved_1((uint64_t)l_pcre);
                                        }
                                }
                        }
                        // ---------------------------------
                        // append the (possibly modified)
                        // variable to the list
                        // ---------------------------------
                        l_new_vars_for_rule.push_back(l_new_var);
                }
                // ---------------------------------
                // if no change - go to next part
                // of rule
                // ---------------------------------
                if (!l_is_modified)
                {
                        l_cr_idx++;
                        continue;
                }
                // ---------------------------------
                // shrink vector to save space
                // ---------------------------------
                l_new_vars_for_rule.shrink_to_fit();
                // ---------------------------------
                // update the rtu map
                // ---------------------------------
                // NDBG_PRINT("setting %s\n", l_var_key.c_str());
                (*ao_var_map)[l_var_key] = l_new_vars_for_rule;
                // ---------------------------------
                // on to next rule in chain
                // ---------------------------------
                l_cr_idx++;
        } while (l_cr_idx < a_rule.chained_rule_size());
        // -------------------------------------------------
        // return once rule is processed
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: Modify the directives based on a_dr_id_set, ao_id_tv_map
//!           and ao_id_tv_replace_map. The modified rules are stored in
//!           ao_mx_directive_list (m_mx_rule_list) and the references to rules
//!           in _compiled_config are updated to refer these
//!           instead of the rules in global rulesets
//! \return:  TODO
//! \param:   ao_directive_list: list of all directives
//!           ao_mx_directive_list: list of all modified directives
//!           ao_rx_list: list of all compiled regex
//!           ao_var_map: list of all variable list for rules with rtus
//!           a_dr_id_set: ids of rule to be removed
//!           ao_id_tv_map: rule id to variable map, for updating target
//!           ao_id_tv_replace_map: rule id to varaible replace map
//! ----------------------------------------------------------------------------
static int32_t modify_directive_list(directive_list_t &ao_directive_list,
                                     directive_list_t &ao_mx_directive_list,
                                     regex_list_t &ao_rx_list,
                                     update_variable_map_t &ao_var_map,
                                     const disabled_rule_id_set_t &a_dr_id_set,
                                     const _id_tv_map_t &ao_id_tv_map,
                                     const _id_tv_map_t &ao_id_tv_replace_map)
{
        // -------------------------------------------------
        // find rules
        // -------------------------------------------------
        for(directive_list_t::iterator i_d = ao_directive_list.begin();
            i_d != ao_directive_list.end();)
        {
                if(!(*i_d))
                {
                        ++i_d;
                        continue;
                }
                const ::waflz_pb::directive_t& l_d = **i_d;
                if(!l_d.has_sec_rule() ||
                   !l_d.sec_rule().has_action() ||
                   !l_d.sec_rule().action().has_id())
                {
                        ++i_d;
                        continue;
                }
                const std::string& l_id = l_d.sec_rule().action().id();
                // -----------------------------------------
                // check for remove rule id
                // -----------------------------------------
                if((a_dr_id_set.find(l_id) != a_dr_id_set.end()))
                {
                        ao_directive_list.erase(i_d++);
                        continue;
                }
                _id_tv_map_t::const_iterator i_id;
                // -----------------------------------------
                // id in map (replace)
                // -----------------------------------------
                i_id = ao_id_tv_replace_map.find(l_id);
                if(i_id != ao_id_tv_replace_map.end())
                {
                        const _type_var_map_t& l_tv_map = i_id->second;
                        const ::waflz_pb::sec_rule_t& l_r = l_d.sec_rule();
                        // ---------------------------------
                        // check for modified
                        // ---------------------------------
                        bool l_is_modified = false;
                        for(int32_t i_v = 0; i_v < l_r.variable_size(); ++i_v)
                        {
                                const ::waflz_pb::variable_t& l_v = l_r.variable(i_v);
                                if(!l_v.has_type())
                                {
                                        continue;
                                }
                                if(l_tv_map.find(l_v.type()) != l_tv_map.end())
                                {
                                        l_is_modified = true;
                                        break;
                                }
                        }
                        // ---------------------------------
                        // if modified update rule
                        // ---------------------------------
                        if(l_is_modified)
                        {
                                int32_t l_s;
                                l_s = create_modified_variable_list(&ao_var_map, ao_rx_list, l_tv_map, l_r, true);
                                if(l_s != WAFLZ_STATUS_OK)
                                {
                                        return WAFLZ_STATUS_ERROR;
                                }
                        }
                }
                // -----------------------------------------
                // id in map
                // -----------------------------------------
                i_id = ao_id_tv_map.find(l_id);
                if(i_id != ao_id_tv_map.end())
                {       
                        int32_t l_cr_idx = -1;
                        const ::waflz_pb::sec_rule_t& l_r = l_d.sec_rule();
                        // check for chained rules as well.
                        do
                        {
                                const waflz_pb::sec_rule_t *l_rule = NULL;
                                if(l_cr_idx == -1)
                                {
                                        l_rule = &l_r;
                                }
                                if((l_cr_idx >= 0) &&
                                    (l_cr_idx < l_d.sec_rule().chained_rule_size()))
                                {
                                        l_rule = &(l_r.chained_rule(l_cr_idx));
                                }
                                const _type_var_map_t& l_tv_map = i_id->second;
                                // ---------------------------------
                                // check for modified
                                // ---------------------------------
                                bool l_is_modified = false;
                                for(int32_t i_v = 0; i_v < l_rule->variable_size(); ++i_v)
                                {
                                        const ::waflz_pb::variable_t& l_v = l_rule->variable(i_v);
                                        // ---------------------------------
                                        // variable type doesn't match
                                        // move on to next.
                                        // ---------------------------------
                                        if(!l_v.has_type())
                                        {
                                                continue;
                                        }
                                        if(l_tv_map.find(l_v.type()) != l_tv_map.end())
                                        {
                                                l_is_modified = true;
                                                break;
                                        }
                                }
                                // ---------------------------------
                                // if modified update rule
                                // ---------------------------------
                                if(l_is_modified)
                                {
                                        int32_t l_s;
                                        l_s = create_modified_variable_list(&ao_var_map, ao_rx_list, l_tv_map, l_r, false);
                                        if(l_s != WAFLZ_STATUS_OK)
                                        {
                                                return WAFLZ_STATUS_ERROR;
                                        }
                                }
                                ++l_cr_idx;
                        } while (l_cr_idx < l_d.sec_rule().chained_rule_size());
                }
                ++i_d;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t waf::compile(void)
{
        // -------------------------------------------------
        // compile
        // -------------------------------------------------
        int32_t l_s;
        l_s = m_engine.compile(*m_compiled_config, *m_pb, m_ruleset_dir);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "%s", m_engine.get_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // *************************************************
        //          C O N F I G   U P D A T E S
        // *************************************************
        // -------------------------------------------------
        // -------------------------------------------------
        // disabled rules
        // -------------------------------------------------
        disabled_rule_id_set_t l_dr_id_set;
        for(int32_t i_dr = 0; i_dr < m_pb->rule_remove_by_id_size(); ++i_dr)
        {
                const std::string &l_dr = m_pb->rule_remove_by_id(i_dr);
                l_dr_id_set.insert(l_dr);
        }
        // -------------------------------------------------
        // rule target updates
        // -------------------------------------------------
        _id_tv_map_t *l_id_tv_map = new _id_tv_map_t();
        _id_tv_map_t *l_id_tv_replace_map = new _id_tv_map_t();
        for(int32_t i_rtu = 0; i_rtu < m_pb->update_target_by_id_size(); ++i_rtu)
        {
                const ::waflz_pb::update_target_t& l_rtu = m_pb->update_target_by_id(i_rtu);
                if(!l_rtu.has_id() && l_rtu.id_list_size() == 0)
                {
                        continue;
                }
                // -----------------------------------------
                // replace
                // -----------------------------------------
                if(l_rtu.has_replace())
                {
                        if(!l_rtu.replace().empty() &&
                            l_rtu.variable_size() &&
                            l_rtu.variable(0).has_type())
                        {
                                // -------------------------
                                // for each match
                                // -------------------------
                                const ::waflz_pb::variable_t& l_v = l_rtu.variable(0);
                                for(int32_t i_m = 0; i_m < l_v.match_size(); ++i_m)
                                {
                                        const ::waflz_pb::variable_t_match_t& l_m = l_v.match(i_m);
                                        // -----------------
                                        // only is negated for now..
                                        // -----------------
                                        if(!l_m.is_negated())
                                        {
                                                continue;
                                        }
                                        if ( l_rtu.id_list_size() >= 1 )
                                        {
                                                for (int i_rule_id_index = 0;
                                                i_rule_id_index < l_rtu.id_list_size();
                                                i_rule_id_index++)
                                                {
                                                        const std::string rule_id = l_rtu.id_list(i_rule_id_index);
                                                        if(l_id_tv_replace_map->find(rule_id) == l_id_tv_replace_map->end())
                                                        {
                                                                _type_var_map_t l_tmp;
                                                                (*l_id_tv_replace_map)[rule_id] = l_tmp;
                                                        }
                                                        _type_var_map_t& l_tv_map = (*l_id_tv_replace_map)[rule_id];
                                                        if(l_tv_map.find(l_v.type()) == l_tv_map.end())
                                                        {
                                                                waflz_pb::variable_t l_tmp;
                                                                l_tmp.set_type(l_v.type());
                                                                l_tv_map[l_v.type()] = l_tmp;
                                                        }
                                                        ::waflz_pb::variable_t& l_rm_v = l_tv_map[l_v.type()];
                                                        l_rm_v.add_match()->CopyFrom(l_m);
                                                }
                                        }
                                        else
                                        {
                                                if(l_id_tv_replace_map->find(l_rtu.id()) == l_id_tv_replace_map->end())
                                                {
                                                        _type_var_map_t l_tmp;
                                                        (*l_id_tv_replace_map)[l_rtu.id()] = l_tmp;
                                                }
                                                _type_var_map_t& l_tv_map = (*l_id_tv_replace_map)[l_rtu.id()];
                                                if(l_tv_map.find(l_v.type()) == l_tv_map.end())
                                                {
                                                        waflz_pb::variable_t l_tmp;
                                                        l_tmp.set_type(l_v.type());
                                                        l_tv_map[l_v.type()] = l_tmp;
                                                }
                                                ::waflz_pb::variable_t& l_rm_v = l_tv_map[l_v.type()];
                                                l_rm_v.add_match()->CopyFrom(l_m);
                                        }
                                }
                                continue;
                        }
                }
                // -----------------------------------------
                // for each var
                // -----------------------------------------
                for(int32_t i_v = 0; i_v < l_rtu.variable_size(); ++i_v)
                {
                        const ::waflz_pb::variable_t& l_v = l_rtu.variable(i_v);
                        if(!l_v.has_type())
                        {
                                continue;
                        }
                        // ---------------------------------
                        // for each match
                        // ---------------------------------
                        for(int32_t i_m = 0; i_m < l_v.match_size(); ++i_m)
                        {
                                const ::waflz_pb::variable_t_match_t& l_m = l_v.match(i_m);
                                // -------------------------
                                // only is negated for now..
                                // -------------------------
                                if(!l_m.is_negated())
                                {
                                        continue;
                                }
                                if ( l_rtu.id_list_size() >= 1 )
                                {
                                        for (int i_rule_id_index = 0;
                                             i_rule_id_index < l_rtu.id_list_size();
                                             i_rule_id_index++)
                                        {
                                                const std::string rule_id = l_rtu.id_list(i_rule_id_index);
                                                if(l_id_tv_map->find(rule_id) == l_id_tv_map->end())
                                                {
                                                        _type_var_map_t l_tmp;
                                                        (*l_id_tv_map)[rule_id] = l_tmp;
                                                }
                                                _type_var_map_t& l_tv_map = (*l_id_tv_map)[rule_id];
                                                if(l_tv_map.find(l_v.type()) == l_tv_map.end())
                                                {
                                                        waflz_pb::variable_t l_tmp;
                                                        l_tmp.set_type(l_v.type());
                                                        l_tv_map[l_v.type()] = l_tmp;
                                                }
                                                ::waflz_pb::variable_t& l_rm_v = l_tv_map[l_v.type()];
                                                l_rm_v.add_match()->CopyFrom(l_m);
                                        }
                                }
                                else
                                {
                                        if(l_id_tv_map->find(l_rtu.id()) == l_id_tv_map->end())
                                        {
                                                _type_var_map_t l_tmp;
                                                (*l_id_tv_map)[l_rtu.id()] = l_tmp;
                                        }
                                        _type_var_map_t& l_tv_map = (*l_id_tv_map)[l_rtu.id()];
                                        if(l_tv_map.find(l_v.type()) == l_tv_map.end())
                                        {
                                                waflz_pb::variable_t l_tmp;
                                                l_tmp.set_type(l_v.type());
                                                l_tv_map[l_v.type()] = l_tmp;
                                        }
                                        ::waflz_pb::variable_t& l_rm_v = l_tv_map[l_v.type()];
                                        l_rm_v.add_match()->CopyFrom(l_m);
                                }
                        }
                }
        }
        // -------------------------------------------------
        // clear old rtus if the exist
        // -------------------------------------------------
        m_rtu_variable_map.clear();
        // -------------------------------------------------
        // modifications...
        // -------------------------------------------------
        l_s = modify_directive_list(m_compiled_config->m_directive_list_phase_1,
                                    m_mx_rule_list,
                                    m_compiled_config->m_regex_list,
                                    m_rtu_variable_map,
                                    l_dr_id_set,
                                    *l_id_tv_map,
                                    *l_id_tv_replace_map);
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(l_id_tv_replace_map) { delete l_id_tv_replace_map; l_id_tv_replace_map = NULL; }
                if(l_id_tv_map) { delete l_id_tv_map; l_id_tv_map = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        l_s = modify_directive_list(m_compiled_config->m_directive_list_phase_2,
                                    m_mx_rule_list,
                                    m_compiled_config->m_regex_list,
                                    m_rtu_variable_map,
                                    l_dr_id_set,
                                    *l_id_tv_map,
                                    *l_id_tv_replace_map);
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(l_id_tv_replace_map) { delete l_id_tv_replace_map; l_id_tv_replace_map = NULL; }
                if(l_id_tv_map) { delete l_id_tv_map; l_id_tv_map = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        if(l_id_tv_map) { delete l_id_tv_map; l_id_tv_map = NULL; }
        if(l_id_tv_replace_map) { delete l_id_tv_replace_map; l_id_tv_replace_map = NULL; }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: initialize waf from a file path.
//!           Called from bots.cc/rules.cc/waflz_server
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t waf::init(config_parser::format_t a_format,
                  const std::string &a_path,
                  bool a_apply_defaults,
                  bool a_custom_rules)
{
        // Check if already is initd
        if(m_is_initd)
        {
                return WAFLZ_STATUS_OK;
        }
        if(m_pb)
        {
                delete m_pb;
                m_pb = NULL;
        }
        // -------------------------------------------------
        // set defaults for missing values...
        // -------------------------------------------------
        int32_t l_s;
        waflz_pb::sec_config_t *l_pb = NULL;
        if(a_apply_defaults)
        {
                m_pb = new waflz_pb::sec_config_t();
                l_s = set_defaults(a_custom_rules);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "set_defaults failed");
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // parse
        // -------------------------------------------------
        config_parser *l_parser = new config_parser();
        l_pb = new waflz_pb::sec_config_t();
        l_s = l_parser->parse_config(*l_pb, a_format, a_path);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "parse error %.*s", WAFLZ_ERR_REASON_LEN, l_parser->get_err_msg());
                if(l_parser) { delete l_parser; l_parser = NULL;}
                if(l_pb) { delete l_pb; l_pb = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        if(m_pb)
        {
                m_pb->MergeFrom(*l_pb);
                delete l_pb;
                l_pb = NULL;
        }
        else
        {
                m_pb = l_pb;
        }
        // TODO remove -debug...
        //l_parser->show_status();
        if(l_parser) { delete l_parser; l_parser = NULL;}
        // -------------------------------------------------
        // ruleset info
        // -------------------------------------------------
        if(!m_pb->has_ruleset_id())
        {
                 m_pb->set_ruleset_id("__na__");
        }
        if(!m_pb->has_ruleset_version())
        {
                m_pb->set_ruleset_version("__na__");
        }
        // -------------------------------------------------
        // set id
        // -------------------------------------------------
        m_id = m_pb->id();
        m_cust_id = m_pb->customer_id();
        m_name = m_pb->name();
        if (m_pb->has_team_config())
        {
                m_team_config = m_pb->team_config();
        }
        // -------------------------------------------------
        // set ruleset info for custom rules
        // -------------------------------------------------
        if(a_custom_rules)
        {
                m_ruleset_dir = m_engine.get_ruleset_dir();
                m_ruleset_dir.append(m_pb->ruleset_id());
                m_ruleset_dir.append("/version/");
                m_ruleset_dir.append(m_pb->ruleset_version());
                m_ruleset_dir.append("/policy/");
                // -----------------------------------------
                // update includes to full path
                // -----------------------------------------
                for(int i_d = 0; i_d < m_pb->directive_size(); ++i_d)
                {
                        ::waflz_pb::directive_t* l_d = m_pb->mutable_directive(i_d);
                        // ---------------------------------
                        // include
                        // ---------------------------------
                        if(l_d->has_include())
                        {
                                std::string l_inc;
                                l_inc.append(m_ruleset_dir);
                                l_inc.append(l_d->include());
                                l_d->set_include(l_inc);
                        }
                }
        }
        // -------------------------------------------------
        // compile
        // -------------------------------------------------
        l_s = compile();
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        m_is_initd = true;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t waf::init(void* a_js,
                  bool a_apply_defaults,
                  bool a_custom_rules)
{
        // Check if already is initd
        if(m_is_initd)
        {
                return WAFLZ_STATUS_OK;
        }
        if(m_pb)
        {
                delete m_pb;
                m_pb = NULL;
        }
        // -------------------------------------------------
        // set defaults for missing values...
        // -------------------------------------------------
        int32_t l_s;
        waflz_pb::sec_config_t *l_pb = NULL;
        if(a_apply_defaults)
        {
                m_pb = new waflz_pb::sec_config_t();
                l_s = set_defaults(a_custom_rules);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "set_defaults failed");
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // parse
        // -------------------------------------------------
        config_parser *l_parser = new config_parser();
        l_pb = new waflz_pb::sec_config_t();
        l_s = l_parser->parse_config(*l_pb, a_js);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "parse error %.*s", WAFLZ_ERR_REASON_LEN, l_parser->get_err_msg());
                if(l_parser) { delete l_parser; l_parser = NULL;}
                if(l_pb) { delete l_pb; l_pb = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        if(m_pb)
        {
                m_pb->MergeFrom(*l_pb);
                delete l_pb;
                l_pb = NULL;
        }
        else
        {
                m_pb = l_pb;
        }
        // TODO remove -debug...
        //l_parser->show_status();
        if(l_parser) { delete l_parser; l_parser = NULL;}
        // -------------------------------------------------
        // ruleset info
        // -------------------------------------------------
        if(!m_pb->has_ruleset_id())
        {
                 m_pb->set_ruleset_id("__na__");
        }
        if(!m_pb->has_ruleset_version())
        {
                m_pb->set_ruleset_version("__na__");
        }
        m_ruleset_dir = m_engine.get_ruleset_dir();
        m_ruleset_dir.append(m_pb->ruleset_id());
        m_ruleset_dir.append("/version/");
        m_ruleset_dir.append(m_pb->ruleset_version());
        m_ruleset_dir.append("/policy/");
        // -------------------------------------------------
        // set id
        // -------------------------------------------------
        m_id = m_pb->id();
        m_cust_id = m_pb->customer_id();
        m_name = m_pb->name();
        if (m_pb->has_team_config())
        {
                m_team_config = m_pb->team_config();
        }
        // -------------------------------------------------
        // update includes to full path
        // -------------------------------------------------
        for(int i_d = 0; i_d < m_pb->directive_size(); ++i_d)
        {
                ::waflz_pb::directive_t* l_d = m_pb->mutable_directive(i_d);
                // -----------------------------------------
                // include
                // -----------------------------------------
                if(l_d->has_include())
                {
                        std::string l_inc;
                        l_inc.append(m_ruleset_dir);
                        l_inc.append(l_d->include());
                        l_d->set_include(l_inc);
                }

        }
        // -------------------------------------------------
        // compile
        // -------------------------------------------------
        l_s = compile();
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "compilation failed");
                return WAFLZ_STATUS_ERROR;
        }
        m_is_initd = true;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void set_var_tx(waflz_pb::sec_config_t &ao_conf_pb,
                const char *a_id,
                const char *a_var,
                const std::string a_val)
{
        ::waflz_pb::sec_action_t* l_a = NULL;
        l_a = ao_conf_pb.add_directive()->mutable_sec_action();
        l_a->set_id(a_id);
        l_a->set_phase(1);
        l_a->add_t(waflz_pb::sec_action_t_transformation_type_t_NONE);
        l_a->set_nolog(true);
        l_a->set_action_type(waflz_pb::sec_action_t_action_type_t_PASS);
        ::waflz_pb::sec_action_t_setvar_t* l_sv = NULL;
        l_sv = l_a->add_setvar();
        l_sv->set_scope(waflz_pb::sec_action_t_setvar_t_scope_t_TX);
        l_sv->set_var(a_var);
        l_sv->set_val(a_val);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void set_resp_var_tx(waflz_pb::sec_config_t &ao_conf_pb,
                const char *a_id,
                const char *a_var,
                const std::string a_val)
{
        ::waflz_pb::sec_action_t* l_a = NULL;
        l_a = ao_conf_pb.add_directive()->mutable_sec_action();
        l_a->set_id(a_id);
        l_a->set_phase(3);
        l_a->add_t(waflz_pb::sec_action_t_transformation_type_t_NONE);
        l_a->set_nolog(true);
        l_a->set_action_type(waflz_pb::sec_action_t_action_type_t_PASS);
        ::waflz_pb::sec_action_t_setvar_t* l_sv = NULL;
        l_sv = l_a->add_setvar();
        l_sv->set_scope(waflz_pb::sec_action_t_setvar_t_scope_t_TX);
        l_sv->set_var(a_var);
        l_sv->set_val(a_val);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t waf::set_defaults(bool a_custom_rules)
{
        ::waflz_pb::sec_config_t& l_conf_pb = *m_pb;
        // -------------------------------------------------
        // paranoia config
        // -------------------------------------------------
        set_var_tx(l_conf_pb, "900000", "paranoia_level", "1");
        set_var_tx(l_conf_pb, "900101", "blocking_paranoia_level", "1");
        // -------------------------------------------------
        // anomaly settings
        // -------------------------------------------------
        set_var_tx(l_conf_pb, "900001", "critical_anomaly_score", "5");
        set_var_tx(l_conf_pb, "900002", "error_anomaly_score", "4");
        set_var_tx(l_conf_pb, "900003", "warning_anomaly_score", "3");
        set_var_tx(l_conf_pb, "900004", "notice_anomaly_score", "2");
        set_var_tx(l_conf_pb, "900005", "anomaly_score", "0");
        if(a_custom_rules)
        {
                set_var_tx(l_conf_pb, "900010", "inbound_anomaly_score_threshold", "0");
        }
        else
        {
                set_var_tx(l_conf_pb, "900010", "inbound_anomaly_score_threshold", "1");
        }
        set_var_tx(l_conf_pb, "900006", "sql_injection_score", "0");
        set_var_tx(l_conf_pb, "900007", "xss_score", "0");
        set_var_tx(l_conf_pb, "900008", "inbound_anomaly_score", "0");
        set_var_tx(l_conf_pb, "900012", "inbound_anomaly_score_level", "1");
        set_var_tx(l_conf_pb, "900014", "anomaly_score_blocking", "on");
        // -------------------------------------------------
        // general settings
        // -------------------------------------------------
        set_var_tx(l_conf_pb, "900015", "max_num_args", "512");
        set_var_tx(l_conf_pb, "900016", "arg_name_length", "1024");
        set_var_tx(l_conf_pb, "900017", "arg_length", "8000");
        set_var_tx(l_conf_pb, "900018", "total_arg_length", "64000");
        set_var_tx(l_conf_pb, "900020", "combined_file_sizes", "6291456");
        // -------------------------------------------------
        // outbound anomaly settings
        // -------------------------------------------------
        set_resp_var_tx(l_conf_pb, "900050", "outbound_anomaly_score_threshold", "1");
        set_resp_var_tx(l_conf_pb, "900051", "outbound_anomaly_score", "0");
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: adds the rule ids in rule_id_list to the custom score map
//! \return:  
//! \param:   a_custom_score: a custom_score_t object
//! ----------------------------------------------------------------------------
void waf::process_multi_custom_score_entry(
        waflz_pb::profile_custom_score_t& a_custom_score)
{
        // -------------------------------------------------
        // exit early if no rules
        // -------------------------------------------------
        if (a_custom_score.rule_id_list_size() == 0) return;
        // -------------------------------------------------
        // add every rule_id to the custom score map
        // -------------------------------------------------
        auto l_rule_list = a_custom_score.rule_id_list();
        uint32_t l_score = a_custom_score.score();
        for ( auto i_rule_id = l_rule_list.begin();
              i_rule_id != l_rule_list.end(); 
              i_rule_id++ )
        {
                m_custom_score_map[*i_rule_id] = l_score;
        }
}
//! ----------------------------------------------------------------------------
//! \details: Intialize waf object for profile
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t waf::init(profile &a_profile)
{
        if(!a_profile.get_pb())
        {
                return WAFLZ_STATUS_ERROR;
        }
        const ::waflz_pb::profile& l_prof_pb = *(a_profile.get_pb());
        if(m_pb)
        {
                delete m_pb;
                m_pb = NULL;
        }
        m_pb = new waflz_pb::sec_config_t();
        ::waflz_pb::sec_config_t& l_conf_pb = *m_pb;
        // -------------------------------------------------
        // general settings
        // -------------------------------------------------
        const ::waflz_pb::profile_general_settings_t& l_gs = l_prof_pb.general_settings();
        // -------------------------------------------------
        // error action...
        // -------------------------------------------------
        {
        ::waflz_pb::sec_rule_t* l_r = NULL;
        ::waflz_pb::variable_t* l_v = NULL;
        ::waflz_pb::variable_t_match_t* l_m = NULL;
        ::waflz_pb::sec_rule_t_operator_t* l_o = NULL;
        ::waflz_pb::sec_action_t* l_a = NULL;
        l_r = l_conf_pb.add_directive()->mutable_sec_rule();
        l_v = l_r->add_variable();
        l_v->set_type(::waflz_pb::variable_t_type_t_TX);
        l_m = l_v->add_match();
        l_m->set_is_regex(true);
        l_m->set_value("^MSC_");
        l_o = l_r->mutable_operator_();
        l_o->set_type(::waflz_pb::sec_rule_t_operator_t_type_t_STREQ);
        l_o->set_is_negated(true);
        l_o->set_value("0");
        l_a = l_r->mutable_action();
        l_a->set_id("200004");
        l_a->set_phase(2);
        l_a->add_t(waflz_pb::sec_action_t_transformation_type_t_NONE);
        l_a->set_action_type(waflz_pb::sec_action_t_action_type_t_DENY);
        l_a->set_msg("ModSecurity internal error flagged: %{MATCHED_VAR_NAME}");
        }
        // -------------------------------------------------
        // paranoia config
        // -------------------------------------------------
        uint32_t l_paranoia_level = 1;
        if(l_gs.has_paranoia_level() &&
           (l_gs.paranoia_level() > 0))
        {
                l_paranoia_level = l_gs.paranoia_level();
        }
        // -------------------------------------------------
        // crs < 4
        // -------------------------------------------------
        set_var_tx(l_conf_pb, "900000", "paranoia_level", to_string(l_paranoia_level));
        set_var_tx(l_conf_pb, "900100", "executing_paranoia_level", to_string(l_paranoia_level));
        // -------------------------------------------------
        // crs > 4
        // -------------------------------------------------
        set_var_tx(l_conf_pb, "900101", "detection_paranoia_level", to_string(l_paranoia_level));
        // -------------------------------------------------
        // anomaly settings
        // -------------------------------------------------
        set_var_tx(l_conf_pb, "900001", "critical_anomaly_score", "5");
        set_var_tx(l_conf_pb, "900002", "error_anomaly_score", "4");
        set_var_tx(l_conf_pb, "900003", "warning_anomaly_score", "3");
        set_var_tx(l_conf_pb, "900004", "notice_anomaly_score", "2");
        set_var_tx(l_conf_pb, "900005", "anomaly_score", "0");
        set_var_tx(l_conf_pb, "900006", "sql_injection_score", "0");
        set_var_tx(l_conf_pb, "900007", "xss_score", "0");
        set_var_tx(l_conf_pb, "900008", "inbound_anomaly_score", "0");
        // -------------------------------------------------
        // Default anomaly threshold
        // -------------------------------------------------
        std::string l_anomaly_threshold = "5";
        // Use top level threshold setting
        l_anomaly_threshold = to_string(l_gs.anomaly_threshold());
        set_var_tx(l_conf_pb, "900010", "inbound_anomaly_score_threshold", l_anomaly_threshold);
        // -------------------------------------------------
        // response var settings
        // Outbound anomaly settings. Use inbound value
        // in case outbound is missing
        // -------------------------------------------------
        std::string l_outbound_anomaly_threshold = l_anomaly_threshold;
        if (l_gs.has_outbound_anomaly_threshold())
        {
                l_outbound_anomaly_threshold = to_string(l_gs.outbound_anomaly_threshold());
        }
        uint32_t l_outbound_paranoia_level = l_paranoia_level;
        if (l_gs.has_outbound_paranoia_level() &&
            (l_gs.outbound_paranoia_level() > 0))
        {
                l_outbound_paranoia_level = l_gs.outbound_paranoia_level();
        }
        set_resp_var_tx(l_conf_pb, "900200", "paranoia_level", to_string(l_outbound_paranoia_level));
        set_resp_var_tx(l_conf_pb, "900201", "executing_paranoia_level", to_string(l_outbound_paranoia_level));
        set_resp_var_tx(l_conf_pb, "900202", "detection_paranoia_level", to_string(l_outbound_paranoia_level));
        set_resp_var_tx(l_conf_pb, "900050", "outbound_anomaly_score_threshold", l_outbound_anomaly_threshold);
        set_resp_var_tx(l_conf_pb, "900051", "outbound_anomaly_score", "0");
        set_resp_var_tx(l_conf_pb, "900052", "critical_anomaly_score", "5");
        set_resp_var_tx(l_conf_pb, "900053", "error_anomaly_score", "4");
        set_resp_var_tx(l_conf_pb, "900054", "warning_anomaly_score", "3");
        set_resp_var_tx(l_conf_pb, "900055", "sql_injection_score", "0");
        set_resp_var_tx(l_conf_pb, "900056", "xss_score", "0");
        set_resp_var_tx(l_conf_pb, "900057", "notice_anomaly_score", "2");
        // -------------------------------------------------
        // general settings
        // -------------------------------------------------
        set_var_tx(l_conf_pb, "900015", "max_num_args", to_string(l_gs.max_num_args()));
        set_var_tx(l_conf_pb, "900016", "arg_name_length", to_string(l_gs.arg_name_length()));
        set_var_tx(l_conf_pb, "900017", "arg_length", to_string(l_gs.arg_length()));
        set_var_tx(l_conf_pb, "900018", "total_arg_length", to_string(l_gs.total_arg_length()));
        // -------------------------------------------------
        // validate utf8 encoding please
        // -------------------------------------------------
        if(l_gs.validate_utf8_encoding())
        {
                set_var_tx(l_conf_pb, "900026", "crs_validate_utf8_encoding", to_string(1));
        }
        // -------------------------------------------------
        // ???
        // -------------------------------------------------
        {
        ::waflz_pb::sec_rule_t* l_r = NULL;
        ::waflz_pb::variable_t* l_v = NULL;
        ::waflz_pb::variable_t_match_t* l_m = NULL;
        ::waflz_pb::sec_rule_t_operator_t* l_o = NULL;
        ::waflz_pb::sec_action_t* l_a = NULL;
        ::waflz_pb::sec_action_t_setvar_t* l_sv = NULL;
        l_r = l_conf_pb.add_directive()->mutable_sec_rule();
        l_v = l_r->add_variable();
        l_v->set_type(::waflz_pb::variable_t_type_t_REQUEST_HEADERS);
        l_m = l_v->add_match();
        l_m->set_value("User-Agent");
        l_o = l_r->mutable_operator_();
        l_o->set_type(::waflz_pb::sec_rule_t_operator_t_type_t_RX);
        l_o->set_is_regex(true);
        l_o->set_value("^(.*)$");
        l_a = l_r->mutable_action();
        l_a->set_id("900027");
        l_a->set_phase(1);
        l_a->add_t(waflz_pb::sec_action_t_transformation_type_t_NONE);
        l_a->add_t(waflz_pb::sec_action_t_transformation_type_t_SHA1);
        l_a->add_t(waflz_pb::sec_action_t_transformation_type_t_HEXENCODE);
        l_a->set_action_type(waflz_pb::sec_action_t_action_type_t_PASS);
        l_a->set_msg("__na__");
        l_sv = l_a->add_setvar();
        l_sv->set_scope(waflz_pb::sec_action_t_setvar_t_scope_t_TX);
        l_sv->set_var("ua_hash");
        l_sv->set_val("%{matched_var}");
        }
        // -------------------------------------------------
        // ???
        // -------------------------------------------------
        {
        ::waflz_pb::sec_rule_t* l_r = NULL;
        ::waflz_pb::variable_t* l_v = NULL;
        ::waflz_pb::sec_rule_t_operator_t* l_o = NULL;
        ::waflz_pb::sec_action_t* l_a = NULL;
        ::waflz_pb::sec_action_t_setvar_t* l_sv = NULL;
        l_r = l_conf_pb.add_directive()->mutable_sec_rule();
        l_v = l_r->add_variable();
        l_v->set_type(::waflz_pb::variable_t_type_t_REMOTE_ADDR);
        l_o = l_r->mutable_operator_();
        l_o->set_type(::waflz_pb::sec_rule_t_operator_t_type_t_RX);
        l_o->set_is_regex(true);
        l_o->set_value("^(.*)$");
        l_a = l_r->mutable_action();
        l_a->set_id("900028");
        l_a->set_phase(1);
        l_a->set_capture(true);
        l_a->add_t(waflz_pb::sec_action_t_transformation_type_t_NONE);
        l_a->set_action_type(waflz_pb::sec_action_t_action_type_t_PASS);
        l_a->set_msg("__na__");
        l_sv = l_a->add_setvar();
        l_sv->set_scope(waflz_pb::sec_action_t_setvar_t_scope_t_TX);
        l_sv->set_var("real_ip");
        l_sv->set_val("%{tx.1}");
        }
        // -------------------------------------------------
        // ???
        // -------------------------------------------------
        {
        ::waflz_pb::sec_rule_t* l_r = NULL;
        ::waflz_pb::variable_t* l_v = NULL;
        ::waflz_pb::variable_t_match_t* l_m = NULL;
        ::waflz_pb::sec_rule_t_operator_t* l_o = NULL;
        ::waflz_pb::sec_action_t* l_a = NULL;
        l_r = l_conf_pb.add_directive()->mutable_sec_rule();
        l_v = l_r->add_variable();
        l_v->set_is_count(true);
        l_v->set_type(::waflz_pb::variable_t_type_t_TX);
        l_m = l_v->add_match();
        l_m->set_value("REAL_IP");
        l_o = l_r->mutable_operator_();
        l_o->set_type(::waflz_pb::sec_rule_t_operator_t_type_t_EQ);
        l_o->set_value("0");
        l_a = l_r->mutable_action();
        l_a->set_id("900029");
        l_a->set_phase(1);
        l_a->add_t(waflz_pb::sec_action_t_transformation_type_t_NONE);
        l_a->set_action_type(waflz_pb::sec_action_t_action_type_t_PASS);
        l_a->set_msg("__na__");
        }
        // -------------------------------------------------
        // ???
        // -------------------------------------------------
        {
        ::waflz_pb::sec_rule_t* l_r = NULL;
        ::waflz_pb::variable_t* l_v = NULL;
        ::waflz_pb::variable_t_match_t* l_m = NULL;
        ::waflz_pb::sec_rule_t_operator_t* l_o = NULL;
        ::waflz_pb::sec_action_t* l_a = NULL;
        ::waflz_pb::sec_action_t_setvar_t* l_sv = NULL;
        l_r = l_conf_pb.add_directive()->mutable_sec_rule();
        l_v = l_r->add_variable();
        l_v->set_is_count(true);
        l_v->set_type(::waflz_pb::variable_t_type_t_TX);
        l_m = l_v->add_match();
        l_m->set_value("REAL_IP");
        l_o = l_r->mutable_operator_();
        l_o->set_type(::waflz_pb::sec_rule_t_operator_t_type_t_EQ);
        l_o->set_value("0");
        l_a = l_r->mutable_action();
        l_a->set_id("900030");
        l_a->set_phase(1);
        l_a->add_t(waflz_pb::sec_action_t_transformation_type_t_NONE);
        l_a->set_action_type(waflz_pb::sec_action_t_action_type_t_PASS);
        l_a->set_msg("__na__");
        l_sv = l_a->add_setvar();
        l_sv->set_scope(waflz_pb::sec_action_t_setvar_t_scope_t_TX);
        l_sv->set_var("real_ip");
        l_sv->set_val("%{remote_addr}");
        }
        // -------------------------------------------------
        // conf file functor
        // -------------------------------------------------
        // look at list of config files and strip
        // disabled ones
        // -------------------------------------------------
        class is_conf_file
        {
        public:
                static int compare(const struct dirent* a_dirent)
                {
                        //TRACE("Looking at file: '%s'", a_dirent->d_name);
                        switch (a_dirent->d_name[0])
                        {
                        case 'a' ... 'z':
                        case 'A' ... 'Z':
                        case '0' ... '9':
                        case '_':
                        {
                                // valid path name to consider
                                const char* l_found = NULL;
                                // look for the .conf suffix
                                l_found = ::strcasestr(a_dirent->d_name, ".conf");
                                if(l_found == NULL)
                                {
                                        // not a .conf file
                                        //NDBG_PRINT("Failed to find .conf or .conf.json suffix\n");
                                        goto done;
                                }
                                if(::strlen(l_found) != 5 &&
                                   ::strlen(l_found) != 10)
                                {
                                        // failed to find .conf right at the end
                                        //NDBG_PRINT("found in the wrong place. %zu\n", ::strlen(l_found));
                                        goto done;
                                }
                                // we want this file
                                return 1;
                                break;
                        }
                        default:
                                //TRACE("Found invalid first char: '%c'", a_dirent->d_name[0]);
                                goto done;
                        }
done:
                        return 0;
                }
        };
        // -------------------------------------------------
        // construct ruleset dir
        // -------------------------------------------------
        l_conf_pb.set_ruleset_id(l_prof_pb.ruleset_id());
        l_conf_pb.set_ruleset_version(l_prof_pb.ruleset_version());
        {
        struct dirent** l_conf_list = NULL;
        m_ruleset_dir = m_engine.get_ruleset_dir();
        m_ruleset_dir.append(l_prof_pb.ruleset_id());
        m_ruleset_dir.append("/version/");
        m_ruleset_dir.append(l_prof_pb.ruleset_version());
        m_ruleset_dir.append("/policy/");
        // -------------------------------------------------
        // scan ruleset dir
        // -------------------------------------------------
        int l_num_files = -1;
        l_num_files = ::scandir(m_ruleset_dir.c_str(),
                                &l_conf_list,
                                is_conf_file::compare,
                                alphasort);
        if(l_num_files == -1)
        {
                // failed to build the list of directory entries
                WAFLZ_PERROR(m_err_msg, "Failed to compile modsecurity json instance-profile settings.  Reason: failed to scan profile directory: %s: %s", m_ruleset_dir.c_str(), (errno == 0 ? "unknown" : strerror(errno)));
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // include policies
        // -------------------------------------------------
        typedef std::set<std::string> policy_t;
        if(l_prof_pb.policies_size())
        {
                policy_t l_enable_policies;
                for(int32_t i_p = 0; i_p < l_prof_pb.policies_size(); ++i_p)
                {
                        l_enable_policies.insert(l_prof_pb.policies(i_p));
                }
                for(int32_t i_f = 0; i_f < l_num_files; ++i_f)
                {
                        if(l_enable_policies.find(l_conf_list[i_f]->d_name) != l_enable_policies.end())
                        {
                                std::string &l_inc = *(l_conf_pb.add_directive()->mutable_include());
                                l_inc.append(m_ruleset_dir);
                                l_inc.append(l_conf_list[i_f]->d_name);
                        }
                }
        }
        if(l_conf_list)
        {
                for(int32_t i_f = 0; i_f < l_num_files; ++i_f)
                {
                        if(l_conf_list[i_f])
                        {
                                free(l_conf_list[i_f]);
                                l_conf_list[i_f] = NULL;
                        }
                }
                free(l_conf_list);
                l_conf_list = NULL;
        }
        }
        // -------------------------------------------------
        // disable rules
        // -------------------------------------------------
        // disable the rules with the given ids
        // -------------------------------------------------
        for(int32_t i_r = 0; i_r < l_prof_pb.disabled_rules_size(); ++i_r)
        {
                if(!l_prof_pb.disabled_rules(i_r).has_rule_id() ||
                   l_prof_pb.disabled_rules(i_r).rule_id().empty())
                {
                        continue;
                }
                l_conf_pb.add_rule_remove_by_id(l_prof_pb.disabled_rules(i_r).rule_id());
        }
        // -------------------------------------------------
        // custom score loads
        // -------------------------------------------------
        for ( int32_t i_r = 0;
              i_r < l_prof_pb.custom_scores_size();
              ++i_r)
        {
                // -----------------------------------------
                // custom score object
                // -----------------------------------------
                waflz_pb::profile_custom_score_t l_custom_score = \
                        l_prof_pb.custom_scores(i_r);
                // -----------------------------------------
                // skip if missing score
                // -----------------------------------------
                bool l_missing_score = !l_custom_score.has_score();
                if (l_missing_score) { continue; }
                // -----------------------------------------
                // skip if missing rule id and rule_id_list
                // -----------------------------------------
                bool l_missing_rule = !l_custom_score.has_rule_id();
                bool l_missing_rule_list = l_custom_score.rule_id_list_size() == 0;
                if (l_missing_rule && l_missing_rule_list) 
                {
                        continue; 
                }
                // -----------------------------------------
                // process rule_id_list if present
                // -----------------------------------------
                if (!l_missing_rule_list)
                {
                        this->process_multi_custom_score_entry(l_custom_score);
                        continue;
                }
                // -----------------------------------------
                // otherwise we process a single rule_id
                // -----------------------------------------
                std::string l_rule_id = l_custom_score.rule_id();
                // -----------------------------------------
                // skip if rule_id is empty
                // -----------------------------------------
                bool l_missing_rule_id = l_rule_id.empty();
                if ( l_missing_rule_id ) { continue; }
                // -----------------------------------------
                // add custom score to map
                // -----------------------------------------
                m_custom_score_map[l_rule_id] = l_custom_score.score();
        }
        // -------------------------------------------------
        // rule target updates
        // -------------------------------------------------
        // update the targets for a given rule
        // "rule_target_updates": [
        //     {
        //         "rule_id": "981172",
        //         "target": "ARGS",
        //         "target_match": "email",
        //         "is_regex": false,
        //         "is_negated": true,
        //         "replace_target": ""
        //     }
        // ]
        // -------------------------------------------------
        for(int32_t i_rtu = 0; i_rtu < l_prof_pb.rule_target_updates_size(); ++i_rtu)
        {
                const ::waflz_pb::profile_rule_target_update_t& l_rtu = l_prof_pb.rule_target_updates(i_rtu);
                if(
                   (!l_rtu.has_rule_id() && l_rtu.rule_id_list_size() == 0) ||
                   !l_rtu.has_target())
                {
                       continue;
                }
                // -----------------------------------------
                // make an update target for this rtu
                // -----------------------------------------
                ::waflz_pb::update_target_t& l_ut = *(l_conf_pb.add_update_target_by_id());
                // -----------------------------------------
                // if there is a list of ids, set the list
                // -----------------------------------------
                if (l_rtu.rule_id_list_size() >= 1)
                {
                        for (int i_rule_id_index = 0;
                             i_rule_id_index < l_rtu.rule_id_list_size();
                             i_rule_id_index++)
                        {
                                l_ut.add_id_list(l_rtu.rule_id_list(i_rule_id_index));                       
                        }
                }
                // -----------------------------------------
                // otherwise, set id
                // -----------------------------------------
                else
                {
                        l_ut.set_id(l_rtu.rule_id());                       
                }
                // -----------------------------------------
                // set replace_target
                // -----------------------------------------
                if(l_rtu.has_replace_target())
                {
                        l_ut.set_replace(l_rtu.replace_target());
                }
                // -----------------------------------------
                // add match...
                // -----------------------------------------
                ::waflz_pb::variable_t& l_var = *(l_ut.add_variable());
                if(l_rtu.has_target_match())
                {
                        ::waflz_pb::variable_t_match_t& l_match = *(l_var.add_match());
                        l_match.set_value(l_rtu.target_match());
                        // set is_negated by default
                        l_match.set_is_negated(true);
                        if(l_rtu.is_regex())
                        {
                                l_match.set_is_regex(true);
                        }
                }
                // -----------------------------------------
                // str to type reflection...
                // -----------------------------------------
                const google::protobuf::Descriptor* l_des = l_var.GetDescriptor();
                const google::protobuf::Reflection* l_ref = l_var.GetReflection();
                const google::protobuf::FieldDescriptor* l_f = l_des->FindFieldByName("type");
                if(l_f == NULL)
                {
                        WAFLZ_PERROR(m_err_msg, "can't find field by type");
                        return WAFLZ_STATUS_ERROR;
                }
                const google::protobuf::EnumValueDescriptor* l_desc =
                                waflz_pb::variable_t_type_t_descriptor()->FindValueByName(l_rtu.target());
                if(l_desc == NULL)
                {
                        WAFLZ_PERROR(m_err_msg, "invalid rule target update target type spec: %s", l_rtu.target().c_str());
                        return WAFLZ_STATUS_ERROR;
                }
                l_ref->SetEnum(&l_var, l_f, l_desc);
                //NDBG_PRINT("rtu: %s\n", l_ut.ShortDebugString().c_str());
        }
        // -------------------------------------------------
        // redacted variables
        // -------------------------------------------------
        for(int32_t i_rv = 0; i_rv < l_prof_pb.redacted_variables_size(); ++i_rv)
        {
                // -----------------------------------------
                // status var
                // -----------------------------------------
                int32_t l_s;
                // -----------------------------------------
                // get single redacted var
                // -----------------------------------------
                const waflz_pb::profile_redacted_var_t& l_rv =  l_prof_pb.redacted_variables(i_rv);
                // -----------------------------------------
                // pluck members out for ease of use
                // -----------------------------------------
                const std::string& l_match_on = l_rv.match_on();
                const std::string& l_val_replacement = l_rv.replacement_value();
                const std::string& l_name_replacement = l_rv.replacement_name();
                // -----------------------------------------
                // compile regex from variables
                // -----------------------------------------
                regex* l_pcre = new regex();
                l_s = l_pcre->init(l_match_on.c_str(), l_match_on.length());
                // -----------------------------------------
                // error out if bad regex
                // -----------------------------------------
                if (l_s != WAFLZ_STATUS_OK)
                {
                        const char* l_err_ptr;
                        int l_err_off;
                        l_pcre->get_err_info(&l_err_ptr, l_err_off);
                        WAFLZ_PERROR(m_err_msg, "Failed to init re from %s. Reason: %s -offset: %d",
                                l_match_on.c_str(),
                                l_err_ptr,
                                l_err_off);
                        if (l_pcre) { delete l_pcre; l_pcre = NULL; }
                        this->clear_redacted_variables_list();
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // save regex for later
                // -----------------------------------------
                m_redacted_vars.push_back(std::make_tuple(l_pcre,
                                                          l_val_replacement,
                                                          l_name_replacement));
        }
        // -------------------------------------------------
        // compile
        // -------------------------------------------------
        int32_t l_s;
        l_s = compile();
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        m_is_initd = true;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t waf::verify_bot_actions_for_directive_list(action_map_t a_actions,
                                                   directive_list_t a_directive_list)
{
        // -------------------------------------------------
        // enforcement_type_t descriptor to get names
        // -------------------------------------------------
        auto *l_enf_desc = waflz_pb::enforcement_type_t_descriptor();
        // -------------------------------------------------
        // run through the directive list
        // -------------------------------------------------
        for (auto i_t = a_directive_list.begin();
             i_t != a_directive_list.end();
             i_t++)
        {
                // -----------------------------------------
                // skip if directive is missing rule
                // -----------------------------------------
                if ( !(*i_t)->has_sec_rule() ) { continue; }
                // -----------------------------------------
                // get the rule - skip if no action
                // -----------------------------------------
                const waflz_pb::sec_rule_t l_rule = (*i_t)->sec_rule();
                if ( !l_rule.has_action() ) { continue; }
                // -----------------------------------------
                // get the action - skip if no bot_action
                // -----------------------------------------
                const waflz_pb::sec_action_t l_action = l_rule.action();
                if ( !l_action.has_bot_action() ) { continue; }
                // -----------------------------------------
                // get the bot_action - skip if no bot action
                // -----------------------------------------
                const waflz_pb::enforcement_type_t l_bot_action = l_action.bot_action();
                // -----------------------------------------
                // convert enforcement_type_t to name
                // -----------------------------------------
                const std::string l_entry_name = l_enf_desc->FindValueByNumber(l_bot_action)->name();
                // -----------------------------------------
                // return error if the bot_action is not found
                // -----------------------------------------
                if ( a_actions.find(l_entry_name) == a_actions.end() )
                {
                        WAFLZ_PERROR(m_err_msg, "found unknown bot_action '%s' in rule '%s'\n",
                                     l_entry_name.c_str(),
                                     l_rule.name().c_str());
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // all rules good
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}

//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t waf::verify_bot_actions(action_map_t a_actions)
{
        // -------------------------------------------------
        // status of verification
        // -------------------------------------------------
        int32_t l_s = WAFLZ_STATUS_OK;
        // -------------------------------------------------
        // check phase 1 rules, return if not valid
        // -------------------------------------------------
        directive_list_t l_directive_list = m_compiled_config->m_directive_list_phase_1;
        l_s = verify_bot_actions_for_directive_list(a_actions, l_directive_list);
        if ( l_s != WAFLZ_STATUS_OK ) { return l_s; }
        // -------------------------------------------------
        // check phase 2 rules, return if not valid
        // -------------------------------------------------
        l_directive_list = m_compiled_config->m_directive_list_phase_2;
        l_s = verify_bot_actions_for_directive_list(a_actions, l_directive_list);
        if ( l_s != WAFLZ_STATUS_OK ) { return l_s; }
        // -------------------------------------------------
        // all rules good
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}

//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t waf::process_rule(waflz_pb::event **ao_event,
                          const waflz_pb::sec_rule_t &a_rule,
                          rqst_ctx &a_ctx)
{
        // -------------------------------------------------
        // top level rule id
        // -------------------------------------------------
        const std::string l_rule_id = a_rule.action().id();
        // -------------------------------------------------
        // chain rule loop
        // -------------------------------------------------
        const waflz_pb::sec_rule_t *l_rule = NULL;
        int32_t l_cr_idx = -1;
        bool i_match = false;
        do {
                //NDBG_PRINT("RULE[%4d]************************************\n", l_cr_idx);
                //NDBG_PRINT("l_cr_idx: %d\n", l_cr_idx);
                // -------------------------------------------------
                // construct id for rtu variables
                // -------------------------------------------------
                std::string l_var_key = l_rule_id + "_" + std::to_string(l_cr_idx + 1);
                uint32_t l_rule_depth = l_cr_idx + 1;
                // -------------------------------------------------
                // get current rule (could be chain)
                // -------------------------------------------------
                if (l_cr_idx == -1)
                {
                        l_rule = &a_rule;
                }
                else if ((l_cr_idx >= 0) &&
                         (l_cr_idx < a_rule.chained_rule_size()))
                {
                        l_rule = &(a_rule.chained_rule(l_cr_idx));
                }
                else
                {
                        WAFLZ_PERROR(m_err_msg, "bad chained rule: %.*s",
                                     WAFLZ_ERR_REASON_LEN,
                                     a_rule.DebugString().c_str());
                        return WAFLZ_STATUS_ERROR;
                }
                // -------------------------------------------------
                // if no action, go to next rule (chain rule)
                // -------------------------------------------------
                if (!l_rule->has_action())
                {
                        // TODO is OK???
                        ++l_cr_idx;
                        continue;
                }
                // -------------------------------------------------
                // if no operator, go to next rule (chain rule)
                // -------------------------------------------------
                if (!l_rule->has_operator_())
                {
                        // TODO this aight???
                        // TODO is OK???
                        ++l_cr_idx;
                        continue;
                }
                // -------------------------------------------------
                // check if the rule matches
                // -------------------------------------------------
                int32_t l_s;
                i_match = false;
                rule_information_t l_rule_information;
                l_rule_information.m_parent_rule_id = l_rule_id;
                l_rule_information.m_depth = l_rule_depth;
                l_s = process_rule_part(
                    ao_event, i_match, *l_rule, a_ctx, l_rule_information);
                // -------------------------------------------------
                // if failed to process rule - return error
                // -------------------------------------------------
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "bad chained rule idx: %d -id: %s",
                                     l_cr_idx,
                                     a_rule.action().id().c_str());
                        return WAFLZ_STATUS_ERROR;
                }
                // -------------------------------------------------
                // if no match - bail and dont check chained rules
                // -------------------------------------------------
                if (!i_match) { return WAFLZ_STATUS_OK; }
                // -------------------------------------------------
                // next rule in chain
                // -------------------------------------------------
                ++l_cr_idx;
        } while(l_cr_idx < a_rule.chained_rule_size());
        // -------------------------------------------------
        // never matched...
        // -------------------------------------------------
        if (!i_match)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // matched...
        // -------------------------------------------------
        if (!a_rule.has_action())
        {
                return WAFLZ_STATUS_OK;
        }

        // -------------------------------------------------
        // process match
        // -------------------------------------------------
        int32_t l_s;
        l_s = process_match(ao_event, a_rule, a_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                NDBG_PRINT("error processing rule\n");
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t waf::process_rule_part(waflz_pb::event **ao_event,
                               bool &ao_match,
                               const waflz_pb::sec_rule_t &a_rule,
                               rqst_ctx &a_ctx,
                               const rule_information_t a_rule_information)
{
        macro *l_macro =  &(m_engine.get_macro());
        ao_match = false;
        const waflz_pb::sec_action_t& l_a = a_rule.action();
        const std::string l_rule_id = l_a.id();
        bool l_multimatch = l_a.multimatch();
        // -------------------------------------------------
        // get operator
        // -------------------------------------------------
        if (!a_rule.has_operator_() ||
            !a_rule.operator_().has_type())
        {
                // TODO log error -shouldn't happen???
                return WAFLZ_STATUS_OK;
        }
        const ::waflz_pb::sec_rule_t_operator_t& l_op = a_rule.operator_();
        op_t l_op_cb = NULL;
        l_op_cb = get_op_cb(l_op.type());
        // -------------------------------------------------
        // check if rtu variables exist
        // -------------------------------------------------
        std::string l_rtu_key = a_rule_information.m_parent_rule_id + "_" + to_string(a_rule_information.m_depth);
        auto l_rtu_map_iterator = m_rtu_variable_map.find(l_rtu_key);
        bool l_rtu_variables_exist = l_rtu_map_iterator != m_rtu_variable_map.end();
        std::vector<waflz_pb::variable_t> l_rtu_variables;
        if (l_rtu_variables_exist) { l_rtu_variables = l_rtu_map_iterator->second; }
        // -------------------------------------------------
        // variable loop
        // -------------------------------------------------
        uint32_t l_var_count = 0;
        for(int32_t i_var = 0; i_var < a_rule.variable_size(); ++i_var)
        {
                // -----------------------------------------
                // get current variable
                // -----------------------------------------
                const waflz_pb::variable_t& l_var = (l_rtu_variables_exist) ? l_rtu_variables[i_var] : a_rule.variable(i_var);
                // -----------------------------------------
                // if no type - no way to process - return
                // -----------------------------------------
                if (!l_var.has_type())
                {
                        return WAFLZ_STATUS_OK;
                }
                get_var_t l_get_var = NULL;
                l_get_var = get_var_cb(l_var.type());
                if(!l_get_var)
                {
                        return WAFLZ_STATUS_OK;
                }
                int32_t l_s;
                const char *l_x_data;
                uint32_t l_x_len;
                // -----------------------------------------
                // extract list of data
                // -----------------------------------------
                const_arg_list_t l_data_list;
                l_s = l_get_var(l_data_list, l_var_count, l_var, &a_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "error getting variable: %d",
                                     l_var.type());
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // Handle count first
                // -----------------------------------------
                if(l_var.is_count())
                {
                        std::string l_v_c = to_string(l_var_count);
                        l_x_data = l_v_c.c_str();
                        l_x_len = l_v_c.length();
                        bool l_match = false;
                        if(!l_op_cb)
                        {
                                continue;
                        }
                        l_s = l_op_cb(l_match, l_op, l_x_data, l_x_len, l_macro, &a_ctx, NULL);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                // TODO log reason???
                                return WAFLZ_STATUS_ERROR;
                        }
                        if(!l_match)
                        {
                                continue;
                        }
                        // Reflect Variable name
                        const google::protobuf::EnumValueDescriptor* l_var_desc =
                                        waflz_pb::variable_t_type_t_descriptor()->FindValueByNumber(l_var.type());
                        a_ctx.m_cx_matched_var.assign(l_x_data, l_x_len);
                        a_ctx.m_cx_matched_var_name = l_var_desc->name();
                        ao_match = true;
                        break;
                }
                // -----------------------------------------
                // data loop
                // -----------------------------------------
                for(const_arg_list_t::const_iterator i_v = l_data_list.begin();
                    i_v != l_data_list.end();
                    ++i_v)
                {
                        // ---------------------------------
                        // transformation loop
                        // ---------------------------------
                        // ---------------------------------
                        // Set size to at least one if no tx
                        // specified
                        // ---------------------------------
                        int32_t l_t_size = l_a.t_size() ? l_a.t_size() : 1;
                        l_x_data = i_v->m_val;
                        l_x_len = i_v->m_val_len;
                        bool l_mutated = false;
                        for(int32_t i_t = 0; i_t < l_t_size; ++i_t)
                        {
                                // -------------------------
                                // *************************
                                //           T X
                                // *************************
                                // -------------------------
                                waflz_pb::sec_action_t_transformation_type_t l_t_type = waflz_pb::sec_action_t_transformation_type_t_NONE;
                                if(i_t > 1 ||
                                   l_a.t_size())
                                {
                                        l_t_type = l_a.t(i_t);
                                }
                                if(l_t_type == waflz_pb::sec_action_t_transformation_type_t_NONE)
                                {
                                        goto run_op;
                                }
                                // -------------------------
                                // if tx...
                                // -------------------------
                                {
                                tx_cb_t l_tx_cb = NULL;
                                l_tx_cb = get_tx_cb(l_t_type);
                                if(!l_tx_cb)
                                {
                                        continue;
                                }
                                char *l_tx_data = NULL;
                                uint32_t l_tx_len = 0;
                                l_s = l_tx_cb(&l_tx_data, l_tx_len, l_x_data, l_x_len);
                                if(l_s != WAFLZ_STATUS_OK)
                                {
                                        // TODO log reason???
                                        return WAFLZ_STATUS_ERROR;
                                }
                                // -------------------------
                                // mark current tx so op can
                                // check if tolower required
                                // by rule.
                                // avoids multiple tolower
                                // called on same string
                                // -------------------------
                                mark_tx_applied(&a_ctx, l_t_type);
                                // -------------------------
                                // if mutated again free
                                // last
                                // -------------------------
                                if(l_mutated)
                                {
                                        free(const_cast <char *>(l_x_data));
                                        l_x_len = 0;
                                        l_mutated = false;
                                }
                                l_mutated = true;
                                l_x_data = l_tx_data;
                                l_x_len = l_tx_len;
                                // -------------------------
                                // break if no data
                                // no point in transforming
                                // or matching further
                                // -------------------------
                                if(!l_x_data ||
                                   !l_x_len)
                                {
                                        break;
                                }
                                }
run_op:
                                // -------------------------
                                // skip op if:
                                // not multimatch
                                // AND
                                // not the end of the list
                                // -------------------------
                                if(!l_multimatch &&
                                   (i_t != (l_t_size - 1)))
                                {
                                        continue;
                                }
                                // -------------------------
                                // *************************
                                //           O P
                                // *************************
                                // -------------------------
                                if(!l_op_cb)
                                {
                                        // TODO log error -shouldn't happen???
                                        continue;
                                }
                                bool l_match = false;
                                l_s = l_op_cb(l_match, l_op, l_x_data, l_x_len, l_macro, &a_ctx, NULL);
                                if(l_s != WAFLZ_STATUS_OK)
                                {
                                        // TODO log reason???
                                        return WAFLZ_STATUS_ERROR;
                                }
                                if(!l_match)
                                {
                                        continue;
                                }
                                if(l_var.type() ==  waflz_pb::variable_t_type_t_ARGS_COMBINED_SIZE)
                                {
                                        a_ctx.m_cx_matched_var_name = "ARGS_COMBINED_SIZE";
                                        a_ctx.m_cx_matched_var = to_string(l_x_len);
                                }
                                else if(l_var.type() ==  waflz_pb::variable_t_type_t_BOT_SCORE)
                                {
                                        a_ctx.m_cx_matched_var_name = "BOT_SCORE";
                                        a_ctx.m_cx_matched_var = to_string(l_x_len);
                                }
                                else
                                {
                                        // Reflect Variable name
                                        const google::protobuf::EnumValueDescriptor* l_var_desc =
                                                        waflz_pb::variable_t_type_t_descriptor()->FindValueByNumber(l_var.type());
                                        a_ctx.m_cx_matched_var.assign(l_x_data, l_x_len);
                                        a_ctx.m_cx_matched_var_name = l_var_desc->name();
                                        if(i_v->m_key_len)
                                        {
                                                std::string l_var_name(i_v->m_key, strnlen(i_v->m_key, i_v->m_key_len));
                                                a_ctx.m_cx_matched_var_name +=":";
                                                a_ctx.m_cx_matched_var_name.append(l_var_name);
                                        }
                                }
                                ao_match = true;
                                break;
                        }
                        // ---------------------------------
                        // final cleanup
                        // ---------------------------------
                        if(l_mutated)
                        {
                                free(const_cast <char *>(l_x_data));
                                l_x_data = NULL;
                                l_x_len = 0;
                                l_mutated = false;
                                a_ctx.m_src_asn_str.m_tx_applied = 0; // Reset
                        }
                        // ---------------------------------
                        // got a match -outtie
                        // ---------------------------------
                        if(ao_match)
                        {
                                break;
                        }
                }
                // -----------------------------------------
                // got a match -outtie
                // -----------------------------------------
                if(ao_match)
                {
                        break;
                }
        }
        // -------------------------------------------------
        // *************************************************
        //                A C T I O N S
        // *************************************************
        // -------------------------------------------------
        if(ao_match)
        {
#define _SET_RULE_INFO(_field, _str) \
if(l_a.has_##_field()) { \
data_t l_k; l_k.m_data = _str; l_k.m_len = sizeof(_str) - 1; \
data_t l_v; \
l_v.m_data = l_a._field().c_str(); \
l_v.m_len = l_a._field().length(); \
a_ctx.m_cx_rule_map[l_k] = l_v; \
}
                // -----------------------------------------
                // set rule info
                // -----------------------------------------
                _SET_RULE_INFO(id, "id");
                _SET_RULE_INFO(msg, "msg");
                // -----------------------------------------
                // TODO -only run
                // non-disruptive???
                // -----------------------------------------
                int32_t l_s = process_action_nd(l_a, a_ctx, a_rule_information.m_parent_rule_id);
                if(l_s == WAFLZ_STATUS_ERROR)
                {
                        NDBG_PRINT("error executing action");
                }
                //NDBG_PRINT("%sACTIONS%s: !!!\n%s%s%s\n",
                //           ANSI_COLOR_BG_CYAN, ANSI_COLOR_OFF,
                //           ANSI_COLOR_FG_CYAN, l_a.ShortDebugString().c_str(), ANSI_COLOR_OFF);
        }
        // -------------------------------------------------
        // null out any set skip values
        // -------------------------------------------------
        else
        {
                a_ctx.m_skip = 0;
                a_ctx.m_skip_after = NULL;
        }
        return WAFLZ_STATUS_OK;
}
/// ----------------------------------------------------------------------------
/// @brief  process the actions in modsec directive or inside a rule
/// @param  a_action, request context
/// @return WAFLZ_STATUS_ERROR or WAFLZ_STATUS_OK
/// ----------------------------------------------------------------------------
int32_t waf::process_action_nd(const waflz_pb::sec_action_t &a_action,
                               rqst_ctx &a_ctx, const std::string a_rule_id = std::string())
{
        // -------------------------------------------------
        // check for skip
        // -------------------------------------------------
        if(a_action.has_skip() &&
           (a_action.skip() > 0))
        {
                a_ctx.m_skip = a_action.skip();
                a_ctx.m_skip_after = NULL;
        }
        // -------------------------------------------------
        // check for skipafter
        // -------------------------------------------------
        if(a_action.has_skipafter() &&
           !a_action.skipafter().empty())
        {
                a_ctx.m_skip = a_action.skip();
                a_ctx.m_skip_after = a_action.skipafter().c_str();
        }
        // -------------------------------------------------
        // for each var
        // -------------------------------------------------
        macro &l_macro = m_engine.get_macro();
        for(int32_t i_sv = 0; i_sv < a_action.setvar_size(); ++i_sv)
        {
                const ::waflz_pb::sec_action_t_setvar_t& l_sv = a_action.setvar(i_sv);
                // NDBG_PRINT("%ssetvar%s: %s%s%s\n",
                //           ANSI_COLOR_BG_GREEN, ANSI_COLOR_OFF,
                //           ANSI_COLOR_FG_GREEN, l_sv.ShortDebugString().c_str(), ANSI_COLOR_OFF);
                //------------------------------------------
                // var before expansion
                //------------------------------------------
                const ::std::string& l_var = l_sv.var();
                const std::string *l_var_ref = &l_var;
                //------------------------------------------
                // check if this is being ran by a rule
                // action + if we are looking at score
                // value
                //------------------------------------------
                bool l_in_rule = !a_rule_id.empty();
                bool l_is_anomaly_score = tx_val_is_score(l_var);
                if (l_in_rule && l_is_anomaly_score)
                {
                        //----------------------------------
                        // apply custom score if available
                        //----------------------------------
                        auto l_custom_score = m_custom_score_map.find( a_rule_id );
                        if (l_custom_score != m_custom_score_map.end())
                        {
                                a_ctx.m_cx_tx_map[l_var] = to_string(l_custom_score->second);
                                continue;
                        }
                }
                //------------------------------------------
                // var expansion
                //------------------------------------------
                std::string l_sv_var;
                if(l_macro.has(l_var))
                {
                        //NDBG_PRINT("%ssetvar%s: VAR!!!!\n", ANSI_COLOR_BG_RED, ANSI_COLOR_OFF);
                        int32_t l_s;
                        l_s = l_macro(l_sv_var, l_var, &a_ctx, NULL);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                        l_var_ref = &l_sv_var;
                }
                //------------------------------------------
                // val expansion
                //------------------------------------------
                const ::std::string& l_val = l_sv.val();
                const std::string *l_val_ref = &l_val;
                std::string l_sv_val;
                if(l_macro.has(l_val))
                {
                        //NDBG_PRINT("%ssetvar%s: VAL!!!!\n", ANSI_COLOR_BG_RED, ANSI_COLOR_OFF);
                        int32_t l_s;
                        l_s = l_macro(l_sv_val, l_val, &a_ctx, NULL);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                        l_val_ref = &l_sv_val;
                }
                //------------------------------------------
                // *****************************************
                //               S C O P E
                // *****************************************
                //------------------------------------------
                switch(l_sv.scope())
                {
                // -----------------------------------------
                // TX
                // -----------------------------------------
                case ::waflz_pb::sec_action_t_setvar_t_scope_t_TX:
                {
                        cx_map_t &l_cx_map = a_ctx.m_cx_tx_map;
                        //----------------------------------
                        // *********************************
                        //              O P
                        // *********************************
                        //----------------------------------
                        switch(l_sv.op())
                        {
                        //----------------------------------
                        // ASSIGN
                        //----------------------------------
                        case ::waflz_pb::sec_action_t_setvar_t_op_t_ASSIGN:
                        {
                                // check for anomaly_pl1
                                // check for custom here
                                l_cx_map[*l_var_ref] =  *l_val_ref;
                                break;
                        }
                        //----------------------------------
                        // DELETE
                        //----------------------------------
                        case ::waflz_pb::sec_action_t_setvar_t_op_t_DELETE:
                        {
                                cx_map_t::iterator i_t = l_cx_map.find(*l_var_ref);
                                if(i_t != l_cx_map.end())
                                {
                                        l_cx_map.erase(i_t);
                                }
                                break;
                        }
                        //----------------------------------
                        // INCREMENT
                        //----------------------------------
                        // e.g setvar:tx.rfi_score=+%{tx.critical_anomaly_score}
                        case ::waflz_pb::sec_action_t_setvar_t_op_t_INCREMENT:
                        {
                                int32_t l_pv = 0;
                                cx_map_t::iterator i_t = l_cx_map.find(*l_var_ref);
                                // -------------------------
                                // TODO -use strntol instead
                                // of atoi...
                                // -------------------------
                                // check for custom here
#if 0
                                int32_t l_in_val;
                                char *l_end_ptr = NULL;
                                l_in_val = strntol(a_buf, a_len, &l_end_ptr, 10);
                                if((l_in_val == LONG_MAX) ||
                                   (l_in_val == LONG_MIN))
                                {
                                        return WAFLZ_STATUS_OK;
                                }
                                if(l_end_ptr == a_buf)
                                {
                                        return WAFLZ_STATUS_OK;
                                }
#endif
                                if(i_t != l_cx_map.end())
                                {
                                        l_pv = atoi(i_t->second.c_str());
                                }
                                int32_t l_nv = 0;
                                l_nv = atoi(l_val_ref->c_str());
                                //NDBG_PRINT("INC: var[%s]: %d by: %d\n", l_var_ref->c_str(), l_pv, l_nv);
                                char l_val_str[8];
                                snprintf(l_val_str, 8, "%d", l_pv + l_nv);
                                l_cx_map[*l_var_ref] = l_val_str;
                                break;
                        }
                        //----------------------------------
                        // DECREMENT
                        //----------------------------------
                        case ::waflz_pb::sec_action_t_setvar_t_op_t_DECREMENT:
                        {
                                int32_t l_pv = 0;
                                cx_map_t::iterator i_t = l_cx_map.find(*l_var_ref);
                                if(i_t != l_cx_map.end())
                                {
                                        l_pv = atoi(i_t->second.c_str());
                                }
                                int32_t l_nv = 0;
                                l_nv = atoi(l_val_ref->c_str());
                                char l_val_str[8];
                                snprintf(l_val_str, 8, "%d", l_pv - l_nv);
                                l_cx_map[*l_var_ref] =  l_val_str;
                                break;
                        }
                        //----------------------------------
                        // default
                        //----------------------------------
                        default:
                        {
                                //NDBG_PRINT("error invalid op\n");
                                break;
                        }
                        }
                        break;
                }
                // -----------------------------------------
                // IP
                // -----------------------------------------
                case ::waflz_pb::sec_action_t_setvar_t_scope_t_IP:
                {
                        // TODO ???
                        continue;
                }
                // -----------------------------------------
                // default
                // -----------------------------------------
                default:
                {
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
uint32_t waf::calculate_rule_anomaly_score( cx_map_t& a_ctx_map, bool a_inbound )
{
        // -------------------------------------------------
        // Based on paranoia level different rules set
        // different scores. The CRS uses the following vars
        // crs < v4             or crs >= v4
        // tx.anomaly_score_pl1 or inbound_anomaly_score_pl1
        // tx.anomaly_score_pl2 or inbound_anomaly_score_pl2
        // tx.anomaly_score_pl3 or inbound_anomaly_score_pl3
        // tx.anomaly_score_pl4 or inbound_anomaly_score_pl4
        // -------------------------------------------------
        // Here we emulate the blocking evaluation config
        // 1. Check current paranoia level
        // 2. Sum up all pl scores until current pl
        // 3. Set the anomaly_score = sum of #2
        // -------------------------------------------------
        uint32_t ao_running_anomaly_score = 0;
        // -------------------------------------------------
        // CRSv4 support for inbound | outbound rules
        // -------------------------------------------------
        std::string l_prefix = a_inbound ? "inbound_" : "outbound_";
        // -------------------------------------------------
        // for each paranoia level
        // -------------------------------------------------
        for ( uint32_t i_current_paranoia_level = 1;
              i_current_paranoia_level <= m_paranoia_level;
              i_current_paranoia_level++)
        {
                // -----------------------------------------
                // get anomaly score for current pl
                // -----------------------------------------
                std::string l_ex_anomaly = l_prefix + "anomaly_score_pl" + to_string(i_current_paranoia_level);
                cx_map_t::const_iterator i_t = a_ctx_map.find(l_ex_anomaly);
                // -----------------------------------------
                // fallback support for CRSv3 (only inbound)
                // -----------------------------------------
                if(a_inbound && i_t == a_ctx_map.end())
                {
                        l_ex_anomaly = "anomaly_score_pl" + to_string(i_current_paranoia_level);
                        i_t = a_ctx_map.find(l_ex_anomaly);
                }
                // -----------------------------------------
                // if pl not found, continue
                // -----------------------------------------
                if (i_t == a_ctx_map.end())
                {
                        continue;
                }
                // -----------------------------------------
                // read pl from tx
                // -----------------------------------------
                uint32_t l_current_anomaly_score = strtoul(i_t->second.c_str(),
                                                          nullptr, 10);
                // -----------------------------------------
                // if the value was read wrong
                // -----------------------------------------
                bool l_bad_input = l_current_anomaly_score == ULONG_MAX;
                if( l_bad_input ) { continue; }
                // -----------------------------------------
                // add current score to running score
                // -----------------------------------------
                ao_running_anomaly_score += l_current_anomaly_score;
        }
        // -------------------------------------------------
        // save final score to transaction if > 0
        // -------------------------------------------------
        if ( ao_running_anomaly_score )
        {
                a_ctx_map["anomaly_score"] = to_string(ao_running_anomaly_score);
        }
        // -------------------------------------------------
        // return the anomaly score
        // -------------------------------------------------
        return atoi(a_ctx_map["anomaly_score"].c_str());
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t waf::process_match(waflz_pb::event** ao_event,
                           const waflz_pb::sec_rule_t& a_rule,
                           rqst_ctx& a_ctx)
{
        // -------------------------------------------------
        // error if we already have an event or no action
        // -------------------------------------------------
        if (!ao_event || !a_rule.has_action())
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // save action and rule id for later
        // -------------------------------------------------
        const waflz_pb::sec_action_t &l_action = a_rule.action();
        const std::string l_rule_id = l_action.id();
        // -------------------------------------------------
        // if no log, then quick return
        // -------------------------------------------------
        const bool l_action_is_pass = (
                l_action.action_type() == 
                ::waflz_pb::sec_action_t_action_type_t_PASS
        );
        const bool l_is_no_log = (
                l_action.has_nolog() && l_action.nolog()
        );
        if ( l_is_no_log && l_action_is_pass )
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // compare...
        // -------------------------------------------------
        // 1. get "anomaly_score"...
        // 2. get "inbound_anomaly_score_threshold" or "inbound_anomaly_score_level" --> threshold
        // 3. if(l_score >= l_threshold) mark as intercepted...
        // -------------------------------------------------
        uint32_t l_anomaly_score = 0;
        // -------------------------------------------------
        // calculate anomaly score if chain_rule or vars
        // are set
        // e.g setvar:'tx.anomaly_score_pl1=+%{tx.notice_anomaly_score}
        // -------------------------------------------------
        const bool l_vars_set = l_action.setvar_size() > 0;
        const bool l_is_chain_rule = a_rule.chained_rule_size() > 0;
        if ( l_vars_set || l_is_chain_rule )
        {
                l_anomaly_score = this->calculate_rule_anomaly_score(a_ctx.m_cx_tx_map, true);
        }
        // -------------------------------------------------
        // skip if no anomaly score and
        // w/o action or PASS types...
        // -------------------------------------------------
        const bool l_has_passible_action = (
                !l_action.has_action_type() || 
                l_action_is_pass
        );
        if ((l_anomaly_score <= 0) && l_has_passible_action)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // skip logging events not contributing to anomaly
        // action
        // -------------------------------------------------
        bool l_seen_higher_score_before = m_anomaly_score_cur >= l_anomaly_score;
        if (l_seen_higher_score_before && l_action_is_pass)
        {
                return WAFLZ_STATUS_OK;
        }
        m_anomaly_score_cur = l_anomaly_score;
        // -------------------------------------------------
        // *************************************************
        // handling anomaly mode natively...
        // *************************************************
        // -------------------------------------------------
        // -------------------------------------------------
        // get field values...
        // -------------------------------------------------
#define _GET_TX_FIELD(_str, _val) do { \
        i_t = a_ctx.m_cx_tx_map.find(_str); \
        if(i_t == a_ctx.m_cx_tx_map.end()) { \
                NDBG_PRINT("rule: %s missing tx field: %s.\n", a_rule.ShortDebugString().c_str(), _str);\
                return WAFLZ_STATUS_ERROR; \
        } \
        _val = strtoul(i_t->second.c_str(), nullptr, 10); \
} while(0)
        uint32_t l_threshold = 0;
        cx_map_t::const_iterator i_t;
        _GET_TX_FIELD("inbound_anomaly_score_threshold", l_threshold);
        // -------------------------------------------------
        // check threshold
        // -------------------------------------------------
        //NDBG_PRINT("%sl_anomaly_score%s: %d\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF, l_anomaly_score);
        //NDBG_PRINT("%sl_threshold%s:     %d\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF, l_threshold);
        if (l_anomaly_score >= l_threshold)
        {
                a_ctx.m_intercepted = true;
        }
        // -------------------------------------------------
        // skip events w/o messages
        // -------------------------------------------------
        if (!l_action.has_msg()) { return WAFLZ_STATUS_OK; }
        // -------------------------------------------------
        // create info...
        // -------------------------------------------------
        waflz_pb::event* l_sub_event = NULL;
        if (!(*ao_event))
        {
                *ao_event = new ::waflz_pb::event();
        }
        //NDBG_PRINT("%sadd_sub_event%s:\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF);
        l_sub_event = (*ao_event)->add_sub_event();
        // -------------------------------------------------
        // populate info
        // -------------------------------------------------
        // -------------------------------------------------
        // bot_action
        // -------------------------------------------------
        if (l_action.has_bot_action())
        {
                l_sub_event->set_bot_action(l_action.bot_action());
        }
        // -------------------------------------------------
        // msg
        // -------------------------------------------------
        std::string l_msg;
        macro &l_macro = m_engine.get_macro();
        if(l_macro.has(l_action.msg()))
        {
                int32_t l_s;
                l_s = l_macro(l_msg, l_action.msg(), &a_ctx, NULL);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        if(!l_msg.empty())
        {
                (*ao_event)->set_rule_msg(l_msg);
                l_sub_event->set_rule_msg(l_msg);
        }
        else
        {
                if(l_action.has_msg()) { l_sub_event->set_rule_msg(l_action.msg()); }
                (*ao_event)->set_rule_msg(l_action.msg());
        }
        // -------------------------------------------------
        // rule info
        // -------------------------------------------------
        if(l_action.has_id()) { l_sub_event->set_rule_id((uint32_t)atol(l_action.id().c_str())); }
        if(a_rule.operator_().has_type())
        {
                const google::protobuf::EnumValueDescriptor* l_op_desc =
                                        waflz_pb::sec_rule_t_operator_t_type_t_descriptor()->FindValueByNumber(a_rule.operator_().type());
                l_sub_event->set_rule_op_name(l_op_desc->name());
        }
        if (a_rule.operator_().has_value())
        {
                l_sub_event->set_rule_op_param(a_rule.operator_().value());
        }
        // -------------------------------------------------
        // tx vars
        // -------------------------------------------------
        l_sub_event->set_total_anomaly_score(l_anomaly_score);
        a_ctx.m_waf_anomaly_score = l_anomaly_score;
        // -------------------------------------------------
        // check if there is an rtu for this rule
        // NOTE: we add "_0" on the end of the id to 
        // check for the top level rule variables
        // -------------------------------------------------
        update_variable_map_t::const_iterator l_rtu = m_rtu_variable_map.find(a_rule.action().id() + "_0");
        bool l_has_rtu_variables = l_rtu != m_rtu_variable_map.end(); 
        // -------------------------------------------------
        // rule targets
        // -------------------------------------------------
        //NDBG_PRINT("rule matched %s\n", a_rule.DebugString().c_str());
        for(int32_t i_k = 0; i_k < a_rule.variable_size(); ++i_k)
        {
                const waflz_pb::variable_t &l_var = (l_has_rtu_variables) ? l_rtu->second[i_k] : a_rule.variable(i_k);
                const google::protobuf::EnumValueDescriptor* l_var_desc =
                                       waflz_pb::variable_t_type_t_descriptor()->FindValueByNumber(l_var.type());
                waflz_pb::event::var_t *l_mvar = NULL;
                l_mvar = l_sub_event->add_rule_target();
                // -----------------------------------------
                // counting???
                // -----------------------------------------
                if (l_var.has_is_count() && l_var.is_count())
                {
                        l_mvar->set_is_counting(true);
                }
                // -----------------------------------------
                // no match info
                // -----------------------------------------
                if (l_var.match_size() <= 0)
                {
                        l_mvar->set_name(l_var_desc->name());
                        continue;
                }
                // -----------------------------------------
                // for each match...
                // -----------------------------------------
                for (int32_t i_m = 0; i_m < l_var.match_size(); ++i_m)
                {
                        // ---------------------------------
                        // name
                        // ---------------------------------
                        l_mvar->set_name(l_var_desc->name());
                        // ---------------------------------
                        // value
                        // ---------------------------------
                        const waflz_pb::variable_t_match_t &l_match = l_var.match(i_m);
                        if (!l_match.value().empty())
                        {
                                // -------------------------
                                // fix up string to indicate
                                // is regex
                                // -------------------------
                                std::string l_val = l_match.value();
                                if (l_match.is_regex())
                                {
                                        l_val.insert(0, "/");
                                        l_val += "/";
                                }
                                l_mvar->set_param(l_val);
                        }
                        // ---------------------------------
                        // negated???
                        // ---------------------------------
                        if(l_match.is_negated())
                        {
                                l_mvar->set_is_negated(true);
                        }
                }
        }
        for(int32_t i_a = 0; i_a < l_action.tag_size(); ++i_a)
        {
                l_sub_event->add_rule_tag(l_action.tag(i_a));
        }
        // -------------------------------------------------
        // intercept status
        // -------------------------------------------------
        l_sub_event->set_rule_intercept_status(HTTP_STATUS_FORBIDDEN);
        waflz_pb::event::var_t* l_m_var = NULL;
        // -------------------------------------------------
        // matched var
        // -------------------------------------------------
        l_m_var = l_sub_event->mutable_matched_var();
        l_m_var->set_name(a_ctx.m_cx_matched_var_name);
        // -------------------------------------------------
        // check for no log or sanitized action
        // -------------------------------------------------
#define CAP_LEN(_len) (_len > 1024 ? 1024: _len)
        if(l_action.sanitisematched() ||
           m_no_log_matched)
        {
                l_m_var->set_value("**SANITIZED**");
        }
        else
        {
                l_m_var->set_value(a_ctx.m_cx_matched_var.c_str(), CAP_LEN(a_ctx.m_cx_matched_var.length()));
        }
        // -------------------------------------------------
        // check for redacted vars and replace on match
        // -------------------------------------------------
        for(redacted_var_list_t::const_iterator i_rv = m_redacted_vars.begin();
            i_rv != m_redacted_vars.end();
            ++i_rv)
        {
                regex* l_match_on = std::get<0>(*i_rv);
                if ( l_match_on->compare(a_ctx.m_cx_matched_var_name) > 0 )
                {
                        // ---------------------------------
                        // replace value on match
                        // ---------------------------------
                        std::string l_v_replace = std::get<1>(*i_rv);
                        l_m_var->set_value(l_v_replace);
                        // ---------------------------------
                        // replace name if provided
                        // ---------------------------------
                        std::string l_n_replace = std::get<2>(*i_rv);
                        if (l_n_replace.length())
                        {
                                a_ctx.m_cx_matched_var_name = l_n_replace;
                                l_m_var->set_name(a_ctx.m_cx_matched_var_name);
                        }
                        break;
                }
        }
        // -------------------------------------------------
        // return done processing match
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t waf::process_phase(waflz_pb::event **ao_event,
                           const directive_list_t &a_dl,
                           const marker_map_t &a_mm,
                           rqst_ctx &a_ctx)
{
        a_ctx.m_intercepted = false;
        for(directive_list_t::const_iterator i_d = a_dl.begin();
            i_d != a_dl.end();
            ++i_d)
        {
                if(!(*i_d))
                {
                        //NDBG_PRINT("SKIPPING\n");
                        continue;
                }
                // -----------------------------------------
                // marker
                // -----------------------------------------
                const ::waflz_pb::directive_t& l_d = **i_d;
                if(l_d.has_marker())
                {
                        //NDBG_PRINT("%sMARKER%s: %s%s%s\n",
                        //           ANSI_COLOR_BG_RED, ANSI_COLOR_OFF,
                        //           ANSI_COLOR_BG_RED, l_d.marker().c_str(), ANSI_COLOR_OFF);
                        continue;
                }
                // -----------------------------------------
                // action
                // -----------------------------------------
                if(l_d.has_sec_action())
                {
                        const waflz_pb::sec_action_t &l_a = l_d.sec_action();
                        int32_t l_s = process_action_nd(l_a, a_ctx, std::string());
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                NDBG_PRINT("error processing rule\n");
                        }
                        continue;
                }
                // -----------------------------------------
                // rule
                // -----------------------------------------
                if(l_d.has_sec_rule())
                {
                        const waflz_pb::sec_rule_t &l_r = l_d.sec_rule();
                        if(!l_r.has_action())
                        {
                                //NDBG_PRINT("error no action for rule: %s\n", l_r.ShortDebugString().c_str());
                                continue;
                        }
                        int32_t l_s;
                        l_s = process_rule(ao_event, l_r, a_ctx);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                }
                // -----------------------------------------
                // break if intercepted
                // -----------------------------------------
                if(a_ctx.m_intercepted)
                {
                        break;
                }
                // -----------------------------------------
                // handle skip
                // -----------------------------------------
                if(a_ctx.m_skip)
                {
                        //NDBG_PRINT("%sskipping%s...: %d\n", ANSI_COLOR_BG_YELLOW, ANSI_COLOR_OFF, a_ctx.m_skip);
                        while(a_ctx.m_skip &&
                              (i_d != a_dl.end()))
                        {
                                ++i_d;
                                --a_ctx.m_skip;
                        }
                        a_ctx.m_skip = 0;
                }
                else if(a_ctx.m_skip_after)
                {
                        //NDBG_PRINT("%sskipping%s...: %s\n", ANSI_COLOR_BG_YELLOW, ANSI_COLOR_OFF, a_ctx.m_skip_after);
                        marker_map_t::const_iterator i_nd;
                        i_nd = a_mm.find(a_ctx.m_skip_after);
                        if(i_nd != a_mm.end())
                        {
                                i_d = i_nd->second;
                        }
                        a_ctx.m_skip_after = NULL;
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t waf::process_resp_match(waflz_pb::event** ao_event,
                                const waflz_pb::sec_rule_t& a_rule,
                                resp_ctx& a_ctx)
{
        // -------------------------------------------------
        // error if we already have an event or no action
        // -------------------------------------------------
        if (!ao_event || !a_rule.has_action())
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // save action and rule id for later
        // -------------------------------------------------
        const waflz_pb::sec_action_t &l_action = a_rule.action();
        const std::string l_rule_id = l_action.id();
        // -------------------------------------------------
        // if no log, then quick return
        // -------------------------------------------------
        const bool l_action_is_pass = (
                l_action.action_type() == 
                ::waflz_pb::sec_action_t_action_type_t_PASS
        );
        const bool l_is_no_log = (
                l_action.has_nolog() && l_action.nolog()
        );
        if ( l_is_no_log && l_action_is_pass )
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // compare...
        // -------------------------------------------------
        // 1. get "anomaly_score"...
        // 2. get "inbound_anomaly_score_threshold" or "inbound_anomaly_score_level" --> threshold
        // 3. if(l_score >= l_threshold) mark as intercepted...
        // -------------------------------------------------
        uint32_t l_anomaly_score = 0;
        // -------------------------------------------------
        // calculate anomaly score if chain_rule or vars
        // are set
        // e.g setvar:'tx.anomaly_score_pl1=+%{tx.notice_anomaly_score}
        // -------------------------------------------------
        const bool l_vars_set = l_action.setvar_size() > 0;
        const bool l_is_chain_rule = a_rule.chained_rule_size() > 0;
        if ( l_vars_set || l_is_chain_rule )
        {
                l_anomaly_score = this->calculate_rule_anomaly_score(a_ctx.m_cx_tx_map, false);
        }
       // -------------------------------------------------
        // skip if no anomaly score and
        // w/o action or PASS types...
        // -------------------------------------------------
        const bool l_has_passible_action =
            (!l_action.has_action_type() || l_action_is_pass);
        if ((l_anomaly_score <= 0) && l_has_passible_action)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // skip logging events not contributing to anomaly
        // action
        // -------------------------------------------------
        bool l_seen_higher_score_before = m_anomaly_score_cur >= l_anomaly_score;
        if (l_seen_higher_score_before && l_action_is_pass)
        {
                return WAFLZ_STATUS_OK;
        }
        m_anomaly_score_cur = l_anomaly_score;
        // -------------------------------------------------
        // *************************************************
        // handling anomaly mode natively...
        // *************************************************
        // -------------------------------------------------
        // -------------------------------------------------
        // get field values...
        // -------------------------------------------------
        uint32_t l_threshold = 0;
        cx_map_t::const_iterator i_t;
        _GET_TX_FIELD("outbound_anomaly_score_threshold", l_threshold);
        //NDBG_PRINT("%sl_anomaly_score%s: %d\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF, l_anomaly_score);
        //NDBG_PRINT("%sl_threshold%s:     %d\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF, l_threshold);
        // -------------------------------------------------
        // check threshold
        // -------------------------------------------------
        if(l_anomaly_score >= l_threshold)
        {
                a_ctx.m_intercepted = true;
        }
        // -------------------------------------------------
        // skip events w/o messages
        // -------------------------------------------------
        if (!l_action.has_msg()) { return WAFLZ_STATUS_OK; }
        // -------------------------------------------------
        // create info...
        // -------------------------------------------------
        waflz_pb::event* l_sub_event = NULL;
        if(!(*ao_event))
        {
                *ao_event = new ::waflz_pb::event();
        }
        //NDBG_PRINT("%sadd_sub_event%s:\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF);
        l_sub_event = (*ao_event)->add_sub_event();
        // -------------------------------------------------
        // populate info
        // -------------------------------------------------
        // -------------------------------------------------
        // msg
        // -------------------------------------------------
        std::string l_msg;
        macro &l_macro = m_engine.get_macro();
        if(l_macro.has(l_action.msg()))
        {
                int32_t l_s;
                l_s = l_macro(l_msg, l_action.msg(), NULL, &a_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        if(!l_msg.empty())
        {
                 (*ao_event)->set_rule_msg(l_msg);
                 l_sub_event->set_rule_msg(l_msg);
        }
        else
        {
                if(l_action.has_msg()) { l_sub_event->set_rule_msg(l_action.msg()); }
                (*ao_event)->set_rule_msg(l_action.msg());
        }
        // -------------------------------------------------
        // rule info
        // -------------------------------------------------
        if(l_action.has_id()) { l_sub_event->set_rule_id((uint32_t)atol(l_action.id().c_str())); }
        if(a_rule.operator_().has_type())
        {
                const google::protobuf::EnumValueDescriptor* l_op_desc =
                                        waflz_pb::sec_rule_t_operator_t_type_t_descriptor()->FindValueByNumber(a_rule.operator_().type());
                l_sub_event->set_rule_op_name(l_op_desc->name());
        }
        if(a_rule.operator_().has_value()) { l_sub_event->set_rule_op_param(a_rule.operator_().value()); }
        // -------------------------------------------------
        // tx vars
        // -------------------------------------------------
        l_sub_event->set_total_anomaly_score(l_anomaly_score);
        // -------------------------------------------------
        // rule targets
        // -------------------------------------------------
        // -------------------------------------------------
        // check if there is an rtu for this rule
        // NOTE: we add "_0" on the end of the id to 
        // check for the top level rule variables
        // -------------------------------------------------
        update_variable_map_t::const_iterator l_rtu = m_rtu_variable_map.find(a_rule.action().id() + "_0");
        bool l_has_rtu_variables = l_rtu != m_rtu_variable_map.end(); 
        //NDBG_PRINT("rule matched %s\n", a_rule.DebugString().c_str());
        for(int32_t i_k = 0; i_k < a_rule.variable_size(); ++i_k)
        {
                const waflz_pb::variable_t &l_var = (l_has_rtu_variables) ? l_rtu->second[i_k] : a_rule.variable(i_k);
                const google::protobuf::EnumValueDescriptor* l_var_desc =
                                       waflz_pb::variable_t_type_t_descriptor()->FindValueByNumber(l_var.type());
                waflz_pb::event::var_t *l_mvar = NULL;
                l_mvar = l_sub_event->add_rule_target();
                // -----------------------------------------
                // counting???
                // -----------------------------------------
                if(l_var.has_is_count() &&
                   l_var.is_count())
                {
                        l_mvar->set_is_counting(true);
                }
                // -----------------------------------------
                // no match info
                // -----------------------------------------
                if(l_var.match_size() <= 0)
                {
                        l_mvar->set_name(l_var_desc->name());
                        continue;
                }
                // -----------------------------------------
                // for each match...
                // -----------------------------------------
                for(int32_t i_m = 0; i_m < l_var.match_size(); ++i_m)
                {
                        // ---------------------------------
                        // name
                        // ---------------------------------
                        l_mvar->set_name(l_var_desc->name());
                        // ---------------------------------
                        // value
                        // ---------------------------------
                        const waflz_pb::variable_t_match_t &l_match = l_var.match(i_m);
                        if(!l_match.value().empty())
                        {
                                // -------------------------
                                // fix up string to indicate
                                // is regex
                                // -------------------------
                                std::string l_val = l_match.value();
                                if(l_match.is_regex())
                                {
                                        l_val.insert(0, "/");
                                        l_val += "/";
                                }
                                l_mvar->set_param(l_val);
                        }
                        // ---------------------------------
                        // negated???
                        // ---------------------------------
                        if(l_match.is_negated())
                        {
                                l_mvar->set_is_negated(true);
                        }
                }
        }
        for(int32_t i_a = 0; i_a < l_action.tag_size(); ++i_a)
        {
                l_sub_event->add_rule_tag(l_action.tag(i_a));
        }
        // -------------------------------------------------
        // intercept status
        // -------------------------------------------------
        // -------------------------------------------------
        // Special logic for handling bot rules:
        // auditlog+pass  = log req + allow req
        // auditlog+block = log req + custom action for auth
        // auditlog+deny  = log req + block req
        // -------------------------------------------------
        if(l_action.has_auditlog())
        {

                switch (l_action.action_type())
                {
                case ::waflz_pb::sec_action_t_action_type_t_PASS:
                {
                        l_sub_event->set_rule_intercept_status(HTTP_STATUS_OK);
                        break;
                }
                case ::waflz_pb::sec_action_t_action_type_t_BLOCK:
                {
                        l_sub_event->set_rule_intercept_status(HTTP_STATUS_AUTHENTICATION_REQUIRED);
                        break;
                }
                // Rules that outright want to deny request
                case ::waflz_pb::sec_action_t_action_type_t_DENY:
                {
                        l_sub_event->set_rule_intercept_status(HTTP_STATUS_FORBIDDEN);
                        break;
                }
                default:
                        l_sub_event->set_rule_intercept_status(HTTP_STATUS_FORBIDDEN);
                }
        }
        else
        {
                l_sub_event->set_rule_intercept_status(HTTP_STATUS_FORBIDDEN);
        }
        waflz_pb::event::var_t* l_m_var = NULL;
        // -------------------------------------------------
        // matched var
        // -------------------------------------------------
        l_m_var = l_sub_event->mutable_matched_var();
        l_m_var->set_name(a_ctx.m_cx_matched_var_name);
        //WFLZ_TRC_MATCH("MATCHED VAR NAME: %s", a_ctx.m_cx_matched_var_name.c_str());
        // -------------------------------------------------
        // check for no log or sanitized action
        // -------------------------------------------------
#define CAP_LEN(_len) (_len > 1024 ? 1024: _len)
        if (l_action.sanitisematched() || m_no_log_matched)
        {
                l_m_var->set_value("**SANITIZED**");
        }
        else
        {
                l_m_var->set_value(a_ctx.m_cx_matched_var.c_str(), CAP_LEN(a_ctx.m_cx_matched_var.length()));
        }
        // -------------------------------------------------
        // check for redacted vars
        // -------------------------------------------------
        for(redacted_var_list_t::const_iterator i_rv = m_redacted_vars.begin();
            i_rv != m_redacted_vars.end();
            ++i_rv)
        {
                regex* l_match_on = std::get<0>(*i_rv);
                if ( l_match_on->compare(a_ctx.m_cx_matched_var_name) > 0 )
                {
                        // ---------------------------------
                        // replace value on match
                        // ---------------------------------
                        std::string l_v_replace = std::get<1>(*i_rv);
                        l_m_var->set_value(l_v_replace);
                        // ---------------------------------
                        // replace name if provided
                        // ---------------------------------
                        std::string l_n_replace = std::get<2>(*i_rv);
                        if (l_n_replace.length())
                        {
                                a_ctx.m_cx_matched_var_name = l_n_replace;
                                l_m_var->set_name(a_ctx.m_cx_matched_var_name);
                        }
                        break;
                }
        }
        // -------------------------------------------------
        // return done processing match
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}
/// ----------------------------------------------------------------------------
/// @brief  process the actions in modsec directive or inside a rule
/// @param  a_action, request context
/// @return WAFLZ_STATUS_ERROR or WAFLZ_STATUS_OK
/// ----------------------------------------------------------------------------
int32_t waf::process_resp_action_nd(const waflz_pb::sec_action_t &a_action,
                                    resp_ctx &a_ctx, std::string a_rule_id)
{
        // -------------------------------------------------
        // check for skip
        // -------------------------------------------------
        if(a_action.has_skip() &&
           (a_action.skip() > 0))
        {
                a_ctx.m_skip = a_action.skip();
                a_ctx.m_skip_after = NULL;
        }
        // -------------------------------------------------
        // check for skipafter
        // -------------------------------------------------
        if(a_action.has_skipafter() &&
           !a_action.skipafter().empty())
        {
                a_ctx.m_skip = a_action.skip();
                a_ctx.m_skip_after = a_action.skipafter().c_str();
        }
        // -------------------------------------------------
        // for each var
        // -------------------------------------------------
        macro &l_macro = m_engine.get_macro();
        for(int32_t i_sv = 0; i_sv < a_action.setvar_size(); ++i_sv)
        {
                const ::waflz_pb::sec_action_t_setvar_t& l_sv = a_action.setvar(i_sv);
                //NDBG_PRINT("%ssetvar%s: %s%s%s\n",
                //           ANSI_COLOR_BG_GREEN, ANSI_COLOR_OFF,
                //           ANSI_COLOR_FG_GREEN, l_sv.ShortDebugString().c_str(), ANSI_COLOR_OFF);

                //------------------------------------------
                // var before expansion
                //------------------------------------------
                const ::std::string& l_var = l_sv.var();
                const std::string *l_var_ref = &l_var;
                //------------------------------------------
                // check if this is being ran by a rule
                // action + if we are looking at score
                // value
                //------------------------------------------
                bool l_in_rule = !a_rule_id.empty();
                bool l_is_anomaly_score = tx_val_is_score(l_var);
                if (l_in_rule && l_is_anomaly_score)
                {
                        //----------------------------------
                        // apply custom score if available
                        //----------------------------------
                        auto l_custom_score = m_custom_score_map.find( a_rule_id );
                        if (l_custom_score != m_custom_score_map.end())
                        {
                                a_ctx.m_cx_tx_map[l_var] = to_string(l_custom_score->second);
                                continue;
                        }
                }
                //------------------------------------------
                // var expansion
                //------------------------------------------
                std::string l_sv_var;
                if(l_macro.has(l_var))
                {
                        //NDBG_PRINT("%ssetvar%s: VAR!!!!\n", ANSI_COLOR_BG_RED, ANSI_COLOR_OFF);
                        int32_t l_s;
                        l_s = l_macro(l_sv_var, l_var, NULL, &a_ctx);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                        l_var_ref = &l_sv_var;
                }
                //------------------------------------------
                // val expansion
                //------------------------------------------
                const ::std::string& l_val = l_sv.val();
                const std::string *l_val_ref = &l_val;
                std::string l_sv_val;
                if(l_macro.has(l_val))
                {
                        //NDBG_PRINT("%ssetvar%s: VAL!!!!\n", ANSI_COLOR_BG_RED, ANSI_COLOR_OFF);
                        int32_t l_s;
                        l_s = l_macro(l_sv_val, l_val, NULL, &a_ctx);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                        l_val_ref = &l_sv_val;
                }
                //------------------------------------------
                // *****************************************
                //               S C O P E
                // *****************************************
                //------------------------------------------
                switch(l_sv.scope())
                {
                // -----------------------------------------
                // TX
                // -----------------------------------------
                case ::waflz_pb::sec_action_t_setvar_t_scope_t_TX:
                {
                        cx_map_t &l_cx_map = a_ctx.m_cx_tx_map;
                        //----------------------------------
                        // *********************************
                        //              O P
                        // *********************************
                        //----------------------------------
                        switch(l_sv.op())
                        {
                        //----------------------------------
                        // ASSIGN
                        //----------------------------------
                        case ::waflz_pb::sec_action_t_setvar_t_op_t_ASSIGN:
                        {
                                l_cx_map[*l_var_ref] =  *l_val_ref;
                                break;
                        }
                        //----------------------------------
                        // DELETE
                        //----------------------------------
                        case ::waflz_pb::sec_action_t_setvar_t_op_t_DELETE:
                        {
                                cx_map_t::iterator i_t = l_cx_map.find(*l_var_ref);
                                if(i_t != l_cx_map.end())
                                {
                                        l_cx_map.erase(i_t);
                                }
                                break;
                        }
                        //----------------------------------
                        // INCREMENT
                        //----------------------------------
                        // e.g setvar:tx.rfi_score=+%{tx.critical_anomaly_score}
                        case ::waflz_pb::sec_action_t_setvar_t_op_t_INCREMENT:
                        {
                                int32_t l_pv = 0;
                                cx_map_t::iterator i_t = l_cx_map.find(*l_var_ref);
                                // -------------------------
                                // TODO -use strntol instead
                                // of atoi...
                                // -------------------------
#if 0
                                int32_t l_in_val;
                                char *l_end_ptr = NULL;
                                l_in_val = strntol(a_buf, a_len, &l_end_ptr, 10);
                                if((l_in_val == LONG_MAX) ||
                                   (l_in_val == LONG_MIN))
                                {
                                        return WAFLZ_STATUS_OK;
                                }
                                if(l_end_ptr == a_buf)
                                {
                                        return WAFLZ_STATUS_OK;
                                }
#endif
                                if(i_t != l_cx_map.end())
                                {
                                        l_pv = atoi(i_t->second.c_str());
                                }
                                int32_t l_nv = 0;
                                l_nv = atoi(l_val_ref->c_str());
                                //NDBG_PRINT("INC: var[%s]: %d by: %d\n", l_var_ref->c_str(), l_pv, l_nv);
                                char l_val_str[8];
                                snprintf(l_val_str, 8, "%d", l_pv + l_nv);
                                l_cx_map[*l_var_ref] = l_val_str;
                                break;
                        }
                        //----------------------------------
                        // DECREMENT
                        //----------------------------------
                        case ::waflz_pb::sec_action_t_setvar_t_op_t_DECREMENT:
                        {
                                int32_t l_pv = 0;
                                cx_map_t::iterator i_t = l_cx_map.find(*l_var_ref);
                                if(i_t != l_cx_map.end())
                                {
                                        l_pv = atoi(i_t->second.c_str());
                                }
                                int32_t l_nv = 0;
                                l_nv = atoi(l_val_ref->c_str());
                                char l_val_str[8];
                                snprintf(l_val_str, 8, "%d", l_pv - l_nv);
                                l_cx_map[*l_var_ref] =  l_val_str;
                                break;
                        }
                        //----------------------------------
                        // default
                        //----------------------------------
                        default:
                        {
                                //NDBG_PRINT("error invalid op\n");
                                break;
                        }
                        }
                        break;
                }
                // -----------------------------------------
                // IP
                // -----------------------------------------
                case ::waflz_pb::sec_action_t_setvar_t_scope_t_IP:
                {
                        // TODO ???
                        continue;
                }
                // -----------------------------------------
                // default
                // -----------------------------------------
                default:
                {
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
int32_t waf::process_resp_rule_part(waflz_pb::event **ao_event,
                                        bool &ao_match,
                                        const waflz_pb::sec_rule_t &a_rule,
                                        resp_ctx &a_ctx,
                                        const rule_information_t a_rule_information)
{
        macro *l_macro =  &(m_engine.get_macro());
        ao_match = false;
        const waflz_pb::sec_action_t &l_a = a_rule.action();
        bool l_multimatch = l_a.multimatch();
        // -------------------------------------------------
        // get operator
        // -------------------------------------------------
        if(!a_rule.has_operator_() ||
           !a_rule.operator_().has_type())
        {
                // TODO log error -shouldn't happen???
                return WAFLZ_STATUS_OK;
        }
        const ::waflz_pb::sec_rule_t_operator_t& l_op = a_rule.operator_();
        op_t l_op_cb = NULL;
        l_op_cb = get_op_cb(l_op.type());
        // -------------------------------------------------
        // check if rtu variables exist
        // -------------------------------------------------
        std::string l_rtu_key = a_rule_information.m_parent_rule_id + "_" + to_string(a_rule_information.m_depth);
        auto l_rtu_map_iterator = m_rtu_variable_map.find(l_rtu_key);
        bool l_rtu_variables_exist = l_rtu_map_iterator != m_rtu_variable_map.end();
        std::vector<waflz_pb::variable_t> l_rtu_variables;
        if (l_rtu_variables_exist) { l_rtu_variables = l_rtu_map_iterator->second; }
        // -------------------------------------------------
        // variable loop
        // -------------------------------------------------
        uint32_t l_var_count = 0;
        for(int32_t i_var = 0; i_var < a_rule.variable_size(); ++i_var)
        {
                // -----------------------------------------
                // get var cb
                // -----------------------------------------
                const waflz_pb::variable_t& l_var = (l_rtu_variables_exist) ? l_rtu_variables[i_var] : a_rule.variable(i_var);
                if(!l_var.has_type())
                {
                        return WAFLZ_STATUS_OK;
                }
                get_resp_var_t l_get_var = NULL;
                l_get_var = get_resp_var_cb(l_var.type());
                if(!l_get_var)
                {
                        return WAFLZ_STATUS_OK;
                }
                int32_t l_s;
                const char *l_x_data;
                uint32_t l_x_len;
                // -----------------------------------------
                // extract list of data
                // -----------------------------------------
                const_arg_list_t l_data_list;
                l_s = l_get_var(l_data_list, l_var_count, l_var, &a_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // Handle count first
                // -----------------------------------------
                if(l_var.is_count())
                {
                        std::string l_v_c = to_string(l_var_count);
                        l_x_data = l_v_c.c_str();
                        l_x_len = l_v_c.length();
                        bool l_match = false;
                        if(!l_op_cb)
                        {
                                continue;
                        }
                        l_s = l_op_cb(l_match, l_op, l_x_data, l_x_len, l_macro, NULL, &a_ctx);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                // TODO log reason???
                                return WAFLZ_STATUS_ERROR;
                        }
                        if(!l_match)
                        {
                                continue;
                        }
                        // Reflect Variable name
                        const google::protobuf::EnumValueDescriptor* l_var_desc =
                                        waflz_pb::variable_t_type_t_descriptor()->FindValueByNumber(l_var.type());
                        a_ctx.m_cx_matched_var.assign(l_x_data, l_x_len);
                        a_ctx.m_cx_matched_var_name = l_var_desc->name();
                        ao_match = true;
                        break;
                }
                // -----------------------------------------
                // data loop
                // -----------------------------------------
                for(const_arg_list_t::const_iterator i_v = l_data_list.begin();
                    i_v != l_data_list.end();
                    ++i_v)
                {
                        // ---------------------------------
                        // transformation loop
                        // ---------------------------------
                        // ---------------------------------
                        // Set size to at least one if no tx
                        // specified
                        // ---------------------------------
                        int32_t l_t_size = l_a.t_size() ? l_a.t_size() : 1;
                        l_x_data = i_v->m_val;
                        l_x_len = i_v->m_val_len;
                        bool l_mutated = false;
                        for(int32_t i_t = 0; i_t < l_t_size; ++i_t)
                        {
                                // -------------------------
                                // *************************
                                //           T X
                                // *************************
                                // -------------------------
                                waflz_pb::sec_action_t_transformation_type_t l_t_type = waflz_pb::sec_action_t_transformation_type_t_NONE;
                                if(i_t > 1 ||
                                   l_a.t_size())
                                {
                                        l_t_type = l_a.t(i_t);
                                }
                                if(l_t_type == waflz_pb::sec_action_t_transformation_type_t_NONE)
                                {
                                        goto run_op;
                                }
                                // -------------------------
                                // if tx...
                                // -------------------------
                                {
                                tx_cb_t l_tx_cb = NULL;
                                l_tx_cb = get_tx_cb(l_t_type);
                                if(!l_tx_cb)
                                {
                                        continue;
                                }
                                char *l_tx_data = NULL;
                                uint32_t l_tx_len = 0;
                                l_s = l_tx_cb(&l_tx_data, l_tx_len, l_x_data, l_x_len);
                                if(l_s != WAFLZ_STATUS_OK)
                                {
                                        // TODO log reason???
                                        return WAFLZ_STATUS_ERROR;
                                }
                                // -------------------------
                                // if mutated again free
                                // last
                                // -------------------------
                                if(l_mutated)
                                {
                                        free(const_cast <char *>(l_x_data));
                                        l_x_len = 0;
                                        l_mutated = false;
                                }
                                l_mutated = true;
                                l_x_data = l_tx_data;
                                l_x_len = l_tx_len;
                                // -------------------------
                                // break if no data
                                // no point in transforming
                                // or matching further
                                // -------------------------
                                if(!l_x_data ||
                                   !l_x_len)
                                {
                                        break;
                                }
                                }
run_op:
                                // -------------------------
                                // skip op if:
                                // not multimatch
                                // AND
                                // not the end of the list
                                // -------------------------
                                if(!l_multimatch &&
                                   (i_t != (l_t_size - 1)))
                                {
                                        continue;
                                }
                                // -------------------------
                                // *************************
                                //           O P
                                // *************************
                                // -------------------------
                                if(!l_op_cb)
                                {
                                        // TODO log error -shouldn't happen???
                                        continue;
                                }
                                bool l_match = false;
                                l_s = l_op_cb(l_match, l_op, l_x_data, l_x_len, l_macro, NULL, &a_ctx);
                                if(l_s != WAFLZ_STATUS_OK)
                                {
                                        // TODO log reason???
                                        return WAFLZ_STATUS_ERROR;
                                }
                                if(!l_match)
                                {
                                        continue;
                                }
                                if(l_var.type() ==  waflz_pb::variable_t_type_t_ARGS_COMBINED_SIZE)
                                {
                                        a_ctx.m_cx_matched_var_name = "ARGS_COMBINED_SIZE";
                                        a_ctx.m_cx_matched_var = to_string(l_x_len);
                                }
                                else
                                {
                                        // Reflect Variable name
                                        const google::protobuf::EnumValueDescriptor* l_var_desc =
                                                        waflz_pb::variable_t_type_t_descriptor()->FindValueByNumber(l_var.type());
                                        a_ctx.m_cx_matched_var.assign(l_x_data, l_x_len);
                                        a_ctx.m_cx_matched_var_name = l_var_desc->name();
                                        if(i_v->m_key_len)
                                        {
                                                std::string l_var_name(i_v->m_key, strnlen(i_v->m_key, i_v->m_key_len));
                                                a_ctx.m_cx_matched_var_name +=":";
                                                a_ctx.m_cx_matched_var_name.append(l_var_name);
                                                //WFLZ_TRC_MATCH("MATCHED VAR : %s\n", a_ctx.m_cx_matched_var_name.c_str());
                                        }
                                }
                                /*WFLZ_TRC_MATCH("%s%s%s\n",
                                                ANSI_COLOR_FG_MAGENTA,
                                                a_rule.ShortDebugString().c_str(),
                                                ANSI_COLOR_OFF);*/
                                ao_match = true;
                                break;
                        }
                        // ---------------------------------
                        // final cleanup
                        // ---------------------------------
                        if(l_mutated)
                        {
                                free(const_cast <char *>(l_x_data));
                                l_x_data = NULL;
                                l_x_len = 0;
                                l_mutated = false;
                                //a_ctx.m_src_asn_str.m_tx_applied = 0; // Reset
                        }
                        // ---------------------------------
                        // got a match -outtie
                        // ---------------------------------
                        if(ao_match)
                        {
                                break;
                        }
                }
                // -----------------------------------------
                // got a match -outtie
                // -----------------------------------------
                if(ao_match)
                {
                        break;
                }
        }
        // -------------------------------------------------
        // *************************************************
        //                A C T I O N S
        // *************************************************
        // -------------------------------------------------
        if(ao_match)
        {
#define _SET_RULE_INFO(_field, _str) \
if(l_a.has_##_field()) { \
data_t l_k; l_k.m_data = _str; l_k.m_len = sizeof(_str) - 1; \
data_t l_v; \
l_v.m_data = l_a._field().c_str(); \
l_v.m_len = l_a._field().length(); \
a_ctx.m_cx_rule_map[l_k] = l_v; \
}
                // -----------------------------------------
                // set rule info
                // -----------------------------------------
                _SET_RULE_INFO(id, "id");
                _SET_RULE_INFO(msg, "msg");
                // -----------------------------------------
                // TODO -only run
                // non-disruptive???
                // -----------------------------------------
                int32_t l_s = process_resp_action_nd(l_a, a_ctx, a_rule_information.m_parent_rule_id);
                if(l_s == WAFLZ_STATUS_ERROR)
                {
                        NDBG_PRINT("error executing action");
                }
                //NDBG_PRINT("%sACTIONS%s: !!!\n%s%s%s\n",
                //           ANSI_COLOR_BG_CYAN, ANSI_COLOR_OFF,
                //           ANSI_COLOR_FG_CYAN, l_a.ShortDebugString().c_str(), ANSI_COLOR_OFF);
        }
        // -------------------------------------------------
        // null out any set skip values
        // -------------------------------------------------
        else
        {
                a_ctx.m_skip = 0;
                a_ctx.m_skip_after = NULL;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t waf::process_resp_rule(waflz_pb::event **ao_event,
                               const waflz_pb::sec_rule_t &a_rule,
                               resp_ctx &a_ctx)
{
        // -------------------------------------------------
        // top level rule id
        // -------------------------------------------------
        const std::string l_rule_id = a_rule.action().id();
        // -------------------------------------------------
        // chain rule loop
        // -------------------------------------------------
        const waflz_pb::sec_rule_t *l_rule = NULL;
        int32_t l_cr_idx = -1;
        bool i_match = false;
        do {
                //NDBG_PRINT("RULE[%4d]************************************\n", l_cr_idx);
                //NDBG_PRINT("l_cr_idx: %d\n", l_cr_idx);
                // -------------------------------------------------
                // construct id for rtu variables
                // -------------------------------------------------
                uint32_t l_rule_depth = l_cr_idx + 1;
                if(l_cr_idx == -1)
                {
                        l_rule = &a_rule;
                }
                else if((l_cr_idx >= 0) &&
                        (l_cr_idx < a_rule.chained_rule_size()))
                {
                        l_rule = &(a_rule.chained_rule(l_cr_idx));
                }
                else
                {
                        //WAFLZ_PERROR(m_err_msg, "bad chained rule idx: %d -size: %d",
                        //             l_cr_idx,
                        //             a_rule.chained_rule_size());
                        return WAFLZ_STATUS_ERROR;
                }
                //show_rule_info(a_rule);
                // Get action
                if(!l_rule->has_action())
                {
                        // TODO is OK???
                        ++l_cr_idx;
                        continue;
                }
                if(!l_rule->has_operator_())
                {
                        // TODO this aight???
                        // TODO is OK???
                        ++l_cr_idx;
                        continue;
                }
                int32_t l_s;
                i_match = false;
                rule_information_t l_rule_information;
                l_rule_information.m_parent_rule_id = l_rule_id;
                l_rule_information.m_depth = l_rule_depth;
                l_s = process_resp_rule_part(
                    ao_event, i_match, *l_rule, a_ctx, l_rule_information);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        //WAFLZ_PERROR(m_err_msg, "bad chained rule idx: %d -size: %d",
                        //             l_cr_idx,
                        //             a_rule.chained_rule_size());
                        return WAFLZ_STATUS_ERROR;
                }
                if(!i_match)
                {
                        // bail out on first un-matched...
                        //WFLZ_TRC_MATCH("bail out on first un-matched...\n");
                        return WAFLZ_STATUS_OK;
                }
                ++l_cr_idx;
        } while(l_cr_idx < a_rule.chained_rule_size());
        // -------------------------------------------------
        // never matched...
        // -------------------------------------------------
        if(!i_match)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // matched...
        // -------------------------------------------------
        if(!a_rule.has_action())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // run disruptive action...
        // -------------------------------------------------
        int32_t l_s;
        l_s = process_resp_match(ao_event, a_rule, a_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                NDBG_PRINT("error processing rule\n");
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t waf::process_resp_phase(waflz_pb::event **ao_event,
                                const directive_list_t &a_dl,
                                const marker_map_t &a_mm,
                                resp_ctx &a_ctx)
{
        a_ctx.m_intercepted = false;
        for(directive_list_t::const_iterator i_d = a_dl.begin();
            i_d != a_dl.end();
            ++i_d)
        {
                if(!(*i_d))
                {
                        //NDBG_PRINT("SKIPPING\n");
                        continue;
                }
                // -----------------------------------------
                // marker
                // -----------------------------------------
                const ::waflz_pb::directive_t& l_d = **i_d;
                if(l_d.has_marker())
                {
                        //NDBG_PRINT("%sMARKER%s: %s%s%s\n",
                        //           ANSI_COLOR_BG_RED, ANSI_COLOR_OFF,
                        //           ANSI_COLOR_BG_RED, l_d.marker().c_str(), ANSI_COLOR_OFF);
                        continue;
                }
                // -----------------------------------------
                // action
                // -----------------------------------------
                if(l_d.has_sec_action())
                {
                        const waflz_pb::sec_action_t &l_a = l_d.sec_action();
                        int32_t l_s = process_resp_action_nd(l_a, a_ctx, "");
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                NDBG_PRINT("error processing rule\n");
                        }
                        continue;
                }
                // -----------------------------------------
                // rule
                // -----------------------------------------
                if(l_d.has_sec_rule())
                {
                        const waflz_pb::sec_rule_t &l_r = l_d.sec_rule();
                        if(!l_r.has_action())
                        {
                                //NDBG_PRINT("error no action for rule: %s\n", l_r.ShortDebugString().c_str());
                                continue;
                        }
                        int32_t l_s;
                        l_s = process_resp_rule(ao_event, l_r, a_ctx);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                }
                // -----------------------------------------
                // break if intercepted
                // -----------------------------------------
                if(a_ctx.m_intercepted)
                {
                        break;
                }
                // -----------------------------------------
                // handle skip
                // -----------------------------------------
                if(a_ctx.m_skip)
                {
                        //NDBG_PRINT("%sskipping%s...: %d\n", ANSI_COLOR_BG_YELLOW, ANSI_COLOR_OFF, a_ctx.m_skip);
                        while(a_ctx.m_skip &&
                              (i_d != a_dl.end()))
                        {
                                ++i_d;
                                --a_ctx.m_skip;
                        }
                        a_ctx.m_skip = 0;
                }
                else if(a_ctx.m_skip_after)
                {
                        //NDBG_PRINT("%sskipping%s...: %s\n", ANSI_COLOR_BG_YELLOW, ANSI_COLOR_OFF, a_ctx.m_skip_after);
                        marker_map_t::const_iterator i_nd;
                        i_nd = a_mm.find(a_ctx.m_skip_after);
                        if(i_nd != a_mm.end())
                        {
                                i_d = i_nd->second;
                        }
                        a_ctx.m_skip_after = NULL;
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t waf::process_response(waflz_pb::event **ao_event,
                              void *a_ctx,
                              resp_ctx **ao_resp_ctx,
                              bool a_custom_rules)
{
        if(!m_pb)
        {
                return WAFLZ_STATUS_ERROR;
        }
#ifdef WAFLZ_NATIVE_ANOMALY_MODE
        m_anomaly_score_cur = 0;
#endif
        int32_t l_s = WAFLZ_STATUS_OK;
        // -------------------------------------------------
        // create new if null
        // -------------------------------------------------
        resp_ctx *l_ctx = NULL;
        if(ao_resp_ctx &&
           *ao_resp_ctx)
        {
                l_ctx = *ao_resp_ctx;
        }
        if(!l_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        if(m_pb->has_request_body_in_memory_limit())
        {
                l_ctx->set_body_max_len(m_pb->request_body_in_memory_limit());
        }
        // -------------------------------------------------
        // *************************************************
        //                   P H A S E  3
        // *************************************************
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        l_s = l_ctx->init_phase_3(m_engine.get_geoip2_mmdb());
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO -log error???
                if(l_ctx && !ao_resp_ctx) { delete l_ctx; l_ctx = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // process
        // -------------------------------------------------
        l_s = process_resp_phase(ao_event,
                                 m_compiled_config->m_directive_list_phase_3,
                                 m_compiled_config->m_marker_map_phase_3,
                                 *l_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO -log error???
                if(l_ctx && !ao_resp_ctx) { delete l_ctx; l_ctx = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        if(l_ctx->m_intercepted)
        {
                goto report;
        }
        // -------------------------------------------------
        // *************************************************
        //                 P H A S E  4
        // *************************************************
        // -------------------------------------------------
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        l_s = l_ctx->init_phase_4();
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO -log error???
                if(l_ctx && !ao_resp_ctx) { delete l_ctx; l_ctx = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // process
        // -------------------------------------------------
        l_s = process_resp_phase(ao_event,
                                 m_compiled_config->m_directive_list_phase_4,
                                 m_compiled_config->m_marker_map_phase_4,
                                 *l_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO -log error???
                if(l_ctx && !ao_resp_ctx) { delete l_ctx; l_ctx = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
report:
        if(!*ao_event)
        {
                if(l_ctx && !ao_resp_ctx) { delete l_ctx; l_ctx = NULL;}
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // add meta
        // -------------------------------------------------
        waflz_pb::event &l_event = **ao_event;      
        if(l_event.sub_event_size())
        {
                const ::waflz_pb::event& l_se = l_event.sub_event(l_event.sub_event_size() - 1);
                // -----------------------------------------
                // rule target...
                // -----------------------------------------
                ::waflz_pb::event_var_t* l_ev = l_event.add_rule_target();
                l_ev->set_name("TX");
                l_ev->set_param("ANOMALY_SCORE");
                // -----------------------------------------
                // matched_var...
                // -----------------------------------------
                if(l_se.has_matched_var())
                {
                        l_event.mutable_matched_var()->CopyFrom(l_se.matched_var());
                }
                // -----------------------------------------
                // Custom rules wont have an anomaly score
                // and setvar for rule msg. Set them here
                // -----------------------------------------
                if (a_custom_rules)
                {
                        l_event.set_rule_msg(l_se.rule_msg());
                }
                // -----------------------------------------
                // op
                // -----------------------------------------
                l_event.mutable_rule_op_name()->assign("gt");
                l_event.mutable_rule_op_param()->assign("0");
        }
#define _SET_IF_EXIST(_str, _field) do { \
if(l_ctx->m_cx_tx_map.find(_str) != l_ctx->m_cx_tx_map.end()) \
{ l_event.set_##_field((uint32_t)(strtoul(l_ctx->m_cx_tx_map[_str].c_str(), NULL, 10))); } \
else { l_event.set_##_field(0); } \
} while(0)
        _SET_IF_EXIST("ANOMALY_SCORE", total_anomaly_score);
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if(l_ctx && !ao_resp_ctx) { delete l_ctx; l_ctx = NULL;}
        return WAFLZ_STATUS_OK;
}


//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t waf::process(waflz_pb::event **ao_event,
                     void *a_ctx,
                     rqst_ctx **ao_rqst_ctx,
                     bool a_custom_rules)
{
        if(!m_pb)
        {
                return WAFLZ_STATUS_ERROR;
        }
#ifdef WAFLZ_NATIVE_ANOMALY_MODE
        m_anomaly_score_cur = 0;
#endif
        int32_t l_s = WAFLZ_STATUS_OK;
        // -------------------------------------------------
        // create new if null
        // -------------------------------------------------
        rqst_ctx *l_ctx = NULL;
        if(ao_rqst_ctx &&
           *ao_rqst_ctx)
        {
                l_ctx = *ao_rqst_ctx;
        }
        if(!l_ctx)
        {
                WAFLZ_PERROR(m_err_msg, "ao_rqst_ctx == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        if(m_pb->has_request_body_in_memory_limit())
        {
                l_ctx->set_body_max_len(m_pb->request_body_in_memory_limit());
        }
        // -------------------------------------------------
        // *************************************************
        //                   P H A S E  1
        // *************************************************
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        l_s = l_ctx->init_phase_1(m_engine);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO -log error???
                if(l_ctx && !ao_rqst_ctx) { delete l_ctx; l_ctx = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // process
        // -------------------------------------------------
        l_s = process_phase(ao_event,
                            m_compiled_config->m_directive_list_phase_1,
                            m_compiled_config->m_marker_map_phase_1,
                            *l_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO -log error???
                if(l_ctx && !ao_rqst_ctx) { delete l_ctx; l_ctx = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        if(l_ctx->m_intercepted)
        {
                goto report;
        }
        // -------------------------------------------------
        // *************************************************
        //                 P H A S E  2
        // *************************************************
        // -------------------------------------------------
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        l_s = l_ctx->init_phase_2(m_ctype_parser_map);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO -log error???
                if(l_ctx && !ao_rqst_ctx) { delete l_ctx; l_ctx = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // Set inspect body flag based on current profile
        // setting. Body is always parsed, for custom rules
        // all parsers are needed, there is no point not parsing
        // it. Set flag here and then in var.cc return variables
        // accordingly
        // -------------------------------------------------
        // -------------------------------------------------
        if(a_custom_rules)
        {
                l_ctx->m_inspect_body = true;
        }
        else
        {
                l_ctx->m_inspect_body = ((l_ctx->m_json_body && m_parse_json) ||
                                        (l_ctx->m_xml_body && m_parse_xml) ||
                                         l_ctx->m_url_enc_body);

        }
        // -------------------------------------------------
        // process
        // -------------------------------------------------
        l_s = process_phase(ao_event,
                            m_compiled_config->m_directive_list_phase_2,
                            m_compiled_config->m_marker_map_phase_2,
                            *l_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO -log error???
                if(l_ctx && !ao_rqst_ctx) { delete l_ctx; l_ctx = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // check for intercepted...
        // -------------------------------------------------
        if(!l_ctx->m_intercepted)
        {
                if(*ao_event)
                {
                        delete *ao_event;
                        *ao_event = NULL;
                }
                if(l_ctx && !ao_rqst_ctx) { delete l_ctx; l_ctx = NULL;}
                return WAFLZ_STATUS_OK;
        }
report:
        if(!*ao_event)
        {
                if(l_ctx && !ao_rqst_ctx) { delete l_ctx; l_ctx = NULL;}
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // add meta
        // -------------------------------------------------
        waflz_pb::event &l_event = **ao_event;
        // -------------------------------------------------
        // *************************************************
        // handling anomaly mode natively...
        // *************************************************
        // -------------------------------------------------
#ifdef WAFLZ_NATIVE_ANOMALY_MODE
        if (!a_custom_rules)
        {
                std::string l_msg;
                const char l_msg_macro[] = "Inbound Anomaly Score Exceeded (Total Score: %{TX.ANOMALY_SCORE}): Last Matched Message: %{tx.msg}";
                macro *l_macro =  &(m_engine.get_macro());
                l_s = (*l_macro)(l_msg, l_msg_macro, l_ctx, NULL);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        if(l_ctx && !ao_rqst_ctx) { delete l_ctx; l_ctx = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                l_event.set_rule_msg(l_msg);
        }
#endif
        if (!a_custom_rules)
        {
                l_event.set_waf_profile_id(m_id);
                l_event.set_waf_profile_name(m_name);
        }
#define _SET_IF_EXIST(_str, _field) do { \
if(l_ctx->m_cx_tx_map.find(_str) != l_ctx->m_cx_tx_map.end()) \
{ l_event.set_##_field((uint32_t)(strtoul(l_ctx->m_cx_tx_map[_str].c_str(), NULL, 10))); } \
else { l_event.set_##_field(0); } \
} while(0)
        _SET_IF_EXIST("ANOMALY_SCORE", total_anomaly_score);
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if(l_ctx && !ao_rqst_ctx) { delete l_ctx; l_ctx = NULL;}
        return WAFLZ_STATUS_OK;
}
}
