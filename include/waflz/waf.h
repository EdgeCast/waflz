//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _WAF_H
#define _WAF_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "waflz/parser.h"
#include <waflz/config_parser.h>
#include "waflz/def.h"
#include "waflz/rqst_ctx.h"
#include "waflz/resp_ctx.h"
#include <set>
#include <vector>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define WAFLZ_NATIVE_ANOMALY_MODE 1
//! ----------------------------------------------------------------------------
//! fwd decl's -proto
//! ----------------------------------------------------------------------------
namespace waflz_pb {
class sec_config_t;
class sec_rule_t;
class sec_action_t;
class profile_custom_score_t;
class directive_t;
class variable_t;
class event;
};

namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
class rqst_ctx;
class nms;
class ac;
class byte_range;
class engine;
class regex;
class profile;
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef std::map <std::string, std::vector<::waflz_pb::variable_t>> update_variable_map_t;
typedef std::list<regex *> regex_list_t;
typedef std::list<ac *> ac_list_t;
typedef std::list<nms *> nms_list_t;
typedef std::list<byte_range *> byte_range_list_t;
typedef std::list<const ::waflz_pb::directive_t *> directive_list_t;
typedef std::map<std::string, directive_list_t::const_iterator> marker_map_t;
typedef std::map<std::string, waflz_pb::enforcement*> action_map_t;
typedef std::set<std::string> disabled_rule_id_set_t;
typedef struct _rule_information {
        std::string m_parent_rule_id;
        uint32_t m_depth;
        _rule_information()
            : m_parent_rule_id(),
              m_depth()
        {};
} rule_information_t;
typedef std::tuple<regex *, std::string, std::string> redacted_var_t;
typedef std::list<redacted_var_t> redacted_var_list_t;
typedef struct _compiled_config {
        // phase 1
        marker_map_t m_marker_map_phase_1;
        directive_list_t m_directive_list_phase_1;
        // phase 2
        marker_map_t m_marker_map_phase_2;
        directive_list_t m_directive_list_phase_2;
         // phase 3
        marker_map_t m_marker_map_phase_3;
        directive_list_t m_directive_list_phase_3;
         // phase 4
        marker_map_t m_marker_map_phase_4;
        directive_list_t m_directive_list_phase_4;
        // storage
        regex_list_t m_regex_list;
        ac_list_t m_ac_list;
        nms_list_t m_nms_list;
        byte_range_list_t m_byte_range_list;
        _compiled_config():
                m_marker_map_phase_1(),
                m_directive_list_phase_1(),
                m_marker_map_phase_2(),
                m_directive_list_phase_2(),
                m_marker_map_phase_3(),
                m_directive_list_phase_3(),
                m_marker_map_phase_4(),
                m_directive_list_phase_4(),
                m_regex_list(),
                m_ac_list(),
                m_nms_list(),
                m_byte_range_list()
        {}
        ~_compiled_config();
} compiled_config_t;
//! ----------------------------------------------------------------------------
//! \details: TODO
//! ----------------------------------------------------------------------------
class waf
{
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        waf(engine &a_engine);
        ~waf();
        void process_multi_custom_score_entry( waflz_pb::profile_custom_score_t& a_custom_score );
        uint32_t calculate_rule_anomaly_score( cx_map_t& a_ctx_map, bool a_inbound );
        int32_t process(waflz_pb::event **ao_event, void *a_ctx, rqst_ctx **ao_rqst_ctx = NULL, bool a_custom_rules = false);
        int32_t process_response(waflz_pb::event **ao_event, void *a_ctx, resp_ctx **ao_resp_ctx = NULL, bool a_custom_rules = false);
        int32_t init(profile &a_profile);
        int32_t init(config_parser::format_t a_format, const std::string &a_path, bool a_apply_defaults = false, bool a_custom_rules = false);
        int32_t init(void* a_js, bool a_apply_defaults = false, bool a_custom_rules = false);
        int32_t get_str(std::string &ao_str, config_parser::format_t a_format);
        int32_t verify_bot_actions(action_map_t a_actions);
        const char *get_err_msg(void) { return m_err_msg; }
        waflz_pb::sec_config_t* get_pb(void) { return m_pb; }
        const std::string& get_id(void) { return m_id; }
        const std::string& get_cust_id(void) { return m_cust_id; }
        const std::string& get_name(void) { return m_name; }
        // -------------------------------------------------
        // properties
        // -------------------------------------------------
        void set_id(const std::string &a_id) { m_id = a_id; }
        void set_name(const std::string &a_name) { m_name = a_name; }
        void set_cust_id(const std::string& a_cust_id) {m_cust_id = a_cust_id; }
        void set_paranoia_level(uint32_t a_paranoia_level) { m_paranoia_level = a_paranoia_level; }
        void set_parse_xml( const bool &a_parse_xml) { m_parse_xml = a_parse_xml; }
        void set_parse_json( const bool &a_parse_json) { m_parse_json = a_parse_json; }
        void set_no_log_matched( const bool &a_no_log_matched) { m_no_log_matched = a_no_log_matched; }
        uint32_t get_paranoia_level(void) { return m_paranoia_level; }
        bool get_parse_xml(void) { return m_parse_xml; }
        bool get_parse_json(void) { return m_parse_json; }
        update_variable_map_t *get_rtu_map(void) { return &m_rtu_variable_map; }
        std::map<std::string, uint32_t> *get_custom_score_map(void) { return &m_custom_score_map; }
        bool is_team_config(void) { return m_team_config; }
        uint32_t get_request_body_in_memory_limit(void);
private:
        // -------------------------------------------------
        // private types
        // -------------------------------------------------
        typedef std::list<ac *> ac_list_t;
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        waf(const waf &);
        waf& operator=(const waf &);
        int32_t verify_bot_actions_for_directive_list(action_map_t a_actions,
                                                      directive_list_t a_directive_list);
        void clear_redacted_variables_list();
        // -------------------------------------------------
        // process request
        // -------------------------------------------------
        int32_t process_phase(waflz_pb::event **ao_event, const directive_list_t &a_dl, const marker_map_t &a_mm, rqst_ctx &a_ctx);
        int32_t process_rule(waflz_pb::event **ao_event, const waflz_pb::sec_rule_t &a_rule, rqst_ctx &a_ctx);
        int32_t process_rule_part(waflz_pb::event **ao_event, bool &ao_match, const waflz_pb::sec_rule_t &a_rule, rqst_ctx &a_ctx, const rule_information_t a_rule_information);
        int32_t process_action_nd(const waflz_pb::sec_action_t &a_action, rqst_ctx &a_ctx, const std::string a_rule_id);
        int32_t process_match(waflz_pb::event **ao_event, const waflz_pb::sec_rule_t &a_rule, rqst_ctx &a_ctx);
        // -------------------------------------------------
        // process response
        // -------------------------------------------------
        int32_t process_resp_phase(waflz_pb::event **ao_event, const directive_list_t &a_dl, const marker_map_t &a_mm, resp_ctx &a_ctx);
        int32_t process_resp_rule(waflz_pb::event **ao_event, const waflz_pb::sec_rule_t &a_rule, resp_ctx &a_ctx);
        int32_t process_resp_rule_part(waflz_pb::event **ao_event, bool &ao_match, const waflz_pb::sec_rule_t &a_rule, resp_ctx &a_ctx, const rule_information_t a_rule_information);
        int32_t process_resp_action_nd(const waflz_pb::sec_action_t &a_action, resp_ctx &a_ctx, const std::string a_rule_id);
        int32_t process_resp_match(waflz_pb::event **ao_event, const waflz_pb::sec_rule_t &a_rule, resp_ctx &a_ctx);
        // -------------------------------------------------
        // compile
        // -------------------------------------------------
        int32_t compile(void);
        int32_t set_defaults(bool a_custom_rules);
        // -------------------------------------------------
        // protobuf
        // -------------------------------------------------
        waflz_pb::sec_config_t *m_pb;
        // -------------------------------------------------
        // compiled...
        // -------------------------------------------------
        compiled_config_t *m_compiled_config;
        ctype_parser_map_t m_ctype_parser_map;
        // -------------------------------------------------
        // rtu variable map
        // -------------------------------------------------
        update_variable_map_t m_rtu_variable_map;
        std::map<std::string, uint32_t> m_custom_score_map;
        // -------------------------------------------------
        // modifications
        // -------------------------------------------------
        redacted_var_list_t m_redacted_vars;
        directive_list_t m_mx_rule_list;
#ifdef WAFLZ_NATIVE_ANOMALY_MODE
        uint32_t m_anomaly_score_cur;
        bool m_is_initd;
        char m_err_msg[WAFLZ_ERR_LEN];
        engine &m_engine;
        // -------------------------------------------------
        // properties
        // -------------------------------------------------
        std::string m_id;
        std::string m_cust_id;
        std::string m_name;
        std::string m_ruleset_dir;
        uint32_t m_paranoia_level;
        bool m_no_log_matched;
        bool m_parse_xml;
        bool m_parse_json;
        bool m_team_config;
#endif
        // -------------------------------------------------
        // sharing private fields with engine...
        // -------------------------------------------------
        friend engine;
};
}
#endif
