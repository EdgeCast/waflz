//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _BOT_MANAGER_H_
#define _BOT_MANAGER_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "waflz/def.h"
#include "waflz/city.h"
#include "waflz/engine.h"
#include "action.pb.h"
#include "bot_manager.pb.h"
#include <string>
#include <set>
#include <string_view>
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
namespace waflz_pb {
class bot_manager;
class event;
class enforcement;
}
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
class bots;
class challenge;
class captcha;
class rqst_ctx;
class engine;
class regex;
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef std::list<regex *> pcre_list_t;
//! ----------------------------------------------------------------------------
//! custom types
//! ----------------------------------------------------------------------------
typedef std::map<std::string, waflz_pb::enforcement*> action_map_t;

typedef struct _action_pkg {
        waflz_pb::enforcement_type_t m_action_type;
        waflz_pb::enforcement_type_t m_spoof_action_type;

        _action_pkg():
                m_action_type(),
                m_spoof_action_type()
                {};

        _action_pkg(const waflz_pb::enforcement_type_t a_action,
                    const waflz_pb::enforcement_type_t a_spoof_action):
                m_action_type(a_action),
                m_spoof_action_type(a_spoof_action)
                {};

        _action_pkg( const _action_pkg& a_action_pkg ):
                m_action_type(a_action_pkg.m_action_type),
                m_spoof_action_type(a_action_pkg.m_spoof_action_type)
                {};

} action_pkg_t;

typedef struct _known_bot_config_info_t {
        ns_waflz::action_pkg_t m_actions;
        const waflz_pb::bot_manager_known_bot_t* m_info;

        _known_bot_config_info_t(const ns_waflz::action_pkg_t a_actions,
                                 const waflz_pb::bot_manager_known_bot_t* a_info):
                m_actions(a_actions),
                m_info(a_info)
                {};

} known_bot_config_info_t;
//! ----------------------------------------------------------------------------
//! TODO
//! ----------------------------------------------------------------------------
class bot_manager
{
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        bot_manager(engine& a_engine, 
                    challenge& a_challenge,
                    captcha& m_captcha);
        ~bot_manager();
        int32_t verify_bot_actions();
        int32_t process(waflz_pb::event** ao_event,
                        const waflz_pb::enforcement** ao_enf,
                        void* a_ctx,
                        rqst_ctx** ao_rqst_ctx = NULL);
        int32_t load(const char* a_buf, uint32_t a_buf_len,
                     const std::string& a_conf_dir_path);
        int32_t load(void* a_js, const std::string& a_conf_dir_path);
        int32_t load(const waflz_pb::bot_manager* a_pb, const std::string& a_conf_dir_path);
        int32_t load_bots(void* a_js, bool& l_update);
        int32_t load_categories_entry();
        int32_t find_config_info_for_data_pkg(const cat_data_pkg_t* a_data_pkg,
                                              action_pkg_t& ao_action_pkg,
                                              const waflz_pb::bot_manager_known_bot_t** ao_bot_info,
                                              bool& a_found);
        int32_t is_spoofed_request(rqst_ctx& a_ctx,
                                   const ns_waflz::known_bot_info_t* a_company,
                                   const waflz_pb::bot_manager_known_bot_t* a_company_config,
                                   bool& a_spoofed,
                                   std::string& a_matched_string);
        int32_t process_known_bots(waflz_pb::event** ao_event,
                                   rqst_ctx& a_ctx,
                                   const waflz_pb::enforcement** ao_enf);
        int32_t process_known_categories(waflz_pb::event** ao_event,
                                         rqst_ctx& a_ctx,
                                         const waflz_pb::enforcement** ao_enf);
        int32_t process_challenge(bool* ao_pass,
                                  waflz_pb::event* ao_event,
                                  ns_waflz::rqst_ctx* a_rqst_ctx,
                                  const waflz_pb::enforcement* a_enf);
        int32_t process_recaptcha(bool* ao_issue_captcha,
                                  waflz_pb::event* ao_event,
                                  ns_waflz::rqst_ctx* a_rqst_ctx,
                                  const waflz_pb::enforcement* a_enf);
        int32_t set_enf_from_action_type(const waflz_pb::enforcement** ao_enf,
                                         std::string a_action_type);
        int32_t create_action_map( );
        bool compare_dates(const char* a_loaded_date, const char* a_new_date);
        //: ------------------------------------------------
        //: \details Get last error message string
        //: \return  last error message (in buffer)
        //: ------------------------------------------------
        const char* get_err_msg(void) { return m_err_msg; }
        const std::string& get_id(void) { return m_id; };
        const std::string& get_cust_id(void) { return m_cust_id; };
        bool is_team_config(void) { return m_team_config; }
        const std::string& get_name(void) { return m_name; };
        const waflz_pb::bot_manager* get_pb(void) { return m_pb; };
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        //DISALLOW_DEFAULT_CTOR(bot_manager);
        // disallow copy/assign
        bot_manager(const bot_manager &);
        bot_manager& operator=(const bot_manager &);
        // -------------------------------------------------
        // process exception list
        // -------------------------------------------------
        int32_t process_exception_list(bool &ao_match, rqst_ctx &a_ctx);
        int32_t regex_list_add(const std::string &a_regex, pcre_list_t &a_pcre_list);
        typedef std::set <std::string> stri_set_t;
        int32_t init(const std::string& a_conf_dir_path);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        bool m_init;
        char m_err_msg[WAFLZ_ERR_LEN];
        waflz_pb::bot_manager* m_pb;
        ns_waflz::bots* m_bots;
        engine& m_engine;
        // -------------------------------------------------
        // actions
        // -------------------------------------------------
        action_map_t m_actions;
        // -------------------------------------------------
        // properties
        // -------------------------------------------------
        std::string m_id;
        std::string m_cust_id;
        bool m_team_config;
        std::string m_name;
        bool m_inspect_known_bots;
        UNORDER_MAP_TYPE<ns_waflz::cat_data_pkg_t, known_bot_config_info_t, ns_waflz::cat_data_compare_unordered> m_kb_info_by_cat_and_comp;
        // -------------------------------------------------
        // bot challenge
        // -------------------------------------------------
        challenge& m_challenge;
        // -------------------------------------------------
        // captcha
        // -------------------------------------------------
        captcha& m_captcha;
        // -------------------------------------------------
        // exception list
        // -------------------------------------------------
        pcre_list_t m_el_url;
        pcre_list_t m_el_user_agent;
        pcre_list_t m_el_cookie;
        stri_set_t m_el_ja3;
        stri_set_t m_el_ja4;
};
}
#endif
