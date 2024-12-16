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
#include "waflz/def.h"
#include "waflz/bot_manager.h"
#include "waflz/bots.h"
#include "waflz/challenge.h"
#include "waflz/captcha.h"
#include "waflz/city.h"
#include "waflz/lm_db.h"
#include "op/regex.h"
#include "jspb/jspb.h"
#include "action.pb.h"
#include "event.pb.h"
#include "rule.pb.h"
#include "support/ndebug.h"
#include "support/time_util.h"
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define _CONFIG_PROFILE_MAX_SIZE (1<<20)
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
#define _GET_HEADER(_header, _val) do { \
        _val = NULL; \
        _val##_len = 0; \
        l_d.m_data = _header; \
        l_d.m_len = sizeof(_header) - 1; \
        data_unordered_map_t::const_iterator i_h = l_hm.find(l_d); \
        if (i_h != l_hm.end()) \
        { \
                _val = i_h->second.m_data; \
                _val##_len = i_h->second.m_len; \
        } \
} while (0)
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
static void clear_exception_list(pcre_list_t &a_pcre_list)
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
static bool key_in_exception_list(const pcre_list_t &a_pcre_list,
                                  const char *a_data,
                                  uint32_t a_data_len)
{
        for (pcre_list_t::const_iterator i_c = a_pcre_list.begin();
            i_c != a_pcre_list.end();
            ++i_c)
        {
                regex *l_regex = *i_c;
                if (!l_regex)
                {
                        continue;
                }
                int32_t l_s;
                // -----------------------------------------
                // match?
                // -----------------------------------------
                l_s = l_regex->compare(a_data, a_data_len);
                // -----------------------------------------
                // We have a match
                // -----------------------------------------
                if (l_s >= 0)
                {
                       return true;
                }
        }
        return false;
}
//! -----------------
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
bot_manager::bot_manager(engine& a_engine,
                         challenge& a_challenge,
                         captcha& a_captcha):
        m_init(false),
        m_err_msg(),
        m_pb(NULL),
        m_bots(NULL),
        m_engine(a_engine),
        m_actions(),
        m_id("__na__"),
        m_cust_id("__na__"),
        m_team_config(false),
        m_name("__na__"),
        m_inspect_known_bots(false),
        m_kb_info_by_cat_and_comp(),
        m_challenge(a_challenge),
        m_captcha(a_captcha),
        m_el_url(),
        m_el_user_agent(),
        m_el_cookie(),
        m_el_ja3(),
        m_el_ja4()
{
}
//! ----------------------------------------------------------------------------
//! \details dtor
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
bot_manager::~bot_manager()
{
        if (m_pb) { delete m_pb; m_pb = NULL; }
        if (m_bots) { delete m_bots; m_bots = NULL; }
        clear_exception_list(m_el_url);
        clear_exception_list(m_el_user_agent);
        clear_exception_list(m_el_cookie);
}
//! ----------------------------------------------------------------------------
//! \details load/update bots during fast path update
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t bot_manager::load_bots(void* a_js, bool& a_update)
{
        // -------------------------------------------------
        // quick exit if we dont have a bot config
        // -------------------------------------------------
        if (!m_bots)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // get the id from the json
        // -------------------------------------------------
        const rapidjson::Document &l_js = *((rapidjson::Document *)a_js);
        if(!l_js.HasMember("id") || !l_js["id"].IsString()) 
        {
                WAFLZ_PERROR(m_err_msg, "missing id");
                return WAFLZ_STATUS_ERROR;
        }
        const std::string l_id = l_js["id"].GetString();
        // -------------------------------------------------
        // quick exit if the bot ids dont match
        // -------------------------------------------------
        if(l_id != m_bots->get_id())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // get the last modified date from the config
        // -------------------------------------------------
        const bool l_has_modified_date = (l_js.HasMember("last_modified_date") &&
                                          l_js["last_modified_date"].IsString());
        // -------------------------------------------------
        // check if the last modified date is older than the
        // current config.
        //
        // exit if the config is older
        // -------------------------------------------------
        const waflz_pb::sec_config_t* l_old_pb = m_bots->get_pb();
        if ((l_old_pb != NULL) &&
           (l_old_pb->has_last_modified_date()) &&
           (l_has_modified_date))
        {
                const std::string l_last_modified_date = l_js["last_modified_date"].GetString();
                if (!compare_dates(l_old_pb->last_modified_date().c_str(),
                                   l_last_modified_date.c_str()))
                {
                        a_update = true;
                        return WAFLZ_STATUS_OK;
                }
        }
        // -------------------------------------------------
        // update the bots config
        // -------------------------------------------------
        if (m_bots) { delete m_bots; m_bots = NULL;}
        m_bots = new bots(m_engine, m_challenge);
        // -------------------------------------------------
        // load the json
        // -------------------------------------------------
        uint32_t l_s = m_bots->load(a_js);
        if (l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "%s", m_bots->get_err_msg());
                if (m_bots) { delete m_bots; m_bots = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // return status ok
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details load using file path. called during init and reloads
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t bot_manager::load(const char* a_buf, uint32_t a_buf_len, const std::string& a_conf_dir_path)
{
        int32_t l_s;
        if (a_buf_len > _CONFIG_PROFILE_MAX_SIZE)
        {
                WAFLZ_PERROR(m_err_msg, "config file size(%u) > max size(%u)",
                             a_buf_len,
                             _CONFIG_PROFILE_MAX_SIZE);
                return WAFLZ_STATUS_ERROR;
        }
        m_init = false;
        if (m_pb)
        {
            delete m_pb; 
            m_pb = NULL;
        }
        m_pb = new waflz_pb::bot_manager();
        // -------------------------------------------------
        // load from json
        // -------------------------------------------------
        l_s = update_from_json(*m_pb, a_buf, a_buf_len);
        if (l_s != JSPB_OK)
        {
                WAFLZ_PERROR(m_err_msg, "%s", get_jspb_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        l_s = init(a_conf_dir_path);
        if (l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details load using json object- this gets called during fast path
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t bot_manager::load(void* a_js, const std::string& a_conf_dir_path)
{
        const rapidjson::Document& l_js = *((rapidjson::Document *)a_js);
        int32_t l_s;
        if (m_pb)
        {
                delete m_pb;
                m_pb = NULL;
        }
        m_pb = new waflz_pb::bot_manager();
        l_s = update_from_json(*m_pb, l_js);
        if (l_s != JSPB_OK)
        {
                WAFLZ_PERROR(m_err_msg, "parsing json. Reason: %s", get_jspb_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        l_s = init(a_conf_dir_path);
        if (l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details makes a bot_manager from a proto
//! \return  waflz status
//! \param   a_pb a bot_manager protobuf
//! \param   a_conf_dir_path the path to the conf directory
//! ----------------------------------------------------------------------------
int32_t bot_manager::load(const waflz_pb::bot_manager* a_pb, const std::string& a_conf_dir_path)
{
        if (!a_pb)
        {
                WAFLZ_PERROR(m_err_msg, "pb == NULL (input)");
                return WAFLZ_STATUS_ERROR;
        }
        m_init = false;
        if (m_pb)
        {
                delete m_pb;
                m_pb = NULL;
        }
        // -------------------------------------------------
        // copy from bot_manager pb
        // -------------------------------------------------
        m_pb = new waflz_pb::bot_manager();
        m_pb->CopyFrom(*a_pb);
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        int32_t l_s;
        l_s = init(a_conf_dir_path);
        if (l_s != WAFLZ_STATUS_OK)
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
int32_t bot_manager::verify_bot_actions()
{
        // -------------------------------------------------
        // enforcement_type_t descriptor to get names
        // -------------------------------------------------
        auto *l_enf_desc = waflz_pb::enforcement_type_t_descriptor();
        // -------------------------------------------------
        // spoof_bot_action_type
        // -------------------------------------------------
        if ( m_pb->has_spoof_bot_action_type() )
        {
                // -----------------------------------------
                // convert enforcement_type_t to name
                // -----------------------------------------
                const waflz_pb::enforcement_type_t l_action_type = m_pb->spoof_bot_action_type(); 
                const std::string l_entry_name = l_enf_desc->FindValueByNumber(l_action_type)->name();
                // -----------------------------------------
                // return error if the bot_action is not found
                // -----------------------------------------
                if ( m_actions.find(l_entry_name) == m_actions.end() )
                {
                        WAFLZ_PERROR(m_err_msg, "found unknown bot_action '%s' in spoof_bot_action_type\n",
                                     l_entry_name.c_str());
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // bots_prod_action_type
        // -------------------------------------------------
        if ( m_pb->has_bots_prod_action_type() )
        {
                // -----------------------------------------
                // convert enforcement_type_t to name
                // -----------------------------------------
                const waflz_pb::enforcement_type_t l_action_type = m_pb->bots_prod_action_type(); 
                const std::string l_entry_name = l_enf_desc->FindValueByNumber(l_action_type)->name();
                // -----------------------------------------
                // return error if the bot_action is not found
                // -----------------------------------------
                if ( m_actions.find(l_entry_name) == m_actions.end() )
                {
                        WAFLZ_PERROR(m_err_msg, "found unknown bot_action '%s' in bots_prod_action_type\n",
                                     l_entry_name.c_str());
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // known_bots
        // -------------------------------------------------
        for(auto i_t = m_pb->known_bots().begin();
            i_t != m_pb->known_bots().end();
            i_t++)
        {
                if ( !(*i_t).has_action_type() ) { continue; }
                // -----------------------------------------
                // convert enforcement_type_t to name
                // -----------------------------------------
                const waflz_pb::enforcement_type_t l_action_type = (*i_t).action_type(); 
                const std::string l_entry_name = l_enf_desc->FindValueByNumber(l_action_type)->name();
                // -----------------------------------------
                // return error if the bot_action is not found
                // -----------------------------------------
                if ( m_actions.find(l_entry_name) == m_actions.end() )
                {
                        WAFLZ_PERROR(m_err_msg, "found unknown bot_action '%s' in known_bot '%s'\n",
                                     l_entry_name.c_str(),
                                     (*i_t).bot_token().c_str());
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // quick exit if categories is not being used
        // -------------------------------------------------
        if (m_engine.get_use_knb_cat())
        {
                // -----------------------------------------
                // known bot categories
                // -----------------------------------------
                for(auto i_t = m_pb->categories().begin();
                i_t != m_pb->categories().end();
                i_t++)
                {
                        if ( !(*i_t).has_action_type() ) { continue; }
                        // ---------------------------------
                        // validate that action_type is
                        // defined
                        // ---------------------------------
                        if ( (*i_t).has_action_type() ) {
                                const waflz_pb::enforcement_type_t l_action_type = (*i_t).action_type(); 
                                const std::string l_entry_name = l_enf_desc->FindValueByNumber(l_action_type)->name();
                                // -------------------------
                                // return error if the
                                // bot_action is not found
                                // -------------------------
                                if ( m_actions.find(l_entry_name) == m_actions.end() )
                                {
                                        WAFLZ_PERROR(m_err_msg, "found unknown bot_action '%s' in category entry '%s'\n",
                                                l_entry_name.c_str(),
                                                (*i_t).category().c_str());
                                        return WAFLZ_STATUS_ERROR;
                                }
                        }
                        // ---------------------------------
                        // validate that spoof_action_type
                        // is defined
                        // ---------------------------------
                        if ( (*i_t).has_spoof_action_type() ) {
                                const waflz_pb::enforcement_type_t l_action_type = (*i_t).spoof_action_type(); 
                                const std::string l_entry_name = l_enf_desc->FindValueByNumber(l_action_type)->name();
                                // -------------------------
                                // return error if the
                                // bot_action is not found
                                // -------------------------
                                if ( m_actions.find(l_entry_name) == m_actions.end() )
                                {
                                        WAFLZ_PERROR(m_err_msg, "found unknown spoof_bot_action '%s' in category entry '%s'\n",
                                                l_entry_name.c_str(),
                                                (*i_t).category().c_str());
                                        return WAFLZ_STATUS_ERROR;
                                }
                        }
                        // ---------------------------------
                        // company entries
                        // ---------------------------------
                        for(auto i_t_comp = (*i_t).companies().begin();
                        i_t_comp != (*i_t).companies().end();
                        i_t_comp++)
                        {
                                // -------------------------
                                // validate that
                                // action_type is defined
                                // -------------------------
                                if ( (*i_t_comp).has_action_type() ) {
                                        const waflz_pb::enforcement_type_t l_action_type = (*i_t_comp).action_type(); 
                                        const std::string l_entry_name = l_enf_desc->FindValueByNumber(l_action_type)->name();
                                        // -----------------
                                        // return error if
                                        // the bot_action 
                                        // is not found
                                        // -----------------
                                        if ( m_actions.find(l_entry_name) == m_actions.end() )
                                        {
                                                WAFLZ_PERROR(m_err_msg, "found unknown bot_action '%s' in category entry '%s' company '%s'\n",
                                                        l_entry_name.c_str(),
                                                        (*i_t).category().c_str(),
                                                        (*i_t_comp).bot_token().c_str());
                                                return WAFLZ_STATUS_ERROR;
                                        }
                                }
                                // -------------------------
                                // validate that 
                                // spoof_action_type is defined
                                // -------------------------
                                if ( (*i_t_comp).has_spoof_action_type() ) {
                                        const waflz_pb::enforcement_type_t l_action_type = (*i_t_comp).spoof_action_type(); 
                                        const std::string l_entry_name = l_enf_desc->FindValueByNumber(l_action_type)->name();
                                        // -----------------
                                        // return error if
                                        // the bot_action
                                        // is not found
                                        // -----------------
                                        if ( m_actions.find(l_entry_name) == m_actions.end() )
                                        {
                                                WAFLZ_PERROR(m_err_msg, "found unknown spoof_bot_action '%s' in category entry '%s' company '%s'\n",
                                                        l_entry_name.c_str(),
                                                        (*i_t).category().c_str(),
                                                        (*i_t_comp).bot_token().c_str());
                                                return WAFLZ_STATUS_ERROR;
                                        }
                                }
                        }
                }
        }
        // -------------------------------------------------
        // verify bot_actions used in rules
        // -------------------------------------------------
        if (!m_bots) { return WAFLZ_STATUS_OK; }
        int32_t l_s = m_bots->verify_bot_actions(m_actions);
        if (l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "%s", m_bots->get_err_msg());
        }
        return l_s;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t bot_manager::regex_list_add(const std::string &a_regex,
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
                WAFLZ_PERROR(m_err_msg, "init failed for regex: '%s' bot manager exception list. Reason: %s -offset: %d",
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
//! \details loads the `categories` entry in the protobuff
//! \return  waflz status
//! -----------------------------------------------------------------------------
int32_t bot_manager::load_categories_entry()
{
        // -------------------------------------------------
        // known bot info so we can validate values in the
        // fields
        // -------------------------------------------------
        auto l_known_bot_categories = m_engine.get_knb_categories();
        auto l_known_bot_companies = m_engine.get_known_bot_info_map();
        // -------------------------------------------------
        // loop through each category
        // -------------------------------------------------
        for (int32_t i_cat_index = 0; i_cat_index < m_pb->categories_size(); i_cat_index++)
        {
                // -----------------------------------------
                // category entry
                // -----------------------------------------
                auto& l_cat_entry = m_pb->categories(i_cat_index);
                // -----------------------------------------
                // VERIFY: there is a category value
                // -----------------------------------------
                if (!l_cat_entry.has_category() || l_cat_entry.category().empty())
                {
                        WAFLZ_PERROR(m_err_msg,
                                     "Failed to parse category entry: 'category' field missing or empty in entry %d",
                                     i_cat_index);
                        return WAFLZ_STATUS_ERROR;
                }
                if (l_known_bot_categories.find(l_cat_entry.category()) == l_known_bot_categories.end())
                {
                        WAFLZ_PERROR(m_err_msg, "Unknown category: '%s'", l_cat_entry.category().c_str());
                        return WAFLZ_STATUS_ERROR;
                }

                // -----------------------------------------
                // insert default action for category
                // -----------------------------------------
                auto l_default_key = cat_data_pkg_t(l_cat_entry.category(), "");
                const waflz_pb::enforcement_type_t l_default_action = l_cat_entry.action_type();
                const waflz_pb::enforcement_type_t l_default_spoof_action = l_cat_entry.has_spoof_action_type() ?
                                                                                l_cat_entry.spoof_action_type() :
                                                                                m_pb->spoof_bot_action_type();
                // -----------------------------------------
                // for every company token
                // -----------------------------------------
                for (int32_t i_comp_index = 0; i_comp_index < l_cat_entry.companies_size(); i_comp_index++)
                {
                        // ---------------------------------
                        // company entry
                        // ---------------------------------
                        auto& l_comp_entry = l_cat_entry.companies(i_comp_index);
                        // ---------------------------------
                        // VERIFY: there is a bot token
                        // ---------------------------------
                        if (!l_comp_entry.has_bot_token() || l_comp_entry.bot_token().empty())
                        {
                                WAFLZ_PERROR(m_err_msg,
                                        "Failed to parse company entry for '%s' category: 'bot_token' field missing or empty in entry %d",
                                        l_cat_entry.category().c_str(),
                                        i_comp_index);
                                return WAFLZ_STATUS_ERROR;
                        }
                        // ---------------------------------
                        // VERIFY: the bot_token (company)
                        // exists
                        // ---------------------------------
                        if ( auto l_known_comp_info = l_known_bot_companies.find(l_comp_entry.bot_token());
                             l_known_comp_info == l_known_bot_companies.end() )
                        {
                                WAFLZ_PERROR(m_err_msg,
                                        "Unknown company entry '%s'",
                                        l_comp_entry.bot_token().c_str());
                                return WAFLZ_STATUS_ERROR;
                        }
                        // ---------------------------------
                        // get action and spoof action
                        // ---------------------------------
                        const waflz_pb::enforcement_type_t l_action_type = l_comp_entry.has_action_type() ?
                                                                        l_comp_entry.action_type() :
                                                                        l_default_action;
                        const waflz_pb::enforcement_type_t l_spoof_action_type = l_comp_entry.has_spoof_action_type() ?
                                                                        l_comp_entry.spoof_action_type() :
                                                                        l_default_spoof_action;
                        // ---------------------------------
                        // insert <cat, comp> ->
                        // <<action, spoof>, config_info>
                        // ---------------------------------
                        auto l_key = cat_data_pkg_t(l_cat_entry.category(), l_comp_entry.bot_token());
                        auto l_val = known_bot_config_info_t(action_pkg_t(l_action_type, l_spoof_action_type), &l_comp_entry);
                        auto l_specific_inserted = m_kb_info_by_cat_and_comp.insert(std::make_pair(l_key,l_val));
                        // ---------------------------------
                        // VERIFY: there is no dup comp in
                        // category
                        // ---------------------------------
                        if (!l_specific_inserted.second)
                        {
                                WAFLZ_PERROR(m_err_msg,
                                        "Failed to parse category entry: duplicate company '%s' detected in category '%s'.",
                                        l_comp_entry.bot_token().c_str(),
                                        l_cat_entry.category().c_str());
                                return WAFLZ_STATUS_ERROR;
                        }
               }
        }
        // -------------------------------------------------
        // done :D
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details Update fields from bot manager proto
//! \return  waflz status
//! \param   
//! -----------------------------------------------------------------------------
int32_t bot_manager::init(const std::string& a_conf_dir_path)
{
        int32_t l_s;
        if (m_init)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // create action map from pb
        // -------------------------------------------------
        l_s = create_action_map();
        if (l_s != WAFLZ_STATUS_OK) { return WAFLZ_STATUS_ERROR; }
        // -------------------------------------------------
        // properties
        // -------------------------------------------------
        m_id = m_pb->id();
        m_cust_id = m_pb->customer_id();
        m_name = m_pb->name();
        m_inspect_known_bots = m_pb->inspect_known_bots();
        if (m_pb->has_team_config())
        {
                m_team_config = m_pb->team_config();
        }
        // -------------------------------------------------
        // make bots obj
        // -------------------------------------------------
        if ( m_pb->has_bots_prod_id())
        {
            std::string l_path;
            l_path = a_conf_dir_path + "/bots/" + m_cust_id + "-" + m_pb->bots_prod_id() +".bots.json";
            bots* l_bots = new bots(m_engine, m_challenge);
            l_s = l_bots->load_file(l_path.c_str(), l_path.length());
            if (l_s != WAFLZ_STATUS_OK)
            {
                    WAFLZ_PERROR(m_err_msg, "error loading conf file-reason: %.*s",
                                 WAFLZ_ERR_REASON_LEN,
                                 l_bots->get_err_msg());
                    if (l_bots) { delete l_bots; l_bots = NULL;}
                    return WAFLZ_STATUS_ERROR;
            }
            m_bots = l_bots;
        }
        // -------------------------------------------------
        // exception list: url
        // -------------------------------------------------
        for(int32_t i_q = 0;
            i_q < m_pb->exception_url_size();
            ++i_q)
        {
                std::string l_url = m_pb->exception_url(i_q);
                l_s = regex_list_add(l_url, m_el_url);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // exception list: user-agent
        // -------------------------------------------------
        for(int32_t i_q = 0;
            i_q < m_pb->exception_user_agent_size();
            ++i_q)
        {
                std::string l_ua = m_pb->exception_user_agent(i_q);
                l_s = regex_list_add(l_ua, m_el_user_agent);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // exception list: cookie
        // -------------------------------------------------
        for(int32_t i_q = 0;
            i_q < m_pb->exception_cookie_size();
            ++i_q)
        {
                std::string l_cookie = m_pb->exception_cookie(i_q);
                l_s = regex_list_add(l_cookie, m_el_cookie);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // exception list: ja3
        // -------------------------------------------------
        for(int32_t i_t = 0; i_t < m_pb->exception_ja3_size(); ++i_t)
        {
                m_el_ja3.insert(m_pb->exception_ja3(i_t));
        }
        // -------------------------------------------------
        // exception list: ja4
        // -------------------------------------------------
        for(int32_t i_t = 0; i_t < m_pb->exception_ja4_size(); ++i_t)
        {
                m_el_ja4.insert(m_pb->exception_ja4(i_t));
        }
        // -------------------------------------------------
        // load categories if enabled in waflz
        // -------------------------------------------------
        if (m_engine.get_use_knb_cat() && load_categories_entry() != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // verify the config works
        // -------------------------------------------------
        if (verify_bot_actions() != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // successful init
        // -------------------------------------------------
        m_init = true;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details process bot mananger config
//! \return  waflz status
//! \param
//! -----------------------------------------------------------------------------
int32_t bot_manager::is_spoofed_request(rqst_ctx& a_ctx,
                                        const ns_waflz::known_bot_info_t* a_company_info,
                                        const waflz_pb::bot_manager_known_bot_t* a_company_config,
                                        bool& a_spoofed,
                                        std::string& a_matched_string)
{
        // -------------------------------------------------
        // check if ip is in nms for company
        // -------------------------------------------------
        bool l_ip_match = false;
        if (a_company_info->m_ips.contains(l_ip_match, a_ctx.m_src_addr.m_data, a_ctx.m_src_addr.m_len) != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "failed on nms");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // set match string and spoofed value
        // -------------------------------------------------
        a_spoofed = !l_ip_match;
        a_matched_string.assign(a_ctx.m_src_addr.m_data,
                                a_ctx.m_src_addr.m_len);
        // -------------------------------------------------
        // at this point,we can return if:
        // 1) the ip was found (not a spoof)
        // 2) the company has strict matching enabled
        // -------------------------------------------------
        if (l_ip_match) { return WAFLZ_STATUS_OK; }
        else if (a_company_config && a_company_config->strict_match())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // check if there is an asn match and update the
        // match string
        // -------------------------------------------------
        if (auto l_asn_found = a_company_info->m_asns.find(a_ctx.m_geo_data.m_src_asn);
            l_asn_found != a_company_info->m_asns.end())
        {

                a_spoofed = false;
                a_matched_string.assign(a_ctx.m_src_asn_str.m_data,
                                        a_ctx.m_src_asn_str.m_len);
        }
        // -------------------------------------------------
        // done :D
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details process bot mananger config
//! \return  waflz status
//! \param
//! -----------------------------------------------------------------------------
int32_t bot_manager::find_config_info_for_data_pkg(const cat_data_pkg_t* a_data_pkg,
                                                   action_pkg_t& ao_action_pkg,
                                                   const waflz_pb::bot_manager_known_bot_t** ao_bot_info,
                                                   bool& a_found)
{
        a_found = false;
        // -------------------------------------------------
        // check if there are <cateogry,company> specific
        // actions
        // -------------------------------------------------
        if (auto l_specific_info = m_kb_info_by_cat_and_comp.find(*a_data_pkg);
            l_specific_info != m_kb_info_by_cat_and_comp.end())
        {
                ao_action_pkg = (*l_specific_info).second.m_actions;
                (*ao_bot_info) = (*l_specific_info).second.m_info;
                a_found = true;
        }
        // -------------------------------------------------
        // done :D
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details process bot mananger config
//! \return  waflz status
//! \param
//! -----------------------------------------------------------------------------
int32_t bot_manager::process_known_categories(waflz_pb::event** ao_event,
                                        rqst_ctx& a_ctx,
                                        const waflz_pb::enforcement** ao_enf)
{
        // -------------------------------------------------
        // STEP 1) find a bot token
        // -------------------------------------------------
        // -------------------------------------------------
        // STEP 1.1) get user agent from request
        // -------------------------------------------------
        auto l_user_agent = a_ctx.get_header(std::string_view("User-Agent"));
        if (!l_user_agent)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // STEP 1.2) search for token in user agent via AC
        // -------------------------------------------------
        std::string l_match_string;
        cat_data_pkg_t* l_data = nullptr;
        ac& l_knb_tokens = m_engine.get_knb_tokens();
        if (!l_knb_tokens.find_with_data(l_user_agent->m_data, l_user_agent->m_len, l_match_string, (void**)&l_data))
        {
                // -----------------------------------------
                // Nothing was found = not a known bot
                // -----------------------------------------
                return WAFLZ_STATUS_OK;
        }
        if (!l_data)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // STEP 2) get actions and check if the customer
        // has this category/bot enabled
        // -------------------------------------------------
        bool l_enabled = false;
        action_pkg_t l_actions;
        const waflz_pb::bot_manager_known_bot_t* l_company_config = nullptr;
        if ((find_config_info_for_data_pkg(l_data, l_actions, &l_company_config, l_enabled) != WAFLZ_STATUS_OK) ||
            (!l_enabled))
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // STEP 3) verify the request is a bot
        // -------------------------------------------------
        bool l_is_spoofed = false;
        std::string l_matched_string = "__na__";
        if (l_data->m_company != "other")
        {
                // -----------------------------------------
                // STEP 3.1) get company information
                // -----------------------------------------
                known_bot_info_map_t l_knb_info_map = m_engine.get_known_bot_info_map();
                auto l_company_entry = l_knb_info_map.find(l_data->m_company);
                if (l_company_entry == l_knb_info_map.end())
                {
                        return WAFLZ_STATUS_OK;
                }
                known_bot_info_t* l_company = l_company_entry->second;
                // -----------------------------------------
                // STEP 3.2) check if the request is spoofed
                // NOTE: fails silently
                // -----------------------------------------
                if ( is_spoofed_request(a_ctx, l_company, l_company_config, l_is_spoofed, l_matched_string) != WAFLZ_STATUS_OK )
                {
                        WAFLZ_PERROR(m_err_msg, "Failed to validate request");
                        return WAFLZ_STATUS_OK;
                }
        }
        // -------------------------------------------------
        // STEP 4) create enforcement and event
        //   
        //   not spoofed (or 'other') = action_type
        //   spoofed = spoof_action_type
        // -------------------------------------------------
        // -------------------------------------------------
        // STEP 4.1) special check - return with no event
        // if appropriate action is set to ignore
        // -------------------------------------------------
        waflz_pb::enforcement_type_t l_action_to_use = l_is_spoofed ?
                                                         l_actions.m_spoof_action_type :
                                                         l_actions.m_action_type;
        if ( l_action_to_use == waflz_pb::enforcement_type_t_IGNORE )
                return WAFLZ_STATUS_OK;
        // -------------------------------------------------
        // STEP 4.2) create enforcement
        // -------------------------------------------------
        auto *l_desc = ::waflz_pb::enforcement_type_t_descriptor();
        std::string l_action_type = l_desc->FindValueByNumber(l_action_to_use)->name();
        if (set_enf_from_action_type(ao_enf, l_action_type) != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "Failed to get enforcement from action type");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // STEP 4.3) create event
        // -------------------------------------------------
        waflz_pb::event* l_event = new ::waflz_pb::event();
        l_event->set_known_bot_type(l_data->m_company);
        l_event->set_known_bot_category(l_data->m_category);
        if (!l_is_spoofed)
        {
                // -----------------------------------------
                // A known bot from <category> is detected
                // -----------------------------------------
                l_event->set_rule_msg("Known bot detected");
                // -----------------------------------------
                // mark request as known bot
                // -----------------------------------------
                a_ctx.m_known_bot = true;
                // -----------------------------------------
                // subevent
                // -----------------------------------------
                waflz_pb::event* l_sevent = l_event->add_sub_event();
                if (l_data->m_company == "other")
                {
                        l_sevent->set_rule_id(70002);
                        l_sevent->set_rule_msg("Known Bot: Other Known Bot");
                        l_sevent->set_rule_op_name("PM");
                        l_sevent->set_rule_op_param("User-Agent");
                }
                else
                {
                        l_sevent->set_rule_id(70001);
                        l_sevent->set_rule_msg("Known Bot: Explicit Known Bot Token");
                        l_sevent->set_rule_op_name("ipMatch&PM");
                        l_sevent->set_rule_op_param("IP&User-Agent");
                }
                // -----------------------------------------
                // matched var
                // -----------------------------------------
                ::waflz_pb::event_var_t* l_var = l_sevent->mutable_matched_var();
                l_var->set_name("known_bot");
                l_var->set_value( (!l_matched_string.empty()) ?
                                  l_matched_string :
                                  "__na__" );
        }
        else
        {
                // -----------------------------------------
                // spoofing attempted
                // -----------------------------------------
                l_event->set_rule_msg("Attempt to spoof a known bot");
                // -----------------------------------------
                // subevent
                // -----------------------------------------
                waflz_pb::event* l_sevent = l_event->add_sub_event();
                l_sevent->set_rule_id(70000);
                l_sevent->set_rule_msg("Spoofed Bot: Client Impersonating A Known Bot");
                l_sevent->set_rule_op_name("ipMatch");
                l_sevent->set_rule_op_param("ipKnownBot");
                l_sevent->add_rule_tag("spoofed bot");
                // -----------------------------------------
                // rule target
                // -----------------------------------------
                waflz_pb::event_var_t* l_rule_target = l_sevent->add_rule_target();
                l_rule_target->set_name("TX");
                l_rule_target->set_param("REAL_IP");
                // -----------------------------------------
                // matched var
                // -----------------------------------------
                ::waflz_pb::event_var_t* l_var = l_sevent->mutable_matched_var();
                l_var->set_name("spoofed_bot");
                l_var->set_value( (!l_matched_string.empty()) ?
                                  l_matched_string :
                                  "__na__" );

        }
        // -------------------------------------------------
        // STEP 5) special actions
        // -------------------------------------------------
        if ((*ao_enf)->enf_type() == waflz_pb::enforcement_type_t_BROWSER_CHALLENGE)
        {
                // ---------------------------------
                // process challenge
                // ---------------------------------
                bool l_pass = false;
                int32_t l_s = process_challenge(&l_pass, l_event, &a_ctx, *ao_enf);
                if (l_pass)
                {
                        if (l_event) { delete l_event; l_event =  NULL; }
                        return l_s;
                }
        }
        else if ((*ao_enf)->enf_type() == waflz_pb::enforcement_type_t_RECAPTCHA)
        {
                bool l_issue_captcha = false;
                int32_t l_s;
                l_s = process_recaptcha(&l_issue_captcha,
                                        l_event,
                                        &a_ctx,
                                        *ao_enf);

                if (l_s == WAFLZ_STATUS_OK)
                {
                        //captcha verification passed. Continue processing
                        if (l_event) { delete l_event; l_event =  NULL; }
                        return WAFLZ_STATUS_OK;
                }
                else if (l_s == WAFLZ_STATUS_WAIT)
                {
                        //sub request in process
                        *ao_event = l_event;
                        return WAFLZ_STATUS_WAIT;
                }
                else
                {
                        // issue captcha
                        if (l_issue_captcha)
                        {
                                // do nothing. issue captcha.
                                // bye sending an event
                        }
                        else
                        {
                                //other processing error.
                                if (l_event) { delete l_event; l_event =  NULL; }
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        // -------------------------------------------------
        // STEP 6) done :D
        // -------------------------------------------------
        (*ao_event) = l_event;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details process bot mananger config
//! \return  waflz status
//! \param
//! -----------------------------------------------------------------------------
int32_t bot_manager::process_known_bots(waflz_pb::event** ao_event,
                                        rqst_ctx& a_ctx,
                                        const waflz_pb::enforcement** ao_enf)
{
        int32_t l_s;
        const char* l_buf = NULL;
        uint32_t l_buf_len = 0;
        data_t l_d;
        const data_unordered_map_t& l_hm = a_ctx.m_header_map;
        // -------------------------------------------------
        // information populated on user-agent match
        // -------------------------------------------------
        std::string l_bot_token;
        known_bot_info_map_t::iterator l_comp_info;
        waflz_pb::bot_manager_known_bot_t* l_bot;
        // -------------------------------------------------
        // get known bot information from the engine
        // -------------------------------------------------
        known_bot_info_map_t l_knb_info_map = m_engine.get_known_bot_info_map();
        if (l_knb_info_map.empty())
        {
                // fail silently?
                WAFLZ_PERROR(m_err_msg, "no data available to check known bots");
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // get user_agent
        // -------------------------------------------------
        _GET_HEADER("User-Agent", l_buf);
        if (!l_buf ||
           !l_buf_len)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // Check UA in ua map first
        // -------------------------------------------------
        std::string l_match_str;
        bool l_ua_match = false;
        for (int32_t i_bot = 0; i_bot < m_pb->known_bots_size(); ++i_bot)
        {
                // -----------------------------------------
                // get known company
                // -----------------------------------------
                l_bot = m_pb->mutable_known_bots(i_bot);
                l_bot_token = l_bot->bot_token();
                // -----------------------------------------
                // get info for company - skip if doesnt
                // exist
                // -----------------------------------------
                l_comp_info = l_knb_info_map.find(l_bot_token);
                if (l_comp_info == l_knb_info_map.end())
                {
                        continue;
                }
                // -----------------------------------------
                // get ac for company
                // -----------------------------------------
                ac* l_user_agents_for_comp = &(l_comp_info->second->m_user_agents);
                // -----------------------------------------
                // look for match with user-agent
                // -----------------------------------------
                l_ua_match = l_user_agents_for_comp->find_first(l_buf, l_buf_len, l_match_str, false);
                if (l_ua_match)
                {
                        *ao_enf = &(l_bot->action());
                        // ---------------------------------
                        // check for action_type to apply
                        // ---------------------------------
                        if ( l_bot->has_action_type() )
                        {
                                // ---------------------------------
                                // get string from bot_action_type_t
                                // ---------------------------------
                                auto *l_desc = ::waflz_pb::enforcement_type_t_descriptor();
                                std::string l_action_type = l_desc->FindValueByNumber(l_bot->action_type())->name();
                                // ---------------------------------
                                // set enf from map
                                // ---------------------------------
                                set_enf_from_action_type(ao_enf, l_action_type);
                        }
                        // -----------------------------------------
                        // if no action_type specified, fall back
                        // to action specified in config
                        // -----------------------------------------
                        else
                        {
                                *ao_enf = &(l_bot->action());
                        }
                        break;
                }
        }
        if (!l_ua_match)
        {
                // ---------------------------------
                // UA didnt match, no need to check
                // further
                // ---------------------------------
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // if they have a user-agent that appears in the
        // other category, we make an event
        // -------------------------------------------------
        if (l_bot_token == "other")
        {
                // -----------------------------------------
                // check if enforcement to apply
                // -----------------------------------------
                if (!(*ao_enf))
                {
                        return WAFLZ_STATUS_OK;
                }
                // -----------------------------------------
                // make event object
                // -----------------------------------------
                waflz_pb::event* l_event = new ::waflz_pb::event();
                l_event->set_rule_msg("A known bot user-agent");
                // -------------------------------------------------
                // TODO: Instead of token, get the actual match
                // from ac object's find_first() routine
                // -------------------------------------------------
                l_event->set_known_bot_type(l_bot_token);
                // -----------------------------------------
                // subevent
                // -----------------------------------------
                ::waflz_pb::event* l_sevent = l_event->add_sub_event();
                l_sevent->set_rule_id(70002);
                l_sevent->set_rule_msg("Known Bot: Other Known Bot Categories");
                l_sevent->set_rule_op_name("PM");
                l_sevent->set_rule_op_param("User-Agent");
                l_sevent->add_rule_tag("known bot");
                ::waflz_pb::event_var_t* l_var = l_sevent->mutable_matched_var();
                l_var->set_name("known_bot");
                if (!l_match_str.empty())
                {
                        l_var->set_value(l_match_str);
                }
                else
                {
                        l_var->set_value("__na__");
                }
                // -----------------------------------------
                //
                // -----------------------------------------
                if ((*ao_enf)->enf_type() == waflz_pb::enforcement_type_t_BROWSER_CHALLENGE)
                {
                        // ---------------------------------
                        // process challenge
                        // ---------------------------------
                        bool l_pass = false;
                        l_s = process_challenge(&l_pass, l_event, &a_ctx, *ao_enf);
                        if (l_pass)
                        {
                                if (l_event) { delete l_event; l_event =  NULL; }
                                return l_s;
                        }
                }
                else if ((*ao_enf)->enf_type() == waflz_pb::enforcement_type_t_RECAPTCHA)
                {
                        bool l_issue_captcha = false;
                        int32_t l_s;
                        l_s = process_recaptcha(&l_issue_captcha,
                                                l_event,
                                                &a_ctx,
                                                *ao_enf);

                        if (l_s == WAFLZ_STATUS_OK)
                        {
                                //captcha verification passed. Continue processing
                                if (l_event) { delete l_event; l_event =  NULL; }
                                return WAFLZ_STATUS_OK;
                        }
                        else if (l_s == WAFLZ_STATUS_WAIT)
                        {
                                //sub request in process
                                *ao_event = l_event;
                                return WAFLZ_STATUS_WAIT;
                        }
                        else
                        {
                                // issue captcha
                                if (l_issue_captcha)
                                {
                                        // do nothing. issue captcha.
                                        // bye sending an event
                                }
                                else
                                {
                                        //other processing error.
                                        if (l_event) { delete l_event; l_event =  NULL; }
                                        return WAFLZ_STATUS_ERROR;
                                }
                        }
                }
                // -----------------------------------------
                // set event and return
                // -----------------------------------------
                *ao_event = l_event;
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // sanity check
        // -------------------------------------------------
        if ( l_comp_info == l_knb_info_map.end() )
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // get nms for company
        // -------------------------------------------------
        bool l_ip_match = false;
        nms* l_nms = &(l_comp_info->second->m_ips);
        if ( l_nms != nullptr )
        {
                // -----------------------------------------
                // check ip is contained in nms
                // -----------------------------------------
                l_s = l_nms->contains(l_ip_match, a_ctx.m_src_addr.m_data, a_ctx.m_src_addr.m_len);
                if (l_s != WAFLZ_STATUS_OK)
                {
                        // TODO log???
                        WAFLZ_PERROR(m_err_msg, "failed on nms");
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // if the ip doesnt match, we are going to allow
        // them to pass through if their asn matches and
        // the config is marked as non-strict
        // -------------------------------------------------
        if (!l_ip_match && l_bot && !l_bot->strict_match())
        {
                // -----------------------------------------
                // get asn for company
                // -----------------------------------------
                unordered_uint_set_t* l_asns_for_comp = &(l_comp_info->second->m_asns);
                if ( l_asns_for_comp != nullptr )
                {
                        // -----------------------------------------
                        // check if there is an asn match and
                        // update ip match to be if the asn is found
                        // instead
                        // -----------------------------------------
                        auto l_asn_found = l_asns_for_comp->find(a_ctx.m_geo_data.m_src_asn);
                        l_ip_match = l_asn_found != l_asns_for_comp->end();
                        if (l_ip_match)
                        {
                                l_match_str.assign(a_ctx.m_src_asn_str.m_data, a_ctx.m_src_asn_str.m_len);
                        }
                }
        }
        // -------------------------------------------------
        // If we reach here, it means user-agent flagged on
        // known bot token. If ip doesn't match our list
        // Mark it as someone spoofing known bot
        // -------------------------------------------------
        waflz_pb::event* l_event = new ::waflz_pb::event();
        if (!l_ip_match)
        {
                // -----------------------------------------
                // check for known bot spoof action_type to
                // apply
                // -----------------------------------------
                if ( l_bot && l_bot->has_spoof_action_type() )
                {
                        auto *l_desc = ::waflz_pb::enforcement_type_t_descriptor();
                        std::string l_action_type = l_desc->FindValueByNumber(l_bot->spoof_action_type())->name();
                        set_enf_from_action_type(ao_enf, l_action_type);
                }
                // -----------------------------------------
                // check for global spoof action to apply
                // -----------------------------------------
                else if ( m_pb->has_spoof_bot_action_type() )
                {
                        auto *l_desc = ::waflz_pb::enforcement_type_t_descriptor();
                        std::string l_action_type = l_desc->FindValueByNumber(m_pb->spoof_bot_action_type())->name();
                        set_enf_from_action_type(ao_enf, l_action_type);
                }
                // -----------------------------------------
                // if no action_type specified, fall back
                // to spoof action
                // -----------------------------------------
                else
                {
                        *ao_enf = &(m_pb->spoof_bot_action());
                }
                // -----------------------------------------
                // if no enforcement, return early
                // -----------------------------------------
                if (!(*ao_enf))
                {
                        if (l_event) { delete l_event; l_event = NULL; }
                        return WAFLZ_STATUS_OK;
                }
                l_event->set_rule_msg("Attempt to spoof a known bot");
                // -------------------------------------------------
                // TODO: Instead of token, get the actual match
                // from ac object's find_first() routine
                // -------------------------------------------------
                l_event->set_known_bot_type(l_bot_token);
                // -----------------------------------------
                // subevent
                // -----------------------------------------
                ::waflz_pb::event* l_sevent = l_event->add_sub_event();
                l_sevent->set_rule_id(70000);
                l_sevent->set_rule_msg("Spoofed Bot: Client Impersonating A Known Bot");
                l_sevent->set_rule_op_name("ipMatch");
                l_sevent->set_rule_op_param("ipKnownBot");
                l_sevent->add_rule_tag("spoofed bot");
                ::waflz_pb::event_var_t* l_rule_target = l_sevent->add_rule_target();
                l_rule_target->set_name("TX");
                l_rule_target->set_param("REAL_IP");
                ::waflz_pb::event_var_t* l_var = l_sevent->mutable_matched_var();
                l_var->set_name("spoofed_bot");
                if (!l_match_str.empty())
                {
                        l_var->set_value(l_match_str);
                }
                else
                {
                        l_var->set_value("__na__");
                }
                // -----------------------------------------
                // handle browser challenge and recaptcha
                // -----------------------------------------
                if ((*ao_enf)->enf_type() == waflz_pb::enforcement_type_t_BROWSER_CHALLENGE)
                {
                        // ---------------------------------
                        // process challenge
                        // ---------------------------------
                        bool l_pass = false;
                        l_s = process_challenge(&l_pass, l_event, &a_ctx, *ao_enf);
                        if (l_pass)
                        {
                                if (l_event) { delete l_event; l_event =  NULL; }
                                return l_s;
                        }
                }
               else if ((*ao_enf)->enf_type() == waflz_pb::enforcement_type_t_RECAPTCHA)
                {
                        bool l_issue_captcha = false;
                        int32_t l_s;
                        l_s = process_recaptcha(&l_issue_captcha,
                                                l_event,
                                                &a_ctx,
                                                *ao_enf);

                        if (l_s == WAFLZ_STATUS_OK)
                        {
                                //captcha verification passed. Continue processing
                                if (l_event) { delete l_event; l_event =  NULL; }
                                return WAFLZ_STATUS_OK;
                        }
                        else if (l_s == WAFLZ_STATUS_WAIT)
                        {
                                //sub request in process
                                *ao_event = l_event;
                                return WAFLZ_STATUS_WAIT;
                        }
                        else
                        {
                                // issue captcha
                                if (l_issue_captcha)
                                {
                                        // do nothing. issue captcha.
                                        // bye sending an event
                                }
                                else
                                {
                                        //other processing error.
                                        if (l_event) { delete l_event; l_event =  NULL; }
                                        return WAFLZ_STATUS_ERROR;
                                }
                        }
                }
                // -----------------------------------------
                // set event and return
                // -----------------------------------------
                *ao_event = l_event;
                return WAFLZ_STATUS_OK;
        }
        if (!(*ao_enf))
        {
                if (l_event) { delete l_event; l_event = NULL; }
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // Its a known bot and no spoof attempt
        // -------------------------------------------------
        l_event->set_rule_msg("Known bot detected");
        // -------------------------------------------------
        // mark the request as coming from a known bot
        // -------------------------------------------------
        a_ctx.m_known_bot = true;
        // -------------------------------------------------
        // TODO: Instead of token, get the actual match
        // from ac object's find_first() routine
        // -------------------------------------------------
        l_event->set_known_bot_type(l_bot_token);
        // -----------------------------------------
        // subevent
        // -----------------------------------------
        ::waflz_pb::event* l_sevent = l_event->add_sub_event();
        l_sevent->set_rule_id(70001);
        l_sevent->set_rule_msg("Known Bot: Explicit Known Bot Token");
        l_sevent->set_rule_op_name("ipMatch&PM");
        l_sevent->set_rule_op_param("IP&User-Agent");
        l_sevent->add_rule_tag("known bot");
        ::waflz_pb::event_var_t* l_var = l_sevent->mutable_matched_var();
        l_var->set_name("known_bot");
        if (!l_match_str.empty())
        {
                l_var->set_value(l_match_str);
        }
        else
        {
                l_var->set_value("__na__");
        }
        // -------------------------------------------------
        // handle browser challenge and recaptcha 
        // -------------------------------------------------
        if ((*ao_enf)->enf_type() == waflz_pb::enforcement_type_t_BROWSER_CHALLENGE)
        {
                // -----------------------------------------
                // process challenge
                // -----------------------------------------
                bool l_pass = false;
                l_s = process_challenge(&l_pass, l_event, &a_ctx, *ao_enf);
                if (l_pass)
                {
                        if (l_event) { delete l_event; l_event =  NULL; }
                        return l_s;
                }
        }
        else if ((*ao_enf)->enf_type() == waflz_pb::enforcement_type_t_RECAPTCHA)
        {
                bool l_issue_captcha = false;
                int32_t l_s;
                l_s = process_recaptcha(&l_issue_captcha,
                                        l_event,
                                        &a_ctx,
                                        *ao_enf);

                if (l_s == WAFLZ_STATUS_OK)
                {
                        //captcha verification passed. Continue processing
                        if (l_event) { delete l_event; l_event =  NULL; }
                        return WAFLZ_STATUS_OK;
                }
                else if (l_s == WAFLZ_STATUS_WAIT)
                {
                        //sub request in process
                        *ao_event = l_event;
                        return WAFLZ_STATUS_WAIT;
                }
                else
                {
                        // issue captcha
                        if (l_issue_captcha)
                        {
                                // do nothing. issue captcha.
                                // bye sending an event
                        }
                        else
                        {
                                //other processing error.
                                if (l_event) { delete l_event; l_event =  NULL; }
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        // -----------------------------------------
        // set event and return
        // -----------------------------------------
        *ao_event = l_event;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details process bot mananger exception list. If a request matches any
//! field in the list, we dont process further
//! \return  waflz status
//! \param
//! -----------------------------------------------------------------------------
int32_t bot_manager::process_exception_list(bool &ao_match, rqst_ctx &a_ctx)
{
        ao_match = false;
        const char *l_buf = NULL;
        uint32_t l_buf_len = 0;
        const data_unordered_map_t& l_hm = a_ctx.m_header_map;
        data_t l_d;
        // -------------------------------------------------
        // JA3 first
        // -------------------------------------------------
        if (!m_el_ja3.size())
        {
                goto ja4_check;
        }
        if (a_ctx.m_virt_ssl_client_ja3_md5.m_len > 0 &&
            a_ctx.m_virt_ssl_client_ja3_md5.m_data)
        {
                std::string l_ja3(a_ctx.m_virt_ssl_client_ja3_md5.m_data, a_ctx.m_virt_ssl_client_ja3_md5.m_len);
                if (m_el_ja3.find(l_ja3) != m_el_ja3.end())
                {
                        // ---------------------------------
                        // found ja3 in exception list, bail!!
                        // ---------------------------------
                        ao_match = true;
                        return WAFLZ_STATUS_OK;
                }
        }
ja4_check:
        // -------------------------------------------------
        // JA4 next
        // -------------------------------------------------
        if (!m_el_ja4.size())
        {
                goto url_check;
        }
        if (a_ctx.m_virt_ssl_client_ja4.m_len > 0 &&
            a_ctx.m_virt_ssl_client_ja4.m_data)
        {
                std::string l_ja4(a_ctx.m_virt_ssl_client_ja4.m_data, a_ctx.m_virt_ssl_client_ja4.m_len);
                if (m_el_ja4.find(l_ja4) != m_el_ja4.end())
                {
                        // ---------------------------------
                        // found ja4 in exception list, bail!!
                        // ---------------------------------
                        ao_match = true;
                        return WAFLZ_STATUS_OK;
                }
        }
url_check:
        if (m_el_url.empty())
        {
                goto user_agent_check;
        }
        if (a_ctx.m_uri.m_data &&
            a_ctx.m_uri.m_len)
        {
                ao_match = key_in_exception_list(m_el_url, a_ctx.m_uri.m_data, a_ctx.m_uri.m_len);
                if (ao_match)
                {
                        return WAFLZ_STATUS_OK;
                }
        }
user_agent_check:
        if (m_el_user_agent.empty())
        {
                goto cookie_check;
        }
        _GET_HEADER("User-Agent", l_buf);
        if (l_buf &&
            l_buf_len)
        {
                ao_match = key_in_exception_list(m_el_user_agent, l_buf, l_buf_len);
                if (ao_match)
                {
                        return WAFLZ_STATUS_OK;
                }
        }
cookie_check:
        if (m_el_cookie.empty())
        {
                return WAFLZ_STATUS_OK;
        }
        _GET_HEADER("Cookie", l_buf);
        if (l_buf &&
            l_buf_len)
        {
                ao_match = key_in_exception_list(m_el_cookie, l_buf, l_buf_len);
                if (ao_match)
                {
                        return WAFLZ_STATUS_OK;
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details process bot mananger config
//! \return  waflz status
//! \param
//! -----------------------------------------------------------------------------
int32_t bot_manager::process(waflz_pb::event** ao_event,
                             const waflz_pb::enforcement** ao_enf,
                             void* a_ctx,
                             rqst_ctx** ao_rqst_ctx)
{
        if (!ao_event)
        {
                WAFLZ_PERROR(m_err_msg, "ao_event == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        int32_t l_s;
        // -------------------------------------------------
        // check rqst ctx exists
        // -------------------------------------------------
        rqst_ctx* l_rqst_ctx = NULL;
        if (ao_rqst_ctx &&
           *ao_rqst_ctx)
        {
                l_rqst_ctx = *ao_rqst_ctx;
        }
        if (!l_rqst_ctx)
        {
                WAFLZ_PERROR(m_err_msg, "ao_rqst_ctx == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // run phase 1 init
        // -------------------------------------------------
        l_s = l_rqst_ctx->init_phase_1(m_engine, NULL, NULL, NULL);
        if (l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "performing rqst_ctx::init_phase_1");
                if (!ao_rqst_ctx && l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // process exception list
        // -------------------------------------------------
        bool l_match = false;
        l_s = process_exception_list(l_match, *l_rqst_ctx);
        if (l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // if exception list matches, we outtie
        // -------------------------------------------------
        if (l_match)
        {
                return WAFLZ_STATUS_OK;
        }
        *ao_event = NULL;
        waflz_pb::event* l_event = NULL;
        const waflz_pb::enforcement* l_enf = NULL;
        // -------------------------------------------------
        // process bot rules
        // -------------------------------------------------
        if (!m_bots)
        {
                goto known_bots;
        }
        l_s = m_bots->process(&l_event, a_ctx, ao_rqst_ctx);
        if (l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "%s", m_bots->get_err_msg());
                if (l_event) { delete l_event; l_event = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        if (!l_event)
        {
                goto known_bots;
        }
        // -------------------------------------------------
        // bots-> process returns an event on rule match. 
        // if there is an event from bots->process,
        // get enforcement from action type.
        // if the enf type is browser challenge, do the
        // challenge verification before setting ao_enf
        // -------------------------------------------------
        if (l_event->sub_event(0).has_bot_action())
        {
                auto *l_desc = ::waflz_pb::enforcement_type_t_descriptor();
                std::string l_action_type = l_desc->FindValueByNumber(l_event->sub_event(0).bot_action())->name();
                l_s = set_enf_from_action_type(&l_enf, l_action_type);
        }
        else
        {
                // Default to alert
                l_enf = m_actions["ALERT"];
        }
        if (!l_enf)
        {
            if (l_event) { delete l_event; l_event =  NULL; }
            goto known_bots;
        }
        if (l_enf->enf_type() == waflz_pb::enforcement_type_t_BROWSER_CHALLENGE)
        {
                bool l_pass = false;
                l_s = process_challenge(&l_pass, l_event, l_rqst_ctx, l_enf);
                if (l_pass)
                {
                        if (l_event) { delete l_event; l_event =  NULL; }
                        return l_s;
                }
        }
        else if (l_enf->enf_type() == waflz_pb::enforcement_type_t_RECAPTCHA)
        {
                bool l_issue_captcha = false;
                int32_t l_s;
                l_s = process_recaptcha(&l_issue_captcha,
                                        l_event,
                                        l_rqst_ctx,
                                        l_enf);

                if (l_s == WAFLZ_STATUS_OK)
                {
                        //captcha verification passed. Continue processing
                        if (l_event) { delete l_event; l_event =  NULL; }
                        return WAFLZ_STATUS_OK;
                }
                else if (l_s == WAFLZ_STATUS_WAIT)
                {
                        //sub request in process
                        l_event->set_bots_config_id(m_bots->get_id());
                        l_event->set_bots_config_name(m_bots->get_name());
                        l_event->set_bot_event(true);
                        l_event->set_bot_manager_config_id(m_id);
                        l_event->set_bot_manager_config_name(m_name);
                        l_event->set_bot_score(l_rqst_ctx->m_bot_score);
                        l_event->set_bot_score_key(l_rqst_ctx->m_bot_score_key);
                        if (!l_rqst_ctx->m_bot_tags.empty())
                                l_event->set_bot_tags(l_rqst_ctx->m_bot_tags);
                        l_event->set_customer_id(l_rqst_ctx->m_cust_id);
                        *ao_event = l_event;
                        return WAFLZ_STATUS_WAIT;
                }
                else
                {
                        // issue captcha
                        if (l_issue_captcha)
                        {
                                // do nothing. issue captcha.
                                // bye sending an event
                        }
                        else
                        {
                                //other processing error.
                                if (l_event) { delete l_event; l_event =  NULL; }
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        // We already have an event from bot rules, finish processing
        if(l_event)
        {
                l_event->set_bots_config_id(m_bots->get_id());
                l_event->set_bots_config_name(m_bots->get_name());
                goto done;
        }
        
known_bots:
        if (!m_inspect_known_bots)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // Process known bots
        // -------------------------------------------------
        if (m_pb->categories_size() && m_engine.get_use_knb_cat())
        {
                l_s = process_known_categories(&l_event, *l_rqst_ctx, &l_enf);
        }
        else
        {
                l_s = process_known_bots(&l_event, *l_rqst_ctx, &l_enf);
        }
        if(l_s == WAFLZ_STATUS_WAIT)
        {
                //sub request in process
                l_event->set_bot_event(true);
                l_event->set_bot_manager_config_id(m_id);
                l_event->set_bot_manager_config_name(m_name);
                l_event->set_bot_score(l_rqst_ctx->m_bot_score);
                if(!l_rqst_ctx->m_bot_tags.empty())
                        l_event->set_bot_tags(l_rqst_ctx->m_bot_tags);
                l_event->set_customer_id(l_rqst_ctx->m_cust_id);
                *ao_event = l_event;
                return WAFLZ_STATUS_WAIT;
        }
        else if (l_s == WAFLZ_STATUS_OK)
        {
                if (l_event)
                {
                        goto done;
                }
                else
                {
                        return WAFLZ_STATUS_OK;
                }
        }
        else
        {
                return WAFLZ_STATUS_ERROR;
        }
done:
        // -------------------------------------------------
        // set event and enf
        // -------------------------------------------------
        l_event->set_bot_event(true);
        l_event->set_bot_manager_config_id(m_id);
        l_event->set_bot_manager_config_name(m_name);
        l_event->set_bot_score(l_rqst_ctx->m_bot_score);
        l_event->set_bot_score_key(l_rqst_ctx->m_bot_score_key);
        l_event->set_bot_action(l_enf->enf_type());
        if(!l_rqst_ctx->m_bot_tags.empty())
                l_event->set_bot_tags(l_rqst_ctx->m_bot_tags);
        l_event->set_customer_id(l_rqst_ctx->m_cust_id);
        *ao_event = l_event;
        *ao_enf = l_enf;
        if ((*ao_enf)->has_status())
        {
                (*ao_rqst_ctx)->m_resp_status = (*ao_enf)->status();
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details Helper function to process browser challenge
//! \return  waflz status
//! ----------------------------------------------------------------------------
int32_t bot_manager::process_challenge(bool* ao_pass,
                                       waflz_pb::event* ao_event,
                                       ns_waflz::rqst_ctx* ao_rqst_ctx,
                                       const waflz_pb::enforcement* a_enf)
{
        // -------------------------------------------------
        // check cookie
        // verify browser challenge
        // -------------------------------------------------
        // default to valid for 10 min
        uint32_t l_valid_for_s = 600;
        if (a_enf->has_valid_for_sec())
        {
                l_valid_for_s = a_enf->valid_for_sec();
        }
        int32_t l_s;
        l_s = m_challenge.verify(*ao_pass, l_valid_for_s, ao_rqst_ctx, &ao_event);
        if (l_s != WAFLZ_STATUS_OK)
        {
                // do nothing -re-issue challenge. bye sending an event
        }
        if (*ao_pass)
        {
                // Challenge passed.
                // move on to next step in scope::process
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // Add challenge duration, difficulty and level
        // -------------------------------------------------
        ao_event->set_token_duration_sec(l_valid_for_s);
        ao_event->set_challenge_difficulty(a_enf->challenge_difficulty());
        uint32_t l_challenge_level = (a_enf->has_challenge_level()) ? a_enf->challenge_level() : 1;
        ao_event->set_challenge_level(l_challenge_level);
        return l_s;
}
//! ----------------------------------------------------------------------------
//! \details Helper function to process recaptcha
//! \return  waflz status
//! ----------------------------------------------------------------------------
int32_t bot_manager::process_recaptcha(bool* ao_issue_captcha,
                                       waflz_pb::event* ao_event,
                                       ns_waflz::rqst_ctx* ao_rqst_ctx,
                                       const waflz_pb::enforcement* a_enf)
{
        // -------------------------------------------------
        //  This check is to let the request slide through,
        //  if the subrequest failed because of third party 
        //  issues. 
        // -------------------------------------------------
        if (ao_rqst_ctx->m_tp_subr_fail)
        {
                return WAFLZ_STATUS_OK;
        }
        int32_t l_s;
        // -------------------------------------------------
        //  Get the captcha failed enf to pass to verify 
        //  endpoint which will copy it rqst ctx,
        //  if subrequest is issued. 
        // -------------------------------------------------
        const waflz_pb::enforcement* l_captcha_enf;
        if (a_enf->has_failed_action_type())
        {
                auto *l_desc = ::waflz_pb::enforcement_type_t_descriptor();
                std::string l_action_type = l_desc->FindValueByNumber
                                            (a_enf->failed_action_type())->name();
                set_enf_from_action_type(&l_captcha_enf, l_action_type);
        }
        else
        {
                set_enf_from_action_type(&l_captcha_enf, "ALERT");
        }
        // get token validity from l_enf for verificatuon
        uint32_t l_valid_for_s = 600;
        if (a_enf->has_valid_for_sec())
        {
                l_valid_for_s = a_enf->valid_for_sec();
        }
        ao_event->set_token_duration_sec(l_valid_for_s);
        // -------------------------------------------------
        //  captcha verify
        // -------------------------------------------------
        l_s = m_captcha.verify(ao_rqst_ctx,
                               l_valid_for_s,
                               ao_event,
                               l_captcha_enf,
                               *ao_issue_captcha);
        return l_s;

}
//! ----------------------------------------------------------------------------
//! \details sets the enforcement if the action is found in the action map
//! \return  waflz status
//! \param   ao_enf : the enforcement to update
//! \param   a_action_type: the key to search in the action map (m_actions)
//! -----------------------------------------------------------------------------
int32_t bot_manager::set_enf_from_action_type(const waflz_pb::enforcement** ao_enf, std::string a_action_type)
{
        // -------------------------------------------------
        // look for action type in action map
        // -------------------------------------------------
        action_map_t::const_iterator l_action = m_actions.find(a_action_type);
        if ( l_action != m_actions.end() )
        {
                // -----------------------------------------
                // set enforcement if found
                // -----------------------------------------
                // NDBG_PRINT("setting to: %s\n", (*l_action).second->DebugString().c_str());
                *ao_enf = (*l_action).second;
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // if not found, use the default action
        // -------------------------------------------------
        // NDBG_PRINT("setting to: %s\n", m_actions["ALERT"]->DebugString().c_str());
        *ao_enf = m_actions["ALERT"];
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t bot_manager::create_action_map( )
{
        //! ------------------------------------------------
        //! check for actions - leave if missing
        //! ------------------------------------------------
        if ( !m_pb->has_actions() ) { return WAFLZ_STATUS_OK; }
        //! ------------------------------------------------
        //! get actions
        //! ------------------------------------------------
        ::waflz_pb::bot_manager_action_list_t *l_list = m_pb->mutable_actions();
        //! ------------------------------------------------
        //! check for ALERT
        //! ------------------------------------------------
        if ( l_list->has_alert() )
        {
                ::waflz_pb::enforcement *l_alert = l_list->mutable_alert();
                if ( !l_alert->has_enf_type() )
                {
                        l_alert->set_enf_type(::waflz_pb::enforcement_type_t_ALERT);
                }
                // NDBG_PRINT("setting Alert: %s\n", l_alert->DebugString().c_str());
                m_actions["ALERT"] = l_alert;
        }
        //! ------------------------------------------------
        //! check for BLOCK_REQUEST
        //! ------------------------------------------------
        if ( l_list->has_block_request() )
        {
                ::waflz_pb::enforcement *l_block_request = l_list->mutable_block_request();
                if ( !l_block_request->has_enf_type() )
                {
                        l_block_request->set_enf_type(::waflz_pb::enforcement_type_t_BLOCK_REQUEST);
                }
                // NDBG_PRINT("setting BLOCK_REQUEST: %s\n", l_block_request->DebugString().c_str());
                m_actions["BLOCK_REQUEST"] = l_block_request;
        }
        //! ------------------------------------------------
        //! check for CUSTOM_RESPONSE
        //! ------------------------------------------------
        if ( l_list->has_custom_response() )
        {
                ::waflz_pb::enforcement *l_custom_response = l_list->mutable_custom_response();
                if ( !l_custom_response->has_enf_type() )
                {
                        l_custom_response->set_enf_type(::waflz_pb::enforcement_type_t_CUSTOM_RESPONSE);
                }
                // NDBG_PRINT("setting CUSTOM_RESPONSE: %s\n", l_custom_response->DebugString().c_str());
                m_actions["CUSTOM_RESPONSE"] = l_custom_response;
        }
        //! ------------------------------------------------
        //! check for BROWSER_CHALLENGE
        //! ------------------------------------------------
        if ( l_list->has_browser_challenge() )
        {
                ::waflz_pb::enforcement *l_browser_challenge = l_list->mutable_browser_challenge();
                if ( !l_browser_challenge->has_enf_type() )
                {
                        l_browser_challenge->set_enf_type(::waflz_pb::enforcement_type_t_BROWSER_CHALLENGE);
                }
                // NDBG_PRINT("setting BROWSER_CHALLENGE: %s\n", l_browser_challenge->DebugString().c_str());
                m_actions["BROWSER_CHALLENGE"] = l_browser_challenge;
        }
        //! ------------------------------------------------
        //! check for RECAPTCHA
        //! ------------------------------------------------
        if ( l_list->has_recaptcha() )
        {
                ::waflz_pb::enforcement *l_recaptcha = l_list->mutable_recaptcha();
                if ( !l_recaptcha->has_enf_type() )
                {
                        l_recaptcha->set_enf_type(::waflz_pb::enforcement_type_t_RECAPTCHA);
                }
                // NDBG_PRINT("setting RECAPTCHA: %s\n", l_recaptcha->DebugString().c_str());
                m_actions["RECAPTCHA"] = l_recaptcha;
        }
        //! ------------------------------------------------
        //! check for REDIRECT_302
        //! ------------------------------------------------
        if ( l_list->has_redirect_302() )
        {
                ::waflz_pb::enforcement *l_redirect = l_list->mutable_redirect_302();
                if ( !l_redirect->has_enf_type() )
                {
                        l_redirect->set_enf_type(::waflz_pb::enforcement_type_t_REDIRECT_302);
                }
                // NDBG_PRINT("setting REDIRECT_302: %s\n", l_redirect->DebugString().c_str());
                m_actions["REDIRECT_302"] = l_redirect;
        }
        //! ------------------------------------------------
        //! check for DROP_REQUEST
        //! ------------------------------------------------
        if ( l_list->has_drop_request() )
        {
                ::waflz_pb::enforcement *l_drop = l_list->mutable_drop_request();
                if ( !l_drop->has_enf_type() )
                {
                        l_drop->set_enf_type(::waflz_pb::enforcement_type_t_DROP_REQUEST);
                }
                // NDBG_PRINT("setting DROP_REQUEST: %s\n", l_drop->DebugString().c_str());
                m_actions["DROP_REQUEST"] = l_drop;
        }
        //! ------------------------------------------------
        //! check for IGNORE_ALERT
        //! ------------------------------------------------
        if ( l_list->has_ignore_alert() )
        {
                ::waflz_pb::enforcement *l_ignore_alert = l_list->mutable_ignore_alert();
                if ( !l_ignore_alert->has_enf_type() )
                {
                        l_ignore_alert->set_enf_type(::waflz_pb::enforcement_type_t_IGNORE_ALERT);
                }
                // NDBG_PRINT("setting IGNORE_ALERT: %s\n", l_ignore_alert->DebugString().c_str());
                m_actions["IGNORE_ALERT"] = l_ignore_alert;
        }
        //! ------------------------------------------------
        //! check for IGNORE_BLOCK
        //! ------------------------------------------------
        if ( l_list->has_ignore_block() )
        {
                ::waflz_pb::enforcement *l_ignore_block = l_list->mutable_ignore_block();
                if ( !l_ignore_block->has_enf_type() )
                {
                        l_ignore_block->set_enf_type(::waflz_pb::enforcement_type_t_IGNORE_BLOCK);
                }
                // NDBG_PRINT("setting IGNORE_BLOCK: %s\n", l_ignore_block->DebugString().c_str());
                m_actions["IGNORE_BLOCK"] = l_ignore_block;
        }
        //! ------------------------------------------------
        //! check for SILENT_CLOSE
        //! ------------------------------------------------
        if ( l_list->has_silent_close() )
        {
                ::waflz_pb::enforcement *l_silent_close = l_list->mutable_silent_close();
                if ( !l_silent_close->has_enf_type() )
                {
                        l_silent_close->set_enf_type(::waflz_pb::enforcement_type_t_SILENT_CLOSE);
                }
                // NDBG_PRINT("setting SILENT_CLOSE: %s\n", l_silent_close->DebugString().c_str());
                m_actions["SILENT_CLOSE"] = l_silent_close;
        }
        //! ------------------------------------------------
        //! check for NULL_ALERT
        //! ------------------------------------------------
        if ( l_list->has_null_alert() )
        {
                ::waflz_pb::enforcement *l_null_alert = l_list->mutable_null_alert();
                if ( !l_null_alert->has_enf_type() )
                {
                        l_null_alert->set_enf_type(::waflz_pb::enforcement_type_t_NULL_ALERT);
                }
                // NDBG_PRINT("setting NULL_ALERT: %s\n", l_null_alert->DebugString().c_str());
                m_actions["NULL_ALERT"] = l_null_alert;
        }
        //! ------------------------------------------------
        //! check for NULL_BLOCK
        //! ------------------------------------------------
        if ( l_list->has_null_block() )
        {
                ::waflz_pb::enforcement *l_null_block = l_list->mutable_null_block();
                if ( !l_null_block->has_enf_type() )
                {
                        l_null_block->set_enf_type(::waflz_pb::enforcement_type_t_NULL_BLOCK);
                }
                // NDBG_PRINT("setting NULL_BLOCK: %s\n", l_null_block->DebugString().c_str());
                m_actions["NULL_BLOCK"] = l_null_block;
        }
        //! ------------------------------------------------
        //! check for IGNORE_CUSTOM_RESPONSE
        //! ------------------------------------------------
        if ( l_list->has_ignore_custom_response() )
        {
                ::waflz_pb::enforcement *l_ignore_custom_resp = l_list->mutable_ignore_custom_response();
                if ( !l_ignore_custom_resp->has_enf_type() )
                {
                        l_ignore_custom_resp->set_enf_type(::waflz_pb::enforcement_type_t_IGNORE_CUSTOM_RESPONSE);
                }
                // NDBG_PRINT("setting IGNORE_CUSTOM_RESPONSE: %s\n", l_ignore_custom_resp->DebugString().c_str());
                m_actions["IGNORE_CUSTOM_RESPONSE"] = l_ignore_custom_resp;
        }
        //! ------------------------------------------------
        //! check for IGNORE
        //! ------------------------------------------------
        if ( l_list->has_ignore() )
        {
                ::waflz_pb::enforcement *l_ignore = l_list->mutable_ignore();
                if ( !l_ignore->has_enf_type() )
                {
                        l_ignore->set_enf_type(::waflz_pb::enforcement_type_t_IGNORE);
                }
                // NDBG_PRINT("setting IGNORE: %s\n", l_ignore->DebugString().c_str());
                m_actions["IGNORE"] = l_ignore;
        }
        //! ------------------------------------------------
        //! return status ok
        //! ------------------------------------------------
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details if a_loaded_date is >= a_new_Date
//! \return  False
//! \param   TODO
//! ----------------------------------------------------------------------------
bool bot_manager::compare_dates(const char* a_loaded_date, const char* a_new_date)
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
}
