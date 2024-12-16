//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _ENGINE_H_
#define _ENGINE_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#ifdef __cplusplus
#include <stdint.h>
#include <list>
#include <string>
#include <map>
#include "waflz/ac.h"
#include "waflz/nms.h"
#include "waflz/waf.h"
#include "waflz/parser.h"
#if defined(__APPLE__) || defined(__darwin__)
    #include <unordered_map>
    #include <unordered_set>
#else
    #include <tr1/unordered_map>
    #include <tr1/unordered_set>
#endif
#endif
#include <rapidjson/document.h>
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! fwd decl's -proto
//! ----------------------------------------------------------------------------
#ifndef __cplusplus
typedef struct engine_t engine;
#endif
#ifdef __cplusplus
namespace waflz_pb {
class directive_t;
class sec_config_t;
};
#endif
#ifdef __cplusplus
namespace ns_waflz
{
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
class regex;
class macro;
class geoip2_mmdb;
// -------------------------------------------------
// known bot attributes
// -------------------------------------------------
#if defined(__APPLE__) || defined(__darwin__)
        #define UNORDER_MAP_TYPE std::unordered_map
        #define UNORDER_SET_TYPE std::unordered_set
#else
        #define UNORDER_MAP_TYPE std::tr1::unordered_map
        #define UNORDER_SET_TYPE std::tr1::unordered_set
#endif
typedef UNORDER_MAP_TYPE<std::string, nms *> str_nms_map_t;
typedef UNORDER_MAP_TYPE<std::string, ac *> str_ac_map_t;
typedef UNORDER_SET_TYPE<uint32_t> unordered_uint_set_t;
typedef UNORDER_SET_TYPE<std::string> unordered_str_set_t;
// -------------------------------------------------
// known bots info data type
// -------------------------------------------------
typedef struct _cat_data_pkg_t {

        std::string m_category;
        std::string m_company;

        _cat_data_pkg_t():
                m_category(),
                m_company()
        {};

        _cat_data_pkg_t(std::string a_cat, std::string a_comp):
                m_category(a_cat),
                m_company(a_comp)
        {};

        std::size_t operator==(const _cat_data_pkg_t& p) const {
                return (m_category == p.m_category) && (m_company == p.m_company);
        };
        std::size_t operator()(const _cat_data_pkg_t& p) const {
                return std::hash<std::string>{}(p.m_category) ^ (std::hash<std::string>{}(p.m_company) << 1);
        };

} cat_data_pkg_t;

struct cat_data_compare_unordered
{
        bool operator()(const _cat_data_pkg_t& p) const
        {
                return std::hash<std::string>{}(p.m_category) ^ (std::hash<std::string>{}(p.m_company) << 1);
        }
};


typedef struct _known_bot_info_t {

        nms m_ips;
        ac m_user_agents;
        unordered_uint_set_t m_asns;

        _known_bot_info_t(bool a_case_sensitve = false):
                m_ips(),
                m_user_agents(a_case_sensitve),
                m_asns()
        {}

} known_bot_info_t;
typedef UNORDER_MAP_TYPE<std::string, known_bot_info_t*> known_bot_info_map_t;
typedef UNORDER_MAP_TYPE<std::string, cat_data_pkg_t*> str_to_data_pkg_map_t;
//! ----------------------------------------------------------------------------
//! engine
//! ----------------------------------------------------------------------------
class engine
{
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        engine();
        ~engine();
        int32_t clear_known_bot_map();
        int32_t init();
        const char* get_err_msg(void) { return m_err_msg; }
        // -------------------------------------------------
        // waf
        // -------------------------------------------------
        macro& get_macro(void){ return *m_macro;}
        const ctype_parser_map_t& get_ctype_parser_map(void) { return m_ctype_parser_map;}
        int32_t compile(compiled_config_t& ao_cx_cfg, waflz_pb::sec_config_t& a_config, const std::string& a_ruleset_dir);
        void set_ruleset_dir(std::string a_ruleset_dir) { m_ruleset_root_dir = a_ruleset_dir; }
        void set_geoip2_dbs(const std::string& a_geoip2_db, const std::string& a_geoip2_isp_db);
        geoip2_mmdb& get_geoip2_mmdb(void) { return *m_geoip2_mmdb; }
        const std::string& get_ruleset_dir(void) { return m_ruleset_root_dir;}
        // -------------------------------------------------
        // unknown bot
        // -------------------------------------------------
        void set_use_bot_lmdb(bool& a_val) { m_use_bot_lmdb = a_val; }
        bool get_use_bot_lmdb() { return m_use_bot_lmdb; }
        void set_bot_lmdb(kv_db& a_db) { m_bot_db = &a_db; }
        kv_db& get_bot_lmdb() { return *m_bot_db; }
        // -------------------------------------------------
        // unknown bot
        // -------------------------------------------------
        void set_use_bot_lmdb_new(bool& a_val) { m_use_bot_lmdb_new = a_val; }
        bool get_use_bot_lmdb_new() { return m_use_bot_lmdb_new; }
        // -------------------------------------------------
        // rate limiting
        // -------------------------------------------------
        void set_use_pop_count(bool& a_val) { m_use_pop_count = a_val; }
        bool get_use_pop_count() { return m_use_pop_count; }
        // -------------------------------------------------
        // known bots
        // -------------------------------------------------
        int32_t load_bot_score_db_file(const char* a_file_path, uint32_t a_file_path_len);
        int32_t load_bot_score_db(const char* a_buf, uint32_t a_buf_len);
        int32_t parse_string_array_to_nms(const rapidjson::Value& a_kb_array, nms& ao_nms);
        int32_t parse_string_array_to_ac(const rapidjson::Value& a_kb_array, ac& ao_ac);
        int32_t parse_uint_array_to_unorder_set(const rapidjson::Value& a_kb_array, unordered_uint_set_t& ao_set);
        int32_t parse_company_category_entry(const rapidjson::Value& a_cat_map,
                                             const std::string& a_company,
                                             str_to_data_pkg_map_t& a_cat_to_ua_map,
                                             unordered_str_set_t& a_categories_found,
                                             ac& a_ua_to_data_ac);
        int32_t load_known_bot_info_file(const char* a_file_path, uint32_t a_file_path_len);
        int32_t load_known_bot(const char* a_buf, uint32_t a_buf_len);
        const known_bot_info_map_t& get_known_bot_info_map(void) { return m_knb_info_map; }
        void set_use_knb_cat(const bool a_bool) { m_use_knb_cat = a_bool; }
        bool get_use_knb_cat(void) { return m_use_knb_cat; }
        ac& get_knb_tokens(void) { return m_knb_tokens; }
        const unordered_str_set_t& get_knb_categories(void) { return m_knb_categories; }
        // -------------------------------------------------
        // client side
        // -------------------------------------------------
        void set_csp_endpoint_uri(const std::string& a_val) { m_csp_endpoint_uri.assign(a_val); }
        std::string& get_csp_endpoint_uri() { return m_csp_endpoint_uri; }
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // Disallow copy/assign
        engine(const engine &);
        engine& operator=(const engine &);
        int32_t process_include(compiled_config_t** ao_cx_cfg, const std::string& a_include, waflz_pb::sec_config_t& a_config, const std::string& a_ruleset_dir);
        int32_t merge(compiled_config_t& ao_cx_cfg, const compiled_config_t& a_cx_cfg);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        // -------------------------------------------------
        // compiled...
        // -------------------------------------------------
        typedef std::list<waflz_pb::sec_config_t *> config_list_t;
        typedef std::map<std::string, compiled_config_t *> compiled_config_map_t;
        // -------------------------------------------------
        // storage...
        // -------------------------------------------------
        macro* m_macro;
        config_list_t m_config_list;
        compiled_config_map_t m_compiled_config_map;
        ctype_parser_map_t m_ctype_parser_map;
        std::string m_ruleset_root_dir;
        std::string m_bot_data_dir;
        known_bot_info_map_t m_knb_info_map;
        bool m_use_knb_cat;
        ac m_knb_tokens;
        str_to_data_pkg_map_t m_knb_ua_to_data_pkg;
        unordered_str_set_t m_knb_categories;
        bool m_use_bot_lmdb;
        bool m_use_bot_lmdb_new;
        bool m_use_pop_count;
        std::string m_csp_endpoint_uri;
        kv_db* m_bot_db;
        // -------------------------------------------------
        // *************************************************
        // geoip2 support
        // *************************************************
        // -------------------------------------------------
        geoip2_mmdb* m_geoip2_mmdb;
        std::string m_geoip2_db;
        std::string m_geoip2_isp_db;
        char m_err_msg[WAFLZ_ERR_LEN];
};
#endif
#ifdef __cplusplus
extern "C" {
#endif
engine* create_waflz_engine(void);
void set_waflz_ruleset_dir(engine* a_engine, char* a_ruleset_dir);
void set_waflz_geoip2_dbs(engine* a_engine, char* a_geoip2_db, char* a_geoip2_isp_db);
int32_t init_waflz_engine(engine* a_engine);
int32_t waflz_engine_cleanup(engine* a_engine);
#ifdef __cplusplus
}
}
#endif // namespace
#endif // header
