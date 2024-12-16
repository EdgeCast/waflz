//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    api_gw.h
//! \details: Manages schemas, loads API_GATEWAY config, creates schema
//! classes,
//!           processes request against appropriate schema.
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _API_GW_H_
#define _API_GW_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <string.h>
#include <set>
#include <utility>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "rapidjson/error/en.h"
#include "rapidjson/schema.h"
#include "waflz/def.h"
#include "waflz/schema.h"
#include "waflz/scopes.h"
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
namespace waflz_pb {
class api_gw;
class event;
class op_t;
}  // namespace waflz_pb
namespace ns_waflz {
class engine;
class rqst_ctx;
class schema;
class regex;
class jwt_parser;
//! ----------------------------------------------------------------------------
//! api_gw
//! ----------------------------------------------------------------------------
class api_gw
{
        friend class scopes;
public:
#if defined(__APPLE__) || defined(__darwin__)
        #define UNORDERED_MAP std::unordered_map
#else
        #define UNORDERED_MAP std::tr1::unordered_map
#endif
        typedef UNORDERED_MAP<std::string, schema*, str_hash> id_schema_map_t;
        typedef UNORDERED_MAP<std::string, jwt_parser*, str_hash> rule_to_jwt_parser_map_t;
        typedef std::unordered_set<data_t, data_t_hash, data_comp_unordered> data_set_t;
        typedef std::unordered_set<data_t, data_t_case_hash, data_case_i_comp_unordered> data_case_i_set_t;
        typedef std::list<regex*> regex_list_t;
        typedef std::list<data_set_t*> data_set_list_t;
        typedef std::list<data_case_i_set_t*> data_case_i_set_list_t;
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        api_gw(engine& a_engine);
        ~api_gw();
        int32_t load(const char* a_buf,
                     uint32_t a_buf_len,
                     const std::string& a_conf_dir_path);
        int32_t load(const waflz_pb::api_gw* a_pb,
                     const std::string& a_conf_dir_path);
        int32_t load(void* a_js, const std::string& a_conf_dir_path);
        int32_t load_file(const char* a_file_buf,
                          const std::string& a_conf_dir_path);
        int32_t process(waflz_pb::event** ao_event,
                        void* a_ctx,
                        ns_waflz::rqst_ctx** ao_ctx);
        int32_t process_response(waflz_pb::event** ao_event,
                        void* a_ctx,
                        ns_waflz::resp_ctx** ao_ctx);
        int32_t compile_op(::waflz_pb::op_t& ao_op);
        void add_schema_to_map(ns_waflz::schema* a_schema);
        //: ------------------------------------------------
        //:               S E T T E R S
        //: ------------------------------------------------
        
        //: ------------------------------------------------
        //:               G E T T E R S
        //: ------------------------------------------------
        const std::string& get_id(void) { return m_id; }
        const std::string& get_cust_id(void) { return m_cust_id; }
        bool is_team_config(void) { return m_team_config; }
        const std::string& get_name(void) { return m_name; }
        const id_schema_map_t& get_schema_map(void) { return m_schema_map; }
        //: ------------------------------------------------
        //: \details Get last error message string
        //: \return  last error message (in buffer)
        //: ------------------------------------------------
        const char* get_err_msg(void) { return m_err_msg; }
        const waflz_pb::api_gw* get_pb(void) { return m_pb; };

private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        int32_t init(const std::string& a_conf_dir_path);
        // -------------------------------------------------
        // disallow copy/assign
        // -------------------------------------------------
        api_gw(const api_gw&);
        api_gw& operator=(const api_gw&);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        bool m_init;
        char m_err_msg[WAFLZ_ERR_LEN];
        engine& m_engine;
        // -------------------------------------------------
        // properties
        // -------------------------------------------------
        std::string m_id;
        std::string m_cust_id;
        bool m_team_config;
        std::string m_name;
        regex_list_t m_regex_list;
        data_set_list_t m_data_set_list;
        data_case_i_set_list_t m_data_case_i_set_list;
        waflz_pb::api_gw* m_pb;
        id_schema_map_t m_schema_map;
        rule_to_jwt_parser_map_t m_jwt_parser_map;
};
}  // namespace ns_waflz
#endif
