//: ----------------------------------------------------------------------------
//: Copyright (C) 2018 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    engine.h
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    02/28/2018
//:
//:   Licensed under the Apache License, Version 2.0 (the "License");
//:   you may not use this file except in compliance with the License.
//:   You may obtain a copy of the License at
//:
//:       http://www.apache.org/licenses/LICENSE-2.0
//:
//:   Unless required by applicable law or agreed to in writing, software
//:   distributed under the License is distributed on an "AS IS" BASIS,
//:   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//:   See the License for the specific language governing permissions and
//:   limitations under the License.
//:
//: ----------------------------------------------------------------------------
#ifndef _ENGINE_H_
#define _ENGINE_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#ifdef __cplusplus
#include <stdint.h>
#include <list>
#include <string>
#include <map>
#include "waflz/waf.h"
#include "waflz/parser.h"
#endif
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
//: ----------------------------------------------------------------------------
//: fwd decl's -proto
//: ----------------------------------------------------------------------------
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
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
class regex;
class ac;
class macro;
class geoip2_mmdb;
//: ----------------------------------------------------------------------------
//: engine
//: ----------------------------------------------------------------------------
class engine
{
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        engine();
        ~engine();
        int32_t init();
        macro &get_macro(void){ return *m_macro;}
        const ctype_parser_map_t &get_ctype_parser_map(void) { return m_ctype_parser_map;}
        int32_t compile(compiled_config_t &ao_cx_cfg, waflz_pb::sec_config_t &a_config, const std::string& a_ruleset_dir);
        geoip2_mmdb& get_geoip2_mmdb(void) { return *m_geoip2_mmdb; }
        const char *get_err_msg(void) { return m_err_msg; }
        void set_ruleset_dir(std::string a_ruleset_dir) { m_ruleset_root_dir = a_ruleset_dir; }
        void set_geoip2_dbs(const std::string& a_geoip2_db, const std::string& a_geoip2_isp_db);
        const std::string& get_ruleset_dir(void) { return m_ruleset_root_dir;}
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // Disallow copy/assign
        engine(const engine &);
        engine& operator=(const engine &);
        int32_t process_include(compiled_config_t **ao_cx_cfg, const std::string &a_include, waflz_pb::sec_config_t &a_config, const std::string& a_ruleset_dir);
        int32_t merge(compiled_config_t &ao_cx_cfg, const compiled_config_t &a_cx_cfg);
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
        macro *m_macro;
        config_list_t m_config_list;
        compiled_config_map_t m_compiled_config_map;
        ctype_parser_map_t m_ctype_parser_map;
        std::string m_ruleset_root_dir;
        // -------------------------------------------------
        // *************************************************
        // geoip2 support
        // *************************************************
        // -------------------------------------------------
        geoip2_mmdb *m_geoip2_mmdb;
        std::string m_geoip2_db;
        std::string m_geoip2_isp_db;
        char m_err_msg[WAFLZ_ERR_LEN];
};
#endif
#ifdef __cplusplus
extern "C" {
#endif
engine *create_waflz_engine(void);
void set_waflz_ruleset_dir(engine *a_engine, char *a_ruleset_dir);
void set_waflz_geoip2_dbs(engine *a_engine, char *a_geoip2_db, char *a_geoip2_isp_db);
int32_t init_waflz_engine(engine *a_engine);
int32_t waflz_engine_cleanup(engine *a_engine);
#ifdef __cplusplus
}
}
#endif // namespace
#endif // header
