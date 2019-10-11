//: ----------------------------------------------------------------------------
//: Copyright (C) 2019 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    scopes.cc
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    06/06/2019
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
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include "waflz/scopes.h"
#include "waflz/rqst_ctx.h"
#include "waflz/config_parser.h"
#include "waflz/acl.h"
#include "waflz/rules.h"
#include "waflz/engine.h"
#include "waflz/limit/rl_obj.h"
#include "waflz/limit/limit.h"
#include "waflz/limit/enforcer.h"
#include "support/ndebug.h"
#include "support/base64.h"
#include "support/file_util.h"
#include "support/time_util.h"
#include "op/nms.h"
#include "op/regex.h"
#include "scope.pb.h"
#include "jspb/jspb.h"
#include "event.pb.h"
#include "limit.pb.h"
#include <fnmatch.h>
//: ----------------------------------------------------------------------------
//: constants
//: ----------------------------------------------------------------------------
#define _SCOPES_MAX_SIZE (1024*1024)
//: ----------------------------------------------------------------------------
//: macros
//: ----------------------------------------------------------------------------
#define VERIFY_HAS(_pb, _field) do { \
        if(!_pb.has_##_field()) { \
                WAFLZ_PERROR(m_err_msg, "missing %s field", #_field); \
                return WAFLZ_STATUS_ERROR; \
        } \
} while(0)
#define _GET_HEADER(_header) do { \
    l_d.m_data = _header; \
    l_d.m_len = sizeof(_header); \
    data_map_t::const_iterator i_h = a_ctx->m_header_map.find(l_d); \
    if(i_h != a_ctx->m_header_map.end()) \
    { \
            l_v.m_data = i_h->second.m_data; \
            l_v.m_len = i_h->second.m_len; \
    } \
    } while(0)
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: utils
//: ----------------------------------------------------------------------------
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t compile_action(waflz_pb::enforcement& ao_axn, char* ao_err_msg)
{
        // -------------------------------------------------
        // convert type string to enf_type
        // -------------------------------------------------
        if(!ao_axn.has_enf_type() &&
            ao_axn.has_type())
        {
                const std::string &l_type = ao_axn.type();
#define _ELIF_TYPE(_str, _type) else \
if(strncasecmp(l_type.c_str(), _str, sizeof(_str)) == 0) { \
        ao_axn.set_enf_type(waflz_pb::enforcement_type_t_##_type); \
}
            if(0) {}
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
            else
            {
                    WAFLZ_PERROR(ao_err_msg, "unrecognized enforcement type string: %s", l_type.c_str());
                    return WAFLZ_STATUS_ERROR;
            }
        }
        // -------------------------------------------------
        // convert b64 encoded resp
        // -------------------------------------------------
        if(!ao_axn.has_response_body() &&
                        ao_axn.has_response_body_base64() &&
           !ao_axn.response_body_base64().empty())
        {
                const std::string& l_b64 = ao_axn.response_body_base64();
                char* l_body = NULL;
                size_t l_body_len = 0;
                int32_t l_s;
                l_s = b64_decode(&l_body, l_body_len, l_b64.c_str(), l_b64.length());
                if(!l_body ||
                   !l_body_len ||
                   (l_s != WAFLZ_STATUS_OK))
                {
                        WAFLZ_PERROR(ao_err_msg, "decoding response_body_base64 string: %s", l_b64.c_str());
                        return WAFLZ_STATUS_ERROR;
                }
                ao_axn.mutable_response_body()->assign(l_body, l_body_len);
                if(l_body) { free(l_body); l_body = NULL; }
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details return short date in form "<mm>/<dd>/<YYYY>"
//: \return  None
//: \param   TODO
//: ----------------------------------------------------------------------------
static const char *get_date_short_str(void)
{
        // TODO thread caching???
        static char s_date_str[128];
        time_t l_time = time(NULL);
        struct tm* l_tm = localtime(&l_time);
        if(0 == strftime(s_date_str, sizeof(s_date_str), "%m/%d/%Y", l_tm))
        {
                return "1/1/1970";
        }
        else
        {
                return s_date_str;
        }
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  None
//: \param   TODO
//: ----------------------------------------------------------------------------
static int32_t add_limit_with_key(waflz_pb::limit &ao_limit,
                                  uint16_t a_key,
                                  rqst_ctx *a_ctx)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // Set operator to streq for all
        // -------------------------------------------------
        const char *l_data = NULL;
        uint32_t l_len = 0;
        switch(a_key)
        {
        // -------------------------------------------------
        // ip
        // -------------------------------------------------
        case waflz_pb::limit_key_t_IP:
        {
                l_data = a_ctx->m_src_addr.m_data;
                l_len = a_ctx->m_src_addr.m_len;
                break;
        }
        // -------------------------------------------------
        // user-agent
        // -------------------------------------------------
        case waflz_pb::limit_key_t_USER_AGENT:
        {
                if(!a_ctx)
                {
                        break;
                }
                data_t l_d;
                data_t l_v;
                _GET_HEADER("User-Agent");
                l_data = l_v.m_data;
                l_len = l_v.m_len;
                break;
        }
        // -------------------------------------------------
        // ???
        // -------------------------------------------------
        default:
        {
                //WAFLZ_PERROR(m_err_msg, "unrecognized dimension type: %u", a_key);
                return WAFLZ_STATUS_ERROR;
        }
        }
        // if no data -no limit
        if(!l_data ||
           (l_len == 0))
        {
                return WAFLZ_STATUS_OK;
        }
        // Add limit for any data
        waflz_pb::condition *l_c = NULL;
        if(ao_limit.condition_groups_size() > 0)
        {
                l_c = ao_limit.mutable_condition_groups(0)->add_conditions();
        }
        else
        {
                l_c = ao_limit.add_condition_groups()->add_conditions();
        }
        // -------------------------------------------------
        // set operator
        // -------------------------------------------------
        // always STREQ
        waflz_pb::op_t* l_operator = l_c->mutable_op();
        l_operator->set_type(waflz_pb::op_t_type_t_STREQ);
        l_operator->set_value(l_data, l_len);
        // -------------------------------------------------
        // set var
        // -------------------------------------------------
        waflz_pb::condition_target_t* l_var = l_c->mutable_target();
        switch(a_key)
        {
        // -------------------------------------------------
        // ip
        // -------------------------------------------------
        case waflz_pb::limit_key_t_IP:
        {
                l_var->set_type(waflz_pb::condition_target_t_type_t_REMOTE_ADDR);
                break;
        }
        // -------------------------------------------------
        // user-agent
        // -------------------------------------------------
        case waflz_pb::limit_key_t_USER_AGENT:
        {
                l_var->set_type(waflz_pb::condition_target_t_type_t_REQUEST_HEADERS);
                l_var->mutable_value()->assign("User-Agent");
                break;
        }
        // -------------------------------------------------
        // ???
        // -------------------------------------------------
        default:
        {
                break;
        }
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details ctor
//: \return  None
//: \param   TODO
//: ----------------------------------------------------------------------------
scopes::scopes(engine &a_engine, kv_db &a_kv_db):
        m_init(false),
        m_pb(NULL),
        m_err_msg(),
        m_engine(a_engine),
        m_db(a_kv_db),
        m_id(),
        m_cust_id(),
        m_id_acl_map(),
        m_id_rules_map(),
        m_id_profile_map(),
        m_id_limit_map(),
        m_enfx(NULL),
        m_enf_limit(false)
{
        m_pb = new waflz_pb::scope_config();
        m_enfx = new enforcer(false);
}
//: ----------------------------------------------------------------------------
//: \brief   dtor
//: \deatils
//: \return  None
//: ----------------------------------------------------------------------------
scopes::~scopes()
{
        if(m_pb) { delete m_pb; m_pb = NULL; }
        if(m_enfx) { delete m_enfx; m_enfx = NULL; }
        // -------------------------------------------------
        // clear parts...
        // -------------------------------------------------
#define _DEL_MAP(_t, _m) do { \
        for(_t::iterator i = _m.begin(); i != _m.end(); ++i) { \
                if(i->second) { delete i->second; i->second = NULL; } \
        } \
} while(0)
        _DEL_MAP(id_acl_map_t, m_id_acl_map);
        _DEL_MAP(id_rules_map_t, m_id_rules_map);
        _DEL_MAP(id_profile_map_t, m_id_profile_map);
        _DEL_MAP(id_limit_map_t, m_id_limit_map);
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  0/-1
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t scopes::validate(void)
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
        if(!m_pb->has_id())
        {
                WAFLZ_PERROR(m_err_msg, "missing id field");
                return WAFLZ_STATUS_ERROR;
        }
        m_id = m_pb->id();
        // -------------------------------------------------
        // TODO -add validation...
        // -------------------------------------------------
        if(m_pb->has_customer_id())
        {
                m_cust_id = m_pb->customer_id();
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t scopes::load_config(const char *a_buf,
                            uint32_t a_buf_len,
                            const std::string& a_conf_dir_path)
{
        if(a_buf_len > _SCOPES_MAX_SIZE)
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
        if(l_s != JSPB_OK)
        {
                WAFLZ_PERROR(m_err_msg, "parsing json. Reason: %s", get_jspb_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // validate
        // -------------------------------------------------
        l_s = validate();
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // for each scope...
        // -------------------------------------------------
        for(int i_s = 0; i_s < m_pb->scopes_size(); ++i_s)
        {
                ::waflz_pb::scope& l_sc = *(m_pb->mutable_scopes(i_s));
                l_s = load_parts(l_sc, a_conf_dir_path);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // done...
        // -------------------------------------------------
        m_init = true;
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t scopes::load_config(void *a_js, const std::string& a_conf_dir_path)
{
        m_init = false;
        // -------------------------------------------------
        // load from js object
        // -------------------------------------------------
        const rapidjson::Document &l_js = *((rapidjson::Document *)a_js);
        int32_t l_s;
        l_s = update_from_json(*m_pb, l_js);
        if(l_s != JSPB_OK)
        {
                WAFLZ_PERROR(m_err_msg, "parsing json. Reason: %s", get_jspb_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // validate
        // -------------------------------------------------
        l_s = validate();
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // for each scope...
        // -------------------------------------------------
        for(int i_s = 0; i_s < m_pb->scopes_size(); ++i_s)
        {
                ::waflz_pb::scope& l_sc = *(m_pb->mutable_scopes(i_s));
                l_s = load_parts(l_sc, a_conf_dir_path);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // done...
        // -------------------------------------------------
        m_init = true;
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t scopes::load_parts(waflz_pb::scope& a_scope,
                           const std::string& a_conf_dir_path)
{
        // -------------------------------------------------
        // acl audit
        // -------------------------------------------------
        if(a_scope.has_acl_audit_id())
        {
                // -----------------------------------------
                // check exist
                // -----------------------------------------
                id_acl_map_t::iterator i_acl = m_id_acl_map.find(a_scope.acl_audit_id());
                if(i_acl != m_id_acl_map.end())
                {
                        a_scope.set__acl_audit__reserved((uint64_t)i_acl->second);
                        goto acl_audit_action;
                }
                // -----------------------------------------
                // make acl obj
                // -----------------------------------------
                acl *l_acl = new acl();
                std::string l_p = a_conf_dir_path + "/acl/" + a_scope.acl_audit_id();
                int32_t l_s;
                char *l_buf = NULL;
                uint32_t l_buf_len;
                l_s = read_file(l_p.c_str(), &l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", ns_waflz::get_err_msg());
                        if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        // TODO cleanup...
                        return WAFLZ_STATUS_ERROR;
                }
                l_s = l_acl->load_config(l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", l_acl->get_err_msg());
                        if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        // TODO cleanup...
                        return WAFLZ_STATUS_ERROR;
                }
                if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
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
        if(a_scope.has_acl_audit_action())
        {
                waflz_pb::enforcement *l_a = a_scope.mutable_acl_audit_action();
                int32_t l_s;
                l_s = compile_action(*l_a, m_err_msg);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // acl audit
        // -------------------------------------------------
        if(a_scope.has_acl_prod_id())
        {
                // -----------------------------------------
                // check exist
                // -----------------------------------------
                id_acl_map_t::iterator i_acl = m_id_acl_map.find(a_scope.acl_prod_id());
                if(i_acl != m_id_acl_map.end())
                {
                        a_scope.set__acl_prod__reserved((uint64_t)i_acl->second);
                        goto acl_prod_action;
                }
                // -----------------------------------------
                // make acl obj
                // -----------------------------------------
                acl *l_acl = new acl();
                std::string l_p = a_conf_dir_path + "/acl/" + a_scope.acl_prod_id();
                int32_t l_s;
                char *l_buf = NULL;
                uint32_t l_buf_len;
                l_s = read_file(l_p.c_str(), &l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", ns_waflz::get_err_msg());
                        if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        // TODO cleanup...
                        return WAFLZ_STATUS_ERROR;
                }
                l_s = l_acl->load_config(l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", l_acl->get_err_msg());
                        if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        // TODO cleanup...
                        return WAFLZ_STATUS_ERROR;
                }
                if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                // -----------------------------------------
                // add to map
                // -----------------------------------------
                a_scope.set__acl_prod__reserved((uint64_t)l_acl);
                m_id_acl_map[a_scope.acl_prod_id()] = l_acl;
        }
acl_prod_action:
        // -------------------------------------------------
        // acl audit action
        // -------------------------------------------------
        if(a_scope.has_acl_prod_action())
        {
                waflz_pb::enforcement *l_a = a_scope.mutable_acl_prod_action();
                int32_t l_s;
                l_s = compile_action(*l_a, m_err_msg);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // rules audit
        // -------------------------------------------------
        if(a_scope.has_rules_audit_id())
        {
                // -----------------------------------------
                // check exist
                // -----------------------------------------
                id_rules_map_t::iterator i_rules = m_id_rules_map.find(a_scope.rules_audit_id());
                if(i_rules != m_id_rules_map.end())
                {
                        a_scope.set__rules_audit__reserved((uint64_t)i_rules->second);
                        goto rules_audit_action;
                }
                // -----------------------------------------
                // make rules obj
                // -----------------------------------------
                std::string l_p = a_conf_dir_path + "/rules/" + a_scope.rules_audit_id();
                rules *l_rules = new rules(m_engine);
                int32_t l_s;
                l_s = l_rules->load_config_file(l_p.c_str(), l_p.length());
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error loading rules (audit) conf file: %s. reason: %s\n",
                                   l_p.c_str(),
                                   "__na__");
                                   // TODO -get reason...
                                   //l_wafl->get_err_msg());
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
        if(a_scope.has_rules_audit_action())
        {
                waflz_pb::enforcement *l_a = a_scope.mutable_rules_audit_action();
                int32_t l_s;
                l_s = compile_action(*l_a, m_err_msg);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // rules prod
        // -------------------------------------------------
        if(a_scope.has_rules_prod_id())
        {
                // -----------------------------------------
                // check exist
                // -----------------------------------------
                id_rules_map_t::iterator i_rules = m_id_rules_map.find(a_scope.rules_prod_id());
                if(i_rules != m_id_rules_map.end())
                {
                        a_scope.set__rules_prod__reserved((uint64_t)i_rules->second);
                        goto rules_prod_action;
                }
                // -----------------------------------------
                // make rules obj
                // -----------------------------------------
                std::string l_p = a_conf_dir_path + "/rules/" + a_scope.rules_prod_id();
                rules *l_rules = new rules(m_engine);
                int32_t l_s;
                l_s = l_rules->load_config_file(l_p.c_str(), l_p.length());
                if(l_s != WAFLZ_STATUS_OK)
                {
                        NDBG_PRINT("error loading rules (prod) conf file: %s. reason: %s\n",
                                   l_p.c_str(),
                                   "__na__");
                                   // TODO -get reason...
                                   //l_wafl->get_err_msg());
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
        if(a_scope.has_rules_prod_action())
        {
                waflz_pb::enforcement *l_a = a_scope.mutable_rules_prod_action();
                int32_t l_s;
                l_s = compile_action(*l_a, m_err_msg);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // profile audit
        // -------------------------------------------------
        if(a_scope.has_profile_audit_id())
        {
                // -----------------------------------------
                // check exist
                // -----------------------------------------
                id_profile_map_t::iterator i_profile = m_id_profile_map.find(a_scope.profile_audit_id());
                if(i_profile != m_id_profile_map.end())
                {
                        a_scope.set__profile_audit__reserved((uint64_t)i_profile->second);
                        goto profile_audit_action;
                }
                // -----------------------------------------
                // make profile obj
                // -----------------------------------------
                profile *l_profile = new profile(m_engine);
                std::string l_p = a_conf_dir_path + "/profile/" + a_scope.profile_audit_id();
                int32_t l_s;
                char *l_buf = NULL;
                uint32_t l_buf_len;
                l_s = read_file(l_p.c_str(), &l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", ns_waflz::get_err_msg());
                        if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        // TODO cleanup...
                        return WAFLZ_STATUS_ERROR;
                }
                l_s = l_profile->load_config(l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", l_profile->get_err_msg());
                        if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        // TODO cleanup...
                        return WAFLZ_STATUS_ERROR;
                }
                if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                // -----------------------------------------
                // add to map
                // -----------------------------------------
                a_scope.set__profile_audit__reserved((uint64_t)l_profile);
                m_id_profile_map[a_scope.profile_audit_id()] = l_profile;
        }
profile_audit_action:
        // -------------------------------------------------
        // acl audit action
        // -------------------------------------------------
        if(a_scope.has_profile_audit_action())
        {
                waflz_pb::enforcement *l_a = a_scope.mutable_profile_audit_action();
                int32_t l_s;
                l_s = compile_action(*l_a, m_err_msg);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // profile prod
        // -------------------------------------------------
        if(a_scope.has_profile_prod_id())
        {
                // -----------------------------------------
                // check exist
                // -----------------------------------------
                id_profile_map_t::iterator i_profile = m_id_profile_map.find(a_scope.profile_prod_id());
                if(i_profile != m_id_profile_map.end())
                {
                        a_scope.set__profile_prod__reserved((uint64_t)i_profile->second);
                        goto profile_prod_action;
                }
                // -----------------------------------------
                // make profile obj
                // -----------------------------------------
                profile *l_profile = new profile(m_engine);
                std::string l_p = a_conf_dir_path + "/profile/" + a_scope.profile_prod_id();
                int32_t l_s;
                char *l_buf = NULL;
                uint32_t l_buf_len;
                l_s = read_file(l_p.c_str(), &l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", ns_waflz::get_err_msg());
                        if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        // TODO cleanup...
                        return WAFLZ_STATUS_ERROR;
                }
                l_s = l_profile->load_config(l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", l_profile->get_err_msg());
                        if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        // TODO cleanup...
                        return WAFLZ_STATUS_ERROR;
                }
                if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                // -----------------------------------------
                // add to map
                // -----------------------------------------
                a_scope.set__profile_prod__reserved((uint64_t)l_profile);
                m_id_profile_map[a_scope.profile_prod_id()] = l_profile;
        }
profile_prod_action:
        // -------------------------------------------------
        // acl audit action
        // -------------------------------------------------
        if(a_scope.has_profile_prod_action())
        {
                waflz_pb::enforcement *l_a = a_scope.mutable_profile_prod_action();
                int32_t l_s;
                l_s = compile_action(*l_a, m_err_msg);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // limits
        // -------------------------------------------------
        for(int i_l = 0; i_l < a_scope.limits_size(); ++i_l)
        {
                if(!a_scope.limits(i_l).has_id())
                {
                        continue;
                }
                const std::string& l_id = a_scope.limits(i_l).id();
                // -----------------------------------------
                // check exist...
                // -----------------------------------------
                id_limit_map_t::iterator i_limit = m_id_limit_map.find(l_id);
                if(i_limit != m_id_limit_map.end())
                {
                        a_scope.mutable_limits(i_l)->set__reserved_1((uint64_t)i_limit->second);
                        goto limit_action;
                }
                // -----------------------------------------
                // make limit obj
                // -----------------------------------------
                {
                limit *l_limit = new limit(m_db);
                std::string l_p = a_conf_dir_path + "/limit/" + a_scope.acl_audit_id();
                int32_t l_s;
                char *l_buf = NULL;
                uint32_t l_buf_len;
                l_s = read_file(l_p.c_str(), &l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", ns_waflz::get_err_msg());
                        if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        // TODO cleanup...
                        return WAFLZ_STATUS_ERROR;
                }
                l_s = l_limit->load(l_buf, l_buf_len);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", l_limit->get_err_msg());
                        if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
                        // TODO cleanup...
                        return WAFLZ_STATUS_ERROR;
                }
                if(l_buf) { free(l_buf); l_buf = NULL; l_buf_len = 0;}
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
                if(a_scope.limits(i_l).has_action())
                {
                        waflz_pb::enforcement *l_a = a_scope.mutable_limits(i_l)->mutable_action();
                        int32_t l_s;
                        l_s = compile_action(*l_a, m_err_msg);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        //NDBG_PRINT("%s\n", a_scope.DebugString().c_str());
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t scopes::process(const waflz_pb::enforcement **ao_enf,
                        waflz_pb::event **ao_audit_event,
                        waflz_pb::event **ao_prod_event,
                        void *a_ctx,
                        rqst_ctx **ao_rqst_ctx)
{
        if(!m_pb)
        {
                WAFLZ_PERROR(m_err_msg, "pb == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // unset
        // -------------------------------------------------
        m_enf_limit = false;
        // -------------------------------------------------
        // create rqst_ctx
        // -------------------------------------------------
        rqst_ctx *l_ctx = NULL;
        // TODO -fix args!!!
        //l_rqst_ctx = new rqst_ctx(a_ctx, l_body_size_max, m_waf->get_parse_json());
        l_ctx = new rqst_ctx(a_ctx, 1024, true);
        if(ao_rqst_ctx)
        {
                *ao_rqst_ctx = l_ctx;
        }
        // -------------------------------------------------
        // run phase 1 init
        // -------------------------------------------------
        int32_t l_s;
        l_s = l_ctx->init_phase_1(m_engine.get_geoip2_mmdb(), NULL, NULL, NULL);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO -log error???
                if(!ao_rqst_ctx && l_ctx) { delete l_ctx; l_ctx = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // for each scope...
        // -------------------------------------------------
        for(int i_s = 0; i_s < m_pb->scopes_size(); ++i_s)
        {
                const ::waflz_pb::scope& l_sc = m_pb->scopes(i_s);
                bool l_m;
                l_s = in_scope(l_m, l_sc, l_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // TODO -log error???
                        if(!ao_rqst_ctx && l_ctx) { delete l_ctx; l_ctx = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // no match continue to next check...
                // -----------------------------------------
                if(!l_m)
                {
                        continue;
                }
                // -----------------------------------------
                // process scope...
                // -----------------------------------------
                l_s = process(ao_enf, ao_audit_event, ao_prod_event, l_sc, a_ctx, ao_rqst_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // TODO -log error???
                        if(!ao_rqst_ctx && l_ctx) { delete l_ctx; l_ctx = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // break out on first scope match
                // -----------------------------------------
                break;
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if(!ao_rqst_ctx && l_ctx) { delete l_ctx; l_ctx = NULL; }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t scopes::process(const waflz_pb::enforcement** ao_enf,
                        waflz_pb::event** ao_audit_event,
                        waflz_pb::event** ao_prod_event,
                        const ::waflz_pb::scope& a_scope,
                        void *a_ctx,
                        rqst_ctx **ao_rqst_ctx)
{
        // -------------------------------------------------
        // sanity checking
        // -------------------------------------------------
        if(!ao_enf ||
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
        // *************************************************
        //                   A U D I T
        // *************************************************
        // -------------------------------------------------
        // -------------------------------------------------
        // acl
        // -------------------------------------------------
        if(a_scope.has__acl_audit__reserved())
        {
                acl *l_acl = (acl *)a_scope._acl_audit__reserved();
                waflz_pb::event *l_event = NULL;
                bool l_wl = false;
                int32_t l_s;
                l_s = l_acl->process(&l_event, l_wl, a_ctx, **ao_rqst_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        if(l_event) { delete l_event; l_event = NULL; }
                        // TODO reason???
                        return WAFLZ_STATUS_ERROR;
                }
                if(!l_event)
                {
                        goto audit_rules;
                }
                *ao_audit_event = l_event;
                if(a_scope.has_acl_audit_action())
                {
                        *ao_enf = &(a_scope.acl_audit_action());
                }
                goto prod;
        }
        // -------------------------------------------------
        // rules
        // -------------------------------------------------
audit_rules:
        if(a_scope.has__rules_audit__reserved())
        {
                rules *l_rules = (rules *)a_scope._rules_audit__reserved();
                waflz_pb::event *l_event = NULL;
                int32_t l_s;
                l_s = l_rules->process(&l_event, a_ctx, ao_rqst_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        if(l_event) { delete l_event; l_event = NULL; }
                        // TODO reason???
                        return WAFLZ_STATUS_ERROR;
                }
                if(!l_event)
                {
                        goto audit_profile;
                }
                *ao_audit_event = l_event;
                if(a_scope.has_rules_audit_action())
                {
                        *ao_enf = &(a_scope.rules_audit_action());
                }
                goto prod;
        }
        // -------------------------------------------------
        // profile
        // -------------------------------------------------
audit_profile:
        if(a_scope.has__profile_audit__reserved())
        {
                int32_t l_s;
                // -----------------------------------------
                // reset phase 1 to handle ignore...
                // -----------------------------------------
                l_s = (*ao_rqst_ctx)->reset_phase_1();
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // TODO reason???
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // profile process
                // -----------------------------------------
                profile *l_profile = (profile *)a_scope._profile_audit__reserved();
                waflz_pb::event *l_event = NULL;
                l_s = l_profile->process(&l_event, a_ctx, ao_rqst_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        if(l_event) { delete l_event; l_event = NULL; }
                        // TODO reason???
                        return WAFLZ_STATUS_ERROR;
                }
                if(!l_event)
                {
                        goto prod;
                }
                *ao_audit_event = l_event;
                if(a_scope.has_profile_audit_action())
                {
                        *ao_enf = &(a_scope.profile_audit_action());
                }
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
        if(a_scope.has__acl_prod__reserved())
        {
                acl *l_acl = (acl *)a_scope._acl_prod__reserved();
                waflz_pb::event *l_event = NULL;
                bool l_wl = false;
                int32_t l_s;
                l_s = l_acl->process(&l_event, l_wl, a_ctx, **ao_rqst_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        if(l_event) { delete l_event; l_event = NULL; }
                        // TODO reason???
                        return WAFLZ_STATUS_ERROR;
                }
                if(!l_event)
                {
                        goto enforcements;
                }
                *ao_prod_event = l_event;
                if(a_scope.has_acl_prod_action())
                {
                        *ao_enf = &(a_scope.acl_prod_action());
                }
                goto done;
        }
        // -------------------------------------------------
        // enforcements
        // -------------------------------------------------
enforcements:
        if(!m_enfx)
        {
                goto limits;
        }
        {
        int32_t l_s;
        l_s = m_enfx->process(ao_enf, *ao_rqst_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "performing enforcer process");
                return WAFLZ_STATUS_ERROR;
        }
        if(*ao_enf)
        {
                goto done;
        }
        }
limits:
        // -------------------------------------------------
        // limits
        // -------------------------------------------------
        for(int i_l = 0; i_l < a_scope.limits_size(); ++i_l)
        {
                const ::waflz_pb::scope_limit_config& l_slc = a_scope.limits(i_l);
                if(!l_slc.has__reserved_1())
                {
                        continue;
                }
                limit *l_limit = (limit *)l_slc._reserved_1();
                bool l_exceeds = false;
                const waflz_pb::condition_group *l_cg = NULL;
                l_limit->process(l_exceeds, &l_cg, *ao_rqst_ctx);
                if(!l_exceeds)
                {
                        continue;
                }
                if(!l_slc.has_action())
                {
                        continue;
                }
                const waflz_pb::enforcement& l_axn = l_slc.action();
                // -----------------------------------------
                // add new exceeds
                // -----------------------------------------
                int32_t l_s;
                waflz_pb::config *l_cfg = NULL;
                l_s = add_exceed_limit(&l_cfg,
                                       *(l_limit->get_pb()),
                                       l_cg,
                                       l_axn,
                                       *ao_rqst_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "performing add_exceed_limit");
                        return WAFLZ_STATUS_ERROR;
                }
                //const ::waflz_pb::enforcement& l_a = a_scope.limits(i_l).action();
                // -----------------------------------------
                // merge enforcement
                // -----------------------------------------
                //NDBG_OUTPUT("l_enfx: %s\n", l_enfcr->ShortDebugString().c_str());
                l_s = m_enfx->merge(*l_cfg);
                // TODO -return enforcer...
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", m_enfx->get_err_msg());
                        return WAFLZ_STATUS_ERROR;
                }
                if(l_cfg) { delete l_cfg; l_cfg = NULL; }
                // -----------------------------------------
                // process enforcer
                // -----------------------------------------
                l_s = m_enfx->process(ao_enf, *ao_rqst_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // enforced???
                // -----------------------------------------
                if(ao_enf)
                {
                        // ---------------------------------
                        // mark as new enf
                        // ---------------------------------
                        m_enf_limit = true;
                        goto done;
                }
        }
        // -------------------------------------------------
        // rules
        // -------------------------------------------------
        if(a_scope.has__rules_prod__reserved())
        {
                // -----------------------------------------
                // process
                // -----------------------------------------
                rules *l_rules = (rules *)a_scope._rules_prod__reserved();
                waflz_pb::event *l_event = NULL;
                int32_t l_s;
                l_s = l_rules->process(&l_event, a_ctx, ao_rqst_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        if(l_event) { delete l_event; l_event = NULL; }
                        // TODO reason???
                        return WAFLZ_STATUS_ERROR;
                }
                if(!l_event)
                {
                        goto prod_profile;
                }
                *ao_prod_event = l_event;
                if(a_scope.has_rules_prod_action())
                {
                        *ao_enf = &(a_scope.rules_prod_action());
                }
                goto done;
        }
        // -------------------------------------------------
        // profile
        // -------------------------------------------------
prod_profile:
        if(a_scope.has__profile_prod__reserved())
        {
                // -----------------------------------------
                // reset phase 1 to handle ignore...
                // -----------------------------------------
                int32_t l_s;
                l_s = (*ao_rqst_ctx)->reset_phase_1();
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // TODO reason???
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // profile process
                // -----------------------------------------
                profile *l_profile = (profile *)a_scope._profile_prod__reserved();
                waflz_pb::event *l_event = NULL;
                l_s = l_profile->process(&l_event, a_ctx, ao_rqst_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        if(l_event) { delete l_event; l_event = NULL; }
                        // TODO reason???
                        return WAFLZ_STATUS_ERROR;
                }
                if(!l_event)
                {
                        goto done;
                }
                *ao_prod_event = l_event;
                if(a_scope.has_profile_prod_action())
                {
                        *ao_enf = &(a_scope.profile_prod_action());
                }
                goto done;
        }
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
done:
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t scopes::add_exceed_limit(waflz_pb::config **ao_cfg,
                                 const waflz_pb::limit& a_limit,
                                 const waflz_pb::condition_group *a_condition_group,
                                 const waflz_pb::enforcement &a_action,
                                 rqst_ctx *a_ctx)
{
        if(!ao_cfg)
        {
                WAFLZ_PERROR(m_err_msg, "enforcer ptr NULL.");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // create enforcement
        // -------------------------------------------------
        waflz_pb::config *l_cfg = new waflz_pb::config();
        l_cfg->set_id("NA");
        l_cfg->set_name("NA");
        l_cfg->set_type(waflz_pb::config_type_t_ENFORCER);
        l_cfg->set_customer_id(m_cust_id);
        l_cfg->set_enabled_date(get_date_short_str());
        // -------------------------------------------------
        // populate limit info
        // -------------------------------------------------
        waflz_pb::limit* l_limit = l_cfg->add_limits();
        l_limit->set_id(a_limit.id());
        if(a_limit.has_name())
        { l_limit->set_name(a_limit.name()); }
        else
        {
                l_limit->set_name("NA");
        }
        l_limit->set_disabled(false);
        // -------------------------------------------------
        // copy "the limit"
        // -------------------------------------------------
        if(a_condition_group)
        {
                waflz_pb::condition_group *l_cg = l_limit->add_condition_groups();
                l_cg->CopyFrom(*a_condition_group);
        }
        // -------------------------------------------------
        // create limits for dimensions
        // -------------------------------------------------
        for(int i_k = 0; i_k < a_limit.keys_size(); ++i_k)
        {
                int32_t l_s;
                l_s = add_limit_with_key(*l_limit,
                                         a_limit.keys(i_k),
                                         a_ctx);
                if(l_s != WAFLZ_STATUS_OK)
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
        waflz_pb::enforcement *l_e = l_limit->mutable_action();
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
        if(l_e->has_duration_sec())
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
//: ----------------------------------------------------------------------------
//: \details  run a limit operator on some data
//: \l_retval number of entries added to ao_match_list
//:           -1 on failure
//: \param    TODO
//: ----------------------------------------------------------------------------
int32_t rl_run_op(bool &ao_matched,
                  const waflz_pb::op_t &a_op,
                  const char *a_data,
                  uint32_t a_len,
                  bool a_case_insensitive)
{
        // assume operator is STREQ
        ao_matched = false;
        waflz_pb::op_t_type_t l_op_type = waflz_pb::op_t_type_t_STREQ;
        if(a_op.has_type())
        {
                // operator type actually provided
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
                if(!a_op.has__reserved_1())
                {
                        return WAFLZ_STATUS_ERROR;
                }
                regex *l_rx = (regex *)(a_op._reserved_1());
                if(!l_rx)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // match?
                // -----------------------------------------
                //TRC_ALL("RX[%p]: %s == %.*s\n", l_rx, l_rx->get_regex_string().c_str(), (int)a_len, a_data);
                int l_s;
                l_s = l_rx->compare(a_data, a_len);
                // if failed to match
                if(l_s < 0)
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
                const std::string &l_op_match = a_op.value();
                uint32_t l_len = l_op_match.length();
                if(l_len != a_len)
                {
                        break;
                }
                int l_cmp = 0;
                if(a_case_insensitive)
                {
                        l_cmp = strncasecmp(l_op_match.c_str(), a_data, l_len);
                }
                else
                {
                        l_cmp = strncmp(l_op_match.c_str(), a_data, l_len);
                }
                if(l_cmp == 0)
                {
                        // matched
                        ao_matched = true;
                        break;
                }
                //TRACE("Got data: '%.*s' and match '%s'", SUBBUF_FORMAT(a_data), l_op_match.c_str());
                break;
        }
        // -------------------------------------------------
        // GLOB (glob -wildcard match)
        // -------------------------------------------------
        case waflz_pb::op_t_type_t_GLOB:
        {
                int l_flags = FNM_NOESCAPE;
                if(a_case_insensitive)
                {
                        l_flags |= FNM_CASEFOLD;
                }
                int l_cmp;
                const std::string &l_op_match = a_op.value();
                l_cmp = fnmatch(l_op_match.c_str(), a_data, l_flags);
                if(l_cmp == 0)
                {
                        // matched
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
                if(!a_op.has__reserved_1())
                {
                        return WAFLZ_STATUS_ERROR;
                }
                nms *l_nms = (nms *)(a_op._reserved_1());
                if(!l_nms)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // match?
                // -----------------------------------------
                int32_t l_s;
                l_s = l_nms->contains(ao_matched, a_data, a_len);
                // if failed to match
                if(l_s < 0)
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
                if(!a_op.has__reserved_1())
                {
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // case insensitive
                // -----------------------------------------
                if(a_op.is_case_insensitive())
                {
                        data_case_i_set_t *l_ds = (data_case_i_set_t *)(a_op._reserved_1());
                        if(!l_ds)
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
                        if((i_d != l_ds->end()) &&
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
                        data_set_t *l_ds = (data_set_t *)(a_op._reserved_1());
                        if(!l_ds)
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
                        if((i_d != l_ds->end()) &&
                           (i_d->m_len == l_d.m_len))
                        {
                                ao_matched = true;
                        }
                }
                break;
        }
        // -------------------------------------------------
        // default
        // -------------------------------------------------
        default:
        {
                // do nothing...
                return WAFLZ_STATUS_OK;
        }
        }
        if(a_op.is_negated())
        {
                // negate value
                ao_matched = !ao_matched;
        }
        // -------------------------------------------------
        // TODO -push matches???
        // -------------------------------------------------
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details check if request "in scope"
//: \return  true if in scope
//:          false if not in scope
//: \param   a_scope TODO
//: \param   a_ctx   TODO
//: ----------------------------------------------------------------------------
int32_t in_scope(bool &ao_match,
                 const waflz_pb::scope &a_scope,
                 rqst_ctx *a_ctx)
{
        ao_match = false;
        if(!a_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // host
        // -------------------------------------------------
        if(a_scope.has_host() &&
           a_scope.host().has_type() &&
           (a_scope.host().has_value() ||
            a_scope.host().values_size()))
        {
                const data_t &l_d = a_ctx->m_host;
                if(!l_d.m_data ||
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
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                if(!l_matched)
                {
                        return WAFLZ_STATUS_OK;
                }
        }
        // -------------------------------------------------
        // path
        // -------------------------------------------------
        if(a_scope.has_path() &&
           a_scope.path().has_type() &&
           (a_scope.path().has_value() ||
            a_scope.path().values_size()))
        {
                data_t l_d = a_ctx->m_uri;
                if(!l_d.m_data ||
                   !l_d.m_len)
                {
                        return WAFLZ_STATUS_OK;
                }
                // use length w/o q string
                // use length w/o q string
                if(a_ctx->m_uri_path_len)
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
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                if(!l_matched)
                {
                        return WAFLZ_STATUS_OK;
                }
        }
        ao_match = true;
        return WAFLZ_STATUS_OK;
}
}
