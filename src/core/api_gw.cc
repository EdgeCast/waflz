//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    api_gw.cc
//! \details: See header
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <utility>

#include "api_gw.pb.h"
#include "event.pb.h"
#include "jspb/jspb.h"
#include "op/regex.h"
#include "rapidjson/error/en.h"
#include "rapidjson/memorystream.h"
#include "rapidjson/schema.h"
#include "support/ndebug.h"
#include "waflz/api_gw.h"
#include "waflz/engine.h"
#include "waflz/schema.h"
#include "waflz/acl.h"
#include "waflz/def.h"
#include "waflz/scopes.h"
#include "waflz/rqst_ctx.h"
#include "waflz/trace.h"
#include "waflz/string_util.h"
#include "support/file_util.h"
#include "support/time_util.h"
#include "waflz/scopes.h"
#include "core/jwt_parser.h"
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
#define _CONFIG_API_GW_MAX_SIZE (1 << 21)
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! \details constructor
//! \return  None
//! \param   None
//! ----------------------------------------------------------------------------
api_gw::api_gw(engine& a_engine)
    : m_init(false),
      m_err_msg(),
      m_engine(a_engine),
      m_id(),
      m_cust_id(),
      m_team_config(false),
      m_name(),
      m_pb(NULL),
      m_schema_map(),
      m_jwt_parser_map()
{}
//! ----------------------------------------------------------------------------
//! \details dtor
//! \return  none
//! ----------------------------------------------------------------------------
api_gw::~api_gw()
{
        // -------------------------------------------------
        // destruct protobuf
        // -------------------------------------------------
        if (m_pb)
        {
                delete m_pb;
                m_pb = NULL;
        }
        // -------------------------------------------------
        // destruct schemas
        // -------------------------------------------------
        for (auto i_s = m_schema_map.begin();
             i_s != m_schema_map.end();
             ++i_s)
        {
                if (i_s->second)
                {
                        delete i_s->second;
                        i_s->second = NULL;
                }
        }
        // -------------------------------------------------
        // destruct jwt parsers
        // -------------------------------------------------
        for (auto i_s = m_jwt_parser_map.begin();
             i_s != m_jwt_parser_map.end();
             ++i_s)
        {
                if (i_s->second)
                {
                        delete i_s->second;
                        i_s->second = NULL;
                }
        }
        // -------------------------------------------------
        // destruct m_regex_list
        // -------------------------------------------------
        for (regex_list_t::iterator i_p = m_regex_list.begin();
             i_p != m_regex_list.end();
             ++i_p)
        {
                if (*i_p)
                {
                        delete *i_p;
                        *i_p = NULL;
                }
        }
        // -------------------------------------------------
        // destruct str_ptr_set_list
        // -------------------------------------------------
        for (data_set_list_t::iterator i_n = m_data_set_list.begin();
             i_n != m_data_set_list.end();
             ++i_n)
        {
                if (*i_n)
                {
                        delete *i_n;
                        *i_n = NULL;
                }
        }
        for (data_case_i_set_list_t::iterator i_n =
                 m_data_case_i_set_list.begin();
             i_n != m_data_case_i_set_list.end();
             ++i_n)
        {
                if (*i_n)
                {
                        delete *i_n;
                        *i_n = NULL;
                }
        }
}
//! ----------------------------------------------------------------------------
//! \details compile_op
//! \return  0/-1
//! \param ao_op: Input operation
//! ----------------------------------------------------------------------------
int32_t api_gw::compile_op(::waflz_pb::op_t& ao_op)
{
        // -------------------------------------------------
        // check if exist...
        // -------------------------------------------------
        if (!ao_op.has_type()) { return WAFLZ_STATUS_OK; }
        // -------------------------------------------------
        // for type...
        // -------------------------------------------------
        switch (ao_op.type())
        {
                // -------------------------------------------------
                // regex
                // -------------------------------------------------
                case ::waflz_pb::op_t_type_t_RX: {
                        if (!ao_op.has_value()) { return WAFLZ_STATUS_ERROR; }
                        const std::string& l_val = ao_op.value();
                        regex* l_rx = new regex();
                        int32_t l_s;
                        l_s = l_rx->init(l_val.c_str(), l_val.length());
                        if (l_s != WAFLZ_STATUS_OK)
                        {
                                WAFLZ_PERROR(m_err_msg,
                                             "failed to compile regex: '%s'.",
                                             l_val.c_str());
                                delete l_rx;
                                l_rx = NULL;
                                return WAFLZ_STATUS_ERROR;
                        }
                        ao_op.set__reserved_1((uint64_t)(l_rx));
                        m_regex_list.push_back(l_rx);
                        break;
                }
                // -------------------------------------------------
                // exact condition list
                // -------------------------------------------------
                case ::waflz_pb::op_t_type_t_EM: {
                        if (!ao_op.has_value() && !ao_op.values_size())
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                        // -----------------------------------------
                        // case insensitive
                        // -----------------------------------------
                        if (ao_op.is_case_insensitive())
                        {
                                data_case_i_set_t* l_ds =
                                    new data_case_i_set_t();
                                // ---------------------------------
                                // prefer values to value
                                // ---------------------------------
                                if (ao_op.values_size())
                                {
                                        for (int32_t i_v = 0;
                                             i_v < ao_op.values_size();
                                             ++i_v)
                                        {
                                                if (ao_op.values(i_v).empty())
                                                {
                                                        continue;
                                                }
                                                data_t l_d;
                                                l_d.m_data =
                                                    ao_op.values(i_v).c_str();
                                                l_d.m_len =
                                                    ao_op.values(i_v).length();
                                                l_ds->insert(l_d);
                                        }
                                }
                                else if (!ao_op.value().empty())
                                {
                                        data_t l_d;
                                        l_d.m_data = ao_op.value().c_str();
                                        l_d.m_len = ao_op.value().length();
                                        l_ds->insert(l_d);
                                }
                                ao_op.set__reserved_1((uint64_t)(l_ds));
                                m_data_case_i_set_list.push_back(l_ds);
                        }
                        // -----------------------------------------
                        // case sensitive
                        // -----------------------------------------
                        else
                        {
                                data_set_t* l_ds = new data_set_t();
                                // ---------------------------------
                                // prefer values to value
                                // ---------------------------------
                                if (ao_op.values_size())
                                {
                                        for (int32_t i_v = 0;
                                             i_v < ao_op.values_size();
                                             ++i_v)
                                        {
                                                if (ao_op.values(i_v).empty())
                                                {
                                                        continue;
                                                }
                                                data_t l_d;
                                                l_d.m_data =
                                                    ao_op.values(i_v).c_str();
                                                l_d.m_len =
                                                    ao_op.values(i_v).length();
                                                l_ds->insert(l_d);
                                        }
                                }
                                else if (!ao_op.value().empty())
                                {
                                        data_t l_d;
                                        l_d.m_data = ao_op.value().c_str();
                                        l_d.m_len = ao_op.value().length();
                                        l_ds->insert(l_d);
                                }
                                ao_op.set__reserved_1((uint64_t)(l_ds));
                                m_data_set_list.push_back(l_ds);
                        }
                        break;
                }
                // -------------------------------------------------
                // default
                // -------------------------------------------------
                default: {
                        break;
                }
        }
        return WAFLZ_STATUS_OK;
}

//! ----------------------------------------------------------------------------
//! \details add schema object to the schema map
//! \return  none
//! \param   a_schema: input schema
//! ----------------------------------------------------------------------------
void api_gw::add_schema_to_map(ns_waflz::schema* a_schema)
{
        std::string l_id = a_schema->get_id();
        m_schema_map[l_id] = a_schema;
}
//! ----------------------------------------------------------------------------
//! \details check if request matches an op_t
//! \return  true if in, false if not in
//! \param   ao_match: output match
//! \param   a_api_rule_pb: a schema protobuf
//! \param   a_method: method 
//! \param   a_uri: uri
//! ----------------------------------------------------------------------------
int32_t rule_match(bool& ao_match,
                   const waflz_pb::api_rule& a_api_rule_pb,
                   data_t a_method,
                   data_t a_uri)
{
        ao_match = false;
        // -------------------------------------------------
        // get request method
        // -------------------------------------------------
        bool l_method_match = false;
        for (int8_t l_it = 0; l_it < a_api_rule_pb.methods_size(); ++l_it)
        {
                // -------------------------------------------------
                // If method matches method in schema, set
                // l_method_match and break
                // -------------------------------------------------
                if (a_method.m_len == a_api_rule_pb.methods(l_it).size() &&
                    strncmp(a_method.m_data,
                            a_api_rule_pb.methods(l_it).c_str(),
                            a_method.m_len) == 0)
                {
                        l_method_match = true;
                        break;
                }
        }
        // -------------------------------------------------
        // If method doesn't match, exit
        // -------------------------------------------------
        if (!l_method_match) { return WAFLZ_STATUS_OK; }
        // -------------------------------------------------
        // path
        // -------------------------------------------------
        if (a_api_rule_pb.has_path() && a_api_rule_pb.path().has_type() &&
            (a_api_rule_pb.path().has_value() ||
             a_api_rule_pb.path().values_size()))
        {
                if (!a_uri.m_data || !a_uri.m_len) { return WAFLZ_STATUS_OK; }
                bool l_matched = false;
                // -------------------------------------------------
                // Run operation for match
                // -------------------------------------------------
                int32_t l_s = rl_run_op(l_matched,
                                        a_api_rule_pb.path(),
                                        a_uri.m_data,
                                        a_uri.m_len,
                                        true);
                if (l_s != WAFLZ_STATUS_OK) { return WAFLZ_STATUS_ERROR; }
                // -------------------------------------------------
                // If no match, return
                // -------------------------------------------------
                if (!l_matched) { return WAFLZ_STATUS_OK; }
        }
        // -------------------------------------------------
        // If match, set ao_match
        // -------------------------------------------------
        ao_match = true;
        return WAFLZ_STATUS_OK;
}

//! ----------------------------------------------------------------------------
//! \details Process request against api gateway
//! \return  waflz status code
//! \param   ao_event: Output event
//! \param   a_ctx: Sailfish context
//! \param   ao_ctx: Output waflz rqst context
//! ----------------------------------------------------------------------------
int32_t api_gw::process(waflz_pb::event** ao_event,
                        void* a_ctx,
                        ns_waflz::rqst_ctx** ao_ctx)
{
        // -------------------------------------------------
        // If pointers empty, error
        // -------------------------------------------------
        if (ao_ctx == NULL || *ao_ctx == NULL) { return WAFLZ_STATUS_ERROR; }
        // -------------------------------------------------
        // Init phase 1 for rqst path, method, etc below
        // -------------------------------------------------
        int32_t l_s = (*ao_ctx)->init_phase_1(
            m_engine, NULL, NULL, NULL);
        if (l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "performing rqst_ctx::init_phase_1");
                return WAFLZ_STATUS_ERROR;
        }
        waflz_pb::event* l_event = NULL;
        // -------------------------------------------------
        // lookup path and method in rules
        // -------------------------------------------------
        for (int32_t l_it = 0; l_it < m_pb->rules_size(); ++l_it)
        {
                bool l_match = false;
                // -------------------------------------------------
                // Check if matches api rule
                // -------------------------------------------------
                int32_t l_s = rule_match(l_match, m_pb->rules(l_it), (*ao_ctx)->m_method, (*ao_ctx)->m_uri);
                if (l_s != WAFLZ_STATUS_OK) { WAFLZ_PERROR(m_err_msg, "rule_match error"); return WAFLZ_STATUS_ERROR; }
                // -------------------------------------------------
                // If no match or rule is not for requests, continue
                // -------------------------------------------------
                if (!l_match) { continue; }
                // -------------------------------------------------
                // verify jwt
                // -------------------------------------------------
                if (m_pb->rules(l_it).has_token())
                {
                        waflz_pb::event* l_event = NULL;
                        ns_waflz::jwt_parser* l_jwt_parser = m_jwt_parser_map[m_pb->rules(l_it).id()];
                        if (!l_jwt_parser)
                        {
                                WAFLZ_PERROR(m_err_msg, "token missing jwt parser");
                                return WAFLZ_STATUS_ERROR;
                        }
                        l_s = l_jwt_parser->process(m_pb->rules(l_it).token(), *ao_ctx, &l_event);
                        if (l_s != WAFLZ_STATUS_OK)
                        {
                                WAFLZ_PERROR(m_err_msg, "%s", l_jwt_parser->get_err_msg());
                                return WAFLZ_STATUS_ERROR;
                        }
                        if (l_event)
                        {
                                l_event->set_rule_msg("JWT validation error");
                                l_event->set_api_gw_rule_id(m_pb->rules(l_it).id());
                                l_event->set_api_gw_rule_name(m_pb->rules(l_it).name());
                                *ao_event = l_event;
                                return WAFLZ_STATUS_OK;
                        }
                }
                if(m_pb->rules(l_it).has_response() && 
                        (!m_pb->has_ignore_response() || !m_pb->ignore_response()))
                {
                        (*ao_ctx)->m_inspect_response = true;
                        continue;
                }
                // -------------------------------------------------
                // If no schema id continue, else get schema ID and...
                // -------------------------------------------------
                if (! m_pb->rules(l_it).has_schema_id())
                {
                        continue;
                }
                std::string l_schema_id = m_pb->rules(l_it).schema_id();
                // -------------------------------------------------
                // Get Schema ptr
                // -------------------------------------------------
                ns_waflz::schema* l_schema = (ns_waflz::schema*) m_pb->rules(l_it)._schema_reserved();
                // -------------------------------------------------
                // get Schema name
                // -------------------------------------------------
                std::string l_schema_name = l_schema->get_name();
                // -------------------------------------------------
                // If no ptr, throw error
                // -------------------------------------------------
                if(!l_schema) {
                        WAFLZ_PERROR(m_err_msg, "Empty schema for schema ID %s", l_schema_id.c_str());
                        return WAFLZ_STATUS_ERROR;
                }
                // -------------------------------------------------
                // Init phase 2 for body
                // -------------------------------------------------
                l_s = (*ao_ctx)->init_phase_2(m_engine.get_ctype_parser_map());
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "performing rqst_ctx::init_phase_2");
                        return WAFLZ_STATUS_ERROR;
                }
                // -------------------------------------------------
                // If url encoded or not json, skip
                // -------------------------------------------------
                if( (*ao_ctx)->m_url_enc_body || !(*ao_ctx)->m_json_body)
                {
                        l_event = new ::waflz_pb::event();
                        l_event->set_schema_config_id(l_schema_id);
                        l_event->set_schema_config_name(l_schema_name);
                        l_event->set_rule_msg("Request JSON Schema Validation Error");
                        ::waflz_pb::event *l_sevent = l_event->add_sub_event();
                        std::string err = "Request body is not JSON";
                        l_sevent->add_rule_tag("API security");
                        l_sevent->set_rule_msg(err);
                        l_event->set_api_gw_rule_id(m_pb->rules(l_it).id());
                        l_event->set_api_gw_rule_name(m_pb->rules(l_it).name());
                        *ao_event = l_event;
                        break;
                }
                // -------------------------------------------------
                // If content length out of bounds and yajl 
                // did not encounter parse errors
                // -------------------------------------------------
                if( (*ao_ctx)->m_content_length > (*ao_ctx)->m_body_len && 
                        (*ao_ctx)->m_cx_tx_map["REQBODY_ERROR"] != "1") 
                {
                        l_event = new ::waflz_pb::event();
                        l_event->set_schema_config_id(l_schema_id);
                        l_event->set_schema_config_name(l_schema_name);
                        l_event->set_rule_msg("Request JSON Schema Validation Error");
                        ::waflz_pb::event *l_sevent = l_event->add_sub_event();
                        std::string err = "Content size exceeded by rqst";
                        l_sevent->set_rule_msg(err);
                        l_sevent->add_rule_tag("API security");
                        l_event->set_api_gw_rule_id(m_pb->rules(l_it).id());
                        l_event->set_api_gw_rule_name(m_pb->rules(l_it).name());
                        *ao_event = l_event;
                        break;
                }
                // -------------------------------------------------
                // Process request against schema
                // -------------------------------------------------
                l_s = l_schema->process(&l_event, a_ctx, (*ao_ctx)->m_body_data, (*ao_ctx)->m_body_len);
                if (l_s != WAFLZ_STATUS_OK) { return WAFLZ_STATUS_ERROR; }
                if (l_event) { 
                        // -------------------------------------------------
                        // Set rule info
                        // -------------------------------------------------
                        l_event->set_rule_msg("Request "+l_event->rule_msg());
                        l_event->set_schema_config_id(l_schema_id);
                        l_event->set_api_gw_rule_id(m_pb->rules(l_it).id());
                        l_event->set_api_gw_rule_name(m_pb->rules(l_it).name());
                }
                // -------------------------------------------------
                // Break on match
                // -------------------------------------------------
                break;
        }
        // -------------------------------------------------
        // If event, add relevant fields
        // -------------------------------------------------
        if (l_event)
        {
                l_event->set_api_gw_config_id(m_id);
                l_event->set_api_gw_config_name(m_name);
                l_event->set_config_last_modified(m_pb->last_modified_date());
                *ao_event = l_event;
        }
        return WAFLZ_STATUS_OK;
}

//! ----------------------------------------------------------------------------
//! \details Process response against api gateway
//! \return  waflz status code
//! \param   ao_event: Output event
//! \param   a_ctx: Sailfish context
//! \param   ao_ctx: Output waflz resp context
//! ----------------------------------------------------------------------------
int32_t api_gw::process_response(waflz_pb::event** ao_event,
                              void* a_ctx,
                              ns_waflz::resp_ctx** ao_ctx)
{
        // -------------------------------------------------
        // If pointers empty, error
        // -------------------------------------------------
        if (ao_ctx == NULL || *ao_ctx == NULL) { return WAFLZ_STATUS_ERROR; }
        // -------------------------------------------------
        // Init phase 3 for rqst path, method, etc below
        // -------------------------------------------------
        int32_t l_s = (*ao_ctx)->init_phase_3(m_engine.get_geoip2_mmdb());
        if (l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "performing resp_ctx::init_phase_3");
                return WAFLZ_STATUS_ERROR;
        }
        waflz_pb::event* l_event = NULL;
        // -------------------------------------------------
        // lookup path and method in rules
        // -------------------------------------------------
        for (int32_t l_it = 0; l_it < m_pb->rules_size(); ++l_it)
        {
                bool l_match = false;
                // -------------------------------------------------
                // Check if matches rule
                // -------------------------------------------------
                int32_t l_s = rule_match(l_match, m_pb->rules(l_it), (*ao_ctx)->m_method, (*ao_ctx)->m_uri);
                if (l_s != WAFLZ_STATUS_OK) { return WAFLZ_STATUS_ERROR; }
                // -------------------------------------------------
                // If no match or not for responses, check next rule
                // -------------------------------------------------
                if (!l_match || !m_pb->rules(l_it).has_response() 
                        || m_pb->rules(l_it).response() != (*ao_ctx)->m_resp_status ) 
                { continue; }
                // -------------------------------------------------
                // else get schema ID and...
                // -------------------------------------------------
                std::string l_schema_id = m_pb->rules(l_it).schema_id();
                // -------------------------------------------------
                // Get Schema ptr
                // -------------------------------------------------
                ns_waflz::schema* l_schema = (ns_waflz::schema*) m_pb->rules(l_it)._schema_reserved();
                // -------------------------------------------------
                // get Schema name
                // -------------------------------------------------
                std::string l_schema_name = l_schema->get_name();
                // -------------------------------------------------
                // If no ptr, throw error
                // -------------------------------------------------
                if(!l_schema) {
                        WAFLZ_PERROR(m_err_msg, "Empty schema for schema ID %s", l_schema_id.c_str());
                        return WAFLZ_STATUS_ERROR;
                }
                // -------------------------------------------------
                // Init phase 4 for body
                // -------------------------------------------------
                l_s = (*ao_ctx)->init_phase_4();
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "performing resp_ctx::init_phase_4");
                        return WAFLZ_STATUS_ERROR;
                }
                // -------------------------------------------------
                // If content length out of bounds and yajl 
                // did not encounter parse errors
                // -------------------------------------------------
                if( (*ao_ctx)->m_content_length > (*ao_ctx)->m_body_len && 
                        (*ao_ctx)->m_cx_tx_map["REQBODY_ERROR"] != "1") 
                {
                        l_event = new ::waflz_pb::event();
                        l_event->set_schema_config_id(l_schema_id);
                        l_event->set_schema_config_name(l_schema_name);
                        l_event->set_rule_msg("Response JSON Schema Validation Error");
                        ::waflz_pb::event *l_sevent = l_event->add_sub_event();
                        std::string err = "Content size exceeded by resp";
                        l_sevent->set_rule_msg(err);
                        l_event->set_api_gw_rule_id(m_pb->rules(l_it).id());
                        l_event->set_api_gw_rule_name(m_pb->rules(l_it).name());
                        *ao_event = l_event;
                        break;
                }
                // -------------------------------------------------
                // Process request against schema
                // -------------------------------------------------
                l_s = l_schema->process(&l_event, a_ctx, (*ao_ctx)->m_body_data, (*ao_ctx)->m_body_len);
                if (l_s != WAFLZ_STATUS_OK) { return WAFLZ_STATUS_ERROR; }
                if (l_event) { 
                        // -------------------------------------------------
                        // Set rule info
                        // -------------------------------------------------
                        l_event->set_rule_msg("Response "+l_event->rule_msg());
                        l_event->set_schema_config_id(l_schema_id);
                        l_event->set_api_gw_rule_id(m_pb->rules(l_it).id());
                        l_event->set_api_gw_rule_name(m_pb->rules(l_it).name());
                }
                // -------------------------------------------------
                // Break on match
                // -------------------------------------------------
                break;
        }
        // -------------------------------------------------
        // If event, add relevant fields
        // -------------------------------------------------
        if (l_event)
        {
                l_event->set_api_gw_config_id(m_id);
                l_event->set_api_gw_config_name(m_name);
                l_event->set_config_last_modified(m_pb->last_modified_date());
                *ao_event = l_event;
        }
        return WAFLZ_STATUS_OK;
}

//! ----------------------------------------------------------------------------
//! \details Load api gateway config from file
//! \return  waflz status code
//! \param   a_file_buf: config file buffer
//! \param   a_conf_dir_path: config directory path
//! ----------------------------------------------------------------------------
int32_t api_gw::load_file(const char* a_file_buf,
                                const std::string& a_conf_dir_path)
{
        // -------------------------------------------------
        // If empty file name, exit
        // -------------------------------------------------
        if (!a_file_buf) { return WAFLZ_STATUS_ERROR; }
        char* l_buf = NULL;
        uint32_t l_buf_len = 0;
        // -------------------------------------------------
        // read schema config from schema config path
        // -------------------------------------------------
        int32_t l_s = read_file(a_file_buf, &l_buf, l_buf_len);
        // -------------------------------------------------
        // If failed to read, cleanup
        // -------------------------------------------------
        if (l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "%s", ns_waflz::get_err_msg());
                if (l_buf) { free(l_buf); }
                return WAFLZ_STATUS_ERROR;
        }
        return load(l_buf, l_buf_len, a_conf_dir_path);
}
//! ----------------------------------------------------------------------------
//! \details Load api gateway config
//! \return  waflz status code
//! \param   a_buf: config buffer
//! \param   a_buf_len: config buffer length
//! \param   a_conf_dir_path: config directory path
//! ----------------------------------------------------------------------------
int32_t api_gw::load(const char* a_buf,
                           uint32_t a_buf_len,
                           const std::string& a_conf_dir_path)
{
        // -------------------------------------------------
        // If nothing to load or too big to load, error
        // -------------------------------------------------
        if (!a_buf) { return WAFLZ_STATUS_ERROR; }
        if (a_buf_len > _CONFIG_API_GW_MAX_SIZE)
        {
                WAFLZ_PERROR(m_err_msg,
                             "config file size(%u) > max size(%u)",
                             a_buf_len,
                             _CONFIG_API_GW_MAX_SIZE);
                return WAFLZ_STATUS_ERROR;
        }
        m_init = false;
        // -------------------------------------------------
        // delete protobuf before initializing
        // -------------------------------------------------
        if (m_pb)
        {
                delete m_pb;
                m_pb = NULL;
        }
        m_pb = new waflz_pb::api_gw();
        // -------------------------------------------------
        // load from json
        // -------------------------------------------------
        int32_t l_s;
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
        if (l_s != WAFLZ_STATUS_OK) { return WAFLZ_STATUS_ERROR; }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details load api gateway protobuf
//! \return  waflz status code
//! \param   a_pb: protobuf
//! \param   a_conf_dir_path: config directory path
//! ----------------------------------------------------------------------------
int32_t api_gw::load(const waflz_pb::api_gw* a_pb,
                     const std::string& a_conf_dir_path)
{
        // -------------------------------------------------
        // If no protobuf passed, error
        // -------------------------------------------------
        if (!a_pb)
        {
                WAFLZ_PERROR(m_err_msg, "a_pb == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        m_init = false;
        // -------------------------------------------------
        // clear protobuf before adding a new one
        // -------------------------------------------------
        if (m_pb)
        {
                delete m_pb;
                m_pb = NULL;
        }
        m_pb = new waflz_pb::api_gw();
        m_pb->CopyFrom(*a_pb);
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        int32_t l_s;
        l_s = init(a_conf_dir_path);
        if (l_s != WAFLZ_STATUS_OK) { return WAFLZ_STATUS_ERROR; }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details load api gateway json
//! \return  waflz status code
//! \param   a_js: json
//! \param   a_conf_dir_path: config directory path
//! ----------------------------------------------------------------------------
int32_t api_gw::load(void* a_js, const std::string& a_conf_dir_path)
{
        const rapidjson::Document& l_js = *((rapidjson::Document *)a_js);
        int32_t l_s;
        // -------------------------------------------------
        // Delete protobuf before loading
        // -------------------------------------------------
        if (m_pb)
        {
                delete m_pb;
                m_pb = NULL;
        }
        m_pb = new waflz_pb::api_gw();
        // -------------------------------------------------
        // Update protobuf from json
        // -------------------------------------------------
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
//! \details Initialize api gateway
//! \return  waflz status code
//! \param   a_conf_dir_path: config directory path
//! ----------------------------------------------------------------------------
int32_t api_gw::init(const std::string& a_conf_dir_path)
{
        // -------------------------------------------------
        // If already initialized, return
        // -------------------------------------------------
        if (m_init) { return WAFLZ_STATUS_OK; }
        // -------------------------------------------------
        // set properties
        // -------------------------------------------------
        m_id = m_pb->id();
        m_cust_id = m_pb->customer_id();
        m_name = m_pb->name();
        if (m_pb->has_team_config())
        {
                m_team_config = m_pb->team_config();
        }
        // -------------------------------------------------
        // Iterate through schema list
        // -------------------------------------------------
        for (int32_t i_t = 0; i_t < m_pb->rules_size(); ++i_t)
        {
                waflz_pb::api_rule& l_rule_pb = *(m_pb->mutable_rules(i_t));
                // -----------------------------------------
                // check for rule id
                // -----------------------------------------
                if ( !l_rule_pb.has_id() || l_rule_pb.id().empty() )
                {
                        WAFLZ_PERROR(m_err_msg,
                                     "missing rule id for rule entry '%s'",
                                     l_rule_pb.DebugString().c_str());
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // Compile path match op
                // -----------------------------------------
                int32_t l_s = compile_op(*(l_rule_pb.mutable_path()));
                if (l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // validate token - for signature
                // verification
                // -----------------------------------------
                if (l_rule_pb.has_token())
                {
                        waflz_pb::jwt l_tok = l_rule_pb.token();
                        // ---------------------------------
                        // reject tokens without jwks
                        // ---------------------------------
                        if (!l_tok.has_jwks())
                        {
                                WAFLZ_PERROR(m_err_msg, "%s", "token missing jwks");
                                return WAFLZ_STATUS_ERROR;
                        }
                        // ---------------------------------
                        // create a new jwt_parser for this
                        // rule
                        // ---------------------------------
                        auto l_parser_inserted = m_jwt_parser_map.insert({l_rule_pb.id(),
                                                                          new ns_waflz::jwt_parser()});
                        ns_waflz::jwt_parser* l_jwt_parser = l_parser_inserted.first->second;
                        if (!l_parser_inserted.second)
                        {
                                WAFLZ_PERROR(m_err_msg, "duplicated rule id '%s' found", l_rule_pb.id().c_str());
                                return WAFLZ_STATUS_ERROR;
                        }
                        // ---------------------------------
                        // load jwt info into parser
                        // ---------------------------------
                        l_s = l_jwt_parser->parse_and_load(l_rule_pb.token());
                        if (l_s != WAFLZ_STATUS_OK)
                        {
                                WAFLZ_PERROR(m_err_msg, "%s", l_jwt_parser->get_err_msg());
                                return WAFLZ_STATUS_ERROR;
                        }
                }
                // -----------------------------------------
                // if no schema, continue
                // -----------------------------------------
                if (!l_rule_pb.has_schema_id())
                {
                        continue;
                }
                std::string l_schema_id = l_rule_pb.schema_id();
                // -----------------------------------------
                // If schema already exists, don't duplicate
                // -----------------------------------------
                if (m_schema_map.find(l_schema_id) != m_schema_map.end())
                {
                        ns_waflz::schema* l_schema = m_schema_map[l_schema_id];
                        l_rule_pb.set__schema_reserved((uint64_t) l_schema);
                        continue;
                }
                // -----------------------------------------
                // make schema obj from config path
                // -----------------------------------------
                std::string l_config_path = a_conf_dir_path + "/api_schema/" + 
                                            m_cust_id + "-" + l_schema_id + 
                                            ".api_schema.json";
                // -----------------------------------------
                // read schema config from schema config
                // path
                // -----------------------------------------
                char* l_buf = NULL;
                uint32_t l_buf_len = 0;
                l_s = read_file(l_config_path.c_str(), &l_buf, l_buf_len);
                // -----------------------------------------
                // If failed to read, cleanup
                // -----------------------------------------
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "%s", ns_waflz::get_err_msg());
                        if (l_buf) { free(l_buf); l_buf = NULL; }
                        return l_s;
                }
                // -----------------------------------------
                // load schema from json buffer
                // -----------------------------------------
                ns_waflz::schema* l_schema = new ns_waflz::schema(m_engine);
                l_s = l_schema->load(l_buf, l_buf_len);
                if (l_buf) { free(l_buf); l_buf = NULL; }
                // -----------------------------------------
                // If failed to load, cleanup
                // -----------------------------------------
                if (l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg,
                                     "error loading conf "
                                     "file-reason: %.*s",
                                     WAFLZ_ERR_REASON_LEN,
                                     l_schema->get_err_msg());
                        if (l_schema) { delete l_schema; l_schema = NULL; }
                        return l_s;
                }
                // -----------------------------------------
                // Map schema id to schema pointer & set
                // schema protobuf message API-Sec->Schema
                // to pointer for fast access
                // -----------------------------------------
                m_schema_map[l_schema_id] = l_schema;
                m_pb->mutable_rules(i_t)->set__schema_reserved((uint64_t) l_schema);
        }
        // -------------------------------------------------
        // Set as initialized
        // -------------------------------------------------
        m_init = true;
        return WAFLZ_STATUS_OK;
}
}  // namespace ns_waflz
