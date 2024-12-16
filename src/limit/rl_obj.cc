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
#include "waflz/rl_obj.h"
#include "waflz/rqst_ctx.h"
#include "waflz/scopes.h"
#include "support/time_util.h"
#include "support/ndebug.h"
#include "support/md5.h"
#include "support/base64.h"
#include "waflz/string_util.h"
#include "op/regex.h"
#include "waflz/nms.h"
#include "limit.pb.h"
#include <rapidjson/document.h>
#include <rapidjson/error/error.h>
#include <rapidjson/error/en.h>
#include <stdlib.h>
#include <string.h>
namespace ns_waflz
{
//! ----------------------------------------------------------------------------
//! \details ctor
//! ----------------------------------------------------------------------------
rl_obj::rl_obj(bool a_case_insensitive_headers):
                m_init(false),
                m_pb(NULL),
                m_err_msg(),
                m_lowercase_headers(a_case_insensitive_headers),
                m_regex_list(),
                m_nms_list(),
                m_data_set_list(),
                m_data_case_i_set_list()
{
        m_pb = new waflz_pb::config();
}
//! ----------------------------------------------------------------------------
//! \details: dtor
//! ----------------------------------------------------------------------------
rl_obj::~rl_obj()
{
        // -------------------------------------------------
        // destruct m_regex_list
        // -------------------------------------------------
        for(regex_list_t::iterator i_p = m_regex_list.begin();
            i_p != m_regex_list.end();
            ++i_p)
        {
                if(*i_p) { delete *i_p; *i_p = NULL;}
        }
        // -------------------------------------------------
        // destruct m_nms_list
        // -------------------------------------------------
        for(nms_list_t::iterator i_n = m_nms_list.begin();
            i_n != m_nms_list.end();
            ++i_n)
        {
                if(*i_n) { delete *i_n; *i_n = NULL;}
        }
        // -------------------------------------------------
        // destruct str_ptr_set_list
        // -------------------------------------------------
        for(data_set_list_t::iterator i_n = m_data_set_list.begin();
            i_n != m_data_set_list.end();
            ++i_n)
        {
                if(*i_n) { delete *i_n; *i_n = NULL;}
        }
        for(data_case_i_set_list_t::iterator i_n = m_data_case_i_set_list.begin();
            i_n != m_data_case_i_set_list.end();
            ++i_n)
        {
                if(*i_n) { delete *i_n; *i_n = NULL;}
        }
        // -------------------------------------------------
        // destruct pb
        // -------------------------------------------------
        if(m_pb)
        {
                delete m_pb;
                m_pb = NULL;
        }
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
const std::string &rl_obj::get_customer_id(void)
{
        static std::string s_na = "XXXNAXXX";
        if(!m_pb ||
           !m_pb->has_customer_id())
        {
                return s_na;
        }
        return m_pb->customer_id();
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t rl_obj::compile_limit(waflz_pb::limit &ao_limit)
{
        // -------------------------------------------------
        // compile rx...
        // -------------------------------------------------
        if(ao_limit.has_scope())
        {
                ::waflz_pb::scope* l_scope = ao_limit.mutable_scope();
                if(l_scope->has_host())
                {
                        int32_t l_s;
                        l_s = compile_op(*(l_scope->mutable_host()));
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                }
                if(l_scope->has_path())
                {
                        int32_t l_s;
                        l_s = compile_op(*(l_scope->mutable_path()));
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        // -------------------------------------------------
        // or...
        // -------------------------------------------------
        for(int i_cg = 0; i_cg < ao_limit.condition_groups_size(); ++i_cg)
        {
                // -------------------------------------------------
                // and...
                // -------------------------------------------------
                ::waflz_pb::condition_group *l_conditions = ao_limit.mutable_condition_groups(i_cg);
                for(int i_m = 0; i_m < l_conditions->conditions_size(); ++i_m)
                {
                        ::waflz_pb::condition *l_c = l_conditions->mutable_conditions(i_m);
                        if(!l_c->has_op())
                        {
                                continue;
                        }
                        // ---------------------------------
                        // coerce ip operators into IPMATCH
                        // ---------------------------------
                        if(l_c->has_target() &&
                           l_c->target().has_type() &&
                           (l_c->target().type() == ::waflz_pb::condition_target_t_type_t_REMOTE_ADDR))
                        {
                                l_c->mutable_op()->set_type(::waflz_pb::op_t_type_t_IPMATCH);
                        }
                        // ---------------------------------
                        // compile
                        // ---------------------------------
                        int32_t l_s;
                        l_s = compile_op(*(l_c->mutable_op()));
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                }
        }
        // -------------------------------------------------
        // creat limit shorthand
        // -------------------------------------------------
        if(ao_limit.has_id())
        {
                md5 l_md5;
                const std::string &l_id = ao_limit.id();
                l_md5.update(l_id.c_str(), l_id.length());
                //mem_display((const uint8_t *)l_md5.get_hash(), 16);
                std::string l_b64;
                l_b64 = b64_encode((const char *)l_md5.get_hash(), 16);
                //NDBG_PRINT("l_b64: %s\n", l_b64.c_str());
                ao_limit.set__reserved_1(l_b64.substr(0,8));
        }
        // -------------------------------------------------
        // enforcement
        // -------------------------------------------------
        if(ao_limit.has_action())
        {
                waflz_pb::enforcement *l_a = ao_limit.mutable_action();
                int32_t l_s;
                l_s = compile_action(*l_a, m_err_msg);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t rl_obj::compile_op(::waflz_pb::op_t& ao_op)
{
        // -------------------------------------------------
        // check if exist...
        // -------------------------------------------------
        if(!ao_op.has_type())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // for type...
        // -------------------------------------------------
        switch(ao_op.type())
        {
        // -------------------------------------------------
        // regex
        // -------------------------------------------------
        case ::waflz_pb::op_t_type_t_RX:
        {
                if(!ao_op.has_value())
                {
                        return WAFLZ_STATUS_ERROR;
                }
                const std::string &l_val = ao_op.value();
                regex* l_rx = new regex();
                int32_t l_s;
                l_s = l_rx->init(l_val.c_str(), l_val.length());
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "failed to compile regex: '%s'.", l_val.c_str());
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
        case ::waflz_pb::op_t_type_t_EM:
        {
                if(!ao_op.has_value() &&
                   !ao_op.values_size())
                {
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // case insensitive
                // -----------------------------------------
                if(ao_op.is_case_insensitive())
                {
                        data_case_i_set_t *l_ds = new data_case_i_set_t();
                        // ---------------------------------
                        // prefer values to value
                        // ---------------------------------
                        if(ao_op.values_size())
                        {
                                for(int32_t i_v = 0; i_v < ao_op.values_size(); ++i_v)
                                {
                                        if(ao_op.values(i_v).empty())
                                        {
                                                continue;
                                        }
                                        data_t l_d;
                                        l_d.m_data = ao_op.values(i_v).c_str();
                                        l_d.m_len = ao_op.values(i_v).length();
                                        l_ds->insert(l_d);
                                }
                        }
                        else if(!ao_op.value().empty())
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
                        data_set_t *l_ds = new data_set_t();
                        // ---------------------------------
                        // prefer values to value
                        // ---------------------------------
                        if(ao_op.values_size())
                        {
                                for(int32_t i_v = 0; i_v < ao_op.values_size(); ++i_v)
                                {
                                        if(ao_op.values(i_v).empty())
                                        {
                                                continue;
                                        }
                                        data_t l_d;
                                        l_d.m_data = ao_op.values(i_v).c_str();
                                        l_d.m_len = ao_op.values(i_v).length();
                                        l_ds->insert(l_d);
                                }
                        }
                        else if(!ao_op.value().empty())
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
        // ip condition list
        // -------------------------------------------------
        case ::waflz_pb::op_t_type_t_IPMATCH:
        {
                if(!ao_op.has_value() &&
                   !ao_op.values_size())
                {
                        return WAFLZ_STATUS_ERROR;
                }
                ip_str_list_t l_ip_str_list;
                // -----------------------------------------
                // prefer values to value
                // -----------------------------------------
                if(ao_op.values_size())
                {
                        for(int32_t i_v = 0; i_v < ao_op.values_size(); ++i_v)
                        {
                                if(ao_op.values(i_v).empty())
                                {
                                        continue;
                                }
                                l_ip_str_list.push_back(&(ao_op.values(i_v)));
                        }
                }
                else if(!ao_op.value().empty())
                {
                        l_ip_str_list.push_back(&(ao_op.value()));
                }
                // -----------------------------------------
                // error if empty...
                // -----------------------------------------
                if(l_ip_str_list.empty())
                {
                        // TODO -log error reason???
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // create a list
                // -----------------------------------------
                int32_t l_s;
                nms *l_nms = NULL;
                l_s = create_nms_from_ip_str_list(&l_nms, l_ip_str_list);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "failed to compile ip_list");
                        return WAFLZ_STATUS_ERROR;
                }
                if(!l_nms)
                {
                        WAFLZ_PERROR(m_err_msg, "failed to compile ip_list");
                        return WAFLZ_STATUS_ERROR;
                }
                ao_op.set__reserved_1((uint64_t)(l_nms));
                m_nms_list.push_back(l_nms);
                break;
        }
        // -------------------------------------------------
        // value conditions
        // -------------------------------------------------
        case ::waflz_pb::op_t_type_t_EQ:
        case ::waflz_pb::op_t_type_t_LE:
        case ::waflz_pb::op_t_type_t_GE:
        case ::waflz_pb::op_t_type_t_LT:
        case ::waflz_pb::op_t_type_t_GT:
        {
                // -----------------------------------------
                // quick exit if no value
                // -----------------------------------------
                if(!ao_op.has_value())
                {
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // convert value to uint32
                // -----------------------------------------
                char* l_error_chk;
                uint64_t l_value_to_match = ns_waflz::strntoul(ao_op.value().c_str(),
                                                               ao_op.value().length(),
                                                               &l_error_chk,
                                                               10);
                // -----------------------------------------
                // error checking
                // -----------------------------------------
                if ((*l_error_chk) || (l_value_to_match >= UINT32_MAX) || (l_value_to_match == ULONG_MAX))
                {
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // save value for later use
                // -----------------------------------------
                ao_op.set__reserved_1(l_value_to_match);
        }
        // -------------------------------------------------
        // default
        // -------------------------------------------------
        default:
        {
                break;
        }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t rl_obj::compile(void)
{
        if(!m_pb)
        {
                WAFLZ_PERROR(m_err_msg, "pb is null");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // cleanup disabled or expired
        // -------------------------------------------------
        int32_t l_s;
        l_s = limit_sweep(*m_pb);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO log error reason
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // validate fields in limits
        // -------------------------------------------------
        for(int i_r = 0; i_r < m_pb->limits_size(); ++i_r)
        {
                waflz_pb::limit *i_r_ptr = m_pb->mutable_limits(i_r);
                // -----------------------------------------
                // compile
                // -----------------------------------------
                l_s = compile_limit(*i_r_ptr);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t rl_obj::process_condition_group(bool &ao_matched,
                                        const waflz_pb::condition_group &a_cg,
                                        rqst_ctx *a_ctx)
{
        ao_matched = false;
        // -----------------------------------------
        // AND match
        // -----------------------------------------
        for(int i_m = 0; i_m < a_cg.conditions_size(); ++i_m)
        {
                const ::waflz_pb::condition &l_match = a_cg.conditions(i_m);
                if(!l_match.has_target())
                {
                        continue;
                }
                if(!l_match.has_op())
                {
                        continue;
                }
                //TRC_DEBUG("MATCH: %s\n", l_match.ShortDebugString().c_str());
                // -----------------------------------------
                // TODO
                // only support single var for now ...
                // -----------------------------------------
                const waflz_pb::condition_target_t &l_tgt = l_match.target();
                if(!l_tgt.has_type())
                {
                        continue;
                }
                std::string l_buf;
                const char *l_data = NULL;
                uint32_t l_data_len = 0,
                l_s = extract(&l_data,
                              l_data_len,
                              l_buf,
                              l_tgt,
                              a_ctx);
                //WFLZ_TRC_ALL("l_data: %.*s\n", l_data_len, l_data);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // TODO log error reason
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // anything to condition?
                // -----------------------------------------
                if((l_data == NULL) ||
                   !l_data_len)
                {
                        // ---------------------------------
                        // no data to analyze
                        // go to the next limit
                        // ---------------------------------
                        if(l_match.has_op() &&
                           l_match.op().has_is_negated() &&
                           l_match.op().is_negated())
                        {
                                // continue checking if no data is is_negated
                                continue;
                        }
                        return WAFLZ_STATUS_OK;
                }
                // -----------------------------------------
                // run op
                // -----------------------------------------
                if(!l_match.has_op())
                {
                        continue;
                }
                bool l_matched = false;
                // -----------------------------------------
                // TEMPORARY HACK for case
                // -----------------------------------------
                bool l_case_i = false;
                if(l_tgt.has_type() &&
                   (l_tgt.type() == waflz_pb::condition_target_t::REQUEST_HEADERS) &&
                   m_lowercase_headers)
                {
                        l_case_i = true;
                }
                //TRC_DEBUG("DATA: %.*s\n", l_data_len, l_data);
                l_s = rl_run_op(l_matched,
                                l_match.op(),
                                l_data,
                                l_data_len,
                                l_case_i);
                //TRC_DEBUG("rl_run_op: l_matched: %d\n", l_matched);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // condition failed
                        // TODO log?
                        //WARNING("Failed to run limit (top level idx %d) at %p variable[%d].  Continuing",
                        //        i_r->second.m_limit_idx, &l_limit,
                        //        i_r->second.m_variable_idx);
                        return WAFLZ_STATUS_OK;
                }
                if(!l_matched)
                {
                        return WAFLZ_STATUS_OK;
                }
        }
        // TODO include conditions???
        ao_matched = true;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t rl_obj::extract(const char **ao_data,
                        uint32_t &ao_data_len,
                        std::string &ao_buf,
                        const waflz_pb::condition_target_t &a_tgt,
                        rqst_ctx *a_ctx)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_OK;
        }
        // initialize to no extracted data
        *ao_data = NULL;
        ao_data_len = 0;
        ao_buf.clear();
        if(!a_tgt.has_type())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // TODO apologies for enum cast
        // -to get around using waflz_pb type in header decl
        // -------------------------------------------------
#define _SET_W_CTX(_var) do { \
        *ao_data = a_ctx->_var.m_data;\
        ao_data_len = a_ctx->_var.m_len;\
} while(0)
        const waflz_pb::condition_target_t_type_t l_type = a_tgt.type();
        switch (l_type)
        {
        // -------------------------------------------------
        // REMOTE_ADDR
        // -------------------------------------------------
        case waflz_pb::condition_target_t::REMOTE_ADDR:
        {
                _SET_W_CTX(m_src_addr);
                break;
        }
        // -------------------------------------------------
        // REQUEST_HOST
        // -------------------------------------------------
        case waflz_pb::condition_target_t::REQUEST_HOST:
        {
                _SET_W_CTX(m_host);
                break;
        }
        // -------------------------------------------------
        // REQUEST_URI
        // -------------------------------------------------
        case waflz_pb::condition_target_t::REQUEST_URI:
        {
                _SET_W_CTX(m_uri);
                // use length w/o q string
                if(a_ctx->m_uri_path_len)
                {
                        ao_data_len = a_ctx->m_uri_path_len;
                }
                break;
        }
        // -------------------------------------------------
        // REQUEST_METHOD
        // -------------------------------------------------
        case waflz_pb::condition_target_t::REQUEST_METHOD:
        {
                _SET_W_CTX(m_method);
                break;
        }
        // -------------------------------------------------
        // REQUEST_HEADERS
        // -------------------------------------------------
        case waflz_pb::condition_target_t::REQUEST_HEADERS:
        {
                if(!a_tgt.has_value())
                {
                        break;
                }
                // for each condition
                const std::string &l_val = a_tgt.value();
                data_t l_d;
                l_d.m_data = l_val.c_str();
                l_d.m_len = l_val.length();
                const data_unordered_map_t &l_map = a_ctx->m_header_map;
                const data_unordered_map_t::const_iterator i_d = l_map.find(l_d);
                if(i_d == l_map.end())
                {
                        break;
                }
                // -------------------------
                // found condition...
                // -------------------------
                *ao_data = i_d->second.m_data;
                ao_data_len = i_d->second.m_len;
                break;
        }
        // -------------------------------------------------
        // QUERY_STRING
        // -------------------------------------------------
        case waflz_pb::condition_target_t::QUERY_STRING:
        {
                _SET_W_CTX(m_query_str);
                break;
        }
        // -------------------------------------------------
        // ARGS_GET
        // -------------------------------------------------
        case waflz_pb::condition_target_t::ARGS_GET:
        {
                if(!a_tgt.has_value())
                {
                        *ao_data = a_ctx->m_query_str.m_data;
                        ao_data_len = a_ctx->m_query_str.m_len;
                }
                else
                {
                        const std::string &l_val = a_tgt.value();
                        data_t l_d;
                        l_d.m_data = l_val.c_str();
                        l_d.m_len = l_val.length();
                        const data_unordered_map_t &l_map = a_ctx->m_header_map;
                        const data_unordered_map_t::const_iterator i_d = l_map.find(l_d);
                        if(i_d == l_map.end())
                        {
                                break;
                        }
                        // -------------------------
                        // found condition...
                        // -------------------------
                        *ao_data = i_d->second.m_data;
                        ao_data_len = i_d->second.m_len;
                        break;
                }
                break;
        }
        // -------------------------------------------------
        // FILE_EXT
        // -------------------------------------------------
        case waflz_pb::condition_target_t::FILE_EXT:
        {
                _SET_W_CTX(m_file_ext);
                if(!(*ao_data) ||
                    !ao_data_len)
                {
                        break;
                }
                // -----------------------------------------
                // Legacy hack: RL configs don't accept '.'
                // in file extensions. We have strip out the
                // first byte. m_file_ext will give you a
                // '.html', but OP expects a match on 'html'
                // move the pointer by 1 place and adjust len
                // -----------------------------------------
                if ((ao_data_len > 1) &&
                   (*ao_data[0] == '.'))
                {
                        ++*ao_data;
                        --ao_data_len;
                }
                break;
        }
        // -------------------------------------------------
        // GEO
        // -------------------------------------------------
        case waflz_pb::condition_target_t::GEO:
        {
                _SET_W_CTX(m_geo_data.m_geo_cn2);
                break;
        }
        // -------------------------------------------------
        // ASN
        // -------------------------------------------------
        case waflz_pb::condition_target_t::REMOTE_ASN:
        {
                _SET_W_CTX(m_src_asn_str);
                break;
        }
        // -------------------------------------------------
        // JA3
        // -------------------------------------------------
        case waflz_pb::condition_target_t::REMOTE_JA3:
        {
                _SET_W_CTX(m_virt_ssl_client_ja3_md5);
                break;
        }
        // -------------------------------------------------
        // JA4
        // -------------------------------------------------
        case waflz_pb::condition_target_t::REMOTE_JA4:
        {
                _SET_W_CTX(m_virt_ssl_client_ja4);
                break;
        }
        // -------------------------------------------------
        // bot score
        // -------------------------------------------------
        case waflz_pb::condition_target_t::BOT_SCORE:
        {
                *ao_data = "BOT_SCORE";
                ao_data_len = a_ctx->m_bot_score;
                break;
        }
        // -------------------------------------------------
        // REQUEST_COOKIES
        // -------------------------------------------------
        case waflz_pb::condition_target_t::REQUEST_COOKIES:
        {
                if(!a_tgt.has_value())
                {
                        break;
                }
                // for each condition
                const std::string &l_val = a_tgt.value();
                data_t l_d;
                l_d.m_data = l_val.c_str();
                l_d.m_len = l_val.length();
                const ns_waflz::data_map_t &l_map = a_ctx->m_cookie_map;
                const ns_waflz::data_map_t::const_iterator i_d = l_map.find(l_d);
                if(i_d == l_map.end())
                {
                        break;
                }
                // -------------------------
                // found condition...
                // -------------------------
                *ao_data = i_d->second.m_data;
                ao_data_len = i_d->second.m_len;
                break;
        }
        // -------------------------------------------------
        // QUERY_ARG
        // -------------------------------------------------
        case waflz_pb::condition_target_t::QUERY_ARG:
        {
                if(!a_tgt.has_value())
                {
                        break;
                }
                // for each condition
                const std::string &l_val = a_tgt.value();
                data_t l_d;
                l_d.m_data = l_val.c_str();
                l_d.m_len = l_val.length();
                const ns_waflz::data_unordered_map_t &l_map = a_ctx->m_query_arg_map;
                const ns_waflz::data_unordered_map_t::const_iterator i_d = l_map.find(l_d);
                if(i_d == l_map.end())
                {
                        break;
                }
                // -------------------------
                // found condition...
                // -------------------------
                *ao_data = i_d->second.m_data;
                ao_data_len = i_d->second.m_len;
                break;
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        default:
        {
                //TRC_DEBUG("default\n");
                // do nothing
                break;
        }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t rl_obj::process_condition_group_for_response(bool &ao_matched,
                                                     const waflz_pb::condition_group &a_cg,
                                                     resp_ctx *a_ctx)
{
        ao_matched = false;
        // -----------------------------------------
        // AND match
        // -----------------------------------------
        for(int i_m = 0; i_m < a_cg.conditions_size(); ++i_m)
        {
                const ::waflz_pb::condition &l_match = a_cg.conditions(i_m);
                if(!l_match.has_target())
                {
                        continue;
                }
                if(!l_match.has_op())
                {
                        continue;
                }
                //TRC_DEBUG("MATCH: %s\n", l_match.ShortDebugString().c_str());
                // -----------------------------------------
                // TODO
                // only support single var for now ...
                // -----------------------------------------
                const waflz_pb::condition_target_t &l_tgt = l_match.target();
                if(!l_tgt.has_type())
                {
                        continue;
                }
                std::string l_buf;
                const char *l_data = NULL;
                uint32_t l_data_len = 0,
                l_s = extract_from_response(&l_data,
                                            l_data_len,
                                            l_buf,
                                            l_tgt,
                                            a_ctx);
                //WFLZ_TRC_ALL("l_data: %.*s\n", l_data_len, l_data);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // TODO log error reason
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // anything to condition?
                // -----------------------------------------
                if((l_data == NULL) ||
                   !l_data_len)
                {
                        // ---------------------------------
                        // no data to analyze
                        // go to the next limit
                        // ---------------------------------
                        if(l_match.has_op() &&
                           l_match.op().has_is_negated() &&
                           l_match.op().is_negated())
                        {
                                // continue checking if no data is is_negated
                                continue;
                        }
                        return WAFLZ_STATUS_OK;
                }
                // -----------------------------------------
                // run op
                // -----------------------------------------
                if(!l_match.has_op())
                {
                        continue;
                }
                bool l_matched = false;
                // -----------------------------------------
                // TEMPORARY HACK for case
                // -----------------------------------------
                bool l_case_i = false;
                if(l_tgt.has_type() &&
                   (l_tgt.type() == waflz_pb::condition_target_t::REQUEST_HEADERS) &&
                   m_lowercase_headers)
                {
                        l_case_i = true;
                }
                //TRC_DEBUG("DATA: %.*s\n", l_data_len, l_data);
                l_s = rl_run_op(l_matched,
                                l_match.op(),
                                l_data,
                                l_data_len,
                                l_case_i);
                //TRC_DEBUG("rl_run_op: l_matched: %d\n", l_matched);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        // condition failed
                        // TODO log?
                        //WARNING("Failed to run limit (top level idx %d) at %p variable[%d].  Continuing",
                        //        i_r->second.m_limit_idx, &l_limit,
                        //        i_r->second.m_variable_idx);
                        return WAFLZ_STATUS_OK;
                }
                if(!l_matched)
                {
                        return WAFLZ_STATUS_OK;
                }
        }
        // TODO include conditions???
        ao_matched = true;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t rl_obj::extract_from_response(const char **ao_data,
                                  uint32_t &ao_data_len,
                                  std::string &ao_buf,
                                  const waflz_pb::condition_target_t &a_tgt,
                                  resp_ctx *a_ctx)
{
        if(!a_ctx)
        {
                return WAFLZ_STATUS_OK;
        }
        // initialize to no extracted data
        *ao_data = NULL;
        ao_data_len = 0;
        ao_buf.clear();
        if(!a_tgt.has_type())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // TODO apologies for enum cast
        // -to get around using waflz_pb type in header decl
        // -------------------------------------------------
#define _SET_W_CTX(_var) do { \
        *ao_data = a_ctx->_var.m_data;\
        ao_data_len = a_ctx->_var.m_len;\
} while(0)
        const waflz_pb::condition_target_t_type_t l_type = a_tgt.type();
        switch (l_type)
        {
        // -------------------------------------------------
        // REMOTE_ADDR
        // -------------------------------------------------
        case waflz_pb::condition_target_t::REMOTE_ADDR:
        {
                _SET_W_CTX(m_src_addr);
                break;
        }
        // -------------------------------------------------
        // REQUEST_HOST
        // -------------------------------------------------
        case waflz_pb::condition_target_t::REQUEST_HOST:
        {
                _SET_W_CTX(m_host);
                break;
        }
        // -------------------------------------------------
        // REQUEST_URI
        // -------------------------------------------------
        case waflz_pb::condition_target_t::REQUEST_URI:
        {
                _SET_W_CTX(m_uri);
                // use length w/o q string
                if(a_ctx->m_uri_path_len)
                {
                        ao_data_len = a_ctx->m_uri_path_len;
                }
                break;
        }
        // -------------------------------------------------
        // REQUEST_METHOD
        // -------------------------------------------------
        case waflz_pb::condition_target_t::REQUEST_METHOD:
        {
                _SET_W_CTX(m_method);
                break;
        }
        // -------------------------------------------------
        // REQUEST_HEADERS
        // -------------------------------------------------
        case waflz_pb::condition_target_t::REQUEST_HEADERS:
        {
                if(!a_tgt.has_value())
                {
                        break;
                }
                // for each condition
                const std::string &l_val = a_tgt.value();
                data_t l_d;
                l_d.m_data = l_val.c_str();
                l_d.m_len = l_val.length();
                const data_unordered_map_t &l_map = a_ctx->m_header_map;
                const data_unordered_map_t::const_iterator i_d = l_map.find(l_d);
                if(i_d == l_map.end())
                {
                        break;
                }
                // -------------------------
                // found condition...
                // -------------------------
                *ao_data = i_d->second.m_data;
                ao_data_len = i_d->second.m_len;
                break;
        }
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        default:
        {
                //TRC_DEBUG("default\n");
                // do nothing
                break;
        }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! utils
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t limit_remove(waflz_pb::config &ao_cfg, uint32_t a_off)
{
        int l_size = ao_cfg.limits_size();
        if((!l_size) ||
           ((int)a_off >= l_size))
        {
                return WAFLZ_STATUS_ERROR;
        }
        typedef google::protobuf::RepeatedPtrField<waflz_pb::limit> limit_ptr_t;
        limit_ptr_t *l_r_ptr = ao_cfg.mutable_limits();
        if(!l_r_ptr)
        {
                return WAFLZ_STATUS_ERROR;
        }
        l_r_ptr->DeleteSubrange((int)a_off,1);
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
typedef google::protobuf::RepeatedPtrField<waflz_pb::limit> limit_ptr_t;
int32_t limit_sweep(waflz_pb::config &ao_cfg)
{
        // -------------------------------------------------
        // find disabled and expired
        // -------------------------------------------------
        for(int i_t = 0; i_t < ao_cfg.limits_size();)
        {
                //NDBG_PRINT("i_t[%d]: check for nop'd limit\n", i_t);
                waflz_pb::limit *i_r_ptr = ao_cfg.mutable_limits(i_t);
                if(!i_r_ptr)
                {
                        // TODO log error reason
                        return WAFLZ_STATUS_ERROR;
                }
                waflz_pb::limit &i_limit = *i_r_ptr;
                // -----------------------------------------
                // disabled???
                // -----------------------------------------
                if(i_limit.has_disabled() &&
                   i_limit.disabled())
                {
                        int32_t l_s;
                        //NDBG_PRINT("removing limit --disabled\n");
                        l_s = limit_remove(ao_cfg, i_t);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                // TODO log error reason
                                return WAFLZ_STATUS_ERROR;
                        }
                }
                // -----------------------------------------
                // expired???
                // -----------------------------------------
                else if((i_limit.has_end_epoch_msec())  &&
                        (i_limit.end_epoch_msec() != 0) &&
                        (i_limit.end_epoch_msec() <= get_time_ms()))
                {
                        int32_t l_s;
                        //NDBG_PRINT("removing limit --timeout\n");
                        l_s = limit_remove(ao_cfg, i_t);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                // TODO log error reason
                                return WAFLZ_STATUS_ERROR;
                        }
                }
                else
                {
                        ++i_t;
                }
        }
        return WAFLZ_STATUS_OK;
}
}
