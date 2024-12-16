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
#include "support/time_util.h"
#include "support/ndebug.h"
#include "jspb/jspb.h"
#include "waflz/enforcer.h"
#include "waflz/rqst_ctx.h"
#include "waflz/def.h"
#include "waflz/scopes.h"
#include <rapidjson/document.h>
#include <rapidjson/error/error.h>
#include <rapidjson/error/en.h>
#include "limit.pb.h"
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
// the maximum size of the json defining configuration for a rl enforcement (1MB)
#define CONFIG_SECURITY_RL_CONFIG_MAX_SIZE (1<<20)
namespace ns_waflz
{
//! ----------------------------------------------------------------------------
//! \details TODO
//! ----------------------------------------------------------------------------
enforcer::enforcer(bool a_case_insensitive_headers):
        rl_obj(a_case_insensitive_headers),
        m_stat_total_limits(0)
{
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! ----------------------------------------------------------------------------
enforcer::enforcer(waflz_pb::config *a_pb,
                   bool a_case_insensitive_headers):
           rl_obj(a_case_insensitive_headers),
           m_stat_total_limits(0)
{
        // initialize pb
        m_pb = a_pb;
        if(m_pb)
        {
                m_stat_total_limits = m_pb->limits_size();
        }
        else
        {
                m_stat_total_limits = 0;
        }
}
//! ----------------------------------------------------------------------------
//! \details dtor
//! ----------------------------------------------------------------------------
enforcer::~enforcer()
{
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t enforcer::validate(void)
{
        // -------------------------------------------------
        // validate pb
        // -------------------------------------------------
        if(!m_pb)
        {
                WAFLZ_PERROR(m_err_msg, "pb == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // validate type
        // -------------------------------------------------
        if(!m_pb->has_type())
        {
                WAFLZ_PERROR(m_err_msg, "missing type field");
                return WAFLZ_STATUS_ERROR;
        }
        if(m_pb->type() != ::waflz_pb::config_type_t_ENFORCER)
        {
                WAFLZ_PERROR(m_err_msg, "type: %d != ENFORCER", m_pb->type());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // validate id
        // -------------------------------------------------
        if(!m_pb->has_id() ||
            m_pb->id().empty())
        {
                WAFLZ_PERROR(m_err_msg, "missing id field or empty");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // validate customer id
        // -------------------------------------------------
        if(!m_pb->has_customer_id() ||
            m_pb->customer_id().empty())
        {
                WAFLZ_PERROR(m_err_msg, "missing customer_id field or empty");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // validate fields in limits
        // -------------------------------------------------
        for(int i_r = 0; i_r < m_pb->limits_size(); ++i_r)
        {
                const waflz_pb::limit &l_r = m_pb->limits(i_r);
                if(!l_r.has_id() ||
                   l_r.id().empty())
                {
                        WAFLZ_PERROR(m_err_msg, "limit missing id field or empty");
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
int32_t enforcer::load(void *a_js)
{
        if(!a_js)
        {
                WAFLZ_PERROR(m_err_msg, "a_js == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        int32_t l_s;
        const rapidjson::Value &l_js = *((rapidjson::Value *)a_js);
        // -------------------------------------------------
        // load pb...
        // -------------------------------------------------
        l_s = update_from_json(*m_pb, l_js);
        if(l_s != JSPB_OK)
        {
                //TRC_DEBUG("error in load_config\n");
                WAFLZ_PERROR(m_err_msg, "parsing json. Reason: %s", get_jspb_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // validate
        // -------------------------------------------------
        l_s = validate();
        //TRC_DEBUG("whole config %s", m_pb->DebugString().c_str());
        if(l_s != WAFLZ_STATUS_OK)
        {
                //TRC_DEBUG("error in validate load_config");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // compile
        // -------------------------------------------------
        l_s = compile();
        //TRC_DEBUG("whole config %s", m_pb->DebugString().c_str());
        if(l_s != WAFLZ_STATUS_OK)
        {
                //TRC_DEBUG("error in compile");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // set any missing end times
        // -------------------------------------------------
        for(int i_r = 0; i_r < m_pb->limits_size(); ++i_r)
        {
                waflz_pb::limit *i_r_ptr = m_pb->mutable_limits(i_r);
                if(i_r_ptr->has_end_epoch_msec() &&
                   i_r_ptr->end_epoch_msec())
                {
                        continue;
                }
                uint32_t l_e_duration_s = 0;
                if(i_r_ptr->has_action() &&
                   i_r_ptr->action().has_duration_sec())
                {
                        l_e_duration_s = i_r_ptr->action().duration_sec();
                }
                else if(i_r_ptr->has_duration_sec())
                {
                        l_e_duration_s = i_r_ptr->duration_sec();
                }
                if(!l_e_duration_s)
                {
                        //TRC_DEBUG("missing duration in either enforcement or limit");
                        return WAFLZ_STATUS_ERROR;
                }
                // set end time for limit -controls expiration
                i_r_ptr->set_start_epoch_msec(get_time_ms());
                i_r_ptr->set_end_epoch_msec(get_time_ms() + l_e_duration_s*1000);
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t enforcer::load(const char *a_buf, uint32_t a_buf_len)
{
        if(a_buf_len > CONFIG_SECURITY_RL_CONFIG_MAX_SIZE)
        {
                WAFLZ_PERROR(m_err_msg, "config file size(%u) > max size(%u)",
                                a_buf_len,
                                CONFIG_SECURITY_RL_CONFIG_MAX_SIZE);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // parse
        // -------------------------------------------------
        rapidjson::Document *l_js = new rapidjson::Document();
        rapidjson::ParseResult l_ok;
        l_ok = l_js->Parse(a_buf, a_buf_len);
        if (!l_ok)
        {
                WAFLZ_PERROR(m_err_msg, "JSON parse error: %s (%d)",
                             rapidjson::GetParseError_En(l_ok.Code()), (int)l_ok.Offset());
                if(l_js) { delete l_js; l_js = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // load...
        // -------------------------------------------------
        int32_t l_s;
        l_s = load((void *)l_js);
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(l_js) { delete l_js; l_js = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        if(l_js) { delete l_js; l_js = NULL;}
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t enforcer::process(rqst_ctx *a_ctx)
{
        return this->process(NULL, a_ctx, false);
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t enforcer::process(const waflz_pb::enforcement** ao_axn, rqst_ctx *a_ctx)
{
        return this->process(ao_axn, a_ctx, true);
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t enforcer::process(const waflz_pb::enforcement** ao_axn, rqst_ctx *a_ctx, const bool a_use_enf)
{
        if(!m_pb)
        {
                WAFLZ_PERROR(m_err_msg, "m_pb == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        if(!a_ctx)
        {
                WAFLZ_PERROR(m_err_msg, "a_ctx == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        if(!ao_axn && a_use_enf)
        {
                WAFLZ_PERROR(m_err_msg, "ao_event == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        // init to null
        if (a_use_enf) { *ao_axn = NULL; }
        waflz_pb::config &l_pb = *(m_pb);
        int32_t l_s;
        // -------------------------------------------------
        // cleanup disabled or expired
        // -------------------------------------------------
        l_s = limit_sweep(l_pb);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO log error reason
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // limits ...
        // -------------------------------------------------
        for(int i_r = 0; i_r < m_pb->limits_size(); ++i_r)
        {
                waflz_pb::limit *i_r_ptr = m_pb->mutable_limits(i_r);
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
                        continue;
                }
                // -----------------------------------------
                // check scope
                // -----------------------------------------
                if(i_limit.has_scope())
                {
                        bool l_match = false;
                        l_s = in_scope(l_match, i_limit.scope(), a_ctx);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                // TODO log error reason
                                return WAFLZ_STATUS_ERROR;
                        }
                        if(!l_match)
                        {
                                continue;
                        }
                }
                // -----------------------------------------
                // match-less limits...
                // -----------------------------------------
                if(i_limit.condition_groups_size() == 0)
                {
                        // ---------------------------------
                        // *************MATCH***************
                        // ---------------------------------
                        //TRC_DEBUG("Matched enforcement limit completely!");
                        // find enforcement...
                        // if we have enforcement -we outtie!
                        if(i_limit.has_action())
                        {
                                if (a_use_enf)
                                {
                                        *ao_axn = &(i_limit.action());
                                        a_ctx->m_limit = i_r_ptr;
                                }
                                else
                                {
                                        a_ctx->m_audit_limit = i_r_ptr;
                                }
                                goto done;
                        }
                        // else couldn't find enforcement -mark as disabled
                        i_limit.set_disabled(true);
                        continue;
                }
                //TRC_DEBUG("limits[%d]\n", i_r);
                // -----------------------------------------
                // limits
                // -----------------------------------------
                // ================= O R ===================
                // -----------------------------------------
                for(int i_cg = 0; i_cg < i_limit.condition_groups_size(); ++i_cg)
                {
                        const waflz_pb::condition_group &l_cg = i_limit.condition_groups(i_cg);
                        bool l_matched = false,
                        l_s = process_condition_group(l_matched,
                                                      l_cg,
                                                      a_ctx);
                        //TRC_DEBUG("limit: %d --match: %d --matched: %d\n", i_r, i_ms, l_matched);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                        if(!l_matched)
                        {
                                continue;
                        }
                        // ---------------------------------
                        // **************MATCH**************
                        // ---------------------------------
                        //TRC_DEBUG("limit: %d --match: %d --enf: %p\n", i_r, i_ms, *ao_axn);
                        // if we have enforcement -we outtie!
                        if(i_limit.has_action())
                        {
                                if (a_use_enf)
                                {
                                        *ao_axn = &(i_limit.action());
                                        a_ctx->m_limit = i_r_ptr;
                                }
                                else
                                {
                                        a_ctx->m_audit_limit = i_r_ptr;
                                }
                                //TRC_DEBUG("print enforcement%s\n", (*ao_axn)->DebugString().c_str());
                                goto done;
                        }
                        // else couldn't find enforcement -mark as disabled
                        i_limit.set_disabled(true);
                        break;
                }
        }
done:
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t enforcer::process_response(const waflz_pb::enforcement** ao_axn, resp_ctx *a_ctx, const bool a_use_enf)
{
        if(!m_pb)
        {
                WAFLZ_PERROR(m_err_msg, "m_pb == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        if(!a_ctx)
        {
                WAFLZ_PERROR(m_err_msg, "a_ctx == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        if(!ao_axn && a_use_enf)
        {
                WAFLZ_PERROR(m_err_msg, "ao_event == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        // init to null
        if (a_use_enf) { *ao_axn = NULL; }
        waflz_pb::config &l_pb = *(m_pb);
        int32_t l_s;
        // -------------------------------------------------
        // cleanup disabled or expired
        // -------------------------------------------------
        l_s = limit_sweep(l_pb);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO log error reason
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // limits ...
        // -------------------------------------------------
        for(int i_r = 0; i_r < m_pb->limits_size(); ++i_r)
        {
                waflz_pb::limit *i_r_ptr = m_pb->mutable_limits(i_r);
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
                        continue;
                }
                // -----------------------------------------
                // check scope
                // -----------------------------------------
                if(i_limit.has_scope())
                {
                        bool l_match = false;
                        l_s = in_scope_response(l_match, i_limit.scope(), a_ctx);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                // TODO log error reason
                                return WAFLZ_STATUS_ERROR;
                        }
                        if(!l_match)
                        {
                                continue;
                        }
                }
                // -----------------------------------------
                // match-less limits...
                // -----------------------------------------
                if(i_limit.condition_groups_size() == 0)
                {
                        // ---------------------------------
                        // *************MATCH***************
                        // ---------------------------------
                        //TRC_DEBUG("Matched enforcement limit completely!");
                        // find enforcement...
                        // if we have enforcement -we outtie!
                        if(i_limit.has_action())
                        {
                                if (a_use_enf)
                                {
                                        *ao_axn = &(i_limit.action());
                                        a_ctx->m_limit = i_r_ptr;
                                }
                                else
                                {
                                        a_ctx->m_audit_limit = i_r_ptr;
                                }
                                goto done;
                        }
                        // else couldn't find enforcement -mark as disabled
                        i_limit.set_disabled(true);
                        continue;
                }
                //TRC_DEBUG("limits[%d]\n", i_r);
                // -----------------------------------------
                // limits
                // -----------------------------------------
                // ================= O R ===================
                // -----------------------------------------
                for(int i_cg = 0; i_cg < i_limit.condition_groups_size(); ++i_cg)
                {
                        const waflz_pb::condition_group &l_cg = i_limit.condition_groups(i_cg);
                        bool l_matched = false,
                        l_s = process_condition_group_for_response(l_matched,
                                                      l_cg,
                                                      a_ctx);
                        //TRC_DEBUG("limit: %d --match: %d --matched: %d\n", i_r, i_ms, l_matched);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                        if(!l_matched)
                        {
                                continue;
                        }
                        // ---------------------------------
                        // **************MATCH**************
                        // ---------------------------------
                        //TRC_DEBUG("limit: %d --match: %d --enf: %p\n", i_r, i_ms, *ao_axn);
                        // if we have enforcement -we outtie!
                        if(i_limit.has_action())
                        {
                                if (a_use_enf)
                                {
                                        *ao_axn = &(i_limit.action());
                                        a_ctx->m_limit = i_r_ptr;
                                }
                                else
                                {
                                        a_ctx->m_audit_limit = i_r_ptr;
                                }
                                // TRC_DEBUG("print enforcement%s\n", (*ao_axn)->DebugString().c_str());
                                goto done;
                        }
                        // else couldn't find enforcement -mark as disabled
                        i_limit.set_disabled(true);
                        break;
                }
        }
done:
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t enforcer::merge(waflz_pb::config &ao_cfg)
{
        if(!m_pb)
        {
                WAFLZ_PERROR(m_err_msg, "m_pb == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        if(ao_cfg.has_id() &&
           (!m_pb->has_id() ||
           (m_pb->id() == "__na__")))
        {
                m_pb->set_id(ao_cfg.id());
        }
        if(ao_cfg.has_name() &&
            (!m_pb->has_name() ||
            (m_pb->name() == "__na__")))
        {
                m_pb->set_name(ao_cfg.name());
        }
        for(int i_r = 0; i_r < ao_cfg.limits_size(); ++i_r)
        {
                m_pb->add_limits()->CopyFrom(ao_cfg.limits(i_r));
                ::waflz_pb::limit* l_r = m_pb->mutable_limits(m_pb->limits_size()-1);
                if(!l_r)
                {
                        WAFLZ_PERROR(m_err_msg, "l_tpl == NULL");
                        return WAFLZ_STATUS_ERROR;
                }
                int32_t l_s;
                l_s = compile_limit(*l_r);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // update limit count
        m_stat_total_limits = m_pb->limits_size();
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
void enforcer::update_start_time(void)
{
        if(!m_pb)
        {
                return;
        }
        for(int i_r = 0; i_r < m_pb->limits_size(); ++i_r)
        {
                waflz_pb::limit *i_r_ptr = m_pb->mutable_limits(i_r);
                i_r_ptr->set_start_epoch_msec(get_time_ms());
        }
}
}
