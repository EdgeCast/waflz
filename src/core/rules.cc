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
#include "waflz/rules.h"
#include "support/ndebug.h"
#include "waflz/engine.h"
#include "waflz/rqst_ctx.h"
#include "waflz/resp_ctx.h"
#include "waflz/waf.h"
#include "event.pb.h"
#include "rule.pb.h"
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define _CONFIG_PROFILE_MAX_SIZE (1<<20)
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
rules::rules(engine &a_engine):
        m_init(false),
        m_err_msg(),
        m_engine(a_engine),
        m_waf(NULL),
        m_id("__na__"),
        m_cust_id("__na__"),
        m_team_config(false),
        m_name("__na__")
{
}
//! ----------------------------------------------------------------------------
//! \details dtor
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
rules::~rules()
{
        if(m_waf) { delete m_waf; m_waf = NULL; }
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t rules::load_file(const char *a_buf, uint32_t a_buf_len)
{
        if(a_buf_len > _CONFIG_PROFILE_MAX_SIZE)
        {
                WAFLZ_PERROR(m_err_msg, "config file size(%u) > max size(%u)",
                             a_buf_len,
                             _CONFIG_PROFILE_MAX_SIZE);
                return WAFLZ_STATUS_ERROR;
        }
        m_init = false;
        // -----------------------------------------
        // make waf obj
        // -----------------------------------------
        if(m_waf) { delete m_waf; m_waf = NULL; }
        m_waf = new waf(m_engine);
        std::string l_p;
        l_p.assign(a_buf, a_buf_len);
        int32_t l_s;
        l_s = m_waf->init(config_parser::JSON, l_p, true, true);
        if(l_s != WAFLZ_STATUS_OK)
        {
                NDBG_PRINT("error loading conf file-reason: %.*s",
                             WAFLZ_ERR_REASON_LEN,
                             m_waf->get_err_msg());
                WAFLZ_PERROR(m_err_msg, "error loading conf file-reason: %.*s",
                             WAFLZ_ERR_REASON_LEN,
                             m_waf->get_err_msg());
                if(m_waf) { delete m_waf; m_waf = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        // -----------------------------------------
        // get properties from m_waf
        // -----------------------------------------
        m_id = m_waf->get_id();
        m_cust_id = m_waf->get_cust_id();
        m_name = m_waf->get_name();
        m_team_config = m_waf->is_team_config();
        // -----------------------------------------
        // done...
        // -----------------------------------------
        m_init = true;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t rules::load(void* a_js)
{
        m_init = false;
        // -----------------------------------------
        // make waf obj
        // -----------------------------------------
        if(m_waf) { delete m_waf; m_waf = NULL; }
        m_waf = new waf(m_engine);
        int32_t l_s;
        l_s = m_waf->init(a_js, true, true);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "error loading conf file-reason: %.*s",
                             WAFLZ_ERR_REASON_LEN,
                             m_waf->get_err_msg());
                if(m_waf) { delete m_waf; m_waf = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        // -----------------------------------------
        // get properties from m_waf
        // -----------------------------------------
        m_id = m_waf->get_id();
        m_cust_id = m_waf->get_cust_id();
        m_name = m_waf->get_name();
        m_team_config = m_waf->is_team_config();
        // -----------------------------------------
        // done...
        // -----------------------------------------
        m_init = true;
        return WAFLZ_STATUS_OK;     
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t rules::process(waflz_pb::event **ao_event,
                       void *a_ctx,
                       rqst_ctx **ao_rqst_ctx)
{
        if(!ao_event)
        {
                WAFLZ_PERROR(m_err_msg, "ao_event == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        *ao_event = NULL;
        int32_t l_s;
        // -------------------------------------------------
        // create new if null
        // -------------------------------------------------
        rqst_ctx *l_rqst_ctx = NULL;
        if(ao_rqst_ctx &&
           *ao_rqst_ctx)
        {
                l_rqst_ctx = *ao_rqst_ctx;
        }
        if(!l_rqst_ctx)
        {
                WAFLZ_PERROR(m_err_msg, "ao_rqst_ctx == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        if(m_waf->get_request_body_in_memory_limit() > 0)
        {
                l_rqst_ctx->set_body_max_len(m_waf->get_request_body_in_memory_limit());
        }
        // -------------------------------------------------
        // run phase 1 init
        // -------------------------------------------------
        l_s = l_rqst_ctx->init_phase_1(m_engine, NULL, NULL, NULL);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "performing rqst_ctx::init_phase_1");
                if(!ao_rqst_ctx && l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        waflz_pb::event *l_event = NULL;
        // -------------------------------------------------
        // process waf...
        // -------------------------------------------------
        l_s = m_waf->process(&l_event, a_ctx, &l_rqst_ctx, true);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "%s", m_waf->get_err_msg());
                if(!ao_rqst_ctx && l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // done...
        // -------------------------------------------------
        if(l_event)
        {
                l_s = l_rqst_ctx->append_rqst_info(*l_event, m_engine.get_geoip2_mmdb());
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "performing rqst_ctx::append_rqst_info");
                        if(!ao_rqst_ctx && l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
                l_event->set_rule_intercept_status(403);
                if(get_pb()->has_last_modified_date())
                {
                        l_event->set_config_last_modified(get_pb()->last_modified_date());
                }
                *ao_event = l_event;
        }
        if(!ao_rqst_ctx && l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        return WAFLZ_STATUS_OK;
}

//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t rules::process_response(waflz_pb::event **ao_event,
                       void *a_ctx,
                       resp_ctx **ao_resp_ctx)
{
        if(!ao_event)
        {
                WAFLZ_PERROR(m_err_msg, "ao_event == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        *ao_event = NULL;
        int32_t l_s;
        // -------------------------------------------------
        // create new if null
        // -------------------------------------------------
        resp_ctx *l_resp_ctx = NULL;
        if(ao_resp_ctx &&
           *ao_resp_ctx)
        {
                l_resp_ctx = *ao_resp_ctx;
        }
        if(!l_resp_ctx)
        {
                WAFLZ_PERROR(m_err_msg, "ao_resp_ctx == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        if(m_waf->get_request_body_in_memory_limit() > 0)
        {
                l_resp_ctx->set_body_max_len(m_waf->get_request_body_in_memory_limit());
        }
        // -------------------------------------------------
        // run phase 3 init
        // -------------------------------------------------
        l_s = l_resp_ctx->init_phase_3(m_engine.get_geoip2_mmdb());
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "performing resp_ctx::init_phase_3");
                if(!ao_resp_ctx && l_resp_ctx) { delete l_resp_ctx; l_resp_ctx = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        waflz_pb::event *l_event = NULL;
        // -------------------------------------------------
        // process waf...
        // -------------------------------------------------
        l_s = m_waf->process_response(&l_event, a_ctx, &l_resp_ctx, true);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "%s", m_waf->get_err_msg());
                if(!ao_resp_ctx && l_resp_ctx) { delete l_resp_ctx; l_resp_ctx = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // done...
        // -------------------------------------------------
        if(l_event)
        {
                l_s = l_resp_ctx->append_resp_info(*l_event);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "performing resp_ctx::append_resp_info");
                        if(!ao_resp_ctx && l_resp_ctx) { delete l_resp_ctx; l_resp_ctx = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
                l_event->set_rule_intercept_status(403);
                if(get_pb()->has_last_modified_date())
                {
                        l_event->set_config_last_modified(get_pb()->last_modified_date());
                }
                *ao_event = l_event;
        }
        if(!ao_resp_ctx && l_resp_ctx) { delete l_resp_ctx; l_resp_ctx = NULL; }
        return WAFLZ_STATUS_OK;
}

//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
const waflz_pb::sec_config_t* rules::get_pb(void)
{
        if(!m_waf)
        {
                return NULL;
        }
        return m_waf->get_pb();
}
}
