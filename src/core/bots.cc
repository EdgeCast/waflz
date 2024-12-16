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
#include "waflz/bots.h"
#include "waflz/engine.h"
#include "waflz/rqst_ctx.h"
#include "waflz/challenge.h"
#include "waflz/waf.h"
#include "action.pb.h"
#include "event.pb.h"
#include "rule.pb.h"
#include "support/ndebug.h"
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
bots::bots(engine &a_engine, challenge& a_challenge):
        m_init(false),
        m_err_msg(),
        m_engine(a_engine),
        m_waf(NULL),
        m_id("__na__"),
        m_cust_id("__na__"),
        m_team_config(false),
        m_name("__na__"),
        m_challenge(a_challenge)
{
}
//! ----------------------------------------------------------------------------
//! \details dtor
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
bots::~bots()
{
        if(m_waf) { delete m_waf; m_waf = NULL; }
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t bots::load_file(const char *a_buf, uint32_t a_buf_len)
{
        if(a_buf_len > _CONFIG_PROFILE_MAX_SIZE)
        {
                WAFLZ_PERROR(m_err_msg, "config file size(%u) > max size(%u)",
                             a_buf_len,
                             _CONFIG_PROFILE_MAX_SIZE);
                return WAFLZ_STATUS_ERROR;
        }
        m_init = false;
        // -------------------------------------------------
        // make waf obj
        // -------------------------------------------------
        if(m_waf) { delete m_waf; m_waf = NULL; }
        m_waf = new waf(m_engine);
        std::string l_p;
        l_p.assign(a_buf, a_buf_len);
        int32_t l_s;
        l_s = m_waf->init(config_parser::JSON, l_p, true, true);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "error loading conf file-reason: %.*s",
                             WAFLZ_ERR_REASON_LEN,
                             m_waf->get_err_msg());
                if(m_waf) { delete m_waf; m_waf = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get properties from m_waf
        // -------------------------------------------------
        m_id = m_waf->get_id();
        m_cust_id = m_waf->get_cust_id();
        m_name = m_waf->get_name();
        m_team_config = m_waf->is_team_config();
        // -------------------------------------------------
        // done...
        // -------------------------------------------------
        m_init = true;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t bots::load(void* a_js)
{
        m_init = false;
        // -------------------------------------------------
        // make waf obj
        // -------------------------------------------------
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
        // -------------------------------------------------
        // get properties from m_waf
        // -------------------------------------------------
        m_id = m_waf->get_id();
        m_cust_id = m_waf->get_cust_id();
        m_name = m_waf->get_name();
        m_team_config = m_waf->is_team_config();
        // -------------------------------------------------
        // done...
        // -------------------------------------------------
        m_init = true;
        return WAFLZ_STATUS_OK;     
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t bots::verify_bot_actions(action_map_t a_action_map)
{
        if ( !m_waf ) { return WAFLZ_STATUS_OK; }
        int32_t l_s = m_waf->verify_bot_actions( a_action_map );
        if (l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "%s", m_waf->get_err_msg());
        }
        return l_s;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t bots::process(waflz_pb::event **ao_event,
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
        // process custom bot rule with waf
        // -------------------------------------------------
        l_s = m_waf->process(&l_event, a_ctx, &l_rqst_ctx, true);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "%s", m_waf->get_err_msg());
                if(!ao_rqst_ctx && l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // waf engine only returns an event on a match
        // -------------------------------------------------
        if(l_event)
        {
                // -----------------------------------------
                // populate event with rqst info
                // -----------------------------------------
                l_s = l_rqst_ctx->append_rqst_info(*l_event, m_engine.get_geoip2_mmdb());
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "performing rqst_ctx::append_rqst_info");
                        if(!ao_rqst_ctx && l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
                        return WAFLZ_STATUS_ERROR;
                }
                l_event->set_rule_intercept_status(l_event->sub_event(0).rule_intercept_status());
                if(get_pb()->has_last_modified_date())
                {
                        l_event->set_config_last_modified(get_pb()->last_modified_date());
                }
        }
        *ao_event = l_event;
        if(!ao_rqst_ctx && l_rqst_ctx) { delete l_rqst_ctx; l_rqst_ctx = NULL; }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
const waflz_pb::sec_config_t* bots::get_pb(void)
{
        if(!m_waf)
        {
                return NULL;
        }
        return m_waf->get_pb();
}
}
