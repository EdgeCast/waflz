//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _SX_SCOPES_H_
#define _SX_SCOPES_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <stdint.h>
#include "waflz/scopes.h"
#include "waflz/scopes_configs.h"
#include "sx.h"
#include "is2/srvr/srvr.h"
#include "is2/srvr/api_resp.h"
#include "is2/support/trace.h"
#include "is2/support/nbq.h"
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#ifndef STATUS_OK
  #define STATUS_OK 0
#endif
#ifndef STATUS_ERROR
  #define STATUS_ERROR -1
#endif
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
namespace ns_waflz {
class engine;
}
namespace ns_waflz_server {
//! ----------------------------------------------------------------------------
//! entity type
//! ----------------------------------------------------------------------------
typedef enum _entity_t {
        ENTITY_TYPE_SCOPES = 0,
        ENTITY_TYPE_ACL,
        ENTITY_TYPE_PROFILE,
        ENTITY_TYPE_RULES,
        ENTITY_TYPE_BOTS,
        ENTITY_TYPE_LIMIT,
        ENTITY_TYPE_BOT_MANAGER,
        ENTITY_TYPE_API_GW,
        ENTITY_TYPE_API_SCHEMA
} entity_t;
//! ----------------------------------------------------------------------------
//! type
//! ----------------------------------------------------------------------------
typedef struct _conf_update_bg {
        char* m_buf;
        uint32_t m_buf_len;
        ns_waflz::scopes_configs* m_scopes_configs;
        _conf_update_bg(void):
                m_buf(NULL),
                m_buf_len(0),
                m_scopes_configs(NULL)
        {
        }
} conf_update_bg_t;
//! ----------------------------------------------------------------------------
//! update_entity_h
//! ----------------------------------------------------------------------------
template <entity_t T>
class update_entity_h: public ns_is2::default_rqst_h
{
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        update_entity_h(ns_waflz::scopes_configs* a_scopes_configs = NULL,
                        bool a_bg_load = false):
                default_rqst_h(),
                m_scopes_configs(a_scopes_configs),
                m_bg_load(a_bg_load)
        {}
        ~update_entity_h()
        {}
        // -------------------------------------------------
        // do post
        // -------------------------------------------------
        ns_is2::h_resp_t do_post(ns_is2::session &a_session,
                                 ns_is2::rqst &a_rqst,
                                 const ns_is2::url_pmap_t &a_url_pmap)
        {
                if(!m_scopes_configs)
                {
                        TRC_ERROR("m_scopes_configs == NULL");
                        return ns_is2::H_RESP_SERVER_ERROR;
                }
                // -----------------------------------------
                // read request body
                // -----------------------------------------
                uint64_t l_buf_len = a_rqst.get_body_len();
                ns_is2::nbq *l_q = a_rqst.get_body_q();
                char *l_buf;
                l_buf = (char *)malloc(l_buf_len);
                l_q->read(l_buf, l_buf_len);
                int32_t l_s;
                // -----------------------------------------
                // make ctx
                // -----------------------------------------
                // -----------------------------------------
                // if bg load...
                // -----------------------------------------
                if(m_bg_load)
                {
                        // ---------------------------------
                        // create job
                        // ---------------------------------
                        conf_update_bg_t* l_up_bg = new conf_update_bg_t();
                        l_up_bg->m_buf = l_buf;
                        l_up_bg->m_buf_len = l_buf_len;
                        l_up_bg->m_scopes_configs = m_scopes_configs;
                        // ---------------------------------
                        // create bg thread
                        // ---------------------------------
                        pthread_t l_t_thread;
                        int32_t l_pthread_error = 0;
                        l_pthread_error = pthread_create(&l_t_thread,
                                                         NULL,
                                                         bg_load,
                                                         l_up_bg);
                        if (l_pthread_error != 0)
                        {
                                return ns_is2::H_RESP_SERVER_ERROR;
                        }
                }
                // -----------------------------------------
                // else fg load
                // -----------------------------------------
                else
                {
                        int32_t l_s = STATUS_OK;
                        l_s = load(m_scopes_configs, l_buf, l_buf_len);
                        if(l_s != STATUS_OK)
                        {
                                return ns_is2::H_RESP_SERVER_ERROR;
                        }
                }
                // -----------------------------------------
                // generate response
                // -----------------------------------------
                std::string l_resp_str = "{\"status\": \"success\"}";
                ns_is2::api_resp &l_api_resp = ns_is2::create_api_resp(a_session);
                l_api_resp.add_std_headers(ns_is2::HTTP_STATUS_OK,
                                           "application/json",
                                           l_resp_str.length(),
                                           a_rqst.m_supports_keep_alives,
                                           a_session.get_server_name());
                l_api_resp.set_body_data(l_resp_str.c_str(), l_resp_str.length());
                l_api_resp.set_status(ns_is2::HTTP_STATUS_OK);
                ns_is2::queue_api_resp(a_session, l_api_resp);
                return ns_is2::H_RESP_DONE;
        }
        // -------------------------------------------------
        // public static methods
        // -------------------------------------------------
        // -------------------------------------------------
        // bg load entity
        // -------------------------------------------------
        static void* bg_load(void* a_context)
        {
                conf_update_bg_t* l_sc = reinterpret_cast<conf_update_bg_t*>(a_context);
                if(!l_sc)
                {
                        return NULL;
                }
                int32_t l_s;
                // -----------------------------------------
                // load per type
                // -----------------------------------------
                switch(m_type)
                {
                // -----------------------------------------
                // scopes
                // -----------------------------------------
                case ENTITY_TYPE_SCOPES:
                {
                        l_s = l_sc->m_scopes_configs->load(l_sc->m_buf, l_sc->m_buf_len);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                TRC_ERROR("performing scopes->load\n");
                                goto done;
                        }
                        break;
                }
                // -----------------------------------------
                // acl
                // -----------------------------------------
                case ENTITY_TYPE_ACL:
                {
                        l_s = l_sc->m_scopes_configs->load_acl(l_sc->m_buf, l_sc->m_buf_len);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                TRC_ERROR("performing scopes->load\n");
                                goto done;
                        }
                        break;
                }
                // -----------------------------------------
                // profile
                // -----------------------------------------
                case ENTITY_TYPE_PROFILE:
                {
                        l_s = l_sc->m_scopes_configs->load_profile(l_sc->m_buf, l_sc->m_buf_len);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                TRC_ERROR("performing scopes->load\n");
                                goto done;
                        }
                        break;
                }
                // -----------------------------------------
                // rules
                // -----------------------------------------
                case ENTITY_TYPE_RULES:
                {
                        l_s = l_sc->m_scopes_configs->load_rules(l_sc->m_buf, l_sc->m_buf_len);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                TRC_ERROR("performing scopes->load\n");
                                goto done;
                        }
                        break;
                }
                // -----------------------------------------
                // bots
                // -----------------------------------------
                case ENTITY_TYPE_BOTS:
                {
                        l_s = l_sc->m_scopes_configs->load_bots(l_sc->m_buf, l_sc->m_buf_len);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                TRC_ERROR("performing scopes->load\n");
                                goto done;
                        }
                        break;
                }
                // -----------------------------------------
                // limit
                // -----------------------------------------
                case ENTITY_TYPE_LIMIT:
                {
                        l_s = l_sc->m_scopes_configs->load_limit(l_sc->m_buf, l_sc->m_buf_len);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                TRC_ERROR("performing scopes->load\n");
                                goto done;
                        }
                        break;
                }
                // -----------------------------------------
                // bot_manager
                // -----------------------------------------
                case ENTITY_TYPE_BOT_MANAGER:
                {
                        l_s = l_sc->m_scopes_configs->load_bot_manager(l_sc->m_buf, l_sc->m_buf_len);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                TRC_ERROR("performing scopes->load\n");
                                goto done;
                        }
                        break;
                }
                // -----------------------------------------
                // api gateway
                // -----------------------------------------
                case ENTITY_TYPE_API_GW:
                {
                        l_s = l_sc->m_scopes_configs->load_api_gw(l_sc->m_buf, l_sc->m_buf_len);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                TRC_ERROR("performing scopes->load\n");
                                goto done;
                        }
                        break;
                }
                // -----------------------------------------
                // api schema
                // -----------------------------------------
                case ENTITY_TYPE_API_SCHEMA:
                {
                        l_s = l_sc->m_scopes_configs->load_schema(l_sc->m_buf, l_sc->m_buf_len);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                printf("load schema failed\n");
                                TRC_ERROR("performing scopes->load\n");
                                goto done;
                        }
                        break;
                }
                // -----------------------------------------
                // default
                // -----------------------------------------
                default:
                {
                        TRC_ERROR("unrecognized entity type: %d\n", m_type);
                        goto done;
                }
                }
done:
                if(l_sc->m_buf) { free(l_sc->m_buf); l_sc->m_buf = NULL;}
                delete l_sc;
                return NULL;
        }
        // -------------------------------------------------
        // bg load entity
        // -------------------------------------------------
        static int32_t load(ns_waflz::scopes_configs* a_scopes_configs,
                            char* a_buf,
                            uint32_t a_buf_len)
        {
                if(!a_scopes_configs ||
                   !a_buf ||
                   !a_buf_len)
                {
                        return STATUS_ERROR;
                }
                int32_t l_ret = STATUS_OK;
                int32_t l_s;
                // -----------------------------------------
                // load per type
                // -----------------------------------------
                switch(m_type)
                {
                // -----------------------------------------
                // scopes
                // -----------------------------------------
                case ENTITY_TYPE_SCOPES:
                {
                        l_s = a_scopes_configs->load(a_buf, a_buf_len);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                TRC_ERROR("performing scopes->load\n");
                                l_ret = STATUS_ERROR;
                                goto done;
                        }
                        break;
                }
                // -----------------------------------------
                // acl
                // -----------------------------------------
                case ENTITY_TYPE_ACL:
                {
                        l_s = a_scopes_configs->load_acl(a_buf, a_buf_len);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                TRC_ERROR("performing scopes->load\n");
                                l_ret = STATUS_ERROR;
                                goto done;
                        }
                        break;
                }
                // -----------------------------------------
                // profile
                // -----------------------------------------
                case ENTITY_TYPE_PROFILE:
                {
                        l_s = a_scopes_configs->load_profile(a_buf, a_buf_len);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                TRC_ERROR("performing scopes->load\n");
                                l_ret = STATUS_ERROR;
                                goto done;
                        }
                        break;
                }
                // -----------------------------------------
                // rules
                // -----------------------------------------
                case ENTITY_TYPE_RULES:
                {
                        l_s = a_scopes_configs->load_rules(a_buf, a_buf_len);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                TRC_ERROR("performing scopes->load\n");
                                l_ret = STATUS_ERROR;
                                goto done;
                        }
                        break;
                }
                // -----------------------------------------
                // bots
                // -----------------------------------------
                case ENTITY_TYPE_BOTS:
                {
                        l_s = a_scopes_configs->load_bots(a_buf, a_buf_len);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                TRC_ERROR("performing scopes->load\n");
                                l_ret = STATUS_ERROR;
                                goto done;
                        }
                        break;
                }
                // -----------------------------------------
                // limit
                // -----------------------------------------
                case ENTITY_TYPE_LIMIT:
                {
                        l_s = a_scopes_configs->load_limit(a_buf, a_buf_len);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                TRC_ERROR("performing scopes->load\n");
                                l_ret = STATUS_ERROR;
                                goto done;
                        }
                        break;
                }
                // -----------------------------------------
                // bot_manager
                // -----------------------------------------
                case ENTITY_TYPE_BOT_MANAGER:
                {
                        l_s = a_scopes_configs->load_bot_manager(a_buf, a_buf_len);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                TRC_ERROR("performing scopes->load\n");
                                l_ret = STATUS_ERROR;
                                goto done;
                        }
                        break;
                }
                // -----------------------------------------
                // api gateway
                // -----------------------------------------
                case ENTITY_TYPE_API_GW:
                {
                        l_s = a_scopes_configs->load_api_gw(a_buf, a_buf_len);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                TRC_ERROR("performing scopes->load\n");
                                goto done;
                        }
                        break;
                }
                // -----------------------------------------
                // api schema
                // -----------------------------------------
                case ENTITY_TYPE_API_SCHEMA:
                {
                        l_s = a_scopes_configs->load_schema(a_buf, a_buf_len);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                TRC_ERROR("performing scopes->load\n");
                                goto done;
                        }
                        break;
                }
                // -----------------------------------------
                // default
                // -----------------------------------------
                default:
                {
                        TRC_ERROR("unrecognized entity type: %d\n", m_type);
                        l_ret = STATUS_ERROR;
                        goto done;
                }
                }
done:
                if(a_buf) { free(a_buf); a_buf = NULL;}
                return l_ret;
        }
        // -------------------------------------------------
        // public const
        // -------------------------------------------------
        static const entity_t m_type = T;
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        ns_waflz::scopes_configs* m_scopes_configs;
        bool m_bg_load;
};
//! ----------------------------------------------------------------------------
//! sx_scopes
//! ----------------------------------------------------------------------------
class sx_scopes: public ns_waflz_server::sx {
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        sx_scopes(ns_waflz::engine& a_engine,
                  ns_waflz::kv_db& a_db,
                  ns_waflz::kv_db& a_bot_db,
                  ns_waflz::challenge& a_challenge,
                  ns_waflz::captcha& a_captcha);
        ~sx_scopes(void);
        int32_t init(void);
        ns_is2::h_resp_t get_id_for_hmsg(ns_is2::rqst& a_msg,
                                         std::string& a_team_id,
                                         uint64_t& a_id);
        ns_is2::h_resp_t handle_rqst(waflz_pb::enforcement **ao_enf,
                                     ns_waflz::rqst_ctx **ao_ctx,
                                     ns_is2::session &a_session,
                                     ns_is2::rqst &a_rqst,
                                     const ns_is2::url_pmap_t &a_url_pmap);
        ns_is2::h_resp_t handle_resp(waflz_pb::enforcement **ao_enf,
                                     ns_waflz::resp_ctx **ao_ctx,
                                     ns_waflz::header_map_t** ao_headers,
                                     ns_is2::subr &a_subr,
                                     ns_waflz_server::waf_resp_pkg &a_resp_pkg);
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        // -------------------------------------------------
        // properties
        // -------------------------------------------------
        bool m_bg_load;
        bool m_is_rand;
        ns_waflz::engine& m_engine;
        ns_waflz::kv_db& m_db;
        ns_waflz::kv_db& m_bot_db;
        ns_waflz::challenge& m_challenge;
        ns_waflz::captcha& m_captcha;
        std::string m_conf_dir;
        ns_waflz::scopes_configs* m_scopes_configs;
        // -------------------------------------------------
        // update endpoints
        // -------------------------------------------------
        update_entity_h<ENTITY_TYPE_SCOPES>* m_update_scopes_h;
        update_entity_h<ENTITY_TYPE_ACL>* m_update_acl_h;
        update_entity_h<ENTITY_TYPE_RULES>* m_update_rules_h;
        update_entity_h<ENTITY_TYPE_BOTS>* m_update_bots_h;
        update_entity_h<ENTITY_TYPE_PROFILE>* m_update_profile_h;
        update_entity_h<ENTITY_TYPE_LIMIT>* m_update_limit_h;
        update_entity_h<ENTITY_TYPE_BOT_MANAGER>* m_update_bot_manager_h;
        update_entity_h<ENTITY_TYPE_API_GW>* m_update_api_gw_h;
        update_entity_h<ENTITY_TYPE_API_SCHEMA>* m_update_api_schema_h;
};
}
#endif
