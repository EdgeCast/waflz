//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _SX_API_GW_H_
#define _SX_API_GW_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include <stdint.h>
#include "sx.h"
#include "waflz/api_gw.h"
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
namespace ns_waflz {
class engine;
class rqst_ctx;
class schema;
class regex;
class api_gw;
class enforcement;
}
namespace ns_waflz_server {
//: ----------------------------------------------------------------------------
//: sx_api_gw
//: ----------------------------------------------------------------------------
class sx_api_gw: public sx {
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        sx_api_gw(ns_waflz::engine& a_engine);
        ~sx_api_gw(void);
        int32_t init(void);
        ns_is2::h_resp_t handle_rqst(waflz_pb::enforcement** ao_enf,
                                     ns_waflz::rqst_ctx** ao_ctx,
                                     ns_is2::session& a_session,
                                     ns_is2::rqst& a_rqst,
                                     const ns_is2::url_pmap_t& a_url_pmap);
        ns_is2::h_resp_t handle_resp(waflz_pb::enforcement **ao_enf,
                                     ns_waflz::resp_ctx **ao_ctx,
                                     ns_waflz::header_map_t** ao_headers,
                                     ns_is2::subr &a_subr,
                                     ns_waflz_server::waf_resp_pkg &a_resp_pkg)
        {
                return ns_is2::H_RESP_DONE;
        }
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        ns_waflz::engine& m_engine;
        std::string m_conf_dir;
        ns_waflz::api_gw* m_api_gw;
        waflz_pb::enforcement *m_action;
        ns_waflz::api_gw::id_schema_map_t* m_schema_map;
};
}
#endif
