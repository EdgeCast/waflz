//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _SX_LIMIT_H_
#define _SX_LIMIT_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include <stdint.h>
#include "sx.h"
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
namespace waflz_pb {
class enforcement;
}
namespace ns_waflz {
class limit;
class enforcement;
class enforcer;
class kv_db;
class geoip2_mmdb;
}
namespace ns_waflz_server {
//: ----------------------------------------------------------------------------
//: sx_limit
//: ----------------------------------------------------------------------------
class sx_limit: public sx {
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        sx_limit(ns_waflz::engine& a_engine, ns_waflz::kv_db &a_db);
        ~sx_limit(void);
        int32_t init(void);
        ns_is2::h_resp_t handle_rqst(waflz_pb::enforcement **ao_enf,
                                     ns_waflz::rqst_ctx **ao_ctx,
                                     ns_is2::session &a_session,
                                     ns_is2::rqst &a_rqst,
                                     const ns_is2::url_pmap_t &a_url_pmap);
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
        ns_waflz::limit* m_limit;
        ns_waflz::kv_db& m_db;
        ns_waflz::geoip2_mmdb* m_geoip2_mmdb;
        std::string m_geoip2_db;
        std::string m_geoip2_isp_db;
        ns_waflz::engine& m_engine;
private:
        // -------------------------------------------------
        // enforcements
        // -------------------------------------------------
        ns_waflz::enforcer *m_enfx;
        waflz_pb::enforcement *m_enf;
};
}
#endif
