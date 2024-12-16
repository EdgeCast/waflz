//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _SX_H_
#define _SX_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include <stdint.h>
#include "is2/srvr/session.h"
#include "is2/srvr/rqst.h"
#include "is2/srvr/resp.h"
#include "is2/srvr/lsnr.h"
#include "waflz/rqst_ctx.h"
#include "waflz/client_waf.h"
#include <cb.h>
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
namespace waflz_pb {
class enforcement;
}
namespace ns_waflz {
class rqst_ctx;
class challenge;
}
namespace ns_waflz_server {
//: ----------------------------------------------------------------------------
//: callbacks
//: ----------------------------------------------------------------------------
class sx {
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        sx(void):
                m_lsnr(NULL),
                m_config(),
                m_resp()
        {};
        virtual ~sx(void) {};
        virtual int32_t init(void) = 0;
        virtual ns_is2::h_resp_t handle_rqst(waflz_pb::enforcement **ao_enf,
                                             ns_waflz::rqst_ctx **ao_ctx,
                                             ns_is2::session &a_session,
                                             ns_is2::rqst &a_rqst,
                                             const ns_is2::url_pmap_t &a_url_pmap) = 0;
        static ns_is2::h_resp_t s_handle_rqst(sx &a_sx,
                                              waflz_pb::enforcement **ao_enf,
                                              ns_waflz::rqst_ctx **ao_ctx,
                                              ns_is2::session &a_session,
                                              ns_is2::rqst &a_rqst,
                                              const ns_is2::url_pmap_t &a_url_pmap)
        {
                return a_sx.handle_rqst(ao_enf, ao_ctx, a_session, a_rqst, a_url_pmap);
        }
        virtual ns_is2::h_resp_t handle_resp(waflz_pb::enforcement **ao_enf,
                                             ns_waflz::resp_ctx **ao_ctx,
                                             ns_waflz::header_map_t** ao_headers,
                                             ns_is2::subr &a_subr,
                                             ns_waflz_server::waf_resp_pkg &a_resp_pkg) = 0;
        static ns_is2::h_resp_t s_handle_resp(sx &a_sx,
                                              waflz_pb::enforcement **ao_enf,
                                              ns_waflz::resp_ctx **ao_ctx,
                                              ns_waflz::header_map_t** ao_headers,
                                              ns_is2::subr &a_subr,
                                              ns_waflz_server::waf_resp_pkg &a_resp_pkg)
        {
                return a_sx.handle_resp(ao_enf, ao_ctx, ao_headers, a_subr, a_resp_pkg);
        }
        // -------------------------------------------------
        // public members
        // -------------------------------------------------
        ns_is2::lsnr *m_lsnr;
        std::string m_config;
        std::string m_resp;
        const ns_waflz::rqst_ctx_callbacks *m_callbacks;
        const ns_waflz::resp_ctx_callbacks *m_resp_callbacks;
};
}
#endif
