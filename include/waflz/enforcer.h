//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _ENFORCER_H_
#define _ENFORCER_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "waflz/rl_obj.h"
//! ----------------------------------------------------------------------------
//! fwd Decl's
//! ----------------------------------------------------------------------------
namespace waflz_pb {
class event;
class config;
class enforcement;
}
namespace ns_waflz
{
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
class rqst_ctx;
//! ----------------------------------------------------------------------------
//! enforcer
//! ----------------------------------------------------------------------------
class enforcer: public rl_obj
{
public:
        // -------------------------------------------------
        // Public methods
        // -------------------------------------------------
        enforcer(bool a_case_insensitive_headers = false);
        enforcer(waflz_pb::config *m_pb, bool a_case_insensitive_headers = false);
        ~enforcer();
        int32_t load(const char *a_buf, uint32_t a_buf_len);
        int32_t load(void *a_js);
        int32_t process(const waflz_pb::enforcement** ao_enf, rqst_ctx* a_ctx, const bool a_use_enf);
        int32_t process_response(const waflz_pb::enforcement** ao_enf, resp_ctx* a_ctx, const bool a_use_enf);
        int32_t process(const waflz_pb::enforcement** ao_enf, rqst_ctx* a_ctx);
        int32_t process(rqst_ctx* a_ctx);
        int32_t merge(waflz_pb::config &ao_cfg);
        void update_start_time(void);
        uint64_t get_total_limits() const { return m_stat_total_limits; }
private:
        // -------------------------------------------------
        // Private methods
        // -------------------------------------------------
        // disallow copy/assign
        enforcer(const enforcer &);
        enforcer& operator=(const enforcer &);
        int32_t validate(void);
        uint64_t m_stat_total_limits;
};
}
#endif
