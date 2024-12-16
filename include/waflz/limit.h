//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _LIMIT_H_
#define _LIMIT_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "waflz/def.h"
#include "waflz/rl_obj.h"
#include <set>
#include <vector>
//! ----------------------------------------------------------------------------
//! fwd Decl's
//! ----------------------------------------------------------------------------
namespace waflz_pb {
        class condition_group;
        class limit;
}
namespace ns_waflz
{
//! ----------------------------------------------------------------------------
//! fwd Decl's
//! ----------------------------------------------------------------------------
class kv_db;
class regex;
//! ----------------------------------------------------------------------------
//! status code ranges
//! ----------------------------------------------------------------------------
typedef struct _status_code_range_t{
public:
        uint32_t m_start;
        uint32_t m_end;

        _status_code_range_t(): m_start(0), m_end(0) {};
        _status_code_range_t(uint32_t a_code): m_start(a_code), m_end(a_code) {};
        _status_code_range_t(uint32_t a_start, uint32_t a_end): m_start(a_start), m_end(a_end) {};

} status_code_range_t;
//! ----------------------------------------------------------------------------
//! config
//! ----------------------------------------------------------------------------
class limit: public rl_obj
{
public:
        // -------------------------------------------------
        // Public methods
        // -------------------------------------------------
        limit(kv_db &a_db, bool a_case_insensitive_headers = false);
        ~limit();
        int32_t load(const char *a_buf, uint32_t a_buf_len);
        int32_t load(void *a_js);
        int32_t load(waflz_pb::limit* a_pb);
        const std::string& get_last_modified_date();
        int32_t process(bool &ao_exceeds,
                        const waflz_pb::condition_group** ao_cg,
                        const std::string& a_scope_id,
                        rqst_ctx* a_ctx,
                        bool a_increment_key);
        int32_t key_is_exceeded(bool &ao_exceeds,
                                const std::string& a_scope_id,
                                rqst_ctx* a_ctx);
        int32_t process_response(bool &ao_exceeds,
                                 const waflz_pb::condition_group** ao_cg,
                                 const std::string& a_scope_id,
                                 resp_ctx* a_ctx);
        const char *get_err_msg(void) { return m_err_msg; }
        waflz_pb::limit *get_pb(void) { return m_pb; }
        const std::string& get_id(void) { return m_id; }
        const std::string& get_cust_id(void) { return m_cust_id; }
        bool is_team_config(void) { return m_team_config; }
        void set_enable_pop_count( const bool a_val ) { m_enable_pop_count = a_val; }
        bool is_response_limit() { return !m_status_codes.empty(); }
        int32_t load_status_codes_key( const std::string& a_input );
        std::vector<_status_code_range_t>* get_status_codes() {return &m_status_codes;};
        void clear_status_codes() { m_status_codes.clear(); };
private:
        // -------------------------------------------------
        // Private methods
        // -------------------------------------------------
        // disallow copy/assign
        limit(const limit &);
        limit& operator=(const limit &);
        int32_t init(void);
        int32_t incr_key(bool &ao_exceeds, const std::string& a_scope_id, rqst_ctx* a_ctx);
        int32_t get_key(char* ao_key, const std::string& a_scope_id, rqst_ctx *a_ctx);
        int32_t incr_key_for_response(bool &ao_exceeds, const std::string& a_scope_id, resp_ctx* a_ctx);
        int32_t get_key_for_response(char* ao_key, const std::string& a_scope_id, resp_ctx* a_ctx);

        int32_t load_status_codes_token( const std::string& a_token );
        // -------------------------------------------------
        // Private members
        // -------------------------------------------------
        bool m_init;
        waflz_pb::limit *m_pb;
        kv_db &m_db;
        std::string m_id;
        std::string m_cust_id;
        bool m_team_config;
        bool m_enable_pop_count;
        std::vector<status_code_range_t> m_status_codes;
};
}
#endif
