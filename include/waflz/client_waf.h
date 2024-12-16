//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _CLIENT_WAF_H_
#define _CLIENT_WAF_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "waflz/def.h"
#include "waflz/resp_ctx.h"
#include <strings.h>
#include <unordered_map>
//! ----------------------------------------------------------------------------
//! proto fwd decl's
//! ----------------------------------------------------------------------------
namespace waflz_pb {
class enforcement;
class client_waf;
}
//! ----------------------------------------------------------------------------
//! waflz namespace
//! ----------------------------------------------------------------------------
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
class resp_ctx;
class engine;
//! ----------------------------------------------------------------------------
//! custom types
//! ----------------------------------------------------------------------------
typedef struct _header{
        std::string m_val;
        bool m_overwrite;

        _header():
                m_val(),
                m_overwrite(false)
        {}

        _header( std::string a_val, bool a_overwrite ):
                m_val(a_val),
                m_overwrite(a_overwrite)
        {}
} header_t;
typedef std::unordered_map<std::string, header_t, str_hash, string_ci_compare_unordered> header_map_t;
//! ----------------------------------------------------------------------------
//! client side class decl
//! ----------------------------------------------------------------------------
class client_waf
{
public:
        // -------------------------------------------------
        // constructor & deconstructor
        // -------------------------------------------------
        client_waf(engine &a_engine);
        ~client_waf();
        // -------------------------------------------------
        // load functions
        // -------------------------------------------------
        int32_t load(waflz_pb::client_waf* a_pb);
        int32_t load(const char *a_buf, uint32_t a_buf_len);
        int32_t load(void *a_js);
        // -------------------------------------------------
        // GETTERS & SETTERS
        // -------------------------------------------------
        const char* get_err_msg(void) { return m_err_msg; }
        const std::string& get_id(void) { return m_id; }
        const std::string& get_cust_id(void) { return m_cust_id; }
        waflz_pb::client_waf* get_pb(void) { return m_pb; }
        bool is_team_config(void) { return m_team_config; }
        header_map_t* get_headers(void) { return &m_headers; }
        const std::string& get_csp_script_nonce(void) { return m_csp_script_nonce; }
private:
        // -------------------------------------------------
        // disallow copy/assign
        // -------------------------------------------------
        client_waf(const client_waf &);
        client_waf& operator=(const client_waf &);
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        int32_t init();
        // -------------------------------------------------
        // proto
        // -------------------------------------------------
        waflz_pb::client_waf *m_pb;
        // -------------------------------------------------
        // common config properties
        // -------------------------------------------------
        bool m_init;
        char m_err_msg[WAFLZ_ERR_LEN];
        engine &m_engine;
        std::string m_id;
        std::string m_cust_id;
        bool m_team_config;
        std::string m_name;
        std::string m_last_modified_date;
        // -------------------------------------------------
        // client side properties
        // -------------------------------------------------
        header_map_t m_headers;
        std::string m_csp_script_nonce;
};
}
#endif