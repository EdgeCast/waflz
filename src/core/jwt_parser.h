//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    jwt_parser.h
//! \details: validation for jwt token
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _JWT_PARSER_H_
#define _JWT_PARSER_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "waflz/def.h"
#include "jwt-cpp/jwt.h"
#include <unordered_map>
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
namespace waflz_pb {
class api_gw;
class credentials;
class event;
}

namespace ns_waflz {
class jwt_parser
{
public:
        jwt_parser();
        ~jwt_parser();
        // Info : to store keys directly in a map with kid
         const char* get_err_msg(void) { return m_err_msg; }
        int32_t process(const waflz_pb::jwt& a_token, rqst_ctx* a_ctx, waflz_pb::event** ao_event);
        int32_t parse_and_load(const waflz_pb::jwt& a_token);
private:
        // -------------------------------------------------
        // disallow copy/assign
        // -------------------------------------------------
        std::unordered_map<std::string, jwt::verifier<jwt::default_clock, jwt::traits::kazuho_picojson>> m_cert_pems;
        char m_err_msg[WAFLZ_ERR_LEN];
};
}
#endif