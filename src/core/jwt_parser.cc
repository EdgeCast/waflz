//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    jwt_parser.cc
//! \details: See header
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "api_gw.pb.h"
#include "event.pb.h"
#include "waflz/def.h"
#include "waflz/rqst_ctx.h"
#include "jspb/jspb.h"
#include "core/jwt_parser.h"
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
#define _GET_HEADER(_header, _val) do { \
        _val = NULL; \
        _val##_len = 0; \
        l_d.m_data = _header; \
        l_d.m_len = sizeof(_header) - 1; \
        data_unordered_map_t::const_iterator i_h = l_hm.find(l_d); \
        if (i_h != l_hm.end()) \
        { \
                _val = i_h->second.m_data; \
                _val##_len = i_h->second.m_len; \
        } \
} while(0)

namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! \details constructor
//! \return  None
//! \param   None
//! ----------------------------------------------------------------------------
jwt_parser::jwt_parser()
           : m_cert_pems(),
             m_err_msg()

{}
//! ----------------------------------------------------------------------------
//! \details constructor
//! \return  None
//! \param   None
//! ----------------------------------------------------------------------------
jwt_parser::~jwt_parser()
{}
//! ----------------------------------------------------------------------------
//! \details process token 
//! \return  WAFLZ_STATUS_OK on success, WAFLZ_STATUS_ERROR and event on failure
//! \param   token config, client token in request ctx and ouput event
//! ----------------------------------------------------------------------------
int32_t jwt_parser::process(const waflz_pb::jwt& a_token,
                            rqst_ctx* a_ctx,
                            waflz_pb::event** ao_event)
{
        // -------------------------------------------------
        // Make sure *ao_event can be accessed
        // -------------------------------------------------
        if (!ao_event) { return WAFLZ_STATUS_ERROR; }
        //--------------------------------------------------
        //Get authorization header from request ctx
        // -------------------------------------------------
        const data_unordered_map_t &l_hm = a_ctx->m_header_map;
        const char *l_buf = NULL;
        uint32_t l_buf_len = 0;
         data_t l_d;
        _GET_HEADER("Authorization", l_buf);
        if ((l_buf == NULL) ||
           (l_buf_len == 0))
        {
                //------------------------------------------
                // Check if bypass authorization header is
                // enabled
                //------------------------------------------
                if (a_token.has_allow_absent_token() &&
                    a_token.allow_absent_token())
                {
                        return WAFLZ_STATUS_OK;
                }
                waflz_pb::event* l_event = new waflz_pb::event();
                l_event->set_jwt_error_reason("Authorization header missing");
                waflz_pb::event *l_sevent = l_event->add_sub_event();
                l_sevent->set_rule_msg("Authorization header missing");
                l_sevent->add_rule_tag("API security");
                l_sevent->set_rule_id(900150);
                *ao_event = l_event;
                return WAFLZ_STATUS_OK;
        }
        std::string l_client_tok(l_buf, l_buf_len);
        //--------------------------------------------------
        // check if it has Bearer scheme
        // -------------------------------------------------
        std::string l_prefix("Bearer ");
        if (!(l_client_tok.compare(0, l_prefix.length(), l_prefix) == 0))
        {
                waflz_pb::event* l_event = new waflz_pb::event();
                l_event->set_jwt_error_reason("Authorization header doesn't have Bearer scheme");
                waflz_pb::event *l_sevent = l_event->add_sub_event();
                l_sevent->set_rule_msg("Authorization header doesn't have Bearer scheme");
                l_sevent->add_rule_tag("API security");
                l_sevent->set_rule_id(900151);
                *ao_event = l_event;
                return WAFLZ_STATUS_OK;
        }
        //--------------------------------------------------
        // Strip Bearer from token
        // -------------------------------------------------
        std::string l_tok = l_client_tok.substr(l_prefix.length(),
                                                l_client_tok.length()-1);
        //--------------------------------------------------
        // Steps
        // 1. Decode token. Get Key id, algorithm and issuer
        //    from token.
        // 2. check if the corresponding key id is present
        //    in the configured jwks
        // 3. use the algorithm (RSA256 or EC256) to verify the
        //    token
        // -------------------------------------------------
        std::string l_kid;
        try
        {
                auto l_decoded_tok = jwt::decode(l_tok);
                //------------------------------------------
                // INFORMATION:
                // Code below only does signature verification
                // To validate other fields in the token
                // such a client id and issuer from the header
                // and payload  use the following api from jwt
                // decoded_tok.get_header_json() and
                // decoded_tok.get_payload_json() 
                // template to store the returned json is
                // jwt::traits::kazuho_picojson::object_type
                //------------------------------------------
                l_kid.assign(l_decoded_tok.get_key_id().c_str());
                std::string l_issuer(l_decoded_tok.get_issuer().c_str()); 
                //------------------------------------------
                // attempt to find parser for kid
                // make an event if no matching kid found
                //------------------------------------------
                auto l_token_verifier = m_cert_pems.find(l_kid);
                if (l_token_verifier == m_cert_pems.end()) {
                        waflz_pb::event* l_event = new waflz_pb::event();
                        waflz_pb::event *l_sevent = l_event->add_sub_event();
                        l_sevent->set_rule_msg("No matching key found for the kid");
                        l_sevent->add_rule_tag("API security");
                        l_sevent->set_rule_id(900152);
                        l_event->set_jwt_failed_kid(l_kid);
                        l_event->set_jwt_error_reason("No matching key found for the kid");
                        *ao_event = l_event;
                        return WAFLZ_STATUS_OK;
                }
                //------------------------------------------
                // verify token with issuer
                //------------------------------------------
                l_token_verifier->second.with_issuer(l_issuer).verify(l_decoded_tok);
        }
        catch (const std::runtime_error& e)
        {
                waflz_pb::event* l_event = new waflz_pb::event();
                waflz_pb::event *l_sevent = l_event->add_sub_event();
                l_sevent->set_rule_msg(e.what());
                l_sevent->add_rule_tag("API security");
                l_sevent->set_rule_id(900153);
                l_event->set_jwt_failed_kid(l_kid);
                l_event->set_jwt_error_reason(e.what());
                *ao_event = l_event;
                return WAFLZ_STATUS_OK;
        }
        catch (const std::exception& e) {
                waflz_pb::event* l_event = new waflz_pb::event();
                waflz_pb::event *l_sevent = l_event->add_sub_event();
                l_sevent->set_rule_msg(e.what());
                l_sevent->add_rule_tag("API security");
                l_sevent->set_rule_id(900154);
                l_event->set_jwt_failed_kid(l_kid);
                l_event->set_jwt_error_reason(e.what());
                *ao_event = l_event;
                return WAFLZ_STATUS_OK;
        }
        return WAFLZ_STATUS_OK;
}

//! ----------------------------------------------------------------------------
//! \details parse and check if manadatory fields are present in the token
//! \return  WAFLZ_STATUS_OK on success, WAFLZ_STATUS_ERROR and on failure
//! \param   
//! ----------------------------------------------------------------------------
int32_t jwt_parser::parse_and_load(const waflz_pb::jwt& a_tok)
{
        if (!a_tok.has_jwks())
        {
                WAFLZ_PERROR(m_err_msg, "%s", "token missing jwks");
                return WAFLZ_STATUS_ERROR;
        }

        const waflz_pb::credentials& l_jwks = a_tok.jwks();
        if ((!l_jwks.keys_size()))
        {
                WAFLZ_PERROR(m_err_msg, "%s", "keys not present in jwks");
                return WAFLZ_STATUS_ERROR;
        }
        //TODO: add validation for num of keys allowed
        for (int i = 0; i < l_jwks.keys_size(); i++)
        {
                std::string l_str_jwk;
                const waflz_pb::jwk& l_jwk = l_jwks.keys(i);
                if (!l_jwk.has_alg())
                {
                        WAFLZ_PERROR(m_err_msg, "missing algorithm in jwk: %s", l_jwk.DebugString().c_str());
                        return WAFLZ_STATUS_ERROR;
                }
                if (!l_jwk.has_kid())
                {
                        WAFLZ_PERROR(m_err_msg, "missing kid in jwk: %s", l_jwk.DebugString().c_str());
                        return WAFLZ_STATUS_ERROR;
                }
                if (!l_jwk.x5c_size())
                {
                        WAFLZ_PERROR(m_err_msg, "missing x5c chain in jwk: %s", l_jwk.DebugString().c_str());
                        return WAFLZ_STATUS_ERROR;
                }
                //--------------------------------------------------
                // create verifier for each key
                // -------------------------------------------------
                auto l_token_verifier = jwt::verify().leeway(60UL);
                //--------------------------------------------------
                // add the allowed algorithm to the verifier
                // -------------------------------------------------
                switch (l_jwk.alg())
                {
                        case waflz_pb::alg_types_t::RS256:
                        {
                                try
                                {
                                        std::string l_cert_pem = jwt::helper::convert_base64_der_to_pem(l_jwk.x5c(0));
                                        l_token_verifier = l_token_verifier.allow_algorithm(jwt::algorithm::rs256(l_cert_pem, "", "", ""));
                                }
                                catch (const std::runtime_error& e)
                                {
                                        WAFLZ_PERROR(m_err_msg, "failed to parse jwk: %s", e.what());
                                        return WAFLZ_STATUS_ERROR;
                                }
                                catch (const std::exception& e) {
                                        WAFLZ_PERROR(m_err_msg, "failed to parse jwk: %s", e.what());
                                        return WAFLZ_STATUS_ERROR;
                                }
                                break;
                        }
                        default:
                        {
                                auto l_unsupported_alg_name = waflz_pb::alg_types_t_Name(l_jwk.alg());
                                WAFLZ_PERROR(m_err_msg, "Unsupported verification algorithm '%s'", l_unsupported_alg_name.c_str());
                                return WAFLZ_STATUS_ERROR;
                        }
                }
                //--------------------------------------------------
                // add verifier to map
                // -------------------------------------------------
                m_cert_pems.insert({l_jwk.kid(), l_token_verifier});
        }
        return WAFLZ_STATUS_OK;
}
}