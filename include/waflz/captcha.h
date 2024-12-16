//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _CAPTCHA_H_
#define _CAPTCHA_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "waflz/def.h"
#include "waflz/rqst_ctx.h"
//! ----------------------------------------------------------------------------
//! fwd Decl's
//! ----------------------------------------------------------------------------
namespace waflz_pb {
        class event;
}
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! captcha
//! ----------------------------------------------------------------------------
class captcha
{
public:
        //--------------------------------------------------
        // public methods
        //--------------------------------------------------
        captcha(void);
        ~captcha();
        int32_t load_file(const char* a_file_path, uint32_t a_file_path_len);
        int32_t verify(rqst_ctx* a_ctx,
                       uint32_t a_valid_for_sec,
                       waflz_pb::event* ao_event,
                       const waflz_pb::enforcement* a_enf,
                       bool& ao_issue_captcha);
        int32_t check_google_token(rqst_ctx* a_ctx,
                                   waflz_pb::event* ao_event,
                                   const waflz_pb::enforcement* a_enf,
                                   bool& ao_issue_captcha);
        int32_t validate_google_token(rqst_ctx* a_ctx,
                                      waflz_pb::event** ao_event,
                                      bool& ao_is_bot);
        int32_t verify_ec_token(data_t* l_ec_token,
                                uint32_t a_valid_for_s,
                                rqst_ctx* a_ctx,
                                bool& ao_issue_captcha,
                                waflz_pb::event *ao_event);
        int32_t set_captcha_verified_ec_token(rqst_ctx* a_ctx);
        void set_google_site_verify_url(const std::string& a_url);
        const std::string& get_captcha_html() { return m_captcha_b64; }; 
        const char* get_err_msg(void)
        {
                return m_err_msg;
        }
private:
        //--------------------------------------------------
        // private methods
        //--------------------------------------------------
        captcha(const captcha &);
        captcha& operator=(const captcha &);
        //--------------------------------------------------
        // private vars
        //--------------------------------------------------
        std::string m_captcha_b64;
        std::string m_g_site_verify_url;
        char m_err_msg[WAFLZ_ERR_LEN];
};
}
#endif
