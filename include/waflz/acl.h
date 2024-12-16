//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _ACL_H_
#define _ACL_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "waflz/def.h"
#include <strings.h>
#include <string>
#include <set>
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
namespace waflz_pb {
class profile;
class profile_access_settings_t;
class event;
class acl;
}
namespace ns_waflz {
class engine;
class regex;
class rqst_ctx;
class nms;
//! ----------------------------------------------------------------------------
//! acl
//! ----------------------------------------------------------------------------
class acl
{
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        acl(engine& a_engine);
        ~acl();
        int32_t load(const char *a_buf, uint32_t a_buf_len);
        int32_t load(const waflz_pb::acl* a_pb);
        int32_t load(void* a_js);
        int32_t process(waflz_pb::event **ao_event, bool &ao_whitelist, void *a_ctx, rqst_ctx **ao_rqst_ctx);
        //: ------------------------------------------------
        //:               G E T T E R S
        //: ------------------------------------------------
        const std::string& get_id(void) { return m_id; }
        const std::string& get_cust_id(void) { return m_cust_id; }
        bool is_team_config(void) { return m_team_config; }
        const std::string& get_name(void) { return m_name; }
        //: ------------------------------------------------
        //:               S E T T E R S
        //: ------------------------------------------------
        void set_allow_anonymous_proxy(bool value) { m_allow_anonymous_proxy = value; }
        //: ------------------------------------------------
        //: \details Get last error message string
        //: \return  last error message (in buffer)
        //: ------------------------------------------------
        const char *get_err_msg(void)
        {
                return m_err_msg;
        }
        const waflz_pb::acl* get_pb(void) { return m_pb; }
private:
        // -------------------------------------------------
        // private types
        // -------------------------------------------------
        struct ci_less_comp
        {
                bool operator() (const std::string& lhs, const std::string& rhs) const
                {
                        return strcasecmp(lhs.c_str(), rhs.c_str()) < 0;
                }
        };
        // -------------------------------------------------
        // private types
        // -------------------------------------------------
        typedef std::set<uint32_t> asn_set_t;
        typedef std::set <std::string, ci_less_comp> stri_set_t;
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        int32_t init();
        // -------------------------------------------------
        // disallow copy/assign
        // -------------------------------------------------
        acl(const acl &);
        acl& operator=(const acl &);
        // -------------------------------------------------
        // process information
        // -------------------------------------------------
        int32_t process_whitelist(bool &ao_match, rqst_ctx &a_ctx);
        int32_t process_accesslist(waflz_pb::event **ao_event, rqst_ctx &a_ctx);
        int32_t process_blacklist(waflz_pb::event **ao_event, rqst_ctx &a_ctx);
        int32_t process_settings(waflz_pb::event **ao_event, rqst_ctx &a_ctx);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        bool m_init;
        char m_err_msg[WAFLZ_ERR_LEN];
        engine &m_engine;
        waflz_pb::acl *m_pb;
        // -------------------------------------------------
        // properties
        // -------------------------------------------------
        std::string m_id;
        std::string m_cust_id;
        bool m_team_config;
        std::string m_name;
        std::string m_resp_header_name;
        bool m_allow_anonymous_proxy;
        // -------------------------------------------------
        // ip
        // -------------------------------------------------
        nms *m_ip_whitelist;
        nms *m_ip_accesslist;
        nms *m_ip_blacklist;
        // -------------------------------------------------
        // country
        // -------------------------------------------------
        stri_set_t m_country_whitelist;
        stri_set_t m_country_accesslist;
        stri_set_t m_country_blacklist;
        // -------------------------------------------------
        // asn
        // -------------------------------------------------
        asn_set_t m_asn_whitelist;
        asn_set_t m_asn_accesslist;
        asn_set_t m_asn_blacklist;
        // -------------------------------------------------
        // SD_ISO
        // -------------------------------------------------
        stri_set_t m_sd_iso_whitelist;
        stri_set_t m_sd_iso_accesslist;
        stri_set_t m_sd_iso_blacklist;
        // -------------------------------------------------
        // ja3
        // -------------------------------------------------
        stri_set_t m_ja3_whitelist;
        stri_set_t m_ja3_accesslist;
        stri_set_t m_ja3_blacklist;
        // -------------------------------------------------
        // ja4
        // -------------------------------------------------
        stri_set_t m_ja4_whitelist;
        stri_set_t m_ja4_accesslist;
        stri_set_t m_ja4_blacklist;
        // -------------------------------------------------
        // url
        // -------------------------------------------------
        regex *m_url_rx_whitelist;
        regex *m_url_rx_accesslist;
        regex *m_url_rx_blacklist;
        // -------------------------------------------------
        // user-agent
        // -------------------------------------------------
        regex *m_ua_rx_whitelist;
        regex *m_ua_rx_accesslist;
        regex *m_ua_rx_blacklist;
        // -------------------------------------------------
        // referer
        // -------------------------------------------------
        regex *m_referer_rx_whitelist;
        regex *m_referer_rx_accesslist;
        regex *m_referer_rx_blacklist;
        // -------------------------------------------------
        // cookie
        // -------------------------------------------------
        regex *m_cookie_rx_whitelist;
        regex *m_cookie_rx_accesslist;
        regex *m_cookie_rx_blacklist;
        // -------------------------------------------------
        // methods
        // -------------------------------------------------
        stri_set_t m_allowed_http_methods;
        // -------------------------------------------------
        // protocol versions
        // -------------------------------------------------
        stri_set_t m_allowed_http_versions;
        // -------------------------------------------------
        // content types
        // -------------------------------------------------
        stri_set_t m_allowed_request_content_types;
        // -------------------------------------------------
        // extensions
        // -------------------------------------------------
        stri_set_t m_disallowed_extensions;
        // -------------------------------------------------
        // headers
        // -------------------------------------------------
        stri_set_t m_disallowed_headers;
};
}
#endif
