//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _WAFLZ_DEF_H_
#define _WAFLZ_DEF_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#ifdef __cplusplus
#include <stdint.h>
#include <list>
#include <map>
#include "waflz/city.h"
#include "waflz/string_util.h"
#endif

#ifndef __cplusplus
#include <stdbool.h>
#endif

#if defined(__APPLE__) || defined(__darwin__)
  #include <strings.h>
#else
  #include <string.h>
#endif
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#ifndef WAFLZ_STATUS_OK
  #define WAFLZ_STATUS_OK 0
#endif

#ifndef WAFLZ_STATUS_ERROR
  #define WAFLZ_STATUS_ERROR -1
#endif

#ifndef WAFLZ_STATUS_WAIT
  #define WAFLZ_STATUS_WAIT 1
#endif

#ifndef WAFLZ_ERR_LEN
  #define WAFLZ_ERR_LEN 4096
#endif
#ifndef WAFLZ_ERR_REASON_LEN
  #define WAFLZ_ERR_REASON_LEN 2048
#endif

#ifndef CONFIG_DATE_FORMAT
  #if defined(__APPLE__) || defined(__darwin__)
    #define CONFIG_DATE_FORMAT "%Y-%m-%dT%H:%M:%S"
  #else
    #define CONFIG_DATE_FORMAT "%Y-%m-%dT%H:%M:%S%Z"
  #endif
#endif 
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
#ifndef WAFLZ_PERROR
#define WAFLZ_PERROR(_str, ...) do { \
  snprintf(_str, WAFLZ_ERR_LEN, __VA_ARGS__); \
} while(0)
#endif
#ifndef DATA_T_EXIST
#define DATA_T_EXIST(_data_t) ( (_data_t.m_len > 0) && _data_t.m_data)
#endif
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
#ifdef __cplusplus
namespace ns_waflz {
typedef enum {
        PART_MK_ACL = 1,
        PART_MK_WAF = 2,
        PART_MK_RULES = 4,
        PART_MK_LIMITS = 8,
        PART_MK_BOTS = 16,
        PART_MK_API_GW = 32,
        PART_MK_CLIENT_WAF = 64,
        PART_MK_ALL = 127,
} part_mk_t;
struct cx_case_i_comp
{
        bool operator() (const std::string& lhs, const std::string& rhs) const
        {
                return strcasecmp(lhs.c_str(), rhs.c_str()) < 0;
        }
};
#endif
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define CAPTCHA_GOOGLE_TOKEN "__ecreha__"
#define CAPTCHA_VERIFIED_TOKEN  "__ecrever__"
#define SITE_VERIFY_URL "https://www.google.com/recaptcha/api/siteverify"
#define DEFAULT_BODY_API_SEC_SIZE_MAX (128*1024)
#define DEFAULT_BODY_SIZE_MAX (8*1024)
#define DEFAULT_RESP_BODY_SIZE_MAX (128*1024)
const short int HTTP_STATUS_OK = 200;
const short int HTTP_STATUS_AUTHENTICATION_REQUIRED = 407;
const short int HTTP_STATUS_FORBIDDEN = 403;
// callbacks
typedef int32_t (*get_rqst_data_size_cb_t)(uint32_t *a, void *);
typedef int32_t (*get_rqst_data_cb_t)(const char **, uint32_t *, void *);
typedef int32_t (*get_rqst_data_w_key_cb_t)(const char **, uint32_t *, void *, const char *, uint32_t);
typedef int32_t (*get_rqst_kv_w_idx_cb_t)(const char **, uint32_t *, const char **, uint32_t *, void *, uint32_t);
typedef int32_t (*get_rqst_body_data_cb_t)(char *, uint32_t *, bool* , void *, uint32_t);

//response callbacks
typedef int32_t (*get_resp_data_size_cb_t)(uint32_t *a, void *);
typedef int32_t (*get_resp_data_cb_t)(const char **, uint32_t *, void *);
typedef int32_t (*get_resp_data_w_key_cb_t)(const char **, uint32_t *, void *, const char *, uint32_t);
typedef int32_t (*get_resp_kv_w_idx_cb_t)(const char **, uint32_t *, const char **, uint32_t *, void *, uint32_t);
typedef int32_t (*get_resp_body_data_cb_t)(char **, uint32_t *, bool* , void *, uint32_t);

#ifdef __cplusplus
typedef int32_t (*get_rqst_data_str_cb_t)(std::string&, void*);
typedef int32_t (*get_data_cb_t)(std::string&, uint32_t *);
typedef int32_t (*get_data_subr_t)(const std::string&, 
                                   const std::string&,
                                   std::string&,
                                   void*,
                                   void*,
                                   int);

typedef struct _data {
        const char *m_data;
        uint32_t m_len;
        _data():
                m_data(NULL),
                m_len(0)
        {};
        _data( const char *a_data, uint32_t a_len ):
                m_data(a_data),
                m_len(a_len)
        {};
} data_t;
typedef struct _mutable_data {
        char *m_data;
        uint16_t m_tx_applied;
        uint32_t m_len;
        _mutable_data():
                m_data(NULL),
                m_tx_applied(0),
                m_len(0)
        {}
} mutable_data_t;

typedef enum tx_applied
{
        TX_APPLIED_TOLOWER = 1 << 0,
        TX_APPLIED_CMDLINE = 1 << 1
} tx_applied_t;

typedef std::list <data_t> data_list_t;
struct data_case_i_comp
{
        bool operator()(const data_t& lhs, const data_t& rhs) const
        {
                //! ----------------------------------------
                //! NOTE: will match on substrings
                //! is this an issue?
                //!
                //! ex: sub == substring
                //! ----------------------------------------
                uint32_t l_len = lhs.m_len > rhs.m_len ? rhs.m_len : lhs.m_len;
                return strncasecmp(lhs.m_data, rhs.m_data, l_len) < 0;
        }
};
typedef std::map <data_t, data_t, data_case_i_comp> data_map_t;
//! ----------------------------------------------------------------------------
//! data_t comparators for unordered data structures
//! ----------------------------------------------------------------------------
struct data_comp_unordered
{
        bool operator()(const data_t& lhs, const data_t& rhs) const
        {
                if(lhs.m_len != rhs.m_len) { return false; }
                uint32_t l_len = lhs.m_len > rhs.m_len ? rhs.m_len : lhs.m_len;
                return strncmp(lhs.m_data, rhs.m_data, l_len) == 0;
        }
};
struct data_case_i_comp_unordered
{
        bool operator()(const data_t& lhs, const data_t& rhs) const
        {
                if(lhs.m_len != rhs.m_len) { return false; }
                uint32_t l_len = lhs.m_len > rhs.m_len ? rhs.m_len : lhs.m_len;
                return strncasecmp(lhs.m_data, rhs.m_data, l_len) == 0;
        }
};
//! ----------------------------------------------------------------------------
//! data_t hash for unordered data structures
//! ----------------------------------------------------------------------------
struct data_t_hash
{
        inline std::size_t operator()(const data_t& a_key) const
        {
                return CityHash64(a_key.m_data, a_key.m_len);
        }
};
struct data_t_case_hash
{
        std::size_t operator()(const data_t& a_key) const
        {
                char* l_data = NULL;
                size_t l_data_len = 0;
                int32_t l_s = convert_to_lower_case(&l_data, l_data_len, a_key.m_data, a_key.m_len);
                if(l_s != WAFLZ_STATUS_OK ||
                   !l_data ||
                   !l_data_len)
                {
                        // ---------------------------------
                        // can't return ERROR from operator
                        // so using length as hash value 
                        // for edge cases
                        // ---------------------------------
                        return a_key.m_len;
                }
                size_t l_hash = CityHash64(l_data, l_data_len);
                if(l_data != NULL) { free(l_data); l_data = NULL; }
                return l_hash; 
        }
};
struct str_hash {
        inline std::size_t operator()(const std::string& a_key) const
        {
                return CityHash64(a_key.c_str(), a_key.length());
        }
};
struct string_ci_compare_unordered
{
        bool operator()(const std::string& lhs, const std::string& rhs) const
        {
                if(lhs.length() != rhs.length()) { return false; }
                return ::strcasecmp(lhs.c_str(), rhs.c_str()) == 0;
        }
};
typedef struct _geoip_data{
        double m_lat;
        double m_long;
        data_t m_cn_name;
        data_t m_city_name;
        data_t m_geo_cn2;
        data_t m_geo_rcc;
        data_t m_src_sd1_iso;
        data_t m_src_sd2_iso;
        bool m_is_anonymous_proxy;
        uint32_t m_src_asn;

        _geoip_data():
                m_lat(0),
                m_long(0),
                m_cn_name(),
                m_city_name(),
                m_geo_cn2(),
                m_geo_rcc(),
                m_src_sd1_iso(),
                m_src_sd2_iso(),
                m_is_anonymous_proxy(false),
                m_src_asn(0)
        {}

} geoip_data;
// ---------------------------------------------------------
// version string
// ---------------------------------------------------------
const char *get_version(void);
}
#endif
#endif
