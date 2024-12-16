//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _PARSE_H
#define _PARSE_H
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "waflz/arg.h"
#include "waflz/rqst_ctx.h"
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! prototypes
//! ----------------------------------------------------------------------------
int32_t css_decode(char **ao_buf, uint32_t &ao_len, const char *a_buf, uint32_t a_len);
int32_t html_entity_decode(char **ao_buf, uint32_t &ao_len, const char *a_buf, uint32_t a_len);
int32_t js_decode_ns(char **ao_buf, uint32_t &ao_len, const char *a_buf, uint32_t a_len);
int32_t normalize_path(char **ao_buf, uint32_t &ao_len, const char *a_buf, uint32_t a_len, bool a_is_windows);
int32_t parse_args(arg_list_t &ao_arg_list , data_unordered_map_t& ao_arg_map, uint32_t &ao_invalid_cnt, const char *a_buf, uint32_t a_len, char a_arg_sep);
int32_t parse_cookies(const_arg_list_t &ao_cookie_list, const char *a_buf, uint32_t a_len);
int32_t urldecode_ns(char **ao_buf, uint32_t &ao_len, uint32_t &ao_invalid_count, const char *a_buf, uint32_t a_len);
int32_t urldecode_uni_ns(char **ao_buf, uint32_t &ao_len, const char *a_buf, uint32_t a_len);
int32_t utf8_to_unicode(char **ao_buf, uint32_t &ao_len, const char *a_buf, uint32_t a_len);
int32_t validate_utf8(bool &ao_valid, const char **ao_err_msg, uint32_t &ao_err_off, const char *a_buf, uint32_t a_len);
int32_t parse_content_type(data_list_t &ao_data_list, const_arg_t *a_hdr);
}
#endif //#ifndef _PARSE_H
