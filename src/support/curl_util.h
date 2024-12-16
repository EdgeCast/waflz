//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <curl/curl.h>
#include <string>

namespace ns_waflz {

    int32_t curl_get(const std::string& a_url, std::string& ao_resp);
    int32_t curl_post(const std::string& a_url,
                      const std::string& a_post_param,
                      std::string& ao_resp);
//! ----------------------------------------------------------------------------
//! \details: Get last error
//! \return:  Last error reason
//! ----------------------------------------------------------------------------
const char* get_curl_err_msg(void);
}

