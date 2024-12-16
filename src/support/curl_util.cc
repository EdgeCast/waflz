//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#include "curl_util.h"
#include "waflz/def.h"
#include <curl/curl.h>
//! ----------------------------------------------------------------------------
//! Macros
//! ----------------------------------------------------------------------------
#define CURL_UTIL_ERR_LEN 4096
#define CURL_UTIL_PERROR(...) do { \
                snprintf(ns_waflz::g_curl_err_msg, CURL_UTIL_ERR_LEN, __VA_ARGS__); \
        }while(0)
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! Globals
//! ----------------------------------------------------------------------------
static char g_curl_err_msg[CURL_UTIL_ERR_LEN];
//! ----------------------------------------------------------------------------
//! \details callback to retrieve the response 
//! \return  size of the response
//! ----------------------------------------------------------------------------
static size_t response_callback(void* a_content, size_t a_size, size_t a_nmemb, void* userp)
{
        ((std::string*)userp)->append((char*)a_content, a_size * a_nmemb);
        return a_size*a_nmemb;
}
//! ----------------------------------------------------------------------------
//! \details Makes a http get request 
//! \param   a_url: url 
//! \param   ao_resp: response
//! \return  WAFLZ_STATUS_OK on Success, WAFLZ_STATUS_ERROR on failure                          
//! ----------------------------------------------------------------------------
int32_t curl_get(const std::string& a_url, std::string& ao_resp)
{
        CURL* l_curl;
        CURLcode l_r;
        std::string l_response;

        curl_global_init(CURL_GLOBAL_ALL);
        l_curl = curl_easy_init();
        if (l_curl == NULL)
        {
                CURL_UTIL_PERROR("curl_easy_init failed");
                return WAFLZ_STATUS_ERROR;
        }

        curl_easy_setopt(l_curl, CURLOPT_URL, a_url.c_str());
        curl_easy_setopt(l_curl, CURLOPT_HTTPGET, 1);
        curl_easy_setopt(l_curl, CURLOPT_WRITEFUNCTION, response_callback);
        curl_easy_setopt(l_curl, CURLOPT_WRITEDATA, &l_response);
        l_r = curl_easy_perform(l_curl);
        if (l_r != CURLE_OK)
        {
                CURL_UTIL_PERROR("curl failed - %s", curl_easy_strerror(l_r));
                curl_easy_cleanup(l_curl);
                curl_global_cleanup();
                return WAFLZ_STATUS_ERROR;
        }
        curl_easy_cleanup(l_curl);
        curl_global_cleanup();
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details Makes a http post request 
//! \param   a_url: url 
//! \param   a_post_param. Eg: a=data1&b=data2
//! \param   ao_resp: response
//! \return  WAFLZ_STATUS_OK on Success, WAFLZ_STATUS_ERROR on failure                          
//! ----------------------------------------------------------------------------
int32_t curl_post(const std::string& a_url,
                  const std::string& a_post_param,
                  std::string& ao_resp)
{
        CURL* l_curl;
        CURLcode l_r;
        curl_global_init(CURL_GLOBAL_ALL);
        l_curl = curl_easy_init();
        if (l_curl == NULL)
        {
                CURL_UTIL_PERROR("curl_easy_init failed");
                return WAFLZ_STATUS_ERROR;
        }
        curl_easy_setopt(l_curl, CURLOPT_URL, a_url.c_str());
        curl_easy_setopt(l_curl, CURLOPT_POST, 1);
        curl_easy_setopt(l_curl, CURLOPT_POSTFIELDS, a_post_param.c_str());
        curl_easy_setopt(l_curl, CURLOPT_WRITEFUNCTION, response_callback);
        curl_easy_setopt(l_curl, CURLOPT_WRITEDATA, &ao_resp);
        l_r = curl_easy_perform(l_curl);
        if (l_r != CURLE_OK)
        {
                CURL_UTIL_PERROR("curl failed - %s", curl_easy_strerror(l_r));
                curl_easy_cleanup(l_curl);
                curl_global_cleanup();
                return WAFLZ_STATUS_ERROR;
        }
        curl_easy_cleanup(l_curl);
        curl_global_cleanup();
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: Get last error
//! \return:  Last error reason
//! ----------------------------------------------------------------------------
const char* get_curl_err_msg(void)
{
        return g_curl_err_msg;
}
}