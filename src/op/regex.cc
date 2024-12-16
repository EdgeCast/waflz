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
#include "waflz/def.h"
#include "regex.h"
#include "pcre.h"
#include "support/ndebug.h"
#include <string.h>
#include <string>
#include <list>
#include "waflz/trace.h"
#include "support/time_util.h"
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define _WAFLZ_PCRE_MATCH_LIMIT 1000
#define _WAFLZ_PCRE_MATCH_LIMIT_RECURSION 1000
namespace ns_waflz
{
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
regex::regex(void):
        m_regex(NULL),
        m_regex_study(NULL),
        m_regex_str(),
        m_err_ptr(NULL),
        m_err_off(-1)
{}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
regex::~regex()
{
        if(m_regex)
        {
                pcre_free(m_regex);
                m_regex = NULL;
        }
        if(m_regex_study)
        {
#ifdef PCRE_STUDY_JIT_COMPILE
                pcre_free_study(m_regex_study);
#else
                pcre_free(m_regex_study);
#endif
                m_regex_study = NULL;
        }
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void regex::get_err_info(const char** a_reason, int& a_offset)
{
        *a_reason = m_err_ptr;
        a_offset = m_err_off;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t regex::init(const char* a_buf, uint32_t a_len)
{
        if(!a_buf ||
           (a_len == 0) ||
           (strnlen(a_buf, a_len) == 0))
        {
                return WAFLZ_STATUS_ERROR;
        }
        m_regex_str.assign(a_buf, a_len);
        // -------------------------------------------------
        // compile
        // -------------------------------------------------
        m_regex = pcre_compile(m_regex_str.c_str(),
                               PCRE_DUPNAMES|PCRE_DOTALL|PCRE_MULTILINE,
                               &m_err_ptr,
                               &m_err_off,
                               NULL);
        if(!m_regex)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // study
        // -------------------------------------------------
        m_regex_study = pcre_study(m_regex,
                                   s_pcre_study_options,
                                   &m_err_ptr);
        // -------------------------------------------------
        // if regex_study NULL not compiled with JIT
        // check m_err_ptr for error
        // -------------------------------------------------
        if(m_err_ptr)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // create study if nul
        // -------------------------------------------------
        if(!m_regex_study)
        {
                m_regex_study = (pcre_extra*)calloc(1, sizeof(pcre_extra));
        }
        // -------------------------------------------------
        // set match limits
        // -------------------------------------------------
        m_regex_study->flags |= PCRE_EXTRA_MATCH_LIMIT;
        m_regex_study->match_limit = _WAFLZ_PCRE_MATCH_LIMIT;
        // -------------------------------------------------
        // set recursion limit
        // -------------------------------------------------
        m_regex_study->flags |= PCRE_EXTRA_MATCH_LIMIT_RECURSION;
        m_regex_study->match_limit_recursion = _WAFLZ_PCRE_MATCH_LIMIT_RECURSION;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int regex::compare(const char* a_buf, uint32_t a_len, std::string* ao_captured)
{
        // -----------------------------------------
        // Check for NULL
        // -----------------------------------------
        if(!a_buf ||
           (a_len == 0) ||
           (strnlen(a_buf, a_len) == 0))
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -----------------------------------------
        // match first only
        // -----------------------------------------
        int l_ovecsize = 2;
        int l_ovector[2] = {0};
        int l_s;
        l_s = pcre_exec(m_regex,
                        m_regex_study,
                        a_buf,
                        a_len,
                        0,
                        0,
                        l_ovector,
                        l_ovecsize);
        if(l_s == PCRE_ERROR_MATCHLIMIT ||
            l_s ==  PCRE_ERROR_RECURSIONLIMIT)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -----------------------------------------
        // Match succeeded but ovector too small
        // -----------------------------------------
        if(l_s == 0)
        {
                l_s = l_ovecsize / 2;
        }
        // -----------------------------------------
        // optional save first capture...
        // -----------------------------------------
        if(ao_captured &&
           (l_s > 0))
        {
                ao_captured->assign(a_buf + l_ovector[0],
                                    (l_ovector[1] - l_ovector[0]));
        }
        return l_s;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int regex::compare(std::string a_input, std::string* ao_captured)
{
        return this->compare(a_input.c_str(), a_input.length(), ao_captured);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int regex::compare_all(const char* a_buf, uint32_t a_len, data_list_t* ao_captured)
{
        // -----------------------------------------
        // No check for empty input
        // Input can be empty. e.g empty headers
        // -----------------------------------------
        int l_ovecsize = 30;
        int l_ovector[30] = {0};
        int l_s;
        int l_offset = 0;
        int l_ret_val = 0;
        // -----------------------------------------
        // Get all matches
        // -----------------------------------------
        do
        {
                l_s = pcre_exec(m_regex,
                                m_regex_study,
                                a_buf,
                                a_len,
                                l_offset,
                                0,
                                l_ovector,
                                l_ovecsize);
                if(l_s == PCRE_ERROR_MATCHLIMIT ||
                    l_s ==  PCRE_ERROR_RECURSIONLIMIT)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                // ---------------------------------
                // loop over matches
                // ---------------------------------
                for(int i_t = 0; i_t < l_s; ++i_t)
                {
                        l_ret_val++;
                        data_t l_data;
                        uint32_t l_start = l_ovector[2*i_t];
                        uint32_t l_end = l_ovector[2*i_t+1];
                        uint32_t l_len = l_end - l_start;
                        if(l_end > a_len)
                        {
                            l_s = 0;
                            break;
                        }
                        if(l_len == 0)
                        {
                            l_s = 0;
                            break;
                        }
                        l_offset = l_start + l_len;
                        if(ao_captured)
                        {
                                l_data.m_data = a_buf + l_start;
                                l_data.m_len = l_len;
                                ao_captured->push_back(l_data);
                        }
                }
        } while (l_s > 0);
        return l_ret_val;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void regex::display(void)
{
        // -------------------------------------------------
        // info
        // -------------------------------------------------
        int l_s;
        UNUSED(l_s);
#define _DISPLAY_PCRE_PROP(_what) do { \
                int l_opt; \
                l_s = pcre_fullinfo(m_regex, m_regex_study, _what, &l_opt); \
                NDBG_OUTPUT(":%s: %d\n", #_what, l_opt); \
        } while(0)
#define _DISPLAY_PCRE_PROP_U(_what) do { \
                uint32_t l_opt; \
                l_s = pcre_fullinfo(m_regex, m_regex_study, _what, &l_opt); \
                NDBG_OUTPUT(":%s: %u\n", #_what, l_opt); \
        } while(0)
#define _DISPLAY_PCRE_PROP_UL(_what) do { \
                size_t l_opt; \
                l_s = pcre_fullinfo(m_regex, m_regex_study, _what, &l_opt); \
                NDBG_OUTPUT(":%s: %lu\n", #_what, l_opt); \
        } while(0)
        _DISPLAY_PCRE_PROP(PCRE_INFO_BACKREFMAX);
        _DISPLAY_PCRE_PROP(PCRE_INFO_CAPTURECOUNT);
        _DISPLAY_PCRE_PROP(PCRE_INFO_JIT);
        _DISPLAY_PCRE_PROP_UL(PCRE_INFO_JITSIZE);
        _DISPLAY_PCRE_PROP(PCRE_INFO_MINLENGTH);
#ifndef WAFLZ_PCRE_INFO_FLAGS_MISSING
        _DISPLAY_PCRE_PROP_U(PCRE_INFO_MATCHLIMIT);
#endif
        _DISPLAY_PCRE_PROP(PCRE_INFO_OPTIONS);
        _DISPLAY_PCRE_PROP(PCRE_INFO_SIZE);
        _DISPLAY_PCRE_PROP_UL(PCRE_INFO_STUDYSIZE);
#ifndef WAFLZ_PCRE_INFO_FLAGS_MISSING
        _DISPLAY_PCRE_PROP_UL(PCRE_INFO_RECURSIONLIMIT);
#endif
        _DISPLAY_PCRE_PROP(PCRE_INFO_REQUIREDCHAR);
}
}
