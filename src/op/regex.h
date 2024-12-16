//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _REGEXX_H_
#define _REGEXX_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "waflz/def.h"
#include <pcre.h>
#include <string>
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
namespace ns_waflz
{
//! ----------------------------------------------------------------------------
//! regex
//! ----------------------------------------------------------------------------
class regex
{
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        regex(void);
        ~regex();
        void get_err_info(const char** a_reason, int& a_offset);
        int32_t init(const char* a_buf, uint32_t a_len);
        int compare(std::string a_input, std::string* ao_captured = NULL);
        int compare(const char* a_buf, uint32_t a_len, std::string* ao_captured = NULL);
        int compare_all(const char* a_buf, uint32_t a_len, data_list_t* ao_captured);
        const std::string& get_regex_string(void) { return m_regex_str; }
        void display(void);
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // TODO FIX!!!
        //DISALLOW_DEFAULT_CTOR(regex);
        // Disallow copy/assign
        regex(const regex&);
        regex& operator=(const regex&);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        pcre* m_regex;
        pcre_extra* m_regex_study;
        std::string m_regex_str;
        // err info
        const char* m_err_ptr;
        int m_err_off;
        // -------------------------------------------------
        // private static
        // -------------------------------------------------
#ifdef PCRE_STUDY_JIT_COMPILE
        static const int s_pcre_study_options = PCRE_STUDY_JIT_COMPILE;
#else
        static const int s_pcre_study_options = 0;
#endif
};
}
#endif
