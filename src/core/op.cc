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
#include "waflz/string_util.h"
#include "rule.pb.h"
#include "core/op.h"
#include "core/macro.h"
#include "core/decode.h"
#include "support/ndebug.h"
#include "op/regex.h"
#include "waflz/ac.h"
#include "waflz/nms.h"
#include "op/byte_range.h"
#include "op/luhn.h"
#include "libinjection/src/libinjection.h"
#include <string.h>
#include <map>
#include <limits.h>
#include "waflz/trace.h"
#include "support/time_util.h"
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
#define SET_IF_NEGATED() do { \
        if(a_op.has_is_negated() && \
           a_op.is_negated()) { \
                ao_match = !ao_match; \
        } } while(0)
#define EXPAND_MACRO(_val) \
        const std::string *l_val_ref = &l_val; \
        std::string l_sv_var; \
        if(a_macro && \
           a_macro->has(l_val)) { \
                int32_t l_s = (*a_macro)(l_sv_var, l_val, a_ctx, a_res_ctx); \
                if(l_s != WAFLZ_STATUS_OK) { return WAFLZ_STATUS_ERROR; } \
                l_val_ref = &l_sv_var; \
        }
#define VALID_HEX(X) \
        (((X >= '0') && (X <= '9')) || \
         ((X >= 'a') && (X <= 'f')) || \
         ((X >= 'A') && (X <= 'F')))
//! ----------------------------------------------------------------------------
//! op macro
//! ----------------------------------------------------------------------------
#define OP(_type) \
        static int32_t _op_cb_##_type(bool& ao_match, \
                                      const waflz_pb::sec_rule_t_operator_t& a_op, \
                                      const char* a_buf, \
                                      const uint32_t a_len, \
                                      macro* a_macro, \
                                      rqst_ctx *a_ctx, \
                                      resp_ctx *a_res_ctx)
namespace ns_waflz {

//! ----------------------------------------------------------------------------
//! \details: Checks if a context object was marked with a tx that uses tolower()
//! \param:   A context(output)
//! \return:  True if a tx that uses tolower() was called.
//! ----------------------------------------------------------------------------
static bool check_if_tolower_tx_was_applied(ns_waflz::rqst_ctx *a_ctx, ns_waflz::resp_ctx *a_res_ctx) {
        if(a_ctx)
        {
                return (a_ctx->m_src_asn_str.m_tx_applied & ns_waflz::TX_APPLIED_TOLOWER) ||
                (a_ctx->m_src_asn_str.m_tx_applied & ns_waflz::TX_APPLIED_CMDLINE);
        }
        else
        {
                return false;
        }
}
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                             O P E R A T I O N S
//! ****************************************************************************
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
OP(EQ)
{
        ao_match = false;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        if(!a_op.has_value())
        {
                return WAFLZ_STATUS_OK;
        }
        const std::string &l_val = a_op.value();
        EXPAND_MACRO(l_val);
        // -------------------------------------------------
        // convert/compare
        // -------------------------------------------------
        long int l_in_val;
        char *l_end_ptr = NULL;
        if(strcmp(a_buf, "BOT_SCORE") == 0)
        {
                l_in_val = a_len;
        }
        else
        {
                l_in_val = strntol(a_buf, a_len, &l_end_ptr, 10);
        }
        if((l_in_val == LONG_MAX) ||
           (l_in_val == LONG_MIN))
        {
                return WAFLZ_STATUS_OK;
        }
        if(l_end_ptr == a_buf)
        {
                return WAFLZ_STATUS_OK;
        }
        long int l_op_val;
        l_op_val = strntol(l_val_ref->c_str(), l_val_ref->length(), &l_end_ptr, 10);
        if((l_op_val == LONG_MAX) ||
           (l_op_val == LONG_MIN))
        {
                return WAFLZ_STATUS_OK;
        }
        if(l_end_ptr == l_val_ref->c_str())
        {
                return WAFLZ_STATUS_OK;
        }
        if(l_op_val == l_in_val)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
OP(GE)
{
        ao_match = false;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        if(!a_op.has_value())
        {
                return WAFLZ_STATUS_OK;
        }
        const std::string &l_val = a_op.value();
        EXPAND_MACRO(l_val);
        // -------------------------------------------------
        // convert/compare
        // -------------------------------------------------
        long int l_in_val;
        char *l_end_ptr = NULL;
        if(strcmp(a_buf, "BOT_SCORE") == 0)
        {
                l_in_val = a_len;
        }
        else
        {
                l_in_val = strntol(a_buf, a_len, &l_end_ptr, 10);
        }
        if((l_in_val == LONG_MAX) ||
           (l_in_val == LONG_MIN))
        {
                return WAFLZ_STATUS_OK;
        }
        if(l_end_ptr == a_buf)
        {
                return WAFLZ_STATUS_OK;
        }
        long int l_op_val;
        l_op_val = strntol(l_val_ref->c_str(), l_val_ref->length(), &l_end_ptr, 10);
        if((l_op_val == LONG_MAX) ||
           (l_op_val == LONG_MIN))
        {
                return WAFLZ_STATUS_OK;
        }
        if(l_end_ptr == l_val_ref->c_str())
        {
                return WAFLZ_STATUS_OK;
        }
        if(l_in_val >= l_op_val)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
OP(GT)
{
        ao_match = false;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        if(!a_op.has_value())
        {
                return WAFLZ_STATUS_OK;
        }
        const std::string &l_val = a_op.value();
        EXPAND_MACRO(l_val);
        // -------------------------------------------------
        // convert/compare
        // -------------------------------------------------
        long int l_in_val;
        char *l_end_ptr = NULL;
        // Special case for args combined size
        // since there is no transformation t:length on input buf
        // The length is specified in a_len
        if(strcmp(a_buf, "ARGS_COMBINED_SIZE") == 0)
        {
                l_in_val = a_len;
        }
        else if(strcmp(a_buf, "BOT_SCORE") == 0)
        {
                l_in_val = a_len;
        }
        else
        {
                l_in_val = strntol(a_buf, a_len, &l_end_ptr, 10);
        }
        if((l_in_val == LONG_MAX) ||
           (l_in_val == LONG_MIN))
        {
                return WAFLZ_STATUS_OK;
        }
        if(l_end_ptr == a_buf)
        {
                return WAFLZ_STATUS_OK;
        }
        long int l_op_val;
        l_op_val = strntol(l_val_ref->c_str(), l_val_ref->length(), &l_end_ptr, 10);
        if((l_op_val == LONG_MAX) ||
           (l_op_val == LONG_MIN))
        {
                return WAFLZ_STATUS_OK;
        }
        if(l_end_ptr == l_val_ref->c_str())
        {
                return WAFLZ_STATUS_OK;
        }
        if(l_in_val > l_op_val)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
OP(LT)
{
        ao_match = false;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        if(!a_op.has_value())
        {
                return WAFLZ_STATUS_OK;
        }
        const std::string &l_val = a_op.value();
        EXPAND_MACRO(l_val);
        // -------------------------------------------------
        // convert/compare
        // -------------------------------------------------
        long int l_in_val;
        char *l_end_ptr = NULL;
        // Special case for args combined size
        // since there is no transformation t:length on input buf
        // The length is specified in a_len
        if(strcmp(a_buf, "ARGS_COMBINED_SIZE") == 0)
        {
                l_in_val = a_len;
        }
        else if(strcmp(a_buf, "BOT_SCORE") == 0)
        {
                l_in_val = a_len;
        }
        else
        {
                l_in_val = strntol(a_buf, a_len, &l_end_ptr, 10);
        }
        if((l_in_val == LONG_MAX) ||
           (l_in_val == LONG_MIN))
        {
                return WAFLZ_STATUS_OK;
        }
        if(l_end_ptr == a_buf)
        {
                return WAFLZ_STATUS_OK;
        }
        long int l_op_val;
        l_op_val = strntol(l_val_ref->c_str(), l_val_ref->length(), &l_end_ptr, 10);
        if((l_op_val == LONG_MAX) ||
           (l_op_val == LONG_MIN))
        {
                return WAFLZ_STATUS_OK;
        }
        if(l_end_ptr == l_val_ref->c_str())
        {
                return WAFLZ_STATUS_OK;
        }
        if(l_in_val < l_op_val)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: Performs numerical comparison and returns true if the input value
//!           is less than or equal to the operator parameter. Macro expansion is
//!           performed on the parameter string before comparison
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
OP(LE)
{
        ao_match = false;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        if(!a_op.has_value())
        {
                return WAFLZ_STATUS_OK;
        }
        const std::string &l_val = a_op.value();
        EXPAND_MACRO(l_val);
        // -------------------------------------------------
        // convert/compare
        // -------------------------------------------------
        long int l_in_val;
        char *l_end_ptr = NULL;
        // Special case for args combined size
        // since there is no transformation t:length on input buf
        // The length is specified in a_len
        if(strcmp(a_buf, "ARGS_COMBINED_SIZE") == 0)
        {
                l_in_val = a_len;
        }
        else if(strcmp(a_buf, "BOT_SCORE") == 0)
        {
                l_in_val = a_len;
        }
        else
        {
                l_in_val = strntol(a_buf, a_len, &l_end_ptr, 10);
        }
        if((l_in_val == LONG_MAX) ||
           (l_in_val == LONG_MIN))
        {
                return WAFLZ_STATUS_OK;
        }
        if(l_end_ptr == a_buf)
        {
                return WAFLZ_STATUS_OK;
        }
        long int l_op_val;
        l_op_val = strntol(l_val_ref->c_str(), l_val_ref->length(), &l_end_ptr, 10);
        if((l_op_val == LONG_MAX) ||
           (l_op_val == LONG_MIN))
        {
                return WAFLZ_STATUS_OK;
        }
        if(l_end_ptr == l_val_ref->c_str())
        {
                return WAFLZ_STATUS_OK;
        }
        if(l_in_val <= l_op_val)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
OP(CONTAINS)
{
        ao_match = false;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        if(!a_op.has_value())
        {
                return WAFLZ_STATUS_OK;
        }
        const std::string &l_val = a_op.value();
        EXPAND_MACRO(l_val);
        // -------------------------------------------------
        // find
        // -------------------------------------------------
        if(l_val_ref->length() > a_len)
        {
                SET_IF_NEGATED();
                return WAFLZ_STATUS_OK;
        }
        char *l_match = NULL;
        l_match = strnstr(a_buf, l_val_ref->c_str(), a_len);
        if(l_match)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
OP(CONTAINSWORD)
{
        ao_match = false;
        // input can be empty, hence &&
        if(!a_buf &&
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        if(!a_op.has_value())
        {
                return WAFLZ_STATUS_OK;
        }
        const std::string &l_val = a_op.value();
        // Empty param target string always matches
        if(l_val.empty())
        {
                ao_match = true;
                SET_IF_NEGATED();
                return WAFLZ_STATUS_OK;
        }
        EXPAND_MACRO(l_val);
        // If op val (target) length > than the input to look for
        // it cannot contain target word.
        if(l_val_ref->length() > a_len)
        {
                SET_IF_NEGATED();
                return WAFLZ_STATUS_OK;
        }
        const char *l_match = l_val_ref->c_str();
        // Instead of iterating for each char
        // Get max num of iter needed.
        // Worst case it will be the last word
        // So dont have to scan more than the diff b/w two
        int32_t l_max_len = a_len - l_val_ref->length();
        for(int32_t i_m = 0; i_m <= l_max_len; ++i_m)
        {
                //check whether previous char was a alnum
                // if yes, then missing boundary, no match
                if((i_m > 0) && (isalnum(a_buf[i_m -1])))
                {
                        continue;
                }
                // First char of op val does not match
                if(l_match[0] != a_buf[i_m])
                {
                        // Move to next char
                        continue;
                }
                //check if remaining matched
                if((l_val_ref->length() == 1) ||
                    (memcmp((l_match + 1), (a_buf + i_m + 1), l_val_ref->length()-1)) == 0)
                {
                        // check boundaries
                        if(i_m == l_max_len)
                        {
                                ao_match = true;
                                break;
                        }
                        else if(!(isalnum(a_buf[i_m + l_val_ref->length()])))
                        {
                                ao_match = true;
                                break;
                        }
                }
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
OP(BEGINSWITH)
{
        ao_match = false;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        if(!a_op.has_value())
        {
                return WAFLZ_STATUS_OK;
        }
        const std::string &l_val = a_op.value();
        EXPAND_MACRO(l_val);
        // -------------------------------------------------
        // find
        // -------------------------------------------------
        uint32_t l_op_val_len = l_val_ref->length();
        if(l_op_val_len > a_len)
        {
                SET_IF_NEGATED();
                return WAFLZ_STATUS_OK;
        }
        int32_t l_s;
        l_s = memcmp(l_val_ref->c_str(), a_buf, l_op_val_len);
        if(l_s == 0)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
OP(ENDSWITH)
{
        ao_match = false;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        if(!a_op.has_value())
        {
                return WAFLZ_STATUS_OK;
        }
        const std::string &l_val = a_op.value();
        EXPAND_MACRO(l_val);
        // -------------------------------------------------
        // find
        // -------------------------------------------------
        uint32_t l_op_val_len = l_val_ref->length();
        if(l_op_val_len > a_len)
        {
                SET_IF_NEGATED();
                return WAFLZ_STATUS_OK;
        }
        int32_t l_s;
        l_s = memcmp(l_val_ref->c_str(), (a_buf + (a_len - l_op_val_len)), l_op_val_len);
        if(l_s == 0)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: compares the std::string to the char* given
//! \return:  True if the strings are equal. otherwise False
//! \param:   a_looking : the given string
//! \param:   a_hav_data: the string needed to match
//! \param:   a_hav_len : the length of the string needed to match
//! ----------------------------------------------------------------------------
bool _streq(const std::string *a_looking, const char *a_hav_data, uint32_t a_hav_len)
{
        if (a_looking->length() != a_hav_len) { return false; }
        int32_t l_s =
            strncmp(a_looking->c_str(), a_hav_data, a_looking->length());
        return l_s == 0;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
OP(STREQ)
{
        ao_match = false;
        // -------------------------------------------------
        // no string - no match
        // -------------------------------------------------
        if (!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // nothing in op to compare - no match
        // -------------------------------------------------
        if (!a_op.has_value() && a_op.values_size() == 0)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // single value case
        // -------------------------------------------------
        if (a_op.has_value())
        {
                const std::string &l_val = a_op.value();
                EXPAND_MACRO(l_val);
                // -----------------------------------------
                // find
                // -----------------------------------------
                ao_match = _streq(l_val_ref, a_buf, a_len);
                SET_IF_NEGATED();
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // multi-value case
        // -------------------------------------------------
        for ( int32_t index = 0; index < a_op.values_size(); index++ )
        {
                const std::string &l_val = a_op.values(index);
                EXPAND_MACRO(l_val);
                // -----------------------------------------
                // find
                // -----------------------------------------
                ao_match = _streq(l_val_ref, a_buf, a_len);
                if ( ao_match ) { break; }
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
OP(STRMATCH)
{
        ao_match = false;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        if(!a_op.has_value())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // find
        // -------------------------------------------------
        const std::string &l_val = a_op.value();
        if(a_len < l_val.length())
        {
                return WAFLZ_STATUS_OK;
        }
        char *l_match = NULL;
        l_match = strnstr(a_buf, l_val.c_str(), a_len);
        if(l_match)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
OP(WITHIN)
{
        ao_match = false;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        if(!a_op.has_value())
        {
                return WAFLZ_STATUS_OK;
        }
        const std::string &l_val = a_op.value();
        EXPAND_MACRO(l_val);
        // -------------------------------------------------
        // find
        // -------------------------------------------------
        if(!l_val_ref->length())
        {
                return WAFLZ_STATUS_OK;
        }
        char *l_match = NULL;
        l_match = strnstr(l_val_ref->c_str(), a_buf, l_val_ref->length());
        if(l_match)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
OP(IPMATCH)
{
        // NDBG_PRINT("a_op: %s%s%s\n", ANSI_COLOR_FG_GREEN, a_op.ShortDebugString().c_str(), ANSI_COLOR_OFF);
        ao_match = false;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        if(!a_op.has__reserved_1() &&
           a_op._reserved_1())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // ac find
        // -------------------------------------------------
        nms *l_nms = (nms *)(a_op._reserved_1());
        int32_t l_s;
        l_s = l_nms->contains(ao_match, a_buf, a_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO log???
                return WAFLZ_STATUS_ERROR;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
OP(IPMATCHF)
{
        //NDBG_PRINT("a_op: %s%s%s\n", ANSI_COLOR_FG_GREEN, a_op.ShortDebugString().c_str(), ANSI_COLOR_OFF);
        ao_match = false;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        if(!a_op.has__reserved_1() &&
           a_op._reserved_1())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // ac find
        // -------------------------------------------------
        nms *l_nms = (nms *)(a_op._reserved_1());
        int32_t l_s;
        l_s = l_nms->contains(ao_match, a_buf, a_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO log???
                return WAFLZ_STATUS_ERROR;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
OP(IPMATCHFROMFILE)
{
        //NDBG_PRINT("a_op: %s%s%s\n", ANSI_COLOR_FG_GREEN, a_op.ShortDebugString().c_str(), ANSI_COLOR_OFF);
        ao_match = false;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        if(!a_op.has__reserved_1() &&
           a_op._reserved_1())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // ac find
        // -------------------------------------------------
        nms *l_nms = (nms *)(a_op._reserved_1());
        int32_t l_s;
        l_s = l_nms->contains(ao_match, a_buf, a_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO log???
                return WAFLZ_STATUS_ERROR;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: Performs a case-insensitive match of the provided phrases against
//! the desired input value. The operator uses a set-based matching algorithm (Aho-Corasick),
//! which means that it will match any number of keywords in parallel.
//! When matching of a large number of keywords is needed, this operator performs much better than a regular expression.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
OP(PM)
{
        //NDBG_PRINT("a_op: %s%s%s\n", ANSI_COLOR_FG_GREEN, a_op.ShortDebugString().c_str(), ANSI_COLOR_OFF);
        ao_match = false;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        if(!a_op.has__reserved_1() &&
           a_op._reserved_1())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // ac find
        // -------------------------------------------------
        ac *l_ac = (ac *)(a_op._reserved_1());
        bool l_match = false;
        std::string l_match_str;
        const bool l_tolower_applied = check_if_tolower_tx_was_applied(a_ctx, a_res_ctx);
        l_match = l_ac->find_first(a_buf, a_len, l_match_str, l_tolower_applied);
        if (a_ctx)
        {
                a_ctx->m_cx_tx_map["0"] = l_match_str;
        }
        else if(a_res_ctx)
        {
                a_res_ctx->m_cx_tx_map["0"] = l_match_str;
        }
        //NDBG_PRINT("l_tolower_applied - %d\n", l_tolower_applied);
        if(l_match)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
OP(PMF)
{
        //NDBG_PRINT("a_op: %s%s%s\n", ANSI_COLOR_FG_GREEN, a_op.ShortDebugString().c_str(), ANSI_COLOR_OFF);
        ao_match = false;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        if(!a_op.has__reserved_1() &&
           a_op._reserved_1())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // ac find
        // -------------------------------------------------
        ac *l_ac = (ac *)(a_op._reserved_1());
        bool l_match = false;
        std::string l_match_str;
        const bool l_tolower_applied = check_if_tolower_tx_was_applied(a_ctx, a_res_ctx);
        l_match = l_ac->find_first(a_buf, a_len, l_match_str, l_tolower_applied);
        if(a_ctx)
        {
                a_ctx->m_cx_tx_map["0"] = l_match_str;
        }
        else if(a_res_ctx)
        {
                a_res_ctx->m_cx_tx_map["0"] = l_match_str;
        }
        //NDBG_PRINT("l_tolower_applied - %d\n", l_tolower_applied);
        if(l_match)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
OP(PMFROMFILE)
{
        //NDBG_PRINT("a_op: %s%s%s\n", ANSI_COLOR_FG_GREEN, a_op.ShortDebugString().c_str(), ANSI_COLOR_OFF);
        ao_match = false;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        if(!a_op.has__reserved_1() &&
           a_op._reserved_1())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // ac find
        // -------------------------------------------------
        ac *l_ac = (ac *)(a_op._reserved_1());
        bool l_match = false;
        std::string l_match_str;
        const bool l_tolower_applied = check_if_tolower_tx_was_applied(a_ctx, a_res_ctx);
        l_match = l_ac->find_first(a_buf, a_len, l_match_str, l_tolower_applied);
        if(a_ctx)
        {
                a_ctx->m_cx_tx_map["0"] = l_match_str;
        }
        else if(a_res_ctx)
        {
                a_res_ctx->m_cx_tx_map["0"] = l_match_str;
        }
        //NDBG_PRINT("l_tolower_applied - %d\n", l_tolower_applied);
        if(l_match)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
OP(RX)
{
        ao_match = false;
        if(!a_op.has__reserved_1() &&
           a_op._reserved_1())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // regex match...
        // -------------------------------------------------
        regex *l_rx = (regex *)(a_op._reserved_1());
        // -------------------------------------------------
        // check if regex has been compiled..
        // -------------------------------------------------
        if(l_rx == NULL)
        {
                return WAFLZ_STATUS_OK;
        }
        int32_t l_s;
        // -------------------------------------------------
        // get capture
        // -------------------------------------------------
        data_list_t l_data_list;
        std::string l_capture;
        l_s = l_rx->compare_all(a_buf, a_len, &l_data_list);
        if(l_s > 0)
        {
                int l_index = 0;
                // -------------------------------------------------
                // save matches...
                // -------------------------------------------------
                for(data_list_t::iterator i_d = l_data_list.begin();
                    i_d != l_data_list.end();
                    ++i_d)
                {
                        l_capture.assign((*i_d).m_data, (*i_d).m_len);
                        if(a_ctx)
                        {
                                a_ctx->m_cx_tx_map[to_string(l_index)] = l_capture;
                        }
                        else if(a_res_ctx)
                        {
                                a_res_ctx->m_cx_tx_map[to_string(l_index)] = l_capture;
                        }
                       
                        ++l_index;
                }
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
OP(VALIDATEURLENCODING)
{
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // validate encoding...
        // -------------------------------------------------
        uint32_t i_c = 0;
        while(i_c < a_len)
        {
                if (a_buf[i_c] != '%')
                {
                        ++i_c;
                        continue;
                }
                // -----------------------------------------
                // check for length
                // -----------------------------------------
                if((i_c + 2) >= a_len)
                {
                        // ---------------------------------
                        // invalid url encoding:
                        // not enough chars
                        // ---------------------------------
                        ao_match = true;
                        return WAFLZ_STATUS_OK;
                }
                // -----------------------------------------
                // decode a %xx combination if it is valid
                // -----------------------------------------
                char l_c1 = a_buf[i_c + 1];
                char l_c2 = a_buf[i_c + 2];
                if(!VALID_HEX(l_c1) ||
                   !VALID_HEX(l_c2))
                {
                        // ---------------------------------
                        // invalid url encoding:
                        // non-hex char used in encoding.
                        // ---------------------------------
                        ao_match = true;
                        return WAFLZ_STATUS_OK;
                }
                i_c += 3;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
OP(VALIDATEBYTERANGE)
{
        //NDBG_PRINT("a_op: %s%s%s\n", ANSI_COLOR_FG_GREEN, a_op.ShortDebugString().c_str(), ANSI_COLOR_OFF);
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        if(!a_op.has__reserved_1() &&
           a_op._reserved_1())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // byte range check
        // -------------------------------------------------
        ao_match = false;
        byte_range *l_br = (byte_range *)(a_op._reserved_1());
        bool l_is_in = false;
        l_is_in = l_br->is_within(a_buf, a_len);
        if(!l_is_in)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
OP(VALIDATEUTF8ENCODING)
{
        //NDBG_PRINT("a_op: %s%s%s\n", ANSI_COLOR_FG_GREEN, a_op.ShortDebugString().c_str(), ANSI_COLOR_OFF);
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        ao_match = false;
        // -------------------------------------------------
        // utf8 encoding check
        // -------------------------------------------------
        bool l_valid = true;
        const char *l_err = NULL;
        uint32_t l_err_off = 0;
        int32_t l_s;
        l_s = validate_utf8(l_valid, &l_err, l_err_off, a_buf, a_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        if(!l_valid)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
OP(VERIFYCC)
{
        ao_match = false;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        if(!a_op.has__reserved_1() &&
           a_op._reserved_1())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // regex match...
        // -------------------------------------------------
        regex *l_rx = (regex *)(a_op._reserved_1());
        // -------------------------------------------------
        // check if regex has been compiled..
        // -------------------------------------------------
        if(l_rx == NULL)
        {
                return WAFLZ_STATUS_OK;
        }
        int32_t l_s;
        // get capture
        data_list_t l_data_list;
        std::string l_match_str;
        l_s = l_rx->compare(a_buf, a_len, &l_match_str);
        // -------------------------------------------------
        // if not match -done...
        // -------------------------------------------------
        if(l_s <= 0)
        {
                SET_IF_NEGATED();
                return WAFLZ_STATUS_OK;
        }
        bool l_cc_valid = false;
        //NDBG_PRINT("CC: check string: %s\n", l_match_str.c_str());
        l_cc_valid = luhn_validate(l_match_str.c_str(), l_match_str.length());
        // -------------------------------------------------
        // if match store result in TX:1
        // modsecurity behavior...
        // -------------------------------------------------
        if(l_cc_valid)
        {
                if(a_ctx)
                {
                        a_ctx->m_cx_tx_map["1"] = l_match_str;
                        ao_match = true;
                }
                else if(a_res_ctx)
                {
                        a_res_ctx->m_cx_tx_map["1"] = l_match_str;
                        ao_match = true;
                }
        }
        //NDBG_PRINT("CC: check status: %d\n", l_cc_valid);
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
OP(DETECTSQLI)
{
        ao_match = false;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        char l_fprnt[8];
        int32_t l_match = 0;
        l_match = libinjection_sqli(a_buf, a_len, l_fprnt, sizeof(l_fprnt));
        if(l_match)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
OP(DETECTXSS)
{
        ao_match = false;
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        int32_t l_match = 0;
        l_match = libinjection_xss(a_buf, a_len);
        if(l_match)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
#define INIT_OP_CB(_type) \
        s_op_cb_vector[waflz_pb::sec_rule_t_operator_t_type_t_##_type] = _op_cb_##_type

//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef std::vector <op_t> op_cb_vector_t;
//! ----------------------------------------------------------------------------
//! vector...
//! ----------------------------------------------------------------------------
static op_cb_vector_t s_op_cb_vector = op_cb_vector_t(1024);
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
void init_op_cb_vector(void)
{
        INIT_OP_CB(BEGINSWITH);
        INIT_OP_CB(CONTAINS);
        INIT_OP_CB(CONTAINSWORD);
        INIT_OP_CB(DETECTSQLI);
        INIT_OP_CB(DETECTXSS);
        INIT_OP_CB(ENDSWITH);
        INIT_OP_CB(EQ);
        INIT_OP_CB(GE);
        INIT_OP_CB(GT);
        INIT_OP_CB(LT);
        INIT_OP_CB(LE);
        INIT_OP_CB(IPMATCH);
        INIT_OP_CB(IPMATCHF);
        INIT_OP_CB(IPMATCHFROMFILE);
        INIT_OP_CB(PM);
        INIT_OP_CB(PMF);
        INIT_OP_CB(PMFROMFILE);
        INIT_OP_CB(RX);
        INIT_OP_CB(STREQ);
        INIT_OP_CB(STRMATCH);
        INIT_OP_CB(VERIFYCC);
        INIT_OP_CB(VALIDATEBYTERANGE);
        INIT_OP_CB(VALIDATEUTF8ENCODING);
        INIT_OP_CB(VALIDATEURLENCODING);
        INIT_OP_CB(WITHIN);
};
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
op_t get_op_cb(waflz_pb::sec_rule_t_operator_t_type_t a_type)
{
        return s_op_cb_vector[a_type];
}
}
