//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: uri encode and decode
//!           based on: RFC1630, RFC1738, RFC2396
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include "waflz/def.h"
#include "waflz/string_util.h"
#include "core/decode.h"
#include "support/ndebug.h"
#include <string>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
#define VALID_HEX(X) \
        (((X >= '0') && (X <= '9')) || \
         ((X >= 'a') && (X <= 'f')) || \
         ((X >= 'A') && (X <= 'F')))
namespace ns_waflz {
typedef std::list<data_t> data_list_t;
//! ----------------------------------------------------------------------------
//! statics
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: Converts a byte given as its hexadecimal representation into a
//!           proper byte. Handles uppercase and lowercase letters but does not
//!           check for overflows.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static unsigned char x2c(const unsigned char *a_nbl)
{
        unsigned char l_c;
        l_c =  ((a_nbl[0] >= 'A') ?
                                   (((a_nbl[0] & 0xdf) - 'A') + 10) :
                                   (a_nbl[0] - '0'));
        l_c *= 16;
        l_c += ((a_nbl[1] >= 'A') ?
                                   (((a_nbl[1] & 0xdf) - 'A') + 10) :
                                   (a_nbl[1] - '0'));
        return l_c;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t css_decode(char **ao_buf,
                   uint32_t &ao_len,
                   const char *a_buf,
                   uint32_t a_len)
{
        // -------------------------------------------------
        // macro to convert hex to char
        // -------------------------------------------------
#define _X2C(_buf) (_buf[0] >= 'A' ? ((_buf[0] & 0xdf) - 'A') + 10 : (_buf[0] - '0'))
        // -------------------------------------------------
        // check exist
        // -------------------------------------------------
        if(!a_buf ||
           !a_len)
        {
                // TODO -log reason???
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // make copy
        // -------------------------------------------------
        uint32_t i_c = 0;
        uint32_t l_count = 0;
        char *l_buf = (char *)malloc(sizeof(char)*a_len + 1);
        memcpy(l_buf, a_buf, a_len);
        l_buf[a_len] = '\0';
        unsigned char *l_d = (unsigned char *)l_buf;
        // -------------------------------------------------
        // for each char...
        // -------------------------------------------------
        while(i_c < a_len)
        {
                // -----------------------------------------
                // not backslash
                // -----------------------------------------
                if(a_buf[i_c] != '\\')
                {
                        // copy/incr
                        *l_d = a_buf[i_c];
                        ++l_d;
                        ++i_c;
                        ++l_count;
                        continue;
                }
                // -----------------------------------------
                // less than one more byte...
                // -----------------------------------------
                if((i_c + 1) >= a_len)
                {
                        ++i_c;
                        continue;
                }
                // -----------------------------------------
                // move past backslash
                // -----------------------------------------
                ++i_c;
                // -----------------------------------------
                // check for 1-6 hex characters following
                // backslash
                // -----------------------------------------
                uint32_t i_j = 0;
                while((i_j < 6) &&
                      ((i_c + i_j) < a_len) &&
                      (VALID_HEX(a_buf[i_c + i_j])))
                {
                        ++i_j;
                }
                // -----------------------------------------
                // no valid hex???
                // -----------------------------------------
                if(i_j <= 0)
                {
                        // newline after backslash ignored
                        if(a_buf[i_c] == '\n')
                        {
                                ++i_c;
                                continue;
                        }
                        // copy/incr
                        *l_d = a_buf[i_c];
                        ++l_d;
                        ++i_c;
                        ++l_count;
                        continue;
                }
                // -----------------------------------------
                // inspect
                // -----------------------------------------
                bool l_do_full_width_check = false;
                switch (i_j) {
                // -----------------------------------------
                // 1 char
                // -----------------------------------------
                case 1:
                {
                        *l_d = _X2C((&a_buf[i_c]));
                        ++l_d;
                        break;
                }
                // -----------------------------------------
                // 2/3 char
                // -----------------------------------------
                case 2:
                case 3:
                {
                        // last two from end...
                        *l_d = x2c((const unsigned char *)(&a_buf[i_c + i_j - 2]));
                        ++l_d;
                        break;
                }
                // -----------------------------------------
                // 4 char
                // -----------------------------------------
                case 4:
                {
                        // last two from end
                        // do full width check
                        *l_d = x2c((const unsigned char *)(&a_buf[i_c + i_j - 2]));
                        l_do_full_width_check = true;
                        break;
                }
                // -----------------------------------------
                // 5 char
                // -----------------------------------------
                case 5:
                {
                        // ---------------------------------
                        // last two from end
                        // do full width check if
                        // num >= 0xFFFF
                        // ---------------------------------
                        *l_d = x2c((const unsigned char *)(&a_buf[i_c + i_j - 2]));
                        // do full width check if first byte is 0
                        if(a_buf[i_c] == '0')
                        {
                                l_do_full_width_check = true;
                        }
                        else
                        {
                                ++l_d;
                        }
                        break;
                }
                // -----------------------------------------
                // 6 char
                // -----------------------------------------
                case 6:
                {
                        // ---------------------------------
                        // last two from end
                        // do full width check if
                        // num >= 0xFFFF
                        // ---------------------------------
                        *l_d = x2c((const unsigned char *)(&a_buf[i_c + i_j - 2]));
                        // ---------------------------------
                        // do full width check if first AND
                        // second byte is 0
                        // ---------------------------------
                        if((a_buf[i_c]     == '0') &&
                           (a_buf[i_c + 1] == '0'))
                        {
                                l_do_full_width_check = true;
                        }
                        else
                        {
                                ++l_d;
                        }
                        break;
                }
                // -----------------------------------------
                // 1 char
                // -----------------------------------------
                default:
                {
                        // nothing...
                }
                }
                // -----------------------------------------
                // full width ASCII
                // (0xff01 - 0xff5e)
                // needs 0x20 added
                // -----------------------------------------
                if(l_do_full_width_check)
                {
                        char l_c1 = a_buf[i_c + i_j - 3];
                        char l_c2 = a_buf[i_c + i_j - 4];
                        if((*l_d > 0x00) &&
                           (*l_d < 0x5f) &&
                           ((l_c1 == 'f') ||
                            (l_c1 == 'F')) &&
                           ((l_c2 == 'f') ||
                            (l_c2 == 'F')))
                        {
                                (*l_d) += 0x20;
                        }
                        ++l_d;
                }
                // -----------------------------------------
                // ignore a single whitespace after a hex escape
                // -----------------------------------------
                if(((i_c + i_j) < a_len) &&
                   isspace(a_buf[i_c + i_j]))
                {
                        ++i_j;
                }
                ++l_count;
                i_c += i_j;
        }
        // -------------------------------------------------
        // terminate...
        // -------------------------------------------------
        *l_d = '\0';
        // -------------------------------------------------
        // l_done...
        // -------------------------------------------------
        *ao_buf = l_buf;
        ao_len = l_count;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t html_entity_decode(char **ao_buf,
                           uint32_t &ao_len,
                           const char *a_buf,
                           uint32_t a_len)
{
        // -------------------------------------------------
        // check exist
        // -------------------------------------------------
        if(!a_buf ||
           !a_len)
        {
                // TODO -log reason???
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // make copy
        // -------------------------------------------------
        uint32_t i_c = 0;
        uint32_t l_count = 0;
        char *l_buf = (char *)malloc(sizeof(char)*a_len + 1);
        memcpy(l_buf, a_buf, a_len);
        l_buf[a_len] = '\0';
        unsigned char *l_d = (unsigned char *)l_buf;
        // -------------------------------------------------
        // for each char...
        // -------------------------------------------------
        while((i_c < a_len) &&
              (l_count < a_len))
        {
                uint32_t l_copy = 1;
                uint32_t i_k;
                uint32_t i_j = i_c + 1;
                // -----------------------------------------
                // require an ampersand and at least one
                // char to start looking into the entity.
                // -----------------------------------------
                if((a_buf[i_c] != '&') ||
                   ((i_c + 1) >= a_len))
                {
                        goto HTML_ENT_OUT;
                }
                // -----------------------------------------
                // numerical entity
                // -----------------------------------------
                if (a_buf[i_j] == '#')
                {
                        ++l_copy;
                        // not enough bytes...
                        if((i_j + 1) >= a_len)
                        {
                                goto HTML_ENT_OUT;
                        }
                        ++i_j;
                        // ---------------------------------
                        // hexadecimal entity
                        // ---------------------------------
                        if((a_buf[i_j] == 'x') ||
                           (a_buf[i_j] == 'X'))
                        {
                                ++l_copy;
                                // not enough bytes...
                                if((i_j + 1) >= a_len)
                                {
                                        goto HTML_ENT_OUT;
                                }
                                // i_j is position of first digit now
                                ++i_j;
                                i_k = i_j;
                                // -------------------------
                                // count digits
                                // -------------------------
                                while((i_j < a_len) &&
                                      (isxdigit(a_buf[i_j])))
                                {
                                        ++i_j;
                                }
                                // -------------------------
                                // at least one digit???
                                // -------------------------
                                if (i_j <= i_k)
                                {
                                        goto HTML_ENT_OUT;
                                }
                                // -------------------------
                                // decode the entity
                                // -------------------------
                                const char *i_buf = &(a_buf[i_k]);
                                uint32_t i_len = i_j - i_k;
                                *l_d = (unsigned char)strntol(i_buf, i_len, NULL, 16);
                                ++l_d;
                                ++l_count;
                                // -------------------------
                                // skip over semicolon
                                // -------------------------
                                if((i_j < a_len) &&
                                   (a_buf[i_j] == ';'))
                                {
                                        i_c = i_j + 1;
                                }
                                else
                                {
                                        i_c = i_j;
                                }
                                continue;
                        }
                        // ---------------------------------
                        // decimal entity
                        // ---------------------------------
                        else
                        {
                                i_k = i_j;
                                // -------------------------
                                // count digits
                                // -------------------------
                                while((i_j < a_len) &&
                                      (isxdigit(a_buf[i_j])))
                                {
                                        ++i_j;
                                }
                                // -------------------------
                                // at least one digit???
                                // -------------------------
                                if (i_j <= i_k)
                                {
                                        goto HTML_ENT_OUT;
                                }
                                // -------------------------
                                // decode the entity
                                // -------------------------
                                const char *i_buf = &(a_buf[i_k]);
                                uint32_t i_len = i_j - i_k;
                                *l_d = (unsigned char)strntol(i_buf, i_len, NULL, 10);
                                ++l_d;
                                ++l_count;
                                // -------------------------
                                // skip over semicolon
                                // -------------------------
                                if((i_j < a_len) &&
                                   (a_buf[i_j] == ';'))
                                {
                                        i_c = i_j + 1;
                                }
                                else
                                {
                                        i_c = i_j;
                                }
                                continue;
                        }
                }
                // -----------------------------------------
                // text entity
                // -----------------------------------------
                else
                {
                        // ---------------------------------
                        // count digits
                        // ---------------------------------
                        i_k = i_j;
                        while((i_j < a_len) &&
                              (isalnum(a_buf[i_j])))
                        {
                                ++i_j;
                        }
                        // ---------------------------------
                        // at least one digit?
                        // ---------------------------------
                        if(i_j <= i_k)
                        {
                                goto HTML_ENT_OUT;
                        }
                        // ---------------------------------
                        // decode entity
                        // ---------------------------------
                        const char *i_buf = &(a_buf[i_k]);
                        uint32_t i_len = i_j - i_k;
                        if(0) {}
#define _NBSP 160
#define _GET_DECODE(_str,_char) \
        else if(strncasecmp(i_buf, _str, i_len) == 0)\
        {\
                *l_d = _char;\
                ++l_d;\
        }
                        _GET_DECODE("quot", '"')
                        _GET_DECODE("amp",  '&')
                        _GET_DECODE("lt",   '<')
                        _GET_DECODE("gt",   '>')
                        _GET_DECODE("nbsp", _NBSP)
                        // ---------------------------------
                        // do no want to convert this entity
                        // copy the raw data over.
                        // ---------------------------------
                        else
                        {
                                l_copy = i_j - i_k + 1;
                                goto HTML_ENT_OUT;
                        }
                        ++l_count;
                        // -------------------------
                        // skip over semicolon
                        // -------------------------
                        if((i_j < a_len) &&
                           (a_buf[i_j] == ';'))
                        {
                                i_c = i_j + 1;
                        }
                        else
                        {
                                i_c = i_j;
                        }
                        continue;
                }
HTML_ENT_OUT:
                // -----------------------------------------
                // copy bytes
                // -----------------------------------------
                for(uint32_t i_z = 0;
                    ((i_z < l_copy) && (l_count < a_len));
                    ++i_z)
                {
                        // copy/incr
                        *l_d = a_buf[i_c];
                        ++l_d;
                        ++i_c;
                        ++l_count;
                }
        }
        // -------------------------------------------------
        // terminate...
        // -------------------------------------------------
        *l_d = '\0';
        // -------------------------------------------------
        // l_done...
        // -------------------------------------------------
        *ao_buf = l_buf;
        ao_len = l_count;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t js_decode_ns(char **ao_buf,
                     uint32_t &ao_len,
                     const char *a_buf,
                     uint32_t a_len)
{
        // -------------------------------------------------
        // macro
        // -------------------------------------------------
#define _ISODIGIT(X) ((X >= '0')&&(X <= '7'))
        // -------------------------------------------------
        // check exist
        // -------------------------------------------------
        if(!a_buf ||
           !a_len)
        {
                // TODO -log reason???
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // make copy
        // -------------------------------------------------
        uint32_t i_c = 0;
        uint32_t l_count = 0;
        char *l_buf = (char *)malloc(sizeof(char)*a_len + 1);
        memcpy(l_buf, a_buf, a_len);
        l_buf[a_len] = '\0';
        unsigned char *l_d = (unsigned char *)l_buf;
        // -------------------------------------------------
        // for each char...
        // -------------------------------------------------
        while(i_c < a_len)
        {
                // -----------------------------------------
                // character not escape...
                // -----------------------------------------
                if(a_buf[i_c] != '\\')
                {
                        // copy/incr
                        *l_d = a_buf[i_c];
                        ++l_d;
                        ++i_c;
                        ++l_count;
                        continue;
                }
                // -----------------------------------------
                // \uHHHH
                // -----------------------------------------
                if((i_c + 5 < a_len) &&
                   (a_buf[i_c + 1] == 'u') &&
                   (VALID_HEX(a_buf[i_c + 2])) &&
                   (VALID_HEX(a_buf[i_c + 3])) &&
                   (VALID_HEX(a_buf[i_c + 4])) &&
                   (VALID_HEX(a_buf[i_c + 5])) )
                {
                        // use only lower byte.
                        *l_d = x2c((unsigned char *)&(a_buf[i_c + 4]));
                        // ---------------------------------
                        // full width ASCII
                        // (ff01 - ff5e)
                        // needs 0x20 added
                        // ---------------------------------
                        char l_c1 = a_buf[i_c + 2];
                        char l_c2 = a_buf[i_c + 3];
                        if((*l_d > 0x00) &&
                           (*l_d < 0x5f) &&
                           ((l_c1 == 'f') ||
                            (l_c1 == 'F')) &&
                           ((l_c2 == 'f') ||
                            (l_c2 == 'F')))
                        {
                                (*l_d) += 0x20;
                        }
                        ++l_d;
                        ++l_count;
                        i_c += 6;
                }
                // -----------------------------------------
                // \xHH
                // -----------------------------------------
                else if((i_c + 3 < a_len) &&
                        (a_buf[i_c + 1] == 'x') &&
                        VALID_HEX(a_buf[i_c + 2]) &&
                        VALID_HEX(a_buf[i_c + 3]))
                {
                        *l_d = x2c((unsigned char *)&(a_buf[i_c + 2]));
                        ++l_d;
                        ++l_count;
                        i_c += 4;
                }
                // -----------------------------------------
                // \OOO (only one byte, \000 - \377)
                // -----------------------------------------
                else if((i_c + 1 < a_len) &&
                        _ISODIGIT(a_buf[i_c + 1]))
                {
                        char i_buf[4];
                        uint16_t i_j = 0;
                        while(((i_c + 1 + i_j) < a_len) &&
                               (i_j < 3))
                        {
                                i_buf[i_j] = a_buf[i_c + 1 + i_j];
                                ++i_j;
                                if(!_ISODIGIT(a_buf[i_c + 1 + i_j]))
                                {
                                        break;
                                }
                        }
                        i_buf[i_j] = '\0';
                        if(i_j > 0)
                        {
                                /* Do not use 3 characters if we will be > 1 byte */
                                if((i_j == 3) &&
                                  (i_buf[0] > '3'))
                                {
                                        i_j = 2;
                                        i_buf[i_j] = '\0';
                                }
                                *l_d = (unsigned char)strtol(i_buf, NULL, 8);
                                ++l_d;
                                i_c += 1 + i_j;
                                ++l_count;
                        }
                }
                // -----------------------------------------
                // ???
                // -----------------------------------------
                else if(i_c + 1 < a_len)
                {
#define _SET_ESC(_a, _xa) \
        case _a: \
        { \
                l_c = _xa;\
                break;\
        }
                        unsigned char l_c;
                        switch(a_buf[i_c + 1])
                        {
                        _SET_ESC('a','\a')
                        _SET_ESC('b','\b')
                        _SET_ESC('f','\f')
                        _SET_ESC('n','\n')
                        _SET_ESC('r','\r')
                        _SET_ESC('t','\t')
                        _SET_ESC('v','\v')
                        // ---------------------------------
                        // remaining (\?,\\,\',\") are removal
                        // ---------------------------------
                        default:
                        {
                                l_c = a_buf[i_c + 1];
                                break;
                        }
                        }
                        *l_d = l_c;
                        ++l_d;
                        i_c += 2;
                        ++l_count;
                }
                // -----------------------------------------
                // no enough bytes
                // -----------------------------------------
                else
                {
                        while(i_c < a_len)
                        {
                                // copy/incr
                                *l_d = a_buf[i_c];
                                ++l_d;
                                ++i_c;
                                ++l_count;
                        }
                }
        }
        // -------------------------------------------------
        // terminate...
        // -------------------------------------------------
        *l_d = '\0';
        // -------------------------------------------------
        // l_done...
        // -------------------------------------------------
        *ao_buf = l_buf;
        ao_len = l_count;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! \notes:   IMP1 Assumes NUL-terminated.
//! ----------------------------------------------------------------------------
int32_t normalize_path(char **ao_buf,
                       uint32_t &ao_len,
                       const char *a_buf,
                       uint32_t a_len,
                       bool a_is_windows)
{
        // -------------------------------------------------
        // check exist
        // -------------------------------------------------
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // dup
        // -------------------------------------------------
        char *l_buf = NULL;
        l_buf = strndup(a_buf, a_len);
        // -------------------------------------------------
        // calc new length
        // -------------------------------------------------
        uint32_t l_buf_len = a_len;
        l_buf_len = strnlen(l_buf, a_len);
        if(!l_buf ||
           !l_buf_len)
        {
                *ao_buf = NULL;
                ao_len = 0;
                if(l_buf) { free(l_buf); l_buf = NULL; }
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // set vars
        // -------------------------------------------------
        bool l_done = false;
        bool l_root = false;
        char *l_src = l_buf;
        char *l_dst = l_buf;
        const char *l_end = l_buf + (l_buf_len - 1);
        bool l_relative = ((l_buf[0] == '/') ||
                          (a_is_windows && (l_buf[0] == '\\'))) ? false : true;
        bool l_trailing = ((l_end[0] == '/') ||
                          (a_is_windows && (l_end[0] == '\\'))) ? true : false;
        // -------------------------------------------------
        // for each char...
        // -------------------------------------------------
        while(!l_done &&
              (l_src <= l_end) &&
              (l_dst <= l_end))
        {
                 // -----------------------------------------
                // convert backslash to fwd slash on Windows
                // -----------------------------------------
                if(a_is_windows)
                {
                        if(*l_src == '\\')
                        {
                                *l_src = '/';
                        }
                        if((l_src < l_end) &&
                           (*(l_src + 1) == '\\'))
                        {
                                *(l_src + 1) = '/';
                        }
                }
                // -----------------------------------------
                // always normalize end of input
                // -----------------------------------------
                if(l_src == l_end)
                {
                        l_done = true;
                }
                // -----------------------------------------
                // Skip normalization if NOT end of path
                // segment.
                // -----------------------------------------
                else if(l_src[1] != '/')
                {
                        goto copy;
                }
                // -----------------------------------------
                // *****************************************
                //        normalize path segment
                // *****************************************
                // -----------------------------------------
                // -----------------------------------------
                // empty path segment?
                // -----------------------------------------
                if((l_src != l_end) &&
                   (l_src[0] == '/'))
                {
                        goto copy;
                }
                // -----------------------------------------
                // back or self reference?
                // -----------------------------------------
                else if(l_src[0] == '.')
                {
                        // ---------------------------------
                        // back-reference?
                        // ---------------------------------
                        if((l_dst > l_buf) &&
                           (*(l_dst - 1) == '.'))
                        {
                                // -------------------------
                                // if relative path and or
                                // normal form already at
                                // root, or if backref with
                                // no prev path, mark as
                                // root and copy backref
                                // -------------------------
                                if(l_relative &&
                                   (l_root || ((l_dst - 2) <= l_buf)))
                                {
                                        l_root = true;
                                        goto copy;
                                }
                                // -------------------------
                                // remove backref and prev
                                // path segment
                                // -------------------------
                                l_dst -= 3;
                                while((l_dst > l_buf) &&
                                      (l_dst[0] != '/'))
                                {
                                        l_dst--;
                                }
                                // -------------------------
                                // prevent going above root
                                // dir
                                // -------------------------
                                if(l_dst <= l_buf)
                                {
                                        l_root = true;
                                        l_dst = l_buf;
                                        // -----------------
                                        // leave root / if
                                        // no relative and
                                        // end on backref
                                        // -----------------
                                        if(!l_relative &&
                                           (l_src == l_end))
                                        {
                                                l_dst++;
                                        }
                                }
                                if(l_done) { continue; }
                                l_src++;
                        }
                        // ---------------------------------
                        // relative self-reference?
                        // ---------------------------------
                        else if(l_dst == l_buf)
                        {
                                if(l_done) { continue; }
                                l_src++;
                        }
                        // ---------------------------------
                        // self-reference?
                        // ---------------------------------
                        else if(*(l_dst - 1) == '/')
                        {
                                if(l_done) { continue; }
                                l_dst--;
                                l_src++;
                        }
                }
                // -----------------------------------------
                // found a regular path segment.
                // -----------------------------------------
                else if(l_dst > l_buf)
                {
                        l_root = true;
                }
copy:
                // -----------------------------------------
                // *****************************************
                //        copy the byte if required
                // *****************************************
                // -----------------------------------------
                // -----------------------------------------
                // skip to last fwd slash if multiple used.
                // -----------------------------------------
                if(l_src[0] == '/')
                {
                        while((l_src < l_end) &&
                              ((l_src[1] == '/') ||
                              (a_is_windows && (l_src[1] == '\\'))))
                        {
                                ++l_src;
                        }
                        // ---------------------------------
                        // Do not copy forward slash to root
                        // if not elative path.
                        // Move slash to next segment.
                        // ---------------------------------
                        if(l_relative &&
                          (l_dst == l_buf))
                        {
                                ++l_src;
                                continue;
                        }
                }
                l_dst[0] = l_src[0];
                ++l_dst;
                ++l_src;
        }
        // -------------------------------------------------
        // ensure no trailing slash in normalized form if
        // none in original form.
        // -------------------------------------------------
        if(!l_trailing &&
           (l_dst > l_buf) &&
           (*(l_dst - 1) == '/'))
        {
                --l_dst;
        }
        // -------------------------------------------------
        // NULL terminate
        // -------------------------------------------------
        l_dst[0] = '\0';
        // -------------------------------------------------
        // l_done...
        // -------------------------------------------------
        *ao_buf = l_buf;
        ao_len = strnlen(l_buf, l_buf_len);
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: url decode -non strict ???
//! \return:  TODO
//! \param:   TODO
//! \notes:   IMP1 Assumes NUL-terminated
//! ----------------------------------------------------------------------------
int32_t urldecode_ns(char **ao_buf,
                     uint32_t &ao_len,
                     uint32_t &ao_invalid_count,
                     const char *a_buf,
                     uint32_t a_len)
{
        // -------------------------------------------------
        // check exist
        // -------------------------------------------------
        if(!a_buf ||
           !a_len)
        {
                // TODO -log reason???
                return WAFLZ_STATUS_ERROR;
        }
        uint32_t i_char = 0;
        uint32_t l_count = 0;
        char *l_buf = (char *)malloc(sizeof(char)*a_len + 1);
        memcpy(l_buf, a_buf, a_len);
        l_buf[a_len] = '\0';;
        char *l_d = (char *)l_buf;
        while(i_char < a_len)
        {
                // -----------------------------------------
                // encoding...
                // -----------------------------------------
                if(l_buf[i_char] == '%')
                {
                        // ---------------------------------
                        // enough bytes available???
                        // ---------------------------------
                        if(i_char + 2 < a_len)
                        {
                                char l_c1 = l_buf[i_char + 1];
                                char l_c2 = l_buf[i_char + 2];
                                if(VALID_HEX(l_c1) &&
                                   VALID_HEX(l_c2))
                                {
                                        // Valid encoding - decode it.
                                        *l_d = x2c((unsigned char *)(&l_buf[i_char + 1]));
                                        ++l_d;
                                        ++l_count;
                                        i_char += 3;
                                }
                                else
                                {
                                        // Not a valid encoding, skip this %
                                        *l_d = l_buf[i_char];
                                        ++l_d;
                                        ++i_char;
                                        ++l_count;
                                        ++ao_invalid_count;
                                }
                        }
                        // ---------------------------------
                        // not enough bytes available, copy
                        // raw bytes.
                        // ---------------------------------
                        else
                        {
                                // Not enough bytes available, copy the raw bytes.
                                *l_d = l_buf[i_char];
                                ++l_d;
                                ++i_char;
                                ++l_count;
                                ++ao_invalid_count;
                        }
                }
                // -----------------------------------------
                // not encoding maker
                // -----------------------------------------
                else
                {
                        if(l_buf[i_char] == '+')
                        {
                                *l_d = ' ';
                        }
                        else
                        {
                                *l_d = l_buf[i_char];
                        }
                        ++l_d;
                        ++i_char;
                        ++l_count;
                }
        }
        // -------------------------------------------------
        // terminate...
        // -------------------------------------------------
        *l_d = '\0';
        // -------------------------------------------------
        // done...
        // -------------------------------------------------
        ao_len = l_count;
        *ao_buf = l_buf;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: load unicode map file...
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
#if 0
#define CODEPAGE_SEPARATORS  " \t\n\r"
static int unicode_map_create(directory_config *dcfg, char **error_msg)
{
        char errstr[1024];
        apr_pool_t *mp = dcfg->mp;
        unicode_map *u_map = dcfg->u_map;
        apr_int32_t wanted = APR_FINFO_SIZE;
        apr_finfo_t finfo;
        apr_status_t rc;
        apr_size_t nbytes;
        unsigned int codepage = 0;
        char *buf = NULL, *p = NULL, *savedptr = NULL;
        char *ucode = NULL, *hmap = NULL;
        int found = 0, processing = 0;
        int Code = 0, Map = 0;
        if(unicode_map_table != NULL)
        {
                free(unicode_map_table);
                unicode_map_table = NULL;
        }
        if ((rc = apr_file_open(&u_map->map, u_map->mapfn, APR_READ, APR_OS_DEFAULT, mp)) != APR_SUCCESS)
        {
                *error_msg = apr_psprintf(mp, "Could not open unicode map file \"%s\": %s", u_map->mapfn, apr_strerror(rc, errstr, 1024));
                return 0;
        }
        if ((rc = apr_file_info_get(&finfo, wanted, u_map->map)) != APR_SUCCESS)
        {
                *error_msg = apr_psprintf(mp, "Could not cannot get unicode map file information \"%s\": %s", u_map->mapfn, apr_strerror(rc, errstr, 1024));
                apr_file_close(u_map->map);
                return 0;
        }
        buf = (char *)malloc(finfo.size+1);
        if (buf == NULL)
        {
                *error_msg = apr_psprintf(mp, "Could not alloc memory for unicode map");
                apr_file_close(u_map->map);
                return 0;
        }
        rc = apr_file_read_full(u_map->map, buf, finfo.size, &nbytes);
        if (unicode_map_table != NULL)
        {
                memset(unicode_map_table, -1, (sizeof(int)*65536));
        } else
        {
                unicode_map_table = (int *)malloc(sizeof(int) * 65536);
                if(unicode_map_table == NULL)
                {
                        *error_msg = apr_psprintf(mp, "Could not alloc memory for unicode map");
                        free(buf);
                        buf = NULL;
                        apr_file_close(u_map->map);
                        return 0;
                }
                memset(unicode_map_table, -1, (sizeof(int)*65536));
        }
        /* Setting some unicode values - http://tools.ietf.org/html/rfc3490#section-3.1 */
        /* Set 0x3002 -> 0x2e */
        unicode_map_table[0x3002] = 0x2e;
        /* Set 0xFF61 -> 0x2e */
        unicode_map_table[0xff61] = 0x2e;
        /* Set 0xFF0E -> 0x2e */
        unicode_map_table[0xff0e] = 0x2e;
        /* Set 0x002E -> 0x2e */
        unicode_map_table[0x002e] = 0x2e;
        p = apr_strtok(buf,CODEPAGE_SEPARATORS,&savedptr);
        while (p != NULL)
        {
                codepage = atol(p);
                if (codepage == unicode_codepage)
                {
                        found = 1;
                }
                if (found == 1 && (strchr(p,':') != NULL))
                {
                        char *mapping = strdup(p);
                        processing = 1;
                        if(mapping != NULL)
                        {
                                ucode = apr_strtok(mapping,":", &hmap);
                                sscanf(ucode,"%x",&Code);
                                sscanf(hmap,"%x",&Map);
                                if(Code >= 0 && Code <= 65535)
                                {
                                        unicode_map_table[Code] = Map;
                                }
                                free(mapping);
                                mapping = NULL;
                        }
                }
                if (processing == 1 && (strchr(p,':') == NULL))
                {
                        free(buf);
                        buf = NULL;
                        break;
                }
                p = apr_strtok(NULL,CODEPAGE_SEPARATORS,&savedptr);
        }
        apr_file_close(u_map->map);
        if(buf)
        {
                free(buf);
                buf = NULL;
        }
        return 1;
}
#endif
//! ----------------------------------------------------------------------------
//! \details: url decode -non strict ???
//! \return:  TODO
//! \param:   TODO
//! \notes:   IMP1 Assumes NUL-terminated
//! ----------------------------------------------------------------------------
int32_t urldecode_uni_ns(char **ao_buf, uint32_t &ao_len, const char *a_buf, uint32_t a_len)
{
        // -------------------------------------------------
        // check exist
        // -------------------------------------------------
        if(!a_buf ||
           !a_len)
        {
                // TODO -log reason???
                return WAFLZ_STATUS_ERROR;
        }
#define _SET_AND_SKIP() do { \
        *l_d = a_buf[i_c]; \
        ++i_c; \
        ++l_d; \
        ++l_count;\
} while(0)
        // -------------------------------------------------
        // make copy
        // -------------------------------------------------
        uint32_t i_c = 0;
        uint32_t l_count = 0;
        char *l_buf = (char *)malloc(sizeof(char)*a_len + 1);
        memcpy(l_buf, a_buf, a_len);
        l_buf[a_len] = '\0';
        unsigned char *l_d = (unsigned char *)l_buf;
        // -------------------------------------------------
        // for each char...
        // -------------------------------------------------
        while(i_c < a_len)
        {
                // -----------------------------------------
                // not a percent sign...
                // -----------------------------------------
                if(a_buf[i_c] != '%')
                {
                        if(a_buf[i_c] == '+')
                        {
                                *l_d = ' ';
                        } else
                        {
                                *l_d = l_buf[i_c];
                        }
                        ++l_d;
                        ++l_count;
                        ++i_c;
                        continue;
                }
                // -----------------------------------------
                // is a percent sign...
                // -----------------------------------------
                // -----------------------------------------
                // IIS specific %u encoding???
                // -----------------------------------------
                if((i_c + 1 < a_len) &&
                   ((a_buf[i_c + 1] == 'u') ||
                    (a_buf[i_c + 1] == 'U') ))
                {
                        // ---------------------------------
                        // not enough bytes (4 data bytes)
                        // skip %u
                        // ---------------------------------
                        if (i_c + 5 > a_len)
                        {
                                _SET_AND_SKIP();
                                _SET_AND_SKIP();
                                continue;
                        }
                        // ---------------------------------
                        // validate hex
                        // ---------------------------------
                        if((!VALID_HEX(a_buf[i_c + 2])) ||
                           (!VALID_HEX(a_buf[i_c + 3])) ||
                           (!VALID_HEX(a_buf[i_c + 4])) ||
                           (!VALID_HEX(a_buf[i_c + 5])) )
                        {
                                _SET_AND_SKIP();
                                _SET_AND_SKIP();
                                continue;
                        }
                        // ---------------------------------
                        // TODO -fix!!!
                        // --requires SecUnicodeMapFile
                        // and the unicode map functions
                        // above...
                        // ---------------------------------
#if 0
                        int32_t l_code = 0;
                        uint32_t l_fact = 1;
                        int32_t l_hmap = -1;
                        if((unicode_map_table != NULL) &&
                           (unicode_codepage > 0))
                        {
                                uint32_t l_xv = 0;
                                for(int32_t i_j=5; i_j>=2; --i_j)
                                {
                                        char l_u_char = a_buf[i_c+i_j];
                                        if(!isxdigit((l_u_char)))
                                        {
                                                continue;
                                        }
                                        if((l_u_char)>=97)
                                        {
                                                l_xv = ((l_u_char) - 97) + 10;
                                        }
                                        else if((l_u_char) >= 65)
                                        {
                                                l_xv = ((l_u_char) - 65) + 10;
                                        }
                                        else
                                        {
                                                l_xv = (l_u_char) - 48;
                                        }
                                        l_code += (l_xv * l_fact);
                                        l_fact *= 16;
                                }
                                if((l_code >= 0) &&
                                   (l_code <= 65535))
                                {
                                        // TODO -fix!!!
                                        //l_hmap = unicode_map_table[l_code];
                                }
                        }
                        if(l_hmap != -1)
                        {
                                *l_d = l_hmap;
                        }
                        // ---------------------------------
                        // no hmap???
                        // ---------------------------------
                        else
                        {
                                // -------------------------
                                // use lower byte
                                // ignoring higher byte.
                                // -------------------------
                                *l_d = x2c((unsigned char *)(&a_buf[i_c + 4]));
                                // -------------------------
                                // full width ASCII
                                // (ff01 - ff5e)
                                // needs 0x20 added
                                // -------------------------
                                char l_c1 = a_buf[i_c + 2];
                                char l_c2 = a_buf[i_c + 3];
                                if((*l_d > 0x00) &&
                                   (*l_d < 0x5f) &&
                                   ((l_c1 == 'f') ||
                                    (l_c1 == 'F')) &&
                                   ((l_c2 == 'f') ||
                                    (l_c2 == 'F')))
                                {
                                        l_d[0] += 0x20;
                                }
                        }
#else
                        // ---------------------------------
                        // use lower byte
                        // ignoring higher byte.
                        // ---------------------------------
                        *l_d = x2c((unsigned char *)(&a_buf[i_c + 4]));
                        // ---------------------------------
                        // full width ASCII
                        // (ff01 - ff5e)
                        // needs 0x20 added
                        // ---------------------------------
                        char l_c1 = a_buf[i_c + 2];
                        char l_c2 = a_buf[i_c + 3];
                        if((*l_d > 0x00) &&
                           (*l_d < 0x5f) &&
                           ((l_c1 == 'f') ||
                            (l_c1 == 'F')) &&
                           ((l_c2 == 'f') ||
                            (l_c2 == 'F')))
                        {
                                l_d[0] += 0x20;
                        }
#endif
                        ++l_d;
                        ++l_count;
                        i_c += 6;
                        continue;
                }
                // -----------------------------------------
                // standard url encoding
                // -----------------------------------------
                // -----------------------------------------
                // enough bytes (4 data bytes) ???
                // -----------------------------------------
                // -----------------------------------------
                // i_c starts from 0, a_len starts from 1
                // in case i_c + 2 == a_len, if you access
                // a_buf[i_c + 2] it will overflow, hence a_len - 1
                // -----------------------------------------
                if (i_c + 2 > (a_len -1))
                {
                        // skip %u
                        _SET_AND_SKIP();
                        continue;
                }
                // -----------------------------------------
                // decode a %xx combo only if it is valid
                // -----------------------------------------
                char l_c1 = a_buf[i_c + 1];
                char l_c2 = a_buf[i_c + 2];
                if(!VALID_HEX(l_c1) ||
                   !VALID_HEX(l_c2))
                {
                        _SET_AND_SKIP();
                        continue;
                }
                // -----------------------------------------
                // decode...
                // -----------------------------------------
                *l_d = x2c((unsigned char *)(&a_buf[i_c + 1]));
                i_c += 3;
                ++l_d;
                ++l_count;
        }
        // -------------------------------------------------
        // terminate...
        // -------------------------------------------------
        *l_d = '\0';
        // -------------------------------------------------
        // done...
        // -------------------------------------------------
        ao_len = l_count;
        *ao_buf = l_buf;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: convert utf-8 to unicode
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t utf8_to_unicode(char **ao_buf,
                        uint32_t &ao_len,
                        const char *a_buf,
                        uint32_t a_buf_len)
{
        // -------------------------------------------------
        // TODO -move to const...
        // -------------------------------------------------
#define _UNICODE_ERROR_CHARACTERS_MISSING    -1
#define _UNICODE_ERROR_INVALID_ENCODING      -2
#define _UNICODE_ERROR_OVERLONG_CHARACTER    -3
#define _UNICODE_ERROR_RESTRICTED_CHARACTER  -4
#define _UNICODE_ERROR_DECODING_ERROR        -5
        // -------------------------------------------------
        // encoding check...
        // -------------------------------------------------
#define _VALIDATE_ENCODING(_n) do {\
        if (l_left < _n) {\
                l_unicode_len = _UNICODE_ERROR_CHARACTERS_MISSING;\
                goto range_check;\
        }\
        uint16_t l_c = 1;\
        while(l_c < _n) {\
                if (((*(l_utf_c + l_c)) & 0xC0) != 0x80) {\
                        l_unicode_len = _UNICODE_ERROR_INVALID_ENCODING;\
                        goto range_check;\
                }\
                ++l_c;\
        }\
} while(0)
        // -------------------------------------------------
        // check exist
        // -------------------------------------------------
        if(!a_buf ||
           !a_buf_len)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // calculate length
        // -------------------------------------------------
        // ???
        uint32_t l_len = 7*a_buf_len + 1;
        char *l_buf = (char *)malloc(sizeof(char)*l_len);
        char *l_data = l_buf;
        uint32_t l_left = a_buf_len;
        // -------------------------------------------------
        // for each input char...
        // -------------------------------------------------
        uint32_t l_count = 0;
        for(uint32_t i_c = 0; i_c < a_buf_len;)
        {
                unsigned char *l_utf_c = (unsigned char *)(&(a_buf[i_c]));
                unsigned char l_c = *l_utf_c;
                int32_t l_unicode_len = 0;
                uint32_t l_d = 0;
                // -----------------------------------------
                // if first byte begins with binary 0 it is
                // single byte encoding
                // -----------------------------------------
                if((l_c & 0x80) == 0)
                {
                        // ---------------------------------
                        // single byte unicode
                        // (7 bit ASCII equivilent) has no
                        // validation
                        // ---------------------------------
                        ++l_count;
                        if(l_count > l_len)
                        {
                                goto range_check;
                        }
                        if(l_c == 0)
                        {
                                *l_data = '\0';
                        }
                        else
                        {
                                *l_data++ = l_c;
                        }
                }
                // -----------------------------------------
                // if first byte begins with binary 110 it
                // is two byte encoding
                // -----------------------------------------
                else if((l_c & 0xE0) == 0xC0)
                {
                        _VALIDATE_ENCODING(2);
                        l_unicode_len = 2;
                        l_count+=6;
                        if(l_count > l_len)
                        {
                                goto range_check;
                        }
                        // ---------------------------------
                        // compute character number
                        // ---------------------------------
                        l_d = ((l_c & 0x1F) << 6) |
                              (*(l_utf_c + 1) & 0x3F);
                        // ---------------------------------
                        // encoding
                        // ---------------------------------
                        l_data += sprintf(l_data, "%%u%04x", l_d);
                }
                // -----------------------------------------
                // if first byte begins with binary 1110 it
                // is three byte encoding
                // -----------------------------------------
                else if((l_c & 0xF0) == 0xE0)
                {
                        _VALIDATE_ENCODING(3);
                        l_unicode_len = 3;
                        l_count+=6;
                        if(l_count > l_len)
                        {
                                goto range_check;
                        }
                        // ---------------------------------
                        // compute character number
                        // ---------------------------------
                        l_d = ((l_c & 0x0F) << 12) |
                              ((*(l_utf_c + 1) & 0x3F) << 6) |
                              (*(l_utf_c + 2) & 0x3F);
                        // ---------------------------------
                        // encoding
                        // ---------------------------------
                        l_data += sprintf(l_data, "%%u%04x", l_d);
                }
                // -----------------------------------------
                // If first byte begins with binary 11110 it
                // is four byte encoding
                // -----------------------------------------
                else if((l_c & 0xF8) == 0xF0)
                {
                        // ---------------------------------
                        // restrict characters to UTF-8
                        // range (U+0000 - U+10FFFF)
                        // ---------------------------------
                        if(l_c >= 0xF5)
                        {
                                *l_data++ = l_c;
                        }
                        _VALIDATE_ENCODING(4);
                        l_unicode_len = 4;
                        l_count+=7;
                        if(l_count > l_len)
                        {
                                goto range_check;
                        }
                        // ---------------------------------
                        // compute character number
                        // ---------------------------------
                        l_d = ((l_c & 0x07) << 18) |
                              ((*(l_utf_c + 1) & 0x3F) << 12) |
                              ((*(l_utf_c + 2) & 0x3F) << 6) |
                              (*(l_utf_c + 3) & 0x3F);
                        // ---------------------------------
                        // encoding
                        // ---------------------------------
                        l_data += sprintf(l_data, "%%u%04x", l_d);
                }
                // -----------------------------------------
                // any other first byte is invalid (RFC 3629)
                // -----------------------------------------
                else {
                        ++l_count;
                        if(l_count <= l_len)
                        {
                                *l_data++ = l_c;
                        }
                }
range_check:
                // -----------------------------------------
                // invalid UTF-8 character number range
                // (RFC 3629)
                // -----------------------------------------
                if((l_d >= 0xD800) &&
                   (l_d <= 0xDFFF))
                {
                        ++l_count;
                        if(l_count <= l_len)
                        {
                                *l_data++ = l_c;
                        }
                }
                // -----------------------------------------
                // check for overlong
                // four byte could be represented with less
                // bytes
                // -----------------------------------------
                if((l_unicode_len == 4) &&
                   (l_d < 0x010000))
                {
                        ++l_count;
                        if(l_count <= l_len)
                        {
                                *l_data++ = l_c;
                        }
                }
                // -----------------------------------------
                // three byte could be represented with less
                // bytes
                // -----------------------------------------
                else if((l_unicode_len == 3) &&
                        (l_d < 0x0800))
                {
                        ++l_count;
                        if(l_count <= l_len)
                        {
                                *l_data++ = l_c;
                        }
                }
                // -----------------------------------------
                // two byte could be represented with less
                // bytes
                // -----------------------------------------
                else if((l_unicode_len == 2) &&
                        (l_d < 0x80))
                {
                        ++l_count;
                        if(l_count <= l_len)
                        {
                                *l_data++ = l_c;
                        }
                }
                // -----------------------------------------
                // ???
                // -----------------------------------------
                if(l_unicode_len > 0)
                {
                        i_c += l_unicode_len;
                        l_left -= l_unicode_len;
                }
                else
                {
                        ++i_c;
                        --l_left;
                }
        }
        // -------------------------------------------------
        // terminate str
        // -------------------------------------------------
        *l_data ='\0';
        // -------------------------------------------------
        // done...
        // -------------------------------------------------
        *ao_buf = l_buf;
        ao_len = l_count;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: validate buffer is valid utf8 according to RFC 3629
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t validate_utf8(bool &ao_valid,
                      const char **ao_err_msg,
                      uint32_t &ao_err_off,
                      const char *a_buf,
                      uint32_t a_len)
{
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        if(!ao_err_msg)
        {
                return WAFLZ_STATUS_ERROR;
        }
        ao_valid = true;
        // -------------------------------------------------
        // for each char...
        // -------------------------------------------------
        for(uint32_t i_c = 0; i_c < a_len;)
        {
                unsigned char l_c = a_buf[i_c];
                uint32_t l_w = 0;
                uint8_t l_uni_len = 0;
#define _UTF8_LEN_CHECK(_size) do { \
        if(_size < 3) { \
                *ao_err_msg = "Invalid UTF-8 encoding: too few bytes in char"; \
                ao_err_off = i_c; \
                ao_valid = false; \
                return WAFLZ_STATUS_OK; \
        } \
} while(0)
#define _CHECK_UTF8_BYTE(_off) do { \
        if(((a_buf[i_c+_off]) & 0xC0) != 0x80) { \
                *ao_err_msg = "Invalid UTF-8 encoding: invalid encoding"; \
                ao_err_off = i_c; \
                ao_valid = false; \
                return WAFLZ_STATUS_OK; \
        } \
        } while(0)
                // -----------------------------------------
                // *****************************************
                //               D E C O D E
                // *****************************************
                // -----------------------------------------
                // -----------------------------------------
                // if first bytes begins with binary 0
                // single byte encoding
                // -----------------------------------------
                if((l_c & 0x80) == 0)
                {
                        // ---------------------------------
                        // single byte unicode
                        // (7 bit ASCII equivilent)
                        // no validation
                        // ---------------------------------
                        i_c += 1;
                        continue;
                }
                // -----------------------------------------
                // if first byte begins with binary 110
                // two byte encoding
                // -----------------------------------------
                else if((l_c & 0xE0) == 0xC0)
                {
                        _UTF8_LEN_CHECK(2);
                        _CHECK_UTF8_BYTE(1);
                        l_uni_len = 2;
                        // ---------------------------------
                        // compute word
                        // ---------------------------------
                        l_w = ((a_buf[i_c]   & 0x1F) << 6) |
                               (a_buf[i_c+1] & 0x3F);
                }
                // -----------------------------------------
                // if first byte begins with binary 1110
                // three byte encoding
                // -----------------------------------------
                else if((l_c & 0xF0) == 0xE0)
                {
                        _UTF8_LEN_CHECK(3);
                        _CHECK_UTF8_BYTE(1);
                        _CHECK_UTF8_BYTE(2);
                        l_uni_len = 3;
                        // ---------------------------------
                        // compute word
                        // ---------------------------------
                        l_w = ((a_buf[i_c]   & 0x0F) << 12) |
                              ((a_buf[i_c+1] & 0x3F) <<  6) |
                               (a_buf[i_c+2] & 0x3F);
                }
                // -----------------------------------------
                // if first byte begins with binary 11110
                // four byte encoding
                // -----------------------------------------
                else if((l_c & 0xF8) == 0xF0)
                {
                        // ---------------------------------
                        // restricted char use???
                        // ---------------------------------
                        if(l_c >= 0xF5)
                        {
                                *ao_err_msg = "Invalid UTF-8 encoding: use of restricted char";
                                ao_err_off = i_c;
                                ao_valid = false;
                                return WAFLZ_STATUS_OK;
                        }
                        _UTF8_LEN_CHECK(4);
                        _CHECK_UTF8_BYTE(1);
                        _CHECK_UTF8_BYTE(2);
                        _CHECK_UTF8_BYTE(2);
                        l_uni_len = 4;
                        // ---------------------------------
                        // compute word
                        // ---------------------------------
                        l_w = ((a_buf[i_c]   & 0x07) << 18) |
                              ((a_buf[i_c+1] & 0x3F) << 12) |
                              ((a_buf[i_c+2] & 0x3F) << 6)  |
                               (a_buf[i_c+3] & 0x3F);
                }
                // -----------------------------------------
                // any other first byte invalid (RFC 3629)
                // -----------------------------------------
                else
                {
                        *ao_err_msg = "Invalid UTF-8 encoding: invalid encoding";
                        ao_err_off = i_c;
                        ao_valid = false;
                        return WAFLZ_STATUS_OK;
                }
                // -----------------------------------------
                // *****************************************
                //         W O R D   C H E C K
                // *****************************************
                // -----------------------------------------
                // -----------------------------------------
                // invalid UTF-8 character number range
                // (RFC 3629)
                // -----------------------------------------
                if((l_w >= 0xD800) &&
                   (l_w <= 0xDFFF))
                {
                        *ao_err_msg = "Invalid UTF-8 encoding: use of restricted char";
                        ao_err_off = i_c;
                        ao_valid = false;
                        return WAFLZ_STATUS_OK;
                }
                // -----------------------------------------
                // check for overlong
                // -----------------------------------------
#define _ELIF_OVERLONG(_size, _word) \
                else if((l_uni_len == _size) && \
                        (l_w < _word)) { \
                        *ao_err_msg = "Invalid UTF-8 encoding: overlong char"; \
                        ao_err_off = i_c; \
                        ao_valid = false; \
                        return WAFLZ_STATUS_OK; \
                }
                _ELIF_OVERLONG(2, 0x80)
                _ELIF_OVERLONG(3, 0x0800)
                _ELIF_OVERLONG(4, 0x010000)
                // -----------------------------------------
                // incr...
                // -----------------------------------------
                i_c += l_uni_len;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t parse_args(arg_list_t &ao_arg_list,
                   data_unordered_map_t& ao_arg_map,
                   uint32_t &ao_invalid_cnt,
                   const char *a_buf,
                   uint32_t a_buf_len,
                   char a_arg_sep)
{
        //NDBG_PRINT("a_buf:     %p\n", a_buf);
        //NDBG_PRINT("a_buf_len: %d\n", (int)a_buf_len);
        // -------------------------------------------------
        // TODO -make zero copy impl
        // -------------------------------------------------
        if(!a_buf ||
           !a_buf_len)
        {
                // TODO log reason???
                // No query string in request
                return WAFLZ_STATUS_OK;
        }
        char *l_buf;
        l_buf = (char *)malloc(a_buf_len + 1);
        if(!l_buf)
        {
                // TODO log reason???
                return WAFLZ_STATUS_ERROR;
        }
        char *l_val = NULL;
        int32_t l_status = 0;
        uint32_t i_char = 0;
        uint32_t i_w_off = 0;
        uint32_t l_key_orig_len = 0;
        uint32_t l_val_orig_len = 0;
        arg_t l_arg;
        ao_invalid_cnt = 0;
        // -------------------------------------------------
        // parse buffer char by char
        // -------------------------------------------------
        while(i_char < a_buf_len)
        {
                // -----------------------------------------
                // parameter name
                // -----------------------------------------
                // Special case if there is no param
                // e.g ?&a=b&&&c=d
                // status = 0 means a param key
                if(a_buf[i_char] == a_arg_sep &&
                   l_status == 0)
                {
                        ++i_char;
                        continue;
                }
                if(l_status == 0)
                {
                        uint32_t l_key_off = i_char;
                        while((i_char < a_buf_len) &&
                              (a_buf[i_char] != '=') &&
                              (a_buf[i_char] != a_arg_sep))
                        {
                                l_buf[i_w_off] = a_buf[i_char];
                                ++i_w_off;
                                ++i_char;
                        }
                        l_buf[i_w_off++] = '\0';
                        l_key_orig_len = i_char - l_key_off;
                }
                // -----------------------------------------
                // parameter value
                // -----------------------------------------
                else
                {
                        uint32_t l_val_off = i_char;
                        while((i_char < a_buf_len) &&
                              (a_buf[i_char] != a_arg_sep))
                        {
                                l_buf[i_w_off] = a_buf[i_char];
                                ++i_w_off;
                                ++i_char;
                        }
                        l_buf[i_w_off++] = '\0';
                        l_val_orig_len = i_char - l_val_off;
                }
                // -----------------------------------------
                //
                // -----------------------------------------
                if(l_status == 0)
                {
                        //NDBG_PRINT("decode: %.*s\n", (int)l_key_orig_len, l_buf);
                        //Empty key, set it to null
                        if(!l_key_orig_len)
                        {
                                l_arg.m_key = NULL;
                                l_arg.m_key_len = 0;
                        }
                        int32_t l_s;
                        l_s = urldecode_ns(&(l_arg.m_key),
                                           l_arg.m_key_len,
                                           ao_invalid_cnt,
                                           l_buf,
                                           l_key_orig_len);
                        UNUSED(l_s);
                        // TODO -check for error
                        if((i_char < a_buf_len) &&
                           (a_buf[i_char] == a_arg_sep))
                        {
                                // Empty parameter
                                l_arg.m_val = NULL;
                                l_arg.m_val_len = 0;
                                // NDBG_PRINT("%.*s: %.*s\n", l_arg.m_key_len, l_arg.m_key, l_arg.m_val_len, l_arg.m_val);
                                ao_arg_map.insert( std::make_pair<data_t, data_t>( data_t{l_arg.m_key, l_arg.m_key_len}, data_t{l_arg.m_val, l_arg.m_val_len}));
                                ao_arg_list.push_back(l_arg);
                                l_arg.clear();
                                // unchanged
                                l_status = 0;
                                i_w_off = 0;
                        }
                        else
                        {
                                l_status = 1;
                                l_val = &l_buf[i_w_off];
                        }
                }
                else
                {
                        //NDBG_PRINT("decode: %.*s\n", (int)l_val_orig_len, l_val);
                        if(!l_val ||
                           !l_val_orig_len)
                        {
                               // Empty parameter
                                l_arg.m_val = NULL;
                                l_arg.m_val_len = 0;
                                // NDBG_PRINT("%.*s: %.*s\n", l_arg.m_key_len, l_arg.m_key, l_arg.m_val_len, l_arg.m_val);
                                ao_arg_map.insert( std::make_pair<data_t, data_t>( data_t{l_arg.m_key, l_arg.m_key_len}, data_t{l_arg.m_val, l_arg.m_val_len}));
                                ao_arg_list.push_back(l_arg);
                                l_arg.clear();
                                // unchanged
                                l_status = 0;
                                i_w_off = 0;
                        }
                        else
                        {
                                int32_t l_s;
                                l_s = urldecode_ns(&(l_arg.m_val),
                                                   l_arg.m_val_len,
                                                   ao_invalid_cnt,
                                                   l_val,
                                                   l_val_orig_len);
                                UNUSED(l_s);
                                // TODO -check for error
                                // NDBG_PRINT("%.*s: %.*s\n", l_arg.m_key_len, l_arg.m_key, l_arg.m_val_len, l_arg.m_val);
                                ao_arg_map.insert( std::make_pair<data_t, data_t>( data_t{l_arg.m_key, l_arg.m_key_len}, data_t{l_arg.m_val, l_arg.m_val_len}));
                                ao_arg_list.push_back(l_arg);
                                l_arg.clear();
                                l_status = 0;
                                i_w_off = 0;
                        }
                }
                // skip over the separator
                ++i_char;
        }
        // -------------------------------------------------
        // last parameter empty
        // -------------------------------------------------
        if(l_status == 1)
        {
                l_arg.m_val = NULL;
                l_arg.m_val_len = 0;
                // NDBG_PRINT("%.*s: %.*s\n", l_arg.m_key_len, l_arg.m_key, l_arg.m_val_len, l_arg.m_val);
                ao_arg_map.insert( std::make_pair<data_t, data_t>( data_t{l_arg.m_key, l_arg.m_key_len}, data_t{l_arg.m_val, l_arg.m_val_len}));
                ao_arg_list.push_back(l_arg);
        }
        if(l_buf) { free(l_buf); l_buf = NULL;}
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details parse cookie string:
//!          format: 'key1=val1; key2; key3=val3; key4\0'
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
static bool is_char_in_set(const char *a_arr, uint32_t a_arr_len, char a_char)
{
        for(uint32_t i_c = 0; i_c < a_arr_len; ++i_c)
        {
                if(a_char == a_arr[i_c]) return true;
        }
        return false;
}
//! ----------------------------------------------------------------------------
//! \details parse cookie string:
//!          format: 'key1=val1; key2; key3=val3; key4\0'
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t parse_cookies(const_arg_list_t &ao_cookie_list,
                      const char *a_buf,
                      uint32_t a_buf_len)
{
        static const char l_del_set[]    = {'=',';',' ','\t','\f','\r','\n'};
        static const char l_valdel_set[] = {'=',' ','\t','\f','\r','\n'};
        // -------------------------------------------------
        // Parsing logic
        // -------------------------------------------------
        // 1: Skip delimiters
        // 2: Match until ';' or '\0' for key
        // 3: If '=' found, skip to first non-delimiter char
        // 4: Look for value until either ';' or '\0'
        // 5: Back to step 1
        // Example 'cookie: abc= =123  ;def;;;'
        //  - key='abc', val='123'
        //  - key='def', val=''
        // RFC: http://tools.ietf.org/html/rfc6265#section-4.1
        // -------------------------------------------------
        // TODO !!!
        // trim trailing whitespace(s) from values...
        // in ex above -cookie split results in
        //  - key='abc', val='123  '
        // -------------------------------------------------
        // start at first non-delimiter char
        // -------------------------------------------------
        const char *l_key = a_buf;
        const char *l_val=NULL;
        const char *l_keyend=NULL;
        //NDBG_PRINT("SKIP l_del_chars\n");
        for(; is_char_in_set(l_del_set, sizeof(l_del_set), *l_key); ++l_key) {}
        if (*l_key == '\0') return WAFLZ_STATUS_OK;
        //NDBG_PRINT("l_key: %s\n", l_key);
        // -------------------------------------------------
        // NOTE: assume \0 terminated string
        // -------------------------------------------------
        const_arg_t l_arg;
        for(const char* i_p = l_key + 1; ; ++i_p)
        {
                //NDBG_PRINT("i_p: %s\n", i_p);
                switch (*i_p)
                {
                // -----------------------------------------
                // \0
                // -----------------------------------------
                case '\0':
                {
                        if(l_val)
                        {
                                // we got "key=value; "
                                l_arg.m_key = l_key;
                                l_arg.m_key_len = l_keyend - l_key;
                                int l_len = (int)(i_p - l_val);
                                const char *l_p_i = i_p - 1;
                                while(l_len && *l_p_i == ' ') { --l_len; --l_p_i; }
                                l_arg.m_val = l_val;
                                l_arg.m_val_len = l_len;
                                //NDBG_PRINT("l_key: \"%s\"\n", l_key_str.c_str());
                                //NDBG_PRINT("l_val: \"%s\"\n", l_val_str.c_str());
                                ao_cookie_list.push_back(l_arg);
                                l_arg.clear();
                        }
                        else
                        {
                                // we got a key with no value
                                l_arg.m_key = l_key;
                                l_arg.m_key_len = i_p - l_key;
                                l_arg.m_val = NULL;
                                l_arg.m_val_len = 0;
                                ao_cookie_list.push_back(l_arg);
                                l_arg.clear();
                        }
                        return WAFLZ_STATUS_OK;
                }
                // -----------------------------------------
                // =
                // -----------------------------------------
                case '=':
                {
                        if (l_val) break;
                        // ---------------------------------
                        // mark end of key and jump to
                        // next non-delimiter character
                        // ---------------------------------
                        l_keyend = i_p++;
                        //NDBG_PRINT("SKIP l_valdel_chars\n");
                        for(; is_char_in_set(l_valdel_set, sizeof(l_valdel_set), *i_p); ++i_p) {}
                        if (*i_p == '\0') return WAFLZ_STATUS_OK;
                        if (*i_p != ';')
                        {
                                l_val = i_p;
                                break;
                        }
                        // fall-thru
                }
                // -----------------------------------------
                // ;
                // -----------------------------------------
                case ';':
                {
                        if(l_val)
                        {
                                // we got "key=value;"
                                l_arg.m_key = l_key;
                                l_arg.m_key_len = l_keyend - l_key;
                                int l_len = (int)(i_p - l_val);
                                const char *l_p_i = i_p - 1;
                                while(l_len && *l_p_i == ' ') { --l_len; --l_p_i; }
                                l_arg.m_val = l_val;
                                l_arg.m_val_len = l_len;
                                //NDBG_PRINT("l_key: \"%s\"\n", l_key_str.c_str());
                                //NDBG_PRINT("l_val: \"%s\"\n", l_val_str.c_str());
                                ao_cookie_list.push_back(l_arg);
                                l_arg.clear();
                        }
                        else
                        {
                                // we got a key with no value
                                l_arg.m_key = l_key;
                                l_arg.m_key_len = i_p - l_key;
                                l_arg.m_val = NULL;
                                l_arg.m_val_len = 0;
                                ao_cookie_list.push_back(l_arg);
                                l_arg.clear();
                        }
                        // jump to next non-delimiter char
                        ++i_p;
                        //NDBG_PRINT("SKIP l_del_chars\n");
                        for(; is_char_in_set(l_del_set, sizeof(l_del_set), *i_p); ++i_p) {}
                        if (*i_p == '\0') return WAFLZ_STATUS_OK;
                        l_key = i_p;
                        l_val = NULL;
                        l_keyend = NULL;
                }
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details parse cookie string:
//!          format:  Content-type:multipart/form-data; application/xml(asdhbc)  ;   aasdhhhasd;asdajj-asdad    ;; ;;"
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t parse_content_type(data_list_t &ao_data_list, const_arg_t *a_hdr)
{
        uint32_t i_char = 0;
        uint32_t i_offset = 0;
        while(i_char <= a_hdr->m_val_len)
        {
                // separators
                if(a_hdr->m_val[i_char] == ';' ||
                   a_hdr->m_val[i_char] == ' ')
                {
                        data_t l_val;
                        l_val.m_data = a_hdr->m_val + i_offset;
                        l_val.m_len = i_char - i_offset;
                        // if we have something within separators
                        if(l_val.m_len)
                        {
                                ao_data_list.push_back(l_val);
                        }
                        ++i_char;
                        // if the next char is also separators
                        // skip by 1
                        if(a_hdr->m_val[i_char] == ' ' ||
                           a_hdr->m_val[i_char] == ';')
                        {
                                i_offset = i_char + 1;
                        }
                        else
                        {
                                i_offset = i_char;
                        }
                }
                // -------------------------
                // no separators found.
                // Just one type
                // -------------------------
                if(i_char == a_hdr->m_val_len)
                {
                        data_t l_val;
                        l_val.m_data = a_hdr->m_val + i_offset;
                        l_val.m_len = i_char - i_offset;
                        // if not empty
                        if(l_val.m_len)
                        {
                                ao_data_list.push_back(l_val);
                        }
                        break;
                }
                ++i_char;
        }
        return WAFLZ_STATUS_OK;
}
}
