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
#include "waflz/nms.h"
#include <arpa/inet.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <algorithm>
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#ifndef WAFLZ_STATUS_OK
  #define WAFLZ_STATUS_OK 0
#endif
#ifndef WAFLZ_STATUS_ERROR
  #define WAFLZ_STATUS_ERROR -1
#endif
#ifndef WAFLZ_ERR_LEN
  #define WAFLZ_ERR_LEN 4096
#endif

#if defined(__APPLE__) || defined(__darwin__)
/* OSX seems not to define these. */
#ifndef s6_addr16
#define s6_addr16 __u6_addr.__u6_addr16
#endif
#ifndef s6_addr32
#define s6_addr32 __u6_addr.__u6_addr32
#endif
#endif
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
#ifndef NDBG_OUTPUT
#define NDBG_OUTPUT(...) \
        do { \
                fprintf(stdout, __VA_ARGS__); \
                fflush(stdout); \
        } while(0)
#endif
#ifndef NDBG_PRINT
#define NDBG_PRINT(...) \
        do { \
                fprintf(stdout, "%s:%s.%d: ", __FILE__, __FUNCTION__, __LINE__); \
                fprintf(stdout, __VA_ARGS__);               \
                fflush(stdout); \
        } while(0)
#endif
#ifndef WAFLZ_PERROR
#define WAFLZ_PERROR(_str, ...) do { \
  snprintf(_str, WAFLZ_ERR_LEN, "%s.%s.%d: ",__FILE__,__FUNCTION__,__LINE__); \
  int _len = strlen(_str); \
  snprintf(_str + _len, WAFLZ_ERR_LEN - _len, __VA_ARGS__); \
} while(0)
#endif
namespace ns_waflz
{
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                          N E T M A S K   S E T
//! ****************************************************************************
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
nms::nms():
        ipv4_arr(new ipv4_set_t[33]),
        ipv6_arr(new ipv6_set_t[129])
{}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
nms::~nms()
{
        if (ipv4_arr) { delete[] ipv4_arr; ipv4_arr = NULL;}
        if (ipv6_arr) { delete[] ipv6_arr; ipv6_arr = NULL;}
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nms::add(const char* a_buf, uint32_t a_buf_len)
{
        // -------------------------------------------------
        // detect type
        // -------------------------------------------------
        // TODO -address type detection is crude
        if (strchr(a_buf, ':') == NULL)
        {
                return add_ipv4(a_buf, a_buf_len);
        }
        return add_ipv6(a_buf, a_buf_len);
#if 0
        // -------------------------------------------------
        // detect type
        // -------------------------------------------------
        ip_tree::addr_t l_addr = ip_tree::ADDR_NONE;
        l_addr = detect_addr(a_buf, a_buf_len);
        if (l_addr == ip_tree::ADDR_NONE)
        {
                WAFLZ_PERROR(m_err_msg, "invalid ipv address: %.*s",
                             a_buf_len, a_buf);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // add
        // -------------------------------------------------
        switch(l_addr)
        {
        case ip_tree::ADDR_IPV4:
        {
                return add_ipv4(a_buf, a_buf_len);
        }
        case ip_tree::ADDR_IPV6:
        {
                return add_ipv6(a_buf, a_buf_len);
        }
        default:
        {
                WAFLZ_PERROR(m_err_msg, "invalid address type: %d", l_addr);
                return WAFLZ_STATUS_ERROR;
        }
        }
        return WAFLZ_STATUS_ERROR;
#endif
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nms::contains(bool &ao_match, const char* a_buf, uint32_t a_buf_len) const
{
        if (strchr(a_buf, ':') == NULL)
        {
                return contains_ipv4(ao_match, a_buf, a_buf_len);
        }
        return contains_ipv6(ao_match, a_buf, a_buf_len);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
nms::addr_t nms::detect_addr(const char* a_buf, uint32_t a_buf_len) const
{
        nms::addr_t l_addr = nms::ADDR_NONE;
        int l_s;
        if (memchr(a_buf, ':', a_buf_len) == NULL)
        {
                struct in_addr l_in;
                l_s = inet_pton(AF_INET, a_buf, &l_in);
                if (l_s > 0)
                {
                        l_addr = nms::ADDR_IPV4;
                }
        }
        else
        {
                struct in6_addr l_in6;
                l_s = inet_pton(AF_INET6, a_buf, &l_in6);
                if (l_s > 0)
                {
                        l_addr = nms::ADDR_IPV6;
                }
        }
        return l_addr;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nms::add_ipv4_plain(const char* a_buf, uint32_t a_buf_len)
{
        struct in_addr l_in;
        int l_s;
        l_s = inet_pton(AF_INET, a_buf, &l_in);
        if (l_s != 1)
        {
                // TODO log reason???
                return WAFLZ_STATUS_ERROR;
        }
        if (!ipv4_arr)
        {
                ipv4_arr = new ipv4_set_t[33];
        }
        ipv4_arr[32].insert(l_in.s_addr);
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nms::add_ipv4_cidr(const char* a_buf, uint32_t a_buf_len)
{
        // -------------------------------------------------
        // find slash
        // -------------------------------------------------
        char* l_slash_pos = (char *)memchr(a_buf, '/', a_buf_len);
        if (l_slash_pos[1] == '\0')
        {
                // TODO log reason???
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get bits
        // -------------------------------------------------
        char* l_err = NULL;
        uint32_t l_bits;
        l_bits = strtoul(l_slash_pos + 1, &l_err, 10);
        if (*l_err)
        {
                // TODO log reason???
                return WAFLZ_STATUS_ERROR;
        }
        if (l_bits > 32)
        {
                // TODO log reason???
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // build netmask
        // -------------------------------------------------
        uint32_t l_mask;
        l_mask = (l_bits == 0) ? 0 : htonl(~((1 << (32 - l_bits)) - 1));
        // -------------------------------------------------
        // get truncated string
        // -------------------------------------------------
        char l_nm_ip[64];
        if ((size_t)(l_slash_pos - a_buf) >= (sizeof(l_nm_ip)-1))
        {
                // netmask too long
                // TODO log reason???
                return WAFLZ_STATUS_ERROR;
        }
        strncpy(l_nm_ip, a_buf, l_slash_pos - a_buf);
        l_nm_ip[l_slash_pos - a_buf] = '\0';
        // -------------------------------------------------
        // convert to ipaddr
        // -------------------------------------------------
        struct in_addr l_in;
        int l_s;
        l_s = inet_pton(AF_INET, l_nm_ip, &l_in);
        if (l_s != 1)
        {
                // TODO log reason???
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // create masked address
        // -------------------------------------------------
        uint32_t l_masked_addr = l_in.s_addr & l_mask;
        // -------------------------------------------------
        // create sets if not already created
        // -------------------------------------------------
        if (!ipv4_arr)
        {
                ipv4_arr = new ipv4_set_t[33];
        }
        // ----------------------------------------
        // add
        // ----------------------------------------
        ipv4_arr[l_bits].insert(l_masked_addr);
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nms::add_ipv4(const char* a_buf, uint32_t a_buf_len)
{
        if (memchr(a_buf, '/', a_buf_len) == NULL)
        {
                return add_ipv4_plain(a_buf, a_buf_len);
        }
        return add_ipv4_cidr(a_buf, a_buf_len);
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nms::add_ipv6_plain(const char* a_buf, uint32_t a_buf_len)
{
        struct in6_addr l_in6;
        int l_s;
        l_s = inet_pton(AF_INET6, a_buf, &l_in6);
        if (l_s != 1)
        {
                // TODO log reason???
                return WAFLZ_STATUS_ERROR;
        }
        if (!ipv6_arr)
        {
                ipv6_arr = new ipv6_set_t[129];
        }
        ipv6_arr[128].insert(l_in6);
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nms::add_ipv6_cidr(const char* a_buf, uint32_t a_buf_len)
{
        // -------------------------------------------------
        // find slash
        // -------------------------------------------------
        char* l_slash_pos = (char *)memchr(a_buf, '/', a_buf_len);
        if (l_slash_pos[1] == '\0')
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get bits
        // -------------------------------------------------
        char* l_err = NULL;
        uint32_t l_bits;
        l_bits = strtoul(l_slash_pos + 1, &l_err, 10);
        if (*l_err)
        {
                // TODO log reason???
                return WAFLZ_STATUS_ERROR;
        }
        if (l_bits > 128)
        {
                // TODO log reason???
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // build netmask
        // -------------------------------------------------
        in6_addr l_mask;
        for (uint32_t i_c = 0; i_c < 4; ++i_c)
        {
                uint32_t l_v = l_bits - 32*i_c;
                if (l_v >= 32)
                {
                        l_mask.s6_addr32[i_c] = 0xffffffff;
                }
                else if (l_v <= 0)
                {
                        l_mask.s6_addr32[i_c] = 0;
                }
                else
                {
                        l_mask.s6_addr32[i_c] = htonl(~((1 << (32 - l_bits + 32*i_c)) - 1));
                }
        }
        // -------------------------------------------------
        // get truncated string
        // -------------------------------------------------
        char l_nm_ip[64];
        if ((size_t)(l_slash_pos - a_buf) >= (sizeof(l_nm_ip)-1))
        {
                // netmask too long
                // TODO log reason???
                return WAFLZ_STATUS_ERROR;
        }
        strncpy(l_nm_ip, a_buf, l_slash_pos - a_buf);
        l_nm_ip[l_slash_pos - a_buf] = '\0';
        // -------------------------------------------------
        // convert to ipaddr
        // -------------------------------------------------
        struct in6_addr l_in6;
        int l_s;
        l_s = inet_pton(AF_INET6, l_nm_ip, &l_in6);
        if (l_s != 1)
        {
                // TODO log reason???
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // create masked address
        // -------------------------------------------------
        struct in6_addr l_masked_addr;
        for (uint32_t i_c = 0; i_c < 4; ++i_c)
        {
                l_masked_addr.s6_addr32[i_c] = l_in6.s6_addr32[i_c] & l_mask.s6_addr32[i_c];
        }
        if (!ipv6_arr)
        {
                ipv6_arr = new ipv6_set_t[129];
        }
        // -------------------------------------------------
        // add
        // -------------------------------------------------
        ipv6_arr[l_bits].insert(l_masked_addr);
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nms::add_ipv6(const char* a_buf, uint32_t a_buf_len)
{
        if (memchr(a_buf, '/', a_buf_len) == NULL)
        {
                return add_ipv6_plain(a_buf, a_buf_len);
        }
        return add_ipv6_cidr(a_buf, a_buf_len);
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nms::contains_ipv4(bool &ao_match, const char* a_buf, uint32_t a_buf_len) const
{
        ao_match = false;
        if (!ipv4_arr)
        {
                return WAFLZ_STATUS_OK;
        }
        // convert to ipv4
        in_addr l_in;
        int l_s;
        l_s = inet_pton(AF_INET, a_buf, &l_in);
        if (l_s != 1)
        {
                // TODO log reason???
                return WAFLZ_STATUS_ERROR;
        }
        for(uint32_t l_bits=0; l_bits< 33; ++l_bits)
        {
                // -------------------------------------------------
                // Construct prefix mask
                // -------------------------------------------------
                const uint32_t l_nm = (l_bits == 0) ? 0 : htonl(~((1 << (32 - l_bits)) - 1));
                // -------------------------------------------------
                // If prefix found, ip is contained
                // -------------------------------------------------
                if ( ipv4_arr[l_bits].find(l_nm & l_in.s_addr) != ipv4_arr[l_bits].end())
                {
                        ao_match = true;
                        return WAFLZ_STATUS_OK;
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t nms::contains_ipv6(bool &ao_match, const char* a_buf, uint32_t a_buf_len) const
{
        ao_match = false;
        if (!ipv6_arr)
        {
                // error???
                return WAFLZ_STATUS_OK;
        }
        in6_addr l_in6;
        int l_s;
        l_s = inet_pton(AF_INET6, a_buf, &l_in6);
        if (l_s != 1)
        {
                // TODO log reason???
                return WAFLZ_STATUS_ERROR;
        }
        for(uint32_t l_bits=0; l_bits<129; ++l_bits)
        {
                // -------------------------------------------------
                // Construct prefix
                // -------------------------------------------------
                in6_addr l_masked;
                for (uint32_t i_c = 0; i_c < 4; ++i_c)
                {
                        int32_t l_pos = l_bits - 32*i_c;
                        if (l_pos >= 32)
                        {
                                l_masked.s6_addr32[i_c] = l_in6.s6_addr32[i_c] & 0xffffffff;
                        }
                        else if (l_pos <= 0)
                        {
                                l_masked.s6_addr32[i_c] = 0;
                        }
                        else
                        {
                                l_masked.s6_addr32[i_c] = l_in6.s6_addr32[i_c] & htonl(~((1 << (32 - l_bits + 32*i_c)) - 1));
                        }
                }
                // -------------------------------------------------
                // If prefix found, IP is contained
                // -------------------------------------------------
                if (ipv6_arr[l_bits].find(l_masked) != ipv6_arr[l_bits].end())
                {
                        ao_match = true;
                        return WAFLZ_STATUS_OK;
                }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                            U T I L I T I E S
//! ****************************************************************************
//! ----------------------------------------------------------------------------
//! ----------------------------------------------------------------------------
//! constants
//! ----------------------------------------------------------------------------
#define MAX_READLINE_SIZE 4096
#define IP_STR_SEPARATOR ','
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t create_nms_from_str(nms** ao_nms, const std::string &a_str)
{
        //NDBG_PRINT("%sNMS_FROM_STR%s: %s\n",ANSI_COLOR_BG_WHITE, ANSI_COLOR_OFF, a_str.c_str());
        if (!ao_nms)
        {
                return WAFLZ_STATUS_ERROR;
        }
        *ao_nms = NULL;
        // -------------------------------------------------
        // split by IP string sep...
        // -------------------------------------------------
        int32_t l_s;
        nms* l_nms = new nms();
        size_t l_start = 0;
        size_t l_end = 0;
        while((l_end = a_str.find(IP_STR_SEPARATOR, l_start)) != std::string::npos)
        {
                if (l_end != l_start)
                {
                        std::string i_str = a_str.substr(l_start, l_end - l_start);
                        i_str.erase( std::remove_if ( i_str.begin(), i_str.end(), ::isspace ), i_str.end() );
                        l_s = l_nms->add(i_str.c_str(), i_str.length());
                        if (l_s != WAFLZ_STATUS_OK)
                        {
                                if (l_nms) { delete l_nms; l_nms = NULL;}
                                return WAFLZ_STATUS_ERROR;
                        }
                }
                l_start = l_end + 1;
        }
        if (l_end != l_start)
        {
                std::string i_str = a_str.substr(l_start);
                i_str.erase( std::remove_if ( i_str.begin(), i_str.end(), ::isspace ), i_str.end() );
                l_s = l_nms->add(i_str.c_str(), i_str.length());
                if (l_s != WAFLZ_STATUS_OK)
                {
                        if (l_nms) { delete l_nms; l_nms = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
        }
        *ao_nms = l_nms;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t create_nms_from_file(nms** ao_nms, const std::string &a_file)
{
        if (!ao_nms)
        {
                return WAFLZ_STATUS_ERROR;
        }
        *ao_nms = NULL;
        //NDBG_PRINT("%sNMS_FROM_FILE%s: %s\n",ANSI_COLOR_BG_GREEN, ANSI_COLOR_OFF, a_file.c_str());
        FILE * l_fp;
        l_fp = fopen(a_file.c_str(),"r");
        if (l_fp == NULL)
        {
                //NDBG_PRINT("error opening file: %s.  Reason: %s\n", a_file.c_str(), strerror(errno));
                return WAFLZ_STATUS_ERROR;
        }
        nms* l_nms = new nms();
        char l_rline[MAX_READLINE_SIZE];
        while(fgets(l_rline, sizeof(l_rline), l_fp))
        {
                size_t l_rline_len = strnlen(l_rline, MAX_READLINE_SIZE);
                if (!l_rline_len)
                {
                        continue;
                }
                else if (l_rline_len == MAX_READLINE_SIZE)
                {
                        // line was truncated
                        //TRC_OUTPUT("Error: lines must be shorter than %d chars\n", MAX_READLINE_SIZE);
                        if (l_nms) { delete l_nms; l_nms = NULL;}
                        if (l_fp) { fclose(l_fp); l_fp = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // TODO -zero copy version???
                // -----------------------------------------
                // nuke endline
                l_rline[l_rline_len - 1] = '\0';
                std::string l_line(l_rline);
                l_line.erase( std::remove_if ( l_line.begin(), l_line.end(), ::isspace ), l_line.end() );
                if (l_line.empty())
                {
                        continue;
                }
                int32_t l_s;
                l_s = l_nms->add(l_line.c_str(), l_line.length());
                if (l_s != WAFLZ_STATUS_OK)
                {
                        if (l_nms) { delete l_nms; l_nms = NULL;}
                        if (l_fp) { fclose(l_fp); l_fp = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
                //NDBG_PRINT("READLINE: %s\n", l_line.c_str());
        }
        *ao_nms = l_nms;
        // -------------------------------------------------
        // Close file...
        // -------------------------------------------------
        if (l_fp) { fclose(l_fp); l_fp = NULL;}
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t create_nms_from_ip_str_list(nms** ao_nms,
                                    const ip_str_list_t &a_ip_str_list)
{
        if (!ao_nms)
        {
                return WAFLZ_STATUS_ERROR;
        }
        *ao_nms = NULL;
        nms* l_nms = new nms();
        for(ip_str_list_t::const_iterator i_ip = a_ip_str_list.begin();
            i_ip != a_ip_str_list.end();
            ++i_ip)
        {
                if (!*i_ip)
                {
                        continue;
                }
                const std::string &l_ip = **i_ip;
                if (l_ip.empty())
                {
                        continue;
                }
                int32_t l_s;
                l_s = l_nms->add(l_ip.c_str(), l_ip.length());
                if (l_s != WAFLZ_STATUS_OK)
                {
                        if (l_nms) { delete l_nms; l_nms = NULL;}
                        return WAFLZ_STATUS_ERROR;
                }
        }
        *ao_nms = l_nms;
        return WAFLZ_STATUS_OK;
}
}
