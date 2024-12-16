//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _NMS_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <set>
#include <list>
#include <netinet/in.h>
#include <string.h>
#include <string>
namespace ns_waflz
{
//! ----------------------------------------------------------------------------
//! netmask set
//! ----------------------------------------------------------------------------
class nms
{
public:
        // -------------------------------------------------
        // public enums
        // -------------------------------------------------
        typedef enum {
                ADDR_IPV4 = 0,
                ADDR_IPV6,
                ADDR_NONE
        } addr_t;
        struct cmp_in6_addr
        {
                bool operator()(const in6_addr& a,
                                const in6_addr& b) const
                {
                        return (0 > memcmp(&a.s6_addr,
                                           &b.s6_addr,
                                           sizeof(a.s6_addr)));
                }
        };
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        nms();
        ~nms();
        int32_t add(const char *a_buf, uint32_t a_buf_len);
        int32_t contains(bool &ao_match, const char *a_buf, uint32_t a_buf_len) const;
private:
        // -------------------------------------------------
        // private types
        // -------------------------------------------------
        typedef std::set<in_addr_t> ipv4_set_t;
        typedef std::set<in6_addr, cmp_in6_addr> ipv6_set_t;
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // disallow copy/assign
        nms(const nms &);
        nms& operator=(const nms &);
        addr_t detect_addr(const char *a_buf, uint32_t a_buf_len) const;
        int32_t add_ipv4(const char *a_buf, uint32_t a_buf_len);
        int32_t add_ipv4_plain(const char *a_buf, uint32_t a_buf_len);
        int32_t add_ipv4_cidr(const char *a_buf, uint32_t a_buf_len);
        int32_t add_ipv6(const char *a_buf, uint32_t a_buf_len);
        int32_t add_ipv6_plain(const char *a_buf, uint32_t a_buf_len);
        int32_t add_ipv6_cidr(const char *a_buf, uint32_t a_buf_len);
        int32_t contains_ipv4(bool &ao_match, const char *a_buf, uint32_t a_buf_len) const;
        int32_t contains_ipv6(bool &ao_match, const char *a_buf, uint32_t a_buf_len) const;
        // -------------------------------------------------
        // nested data structure:
        // array of sets containing prefixes. Prefix length 
        // of each set is array index. To determine whether 
        // an ip address is contained iterate each possible
        // netmask length, starting from smallest 
        // looking for a match. 
        // -------------------------------------------------
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        ipv4_set_t* ipv4_arr;
        ipv6_set_t* ipv6_arr;
};
//! ----------------------------------------------------------------------------
//! types
//! ----------------------------------------------------------------------------
typedef std::list <const std::string *> ip_str_list_t;
//! ----------------------------------------------------------------------------
//! ****************************************************************************
//!                            U T I L I T I E S
//! ****************************************************************************
//! ----------------------------------------------------------------------------
int32_t create_nms_from_str(nms **ao_nms, const std::string &a_str);
int32_t create_nms_from_file(nms **ao_nms, const std::string &a_file);
int32_t create_nms_from_ip_str_list(nms **ao_nms, const ip_str_list_t &a_ip_str_list);
}
#endif
