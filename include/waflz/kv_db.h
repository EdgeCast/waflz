//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    kv_db.h
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    06/01/2018
//:
//:   Licensed under the Apache License, Version 2.0 (the "License");
//:   you may not use this file except in compliance with the License.
//:   You may obtain a copy of the License at
//:
//:       http://www.apache.org/licenses/LICENSE-2.0
//:
//:   Unless required by applicable law or agreed to in writing, software
//:   distributed under the License is distributed on an "AS IS" BASIS,
//:   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//:   See the License for the specific language governing permissions and
//:   limitations under the License.
//:
//: ----------------------------------------------------------------------------
#ifndef _KV_DB_H_
#define _KV_DB_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include "waflz/def.h"
#include <stdint.h>
// for std::priority_queue
#include <queue>
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
namespace ns_waflz {
// key ttl
typedef struct kv_ttl {
        uint64_t m_ttl_ms;
        std::string *m_key;
        ~kv_ttl() { if(m_key) { delete m_key; m_key = NULL; } }
} kv_ttl_t;
// db stats
typedef struct db_stats {
        uint32_t m_max_readers;
        uint32_t m_readers_used;
        uint32_t m_max_pages;
        uint64_t m_pages_used;
        uint32_t m_page_size;
        uint64_t m_res_mem_used;
        uint64_t m_num_entries;
}db_stats_t;
//: ----------------------------------------------------------------------------
//: Priority queue sorting
//: ----------------------------------------------------------------------------
class pq_compare_events {
public:
        // Returns true if t1 is greater than t2
        bool operator()(kv_ttl_t* t1, kv_ttl_t* t2)
        {
                return (t1->m_ttl_ms > t2->m_ttl_ms);
        }
};
typedef std::priority_queue<kv_ttl_t *, std::vector<kv_ttl_t *>, pq_compare_events> kv_ttl_pq_t;
//: ----------------------------------------------------------------------------
//: kv_db
//: ----------------------------------------------------------------------------
class kv_db {
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        kv_db(void): m_init(false), m_err_msg() {};
        virtual ~kv_db() {};
        virtual int32_t init(void) = 0;
        virtual int32_t increment_key(int64_t &ao_result,
                              const char *a_key,
                              uint32_t a_expires_ms) = 0;
        virtual int32_t get_key(int64_t &ao_val, const char *a_key, uint32_t a_key_len) = 0;
        virtual int32_t print_all_keys(void) = 0;
        virtual int32_t set_opt(uint32_t a_opt, const void *a_buf, uint64_t a_len) = 0;
        virtual int32_t get_opt(uint32_t a_opt, void **a_buf, uint32_t *a_len) = 0;
        virtual int32_t get_db_stats(db_stats_t& a_stats) = 0;
        const char *get_err_msg(void) { return m_err_msg; }
        bool get_init(void) { return m_init; }
protected:
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        bool m_init;
        char m_err_msg[WAFLZ_ERR_LEN];
};
}
#endif
