//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _KV_DB_H_
#define _KV_DB_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#ifdef __cplusplus
#include "waflz/def.h"
#include <stdint.h>
// for std::priority_queue
#include <queue>
#endif
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
#ifndef __cplusplus
typedef struct kv_db_t kv_db;
#endif
#ifdef __cplusplus
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
// bot db val
typedef struct lm_bot_val {
        uint32_t m_score;
        uint32_t m_cust_id;
        char* m_tags;
} lm_bot_val_t;
//! ----------------------------------------------------------------------------
//! Priority queue sorting
//! ----------------------------------------------------------------------------
class pq_compare_events {
public:
        // Returns true if t1 is greater than t2
        bool operator()(kv_ttl_t* t1, kv_ttl_t* t2)
        {
                return (t1->m_ttl_ms > t2->m_ttl_ms);
        }
};
typedef std::priority_queue<kv_ttl_t *, std::vector<kv_ttl_t *>, pq_compare_events> kv_ttl_pq_t;
//! ----------------------------------------------------------------------------
//! kv_db
//! ----------------------------------------------------------------------------
class kv_db {
public:
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        kv_db(void): m_init(false), m_err_msg() {};
        virtual ~kv_db() {};
        virtual int32_t init(void) = 0;
        virtual int32_t init_read_mode(void) = 0;
        virtual int32_t increment_key(int64_t &ao_result,
                              const char *a_key,
                              uint32_t a_expires_ms,
                              bool a_enable_pop_count,
                              bool& a_has_pop_count) = 0;
        virtual int32_t load_bot_file(const std::string& a_js_file_path, bool new_bot_format=false) = 0;
        virtual int32_t get_key(int64_t &ao_val, const char *a_key, uint32_t a_key_len) = 0;
        virtual int32_t get_full_count_for_rl_key(int64_t& ao_val,
                                                  const char* a_key,
                                                  uint32_t a_key_len,
                                                  bool a_missing_error) = 0;
        virtual int32_t get_key(void* a_key, uint32_t a_key_len, uint32_t& ao_val, lm_bot_val* a_bot_val = nullptr, bool new_bot_format = false) = 0;
        virtual int32_t put_key(void* a_key, uint32_t a_key_len, void* a_val, uint32_t a_val_len) = 0;
        virtual int32_t print_all_keys(void) = 0;
        virtual int32_t set_opt(uint32_t a_opt, const void *a_buf, uint64_t a_len) = 0;
        virtual int32_t get_opt(uint32_t a_opt, void **a_buf, uint32_t *a_len) = 0;
        virtual int32_t get_db_stats(db_stats_t& a_stats) = 0;
        virtual int32_t sweep() = 0;
        virtual int32_t clear_keys() = 0;
        const char *get_err_msg(void) { return m_err_msg; }

protected:
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        bool m_init;
        char m_err_msg[WAFLZ_ERR_LEN];
};
#endif
#ifdef __cplusplus
extern "C" {
#endif
kv_db* create_kv_db(const char* a_db_path, uint32_t a_db_path_len);
int32_t cleanup_kv_db(kv_db* a_db);
#ifdef __cplusplus
}
}
#endif
#endif // header
