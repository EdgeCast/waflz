//! ----------------------------------------------------------------------------
//! Copyright Verizon.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _LM_DB_H_
#define _LM_DB_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <stdint.h>
#include <string>
#include <lmdb.h>
#include "waflz/kv_db.h"
#include "waflz/def.h"
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
namespace ns_waflz {
// lmdb val 
typedef struct lm_val {
        uint32_t m_count;
        uint64_t m_ttl_ms;
}lm_val_t;
//! ----------------------------------------------------------------------------
//! lm_db
//! ----------------------------------------------------------------------------
class lm_db : public kv_db {
public:
        // -------------------------------------------------
        // public types
        // -------------------------------------------------
        typedef enum opt_enum
        {
                OPT_LMDB_DIR_PATH = 0,
                OPT_LMDB_READERS = 1,
                OPT_LMDB_MMAP_SIZE = 2
        } opt_t;
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        lm_db(void);
        ~lm_db(void);
        int32_t init(void);
        //: ------------------------------------------------
        //:                  D B   O P S
        //: ------------------------------------------------
        int32_t increment_key(int64_t& ao_result,
                              const char* a_key,
                              uint32_t a_expires_ms);
        int32_t get_key(int64_t &ao_val, const char *a_key, uint32_t a_key_len);
        int32_t set_opt(uint32_t a_opt, const void *a_buf, uint64_t a_len);
        int32_t get_opt(uint32_t a_opt, void **a_buf, uint32_t *a_len);
        int32_t print_all_keys();
        int32_t clear_keys();
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        lm_db(const lm_db &);
        lm_db& operator=(const lm_db &);
        int32_t expire_old_keys(void);
        int32_t get_ttl_and_count(MDB_val* a_val, uint64_t& ao_ttl, uint32_t& ao_count);
        int32_t set_ttl_and_count(MDB_val* a_val, lm_val_t* a_lm_val, uint64_t a_ttl, uint32_t a_count);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        std::string m_db_dir_path;
        uint32_t m_num_readers;
        uint64_t m_mmap_size;
        MDB_env* m_env;
        MDB_txn* m_txn;
        MDB_dbi  m_dbi;
        // -------------------------------------------------
        // timer priority queue -used as min heap
        // -------------------------------------------------
       kv_ttl_pq_t m_kv_ttl_pq;
};
}
#endif

