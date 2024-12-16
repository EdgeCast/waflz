//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#ifndef _REDIS_DB_H_
#define _REDIS_DB_H_
//! ----------------------------------------------------------------------------
//! includes
//! ----------------------------------------------------------------------------
#include <stdint.h>
#include <string>
#include "waflz/kv_db.h"
#include "waflz/def.h"
//! ----------------------------------------------------------------------------
//! fwd decl's
//! ----------------------------------------------------------------------------
struct redisContext;
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! redis_db
//! ----------------------------------------------------------------------------
class redis_db: public kv_db {
public:
        // -------------------------------------------------
        // public types
        // -------------------------------------------------
        typedef enum opt_enum
        {
                OPT_REDIS_HOST = 0,
                OPT_REDIS_PORT = 1,
                OPT_REDIS_SENTINEL = 999
        } opt_t;
        // -------------------------------------------------
        // public methods
        // -------------------------------------------------
        redis_db(void);
        ~redis_db(void);
        int32_t init(void);
        //: ------------------------------------------------
        //:                  D B   O P S
        //: ------------------------------------------------
        int32_t increment_key(int64_t &ao_result,
                              const char *a_key,
                              uint32_t a_expires_ms
                              bool a_enable_pop_count);
        int32_t get_key(int64_t &ao_val, const char *a_key, uint32_t a_key_len);
        int32_t print_all_keys(void);
        int32_t set_opt(uint32_t a_opt, const void *a_buf, uint64_t a_len);
        int32_t get_opt(uint32_t a_opt, void **a_buf, uint32_t *a_len);
        int32_t get_db_stats(db_stats_t& a_stats);
        int32_t sweep();
private:
        // -------------------------------------------------
        // private methods
        // -------------------------------------------------
        // disallow copy/assign
        redis_db(const redis_db &);
        redis_db& operator=(const redis_db &);
        int32_t reconnect(void);
        // -------------------------------------------------
        // private members
        // -------------------------------------------------
        redisContext *m_ctx;
        // -------------------------------------------------
        // config
        // -------------------------------------------------
        std::string m_config_host;
        uint16_t m_config_port;
};
}
#endif
