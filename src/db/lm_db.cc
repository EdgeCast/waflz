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
#include "support/time_util.h"
#include "support/ndebug.h"
#include "liblmdb/lmdb.h"
#include "rapidjson/document.h"
#include "waflz/lm_db.h"
#include "waflz/def.h"
#include <sstream>
#include <fstream>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
namespace ns_waflz {
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
lm_db::lm_db(void):
        kv_db(),
        m_db_dir_path(),
        m_num_readers(6),
        m_mmap_size(10485760),
        m_is_bot_mode(false),
        m_env(NULL),
        m_txn(NULL),
        m_dbi(),
        m_kv_ttl_pq()
{}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
lm_db::~lm_db()
{
        if (m_is_bot_mode)
        {
                mdb_env_close(m_env);
                m_env = NULL;
        }
        // -------------------------------------------------
        // If db exists, sync the env to flush all keys to
        // disk. expire the keys that are created by current
        // process using PQ.
        // -------------------------------------------------
        if ((!m_is_bot_mode) && 
            (m_env != NULL))
        {
                const char* l_path = NULL;
                if(mdb_env_get_path(m_env, &l_path) == MDB_SUCCESS)
                {
                        if(l_path != NULL)
                        {
                                mdb_env_sync(m_env, 1);
                                expire_old_keys();
                                sweep();
                        }
                }
                mdb_env_close(m_env);
                m_env = NULL;
        }
        // -------------------------------------------------
        // clear keys from PQ
        // -------------------------------------------------
        while(!m_kv_ttl_pq.empty())
        {
                kv_ttl_t *l_kv_ttl;
                l_kv_ttl = m_kv_ttl_pq.top();
                if(l_kv_ttl)
                {
                        delete l_kv_ttl;
                        l_kv_ttl = NULL;
                }
                m_kv_ttl_pq.pop();
        }
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t lm_db::init()
{
        int32_t l_s;
        // -------------------------------------------------
        // create env
        // -------------------------------------------------
        l_s = mdb_env_create(&m_env);
        if(l_s != MDB_SUCCESS)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // set max readers
        // -------------------------------------------------
        l_s = mdb_env_set_maxreaders(m_env, m_num_readers);
        if(l_s != MDB_SUCCESS)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // set mmap size. TODO: adjust size after testing
        // -------------------------------------------------
        l_s = mdb_env_set_mapsize(m_env, m_mmap_size);
        if(l_s != MDB_SUCCESS)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // check if db directory exist before env open
        // -------------------------------------------------
        struct stat l_stat;
        l_s = stat(m_db_dir_path.c_str(), &l_stat);
        if(l_s != 0)
        {
                WAFLZ_PERROR(m_err_msg,
                            "Error performing stat on the directory - %s", strerror(errno));
                return  WAFLZ_STATUS_ERROR;
        }
        if(!(S_ISDIR(l_stat.st_mode)))
        {
                WAFLZ_PERROR(m_err_msg,
                            "Error %s is NOT a directory", m_db_dir_path.c_str());
                return WAFLZ_STATUS_ERROR;
        }
        l_s = mdb_env_open(m_env,
                           m_db_dir_path.c_str(), 
                           MDB_WRITEMAP | MDB_MAPASYNC | MDB_NOSYNC | MDB_NOMETASYNC,
                           0666);
        if(l_s != MDB_SUCCESS)
        {
                return WAFLZ_STATUS_ERROR;
        }
        m_init = true;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t lm_db::init_read_mode()
{
        int l_s;
        l_s = mdb_env_create(&m_env);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "env create failed  %d, %s\n",
                             l_s, mdb_strerror(l_s));
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // check if db directory exist before env open
        // -------------------------------------------------
        struct stat l_stat;
        l_s = stat(m_db_dir_path.c_str(), &l_stat);
        if(l_s != 0)
        {
                WAFLZ_PERROR(m_err_msg,
                            "Error performing stat on the directory - %s", strerror(errno));
                return  WAFLZ_STATUS_ERROR;
        }
        if(!(S_ISDIR(l_stat.st_mode)))
        {
                WAFLZ_PERROR(m_err_msg,
                            "Error %s is NOT a directory", m_db_dir_path.c_str());
                return WAFLZ_STATUS_ERROR;
        }
        l_s = mdb_env_open(m_env, m_db_dir_path.c_str(), MDB_RDONLY, 0666);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "env open failed  %d, %s\n",
                             l_s, mdb_strerror(l_s));
                mdb_env_close(m_env);
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t lm_db::set_opt(uint32_t a_opt, const void *a_buf, uint64_t a_len)
{
        switch(a_opt)
        {
        case OPT_LMDB_DIR_PATH:
        {
                m_db_dir_path.assign((char *)a_buf, a_len);
                break;
        }
        case OPT_LMDB_READERS:
        {
                m_num_readers = a_len;
                break;
        }
        case OPT_LMDB_MMAP_SIZE:
        {
                m_mmap_size = a_len;
                break;
        }
        case OPT_LMDB_BOT_MODE:
        {
                m_is_bot_mode = true;
                break;
        }
        default:
        {
                //NDBG_PRINT("Error unsupported option: %d\n", a_opt);
                return WAFLZ_STATUS_ERROR;
        }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t lm_db::get_opt(uint32_t a_opt, void **a_buf, uint32_t *a_len)
{
        switch(a_opt)
        {
        default:
        {
                //NDBG_PRINT("Error unsupported option: %d\n", a_opt);
                return WAFLZ_STATUS_ERROR;
        }
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details: This is used from lmdb_util to debug lmdb.
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
int32_t lm_db::print_all_keys()
{
        int32_t l_s;
        MDB_cursor* l_cur;
        MDB_val l_key, l_val;
        l_s = mdb_txn_begin(m_env, NULL, MDB_RDONLY, &m_txn);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "txn begin failed - %d, %s\n",
                             l_s, mdb_strerror(l_s));
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        l_s = mdb_dbi_open(m_txn, NULL, 0, &m_dbi);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "dbi open failed - %d, %s\n",
                             l_s, mdb_strerror(l_s));
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        l_s = mdb_cursor_open(m_txn, m_dbi, &l_cur);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "cursor openfailed - %d, %s\n",
                             l_s, mdb_strerror(l_s));
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        uint64_t l_counter = 0;
        while ((l_s = mdb_cursor_get(l_cur, &l_key, &l_val, MDB_NEXT)) == 0) {
                std::string key((char*)l_key.mv_data, l_key.mv_size);
                void *ao_bot_val = static_cast<void*>(l_val.mv_data);
                uint32_t l_score = -1, l_cust_id = -1;
                if (ao_bot_val)
                {
                        // -------------------------------------------------
                        // Extract the score from the buffer
                        // -------------------------------------------------
                        l_score = *((uint32_t*)ao_bot_val);
                        printf("Key-%lu, score-%u ",
                           *((long unsigned int*)l_key.mv_data), l_score);
                        if (l_val.mv_size > 4)
                        {
                                // -------------------------------------------------
                                // Extract the customer id from the buffer
                                // -------------------------------------------------
                                l_cust_id = *((uint32_t*)(static_cast<char*>(ao_bot_val)
                                        + sizeof(l_score)));
                                printf("cust_id-%u ",l_cust_id);
                                // -------------------------------------------------
                                // Move the buffer pointer ahead by the size of the
                                // 32-bit integers score & cust_id
                                // -------------------------------------------------
                                char* ptr = static_cast<char*>(ao_bot_val)
                                        + sizeof(l_score)
                                        + sizeof(l_cust_id);
                                // -------------------------------------------------
                                // Extract the tags from the buffer
                                // -------------------------------------------------
                                if (ptr && ptr[0] !='\0')
                                {
                                        printf("tags-%s ",ptr);
                                }
                        }
                        printf("\n");
                }
                l_counter = l_counter + 1;
        }
        printf("Number of keys -%lu\n", l_counter);
        mdb_cursor_close(l_cur);
        mdb_txn_abort(m_txn);
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t lm_db::get_key(int64_t& ao_val, const char* a_key, uint32_t a_key_len)
{
        int32_t l_s;
        // -------------------------------------------------
        // get transcation handle
        // -------------------------------------------------
        l_s = mdb_txn_begin(m_env, NULL, MDB_RDONLY ,&m_txn);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "get_key:txn begin failed - %d, %s\n",
                             l_s, mdb_strerror(l_s));
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get db handle
        // -------------------------------------------------
        l_s = mdb_dbi_open(m_txn, NULL, 0, &m_dbi);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "get_key:dbi open failed - %d, %s\n",
                             l_s, mdb_strerror(l_s));
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // mdb_get
        // -------------------------------------------------
        MDB_val l_key;
        MDB_val l_val;
        l_key.mv_data=(void*)a_key;
        l_key.mv_size= a_key_len;
        l_s = mdb_get(m_txn, m_dbi, &l_key, &l_val);
        if(l_s == MDB_NOTFOUND)
        {
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        if(l_s != 0)
        {
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        if(l_val.mv_data == NULL)
        {
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        ao_val = ((lm_val_t*)l_val.mv_data)->m_count;
        mdb_txn_abort(m_txn);
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t lm_db::get_full_count_for_rl_key(int64_t& ao_val,
                                         const char* a_key,
                                         uint32_t a_key_len,
                                         bool a_missing_error)
{
        int32_t l_s;
        expire_old_keys();
        // -------------------------------------------------
        // get transcation handle
        // -------------------------------------------------
        l_s = mdb_txn_begin(m_env, NULL, 0 ,&m_txn);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "get_full_count_for_rl_key:txn begin failed - %d, %s\n",
                             l_s, mdb_strerror(l_s));
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get db handle
        // -------------------------------------------------
        l_s = mdb_dbi_open(m_txn, NULL, 0, &m_dbi);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "get_full_count_for_rl_key:dbi open failed - %d, %s\n",
                             l_s, mdb_strerror(l_s));
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // mdb_get
        // -------------------------------------------------
        MDB_val l_key;
        MDB_val l_val;
        l_key.mv_data=(void*)a_key;
        l_key.mv_size= a_key_len;
        l_s = mdb_get(m_txn, m_dbi, &l_key, &l_val);
        // -------------------------------------------------
        // leave if missing
        // -------------------------------------------------
        if(l_s == MDB_NOTFOUND)
        {
                mdb_txn_abort(m_txn);
                if (a_missing_error)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // leave if failed to get get
        // -------------------------------------------------
        if(l_s != 0)
        {
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // leave if key found with no data
        // -------------------------------------------------
        if(l_val.mv_data == NULL)
        {
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // at this point the key exists, so cast to proper
        // struct
        // -------------------------------------------------
        lm_val_t *l_p = (lm_val_t*)l_val.mv_data;
        if(l_p == NULL)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // check that we are in the ttl of the given key
        // -------------------------------------------------
        ao_val = 0;
        uint64_t l_now_ms = get_time_ms();
        if(l_now_ms < l_p->m_ttl_ms)
        {
                // -----------------------------------------
                // add count plus pop count if available
                // -----------------------------------------
                ao_val += l_p->m_count;
                if (l_p->m_use_pop_count)
                {
                        ao_val += l_p->m_pop_count;
                }
        }
        mdb_txn_abort(m_txn);
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t lm_db::get_key(void* a_key, uint32_t a_key_len, uint32_t& ao_val, lm_bot_val* a_bot_val, bool a_new_bot_format)
{
        int32_t l_s;
        // -------------------------------------------------
        // get transcation handle
        // -------------------------------------------------
        l_s = mdb_txn_begin(m_env, NULL, 0 ,&m_txn);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "get_key:txn begin failed - %d, %s\n",
                             l_s, mdb_strerror(l_s));
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get db handle
        // -------------------------------------------------
        l_s = mdb_dbi_open(m_txn, NULL, 0, &m_dbi);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "get_key:dbi open failed - %d, %s\n",
                             l_s, mdb_strerror(l_s));
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // mdb_get
        // -------------------------------------------------
        MDB_val l_key;
        MDB_val l_val;
        l_key.mv_data=a_key;
        l_key.mv_size= a_key_len;
        l_s = mdb_get(m_txn, m_dbi, &l_key, &l_val);
        if(l_s == MDB_NOTFOUND)
        {
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_OK;
        }
        if(l_s != 0)
        {
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        if(l_val.mv_data == NULL)
        {
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_OK;
        }
        if (a_new_bot_format && l_val.mv_size > 0)
        {
                void *ao_bot_val = static_cast<void*>(l_val.mv_data);
                if (ao_bot_val)
                {
                        // -------------------------------------------------
                        // Extract the score from the buffer
                        // -------------------------------------------------
                        a_bot_val->m_score = *((uint32_t*)ao_bot_val);
                        // -------------------------------------------------
                        // Extract the customer id from the buffer
                        // -------------------------------------------------
                        a_bot_val->m_cust_id = *((uint32_t*)(static_cast<char*>(ao_bot_val) + sizeof(a_bot_val->m_score)));
                        // -------------------------------------------------
                        // Move the buffer pointer ahead by the size of the
                        // 32-bit integers score & cust_id
                        // -------------------------------------------------
                        char* ptr = static_cast<char*>(ao_bot_val)
                                + sizeof(a_bot_val->m_score)
                                + sizeof(a_bot_val->m_cust_id);
                        // -------------------------------------------------
                        // Extract the tags from the buffer
                        // -------------------------------------------------
                        if (ptr && ptr[0] !='\0')
                        {
                                a_bot_val->m_tags = new char[std::strlen(ptr) + 1];
                                std::strcpy(a_bot_val->m_tags, ptr);
                        }
                }
                else
                {
                        a_bot_val->m_score = 0;
                        a_bot_val->m_cust_id = 0;
                }
        }
        else
        {
                ao_val = *((uint32_t*)l_val.mv_data);
        }
        mdb_txn_abort(m_txn);
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t lm_db::increment_key(int64_t& ao_result,
                             const char* a_key,
                             uint32_t a_expires_ms,
                             bool a_enable_pop_count,
                             bool &a_has_pop_count)
{
        int32_t l_s;
        expire_old_keys();
        // -------------------------------------------------
        // get transcation handle
        // -------------------------------------------------
        l_s = mdb_txn_begin(m_env, NULL, 0 ,&m_txn);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "incr_key:txn begin failed - %d, %s\n",
                             l_s, mdb_strerror(l_s));
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get db handle
        // -------------------------------------------------
        l_s = mdb_dbi_open(m_txn, NULL, 0, &m_dbi);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "incr_key:dbi open failed - %d, %s\n",
                             l_s, mdb_strerror(l_s));
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // mdb_get
        // -------------------------------------------------
        bool l_key_found = false;
        uint64_t l_ttl;
        uint32_t l_key_val = 1;
        MDB_val l_key, l_val;
        l_key.mv_data=(void*)a_key;
        l_key.mv_size= strlen(a_key);
        lm_val_t lm_val;
        l_s = mdb_get(m_txn, m_dbi, &l_key, &l_val);
        if(l_s != MDB_SUCCESS)
        {
                if(l_s != MDB_NOTFOUND)
                {
                        WAFLZ_PERROR(m_err_msg, "incr_key:dbi get failed - %d, %s\n",
                                     l_s, mdb_strerror(l_s));
                        mdb_txn_abort(m_txn);
                        return WAFLZ_STATUS_ERROR;
                }
                // if we don't initialize values in struct
                // it gets garbage values
                lm_val.m_pop_count = 0;
                l_ttl = get_time_ms() + a_expires_ms;
                lm_val.m_ttl_ms = l_ttl;
                lm_val.m_count = l_key_val;
                if(a_enable_pop_count)
                {
                        lm_val.m_use_pop_count = true;
                }
                else
                {
                        lm_val.m_use_pop_count = false;
                }
                l_val.mv_data = static_cast<void*>(&lm_val);
                l_val.mv_size = sizeof(lm_val_t);
        }
        else
        {
                l_key_found = true;
        }
        // -------------------------------------------------
        // mdb_put: zero copy
        // -------------------------------------------------
        lm_val_t *l_p = (lm_val_t*)l_val.mv_data;
        if(l_key_found)
        {
                uint32_t l_count;
                l_s = get_ttl_and_count(&l_val, l_ttl, l_count);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        //TODO:decide abt txn_abort
                        mdb_txn_abort(m_txn);
                        return WAFLZ_STATUS_ERROR;
                }
                uint64_t l_now_ms = get_time_ms();
                if(l_now_ms > l_ttl)
                {
                        l_ttl = l_now_ms + a_expires_ms;
                        l_key_val = 1;
                        l_p->m_pop_count = 0;
                }
                else
                {
                        l_key_val = l_count + 1;
                }
        }
        l_p->m_count = l_key_val;
        l_p->m_ttl_ms = l_ttl;
        l_s = mdb_put(m_txn, m_dbi, &l_key, &l_val, 0);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "incr key:put failed - %d, %s\n",
                             l_s, mdb_strerror(l_s));
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // commit transaction
        // -------------------------------------------------
        l_s = mdb_txn_commit(m_txn);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "incr_key:commit failed - %d,%s\n",
                             l_s, mdb_strerror(l_s));
                return WAFLZ_STATUS_ERROR;
        }
        ao_result = l_key_val;
        if (l_p->m_use_pop_count)
        {
                ao_result += l_p->m_pop_count;
                if(l_p->m_pop_count > 0)
                {
                        a_has_pop_count = true;
                }
        }
        // -------------------------------------------------
        // if new key add to PQ for expiry
        // -------------------------------------------------
        if(!l_key_found)
        {
                kv_ttl_t *l_kv_ttl = new kv_ttl_t();
                std::string *l_k = new std::string(a_key);
                l_kv_ttl->m_ttl_ms = get_time_ms() + a_expires_ms;
                l_kv_ttl->m_key = l_k;
                m_kv_ttl_pq.push(l_kv_ttl);
        }
        return WAFLZ_STATUS_OK;
}
//! ---------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ---------------------------------------------------------------------------
int32_t lm_db::expire_old_keys(void)
{
        int32_t l_s;
        // -------------------------------------------------
        // get transcation handle
        // -------------------------------------------------
        l_s = mdb_txn_begin(m_env, NULL, 0 ,&m_txn);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "expire_keys:txn begin failed - %d, %s\n",
                             l_s, mdb_strerror(l_s));
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get db handle
        // -------------------------------------------------
        l_s = mdb_dbi_open(m_txn, NULL, 0, &m_dbi);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "expire_keys:dbi open failed - %d, %s\n",
                             l_s, mdb_strerror(l_s));
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // pop events off pq until time > now
        // -------------------------------------------------
        while(!m_kv_ttl_pq.empty())
        {
                kv_ttl_t *l_kv_ttl;
                l_kv_ttl = m_kv_ttl_pq.top();
                if(!l_kv_ttl)
                {
                        m_kv_ttl_pq.pop();
                        continue;
                }
                // -------------------------------------------------
                // break if time is not cirrent
                // -------------------------------------------------
                uint64_t l_now_ms = get_time_ms();
                if(l_now_ms < l_kv_ttl->m_ttl_ms)
                {
                        break;
                }
                // -------------------------------------------------
                // remove
                // -------------------------------------------------
                m_kv_ttl_pq.pop();
                if(!l_kv_ttl->m_key)
                {
                        delete l_kv_ttl;
                        l_kv_ttl = NULL;
                        continue;
                }
                // -------------------------------------------------
                // Get the key from db.
                // If key doesn't exist, continue.
                // -------------------------------------------------
                MDB_val l_key, l_val;
                l_key.mv_data = (void*)l_kv_ttl->m_key->c_str();
                l_key.mv_size = l_kv_ttl->m_key->length();
                l_s = mdb_get(m_txn, m_dbi, &l_key, &l_val);
                if(l_s != MDB_SUCCESS)
                {
                        delete l_kv_ttl;
                        l_kv_ttl = NULL;
                        continue;
                }
                // -------------------------------------------------
                // If key exists, delete the key only if value of 
                // ttl in val is not greater than PQ ttl
                // This check is required in the multiple process
                // setup to prevent removing the keys that are
                // currently being counted or recounted by other process
                // after enforcement period.
                // -------------------------------------------------
                uint64_t l_ttl;
                uint32_t l_count;
                l_s = get_ttl_and_count(&l_val,l_ttl, l_count);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        //TRC_ERROR("MDB val corrupted, get ttl and count failed");
                        delete l_kv_ttl;
                        l_kv_ttl = NULL;
                        continue;
                }
                if(l_ttl > l_kv_ttl->m_ttl_ms)
                {   
                        delete l_kv_ttl;
                        l_kv_ttl = NULL;
                        continue;
                }
                // -------------------------------------------------
                // delete. Soft fail on delete because other
                // process PQ also tries to delete
                // -------------------------------------------------
                MDB_val* l_d_val = NULL;
                mdb_del(m_txn, m_dbi, &l_key, l_d_val);
                delete l_kv_ttl;
                l_kv_ttl = NULL;
        }
        // -------------------------------------------------
        // doing batch commit of all deletes
        // -------------------------------------------------
        l_s = mdb_txn_commit(m_txn);
        if(l_s != MDB_SUCCESS)
        {
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//! ---------------------------------------------------------------------------
//! \details load bot scores from json , create cityhash and upload in db
//! \return  TODO
//! \param   TODO
//! ---------------------------------------------------------------------------
int32_t lm_db::load_bot_file(const std::string& a_js_file_path, bool a_new_bot_format)
{
        int32_t l_s;
        std::string l_key, l_bot_score;
        uint32_t l_score;
        uint64_t l_key_hash;
        lm_bot_val_t l_bot_val;
        l_bot_val.m_tags = nullptr;
        void *l_buffer = nullptr;
        size_t l_bot_val_struct_size = 0;
        // -------------------------------------------------
        // load file to stream
        // -------------------------------------------------
        std::ifstream l_file(a_js_file_path);
        if (!l_file.is_open())
        {
                WAFLZ_PERROR(m_err_msg, "unable to open file -%s", a_js_file_path.c_str());    
        }
        std::stringstream l_f_content;
        l_f_content << l_file.rdbuf();
        // -------------------------------------------------
        // parse stream to rapidjson
        // -------------------------------------------------
        rapidjson::Document l_doc;
        l_doc.Parse(l_f_content.str().c_str());
        for (auto& i : l_doc.GetArray())
        {
                if(!i.IsObject())
                {
                        WAFLZ_PERROR(m_err_msg,
                                     "not a valid json object in array");
                        return WAFLZ_STATUS_ERROR;
                        
                }
                // -----------------------------------------
                // error out if missing a levels
                // -----------------------------------------
                if(!(i.HasMember("ja4"))&&
                   !(i.HasMember("asn"))&&
                   !(i.HasMember("ip")))
                {
                        WAFLZ_PERROR(m_err_msg,
                                     "A level field (ja|asn|ip) is missing");
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // error out if missing a score
                // -----------------------------------------
                if(!i.HasMember("score"))
                {
                        WAFLZ_PERROR(m_err_msg,
                                     "A score field is missing");
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // get score value
                // -----------------------------------------
                if (!a_new_bot_format)
                {
                        l_bot_score.assign(i["score"].GetString());
                        l_score = atoi(i["score"].GetString());
                }
                else
                {
                        // -----------------------------------------
                        // get score value
                        // -----------------------------------------
                        l_bot_val.m_score = atoi(i["score"].GetString());
                        l_bot_val_struct_size = sizeof(l_bot_val.m_score);
                        if(i.HasMember("customer_id"))
                        {
                                // -----------------------------------------
                                // get customer id value
                                // -----------------------------------------
                                l_bot_val.m_cust_id = atoi(i["customer_id"].GetString());
                        }
                        else
                        {
                                l_bot_val.m_cust_id = 0;
                        }
                        l_bot_val_struct_size += sizeof(l_bot_val.m_cust_id);
                        // -----------------------------------------
                        // get tags value
                        // -----------------------------------------
                        bool l_has_tags=false;
                        size_t l_bot_tags_size = 0;
                        if (!i.HasMember("tags"))
                        {
                                WAFLZ_PERROR(m_err_msg,
                                             "tags field is missing");
                                // -----------------------------------------
                                // null terminator
                                // -----------------------------------------
                                l_bot_val_struct_size += 1;
                        }
                        else
                        {
                                l_bot_tags_size = i["tags"].GetStringLength();
                                if ( l_bot_tags_size > 0)
                                {
                                        l_has_tags = true;
                                        l_bot_tags_size += 1;
                                        l_bot_val_struct_size += l_bot_tags_size;
                                }
                                else
                                {
                                        // -----------------------------------------
                                        // null terminator
                                        // -----------------------------------------
                                        l_bot_val_struct_size += 1;
                                }
                        }
                        // -----------------------------------------
                        // Create a buffer to hold the struct
                        // -----------------------------------------
                        l_buffer = malloc(l_bot_val_struct_size);
                        if (!l_buffer)
                        {
                                WAFLZ_PERROR(m_err_msg, "mem alloc failure");
                                return WAFLZ_STATUS_ERROR;
                        }
                        // -----------------------------------------
                        // Copy score to buffer
                        // -----------------------------------------
                        memcpy(l_buffer, &l_bot_val.m_score, sizeof(l_bot_val.m_score));
                        // -----------------------------------------
                        // Copy customer id to buffer
                        // -----------------------------------------
                        memcpy(static_cast<char *>(l_buffer) + sizeof(l_bot_val.m_score),
                                &l_bot_val.m_cust_id, sizeof(l_bot_val.m_cust_id));
                        if (l_has_tags)
                        {
                                char l_tags[l_bot_tags_size];
                                strcpy(l_tags, i["tags"].GetString());
                                // -----------------------------------------
                                // copy the tags into the buffer
                                // -----------------------------------------
                                memcpy(static_cast<char *>(l_buffer) + sizeof(l_bot_val.m_score)
                                        + sizeof(l_bot_val.m_cust_id),
                                        &l_tags, l_bot_tags_size);
                        }
                        if (l_bot_tags_size == 0)
                        {
                                // -----------------------------------------
                                // null terminator
                                // -----------------------------------------
                                memcpy(static_cast<char *>(l_buffer) + sizeof(l_bot_val.m_score)
                                        + sizeof(l_bot_val.m_cust_id),
                                        "\0", 1);
                        }
                }
                // -----------------------------------------
                // construct key value
                // -----------------------------------------
                if (i.HasMember("ip")) {l_key.assign(i["ip"].GetString());}
                if (i.HasMember("asn")) {l_key.assign(i["asn"].GetString());}
                if (i.HasMember("ja4")) {l_key.assign(i["ja4"].GetString());}
                if (i.HasMember("user_agent"))
                {
                        l_key.append(":");
                        l_key.append(i["user_agent"].GetString());
                }
                l_key_hash = CityHash64(l_key.c_str(), l_key.length());
                if (!a_new_bot_format)
                {
                        // -----------------------------------------
                        // add key to lmdb
                        // -----------------------------------------
                        l_s = put_key(&l_key_hash, sizeof(l_key_hash), &l_score, sizeof(l_score));
                }
                else
                {
                        // -----------------------------------------
                        // add key to lmdb
                        // -----------------------------------------
                        l_s = put_key(&l_key_hash, sizeof(l_key_hash), l_buffer, l_bot_val_struct_size);
                        // -----------------------------------------
                        // cleanup l_buffer memory
                        // -----------------------------------------
                        if (l_buffer)
                        {
                                free(l_buffer);
                                l_buffer = nullptr;
                        }
                }
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t lm_db::put_key(void* a_key, uint32_t a_key_len, void* a_val, uint32_t a_val_len)
{
        int32_t l_s;
        // -------------------------------------------------
        // get transcation handle
        // -------------------------------------------------
        l_s = mdb_txn_begin(m_env, NULL, 0, &m_txn);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "put_key: get txn handle failed. Reason- %d, %s", 
                             l_s, mdb_strerror(l_s));
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get db handle
        // -------------------------------------------------
        l_s = mdb_dbi_open(m_txn, NULL , 0, &m_dbi);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "put_key:unable to open database. Reason-%d, %s",
                             l_s, mdb_strerror(l_s));
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // mdb_put
        // -------------------------------------------------
        MDB_val l_key, l_val;
        l_key.mv_data = a_key;
        l_key.mv_size = a_key_len;
        l_val.mv_data = a_val;
        l_val.mv_size = a_val_len;
        l_s = mdb_put(m_txn, m_dbi, &l_key, &l_val, 0);
        if(l_s != 0)
        {
                WAFLZ_PERROR(m_err_msg, "put_key:mdb_put failed.Reason -%d, %s",
                             l_s, mdb_strerror(l_s));
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // commit transaction
        // -------------------------------------------------
        l_s = mdb_txn_commit(m_txn);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "put_key:mdb_txn_commit failed-%d,%s\n",
                             l_s, mdb_strerror(l_s));
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        return 0;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t lm_db::clear_keys()
{
        int32_t l_s;
        l_s = mdb_txn_begin(m_env, NULL, 0, &m_txn);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "clear_keys:txn begin failed");
                return WAFLZ_STATUS_ERROR;
        }
        l_s = mdb_dbi_open(m_txn, NULL, 0, &m_dbi);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "clear_keys:dbi open failed");
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        l_s = mdb_drop(m_txn, m_dbi, 0);
        if(l_s != MDB_SUCCESS)
        {
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        l_s = mdb_txn_commit(m_txn);
        if(l_s != MDB_SUCCESS)
        {
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t lm_db::get_ttl_and_count(MDB_val* a_val, uint64_t& ao_ttl, uint32_t& ao_count)
{
        if(a_val == NULL)
        {
                return WAFLZ_STATUS_ERROR;
        }
        lm_val_t* l_v = (lm_val_t*)a_val->mv_data;
        if(l_v == NULL)
        {
                return WAFLZ_STATUS_ERROR;
        }
        ao_ttl = l_v->m_ttl_ms;
        ao_count = l_v->m_count;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details TODO
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t lm_db::get_db_stats(db_stats_t& a_stats)
{
        int32_t l_s;
        MDB_envinfo l_einfo;
        MDB_stat l_stat;
        l_s = mdb_env_stat(m_env, &l_stat);
        if(l_s !=  MDB_SUCCESS)
        {
                return WAFLZ_STATUS_ERROR;
        }
        l_s = mdb_env_info(m_env, &l_einfo);
        if(l_s != MDB_SUCCESS)
        {
                return WAFLZ_STATUS_ERROR;
        }
        a_stats.m_max_readers = l_einfo.me_maxreaders;
        a_stats.m_readers_used = l_einfo.me_numreaders;
        a_stats.m_max_pages = l_einfo.me_mapsize / l_stat.ms_psize;
        a_stats.m_pages_used = l_stat.ms_leaf_pages + l_stat.ms_branch_pages + l_stat.ms_overflow_pages;
        a_stats.m_page_size = l_stat.ms_psize;
        a_stats.m_res_mem_used = a_stats.m_pages_used * a_stats.m_page_size;
        a_stats.m_num_entries = l_stat.ms_entries;
        return WAFLZ_STATUS_OK;
}
//! ----------------------------------------------------------------------------
//! \details delete all expired keys from db
//! \return  TODO
//! \param   TODO
//! ----------------------------------------------------------------------------
int32_t lm_db::sweep()
{
        int32_t l_s;
        MDB_cursor* l_cur;
        MDB_val l_key, l_val;
        l_s = mdb_txn_begin(m_env, NULL, 0, &m_txn);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "sweep:txn begin failed");
                return WAFLZ_STATUS_ERROR;
        }
        l_s = mdb_dbi_open(m_txn, NULL, 0, &m_dbi);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "sweep:dbi open failed");
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get cursor handle
        // -------------------------------------------------
        l_s = mdb_cursor_open(m_txn, m_dbi, &l_cur);
        if(l_s != MDB_SUCCESS)
        {
                WAFLZ_PERROR(m_err_msg, "sweep:cursor open failed-%d, %s",
                             l_s, mdb_strerror(l_s));
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // parse entire db using cursor and delete all
        // expired keys
        // -------------------------------------------------
        uint64_t l_ttl, l_now_ms;
        uint32_t l_count;
        while ((l_s = mdb_cursor_get(l_cur, &l_key, &l_val, MDB_NEXT)) == 0) 
        {
                l_s = get_ttl_and_count(&l_val, l_ttl, l_count);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        WAFLZ_PERROR(m_err_msg, "sweep:get ttl_and count failed");
                        continue;
                }
                l_now_ms = get_time_ms();
                if (l_ttl < l_now_ms)
                {
                        MDB_val* l_d_val = NULL;
                        l_s = mdb_del(m_txn, m_dbi, &l_key, l_d_val);
                        if(l_s != 0)
                        {
                                WAFLZ_PERROR(m_err_msg,"sweep::delete failed");
                                continue;
                        }
                }
        }
        // -------------------------------------------------
        // close cursor and batch commit
        // -------------------------------------------------
        mdb_cursor_close(l_cur);
        l_s = mdb_txn_commit(m_txn);
        if(l_s != MDB_SUCCESS)
        {
                mdb_txn_abort(m_txn);
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}

//! ----------------------------------------------------------------------------
//! \details C binding for third party lib to create a kv db object rl counting
//! \return  an engine object
//! \param   void
//! ----------------------------------------------------------------------------
extern "C" kv_db* create_kv_db(const char* a_db_path,
                               uint32_t a_db_path_len)
{
        int32_t l_s;
        ns_waflz::kv_db* l_db =reinterpret_cast<ns_waflz::kv_db*>(new ns_waflz::lm_db());
        l_db->set_opt(ns_waflz::lm_db::OPT_LMDB_DIR_PATH, a_db_path, a_db_path_len);
        l_s = l_db->init();
        if(l_s != WAFLZ_STATUS_OK)
        {
                return NULL;
        }
        return l_db;
}
//! ----------------------------------------------------------------------------
//! \details C binding for third party lib to cleanup kv object
//! \return  an engine object
//! \param   void
//! ----------------------------------------------------------------------------
extern "C" int32_t cleanup_kv_db(kv_db* a_db)
{
        if(a_db)
        {
                delete a_db;
                a_db = NULL;
        }
        return WAFLZ_STATUS_OK;
}
}


