//! ----------------------------------------------------------------------------
//! Copyright Edgio Inc.
//!
//! \file:    TODO
//! \details: TODO
//!
//! Licensed under the terms of the Apache 2.0 open source license.
//! Please refer to the LICENSE file in the project root for the terms.
//! ----------------------------------------------------------------------------
#include "support/ndebug.h"
#include "waflz/kv_db.h"
#include "waflz/lm_db.h"
#include "waflz/city.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <termios.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>
#include <string.h>
//: ----------------------------------------------------------------------------
//: \details: Print the command line help.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void print_usage(FILE* a_stream, int a_exit_code)
{
        fprintf(a_stream, "Usage: lmdb options\n");
        fprintf(a_stream, "Options:\n");
        fprintf(a_stream, " -h, --help           display this help and exit.\n");
        fprintf(a_stream, " -r, --readmode       load existing db in read mode for printing keys/stats\n");
        fprintf(a_stream, " -w, --writemode      create new db from json file or to get to a key\n");
        fprintf(a_stream, " -m, --memsize        size of db - mandatory in write mode\n");
        fprintf(a_stream, " -d, --dirpath        path where db files will be created\n");
        fprintf(a_stream, " -g, --get            get the value of key\n");
        fprintf(a_stream, " -j, --json           json file to load\n");
        fprintf(a_stream, " -k, --ja3key         name of the key.For eg: ja3:ua\n");
        fprintf(a_stream, " -l, --load           load db\n");
        fprintf(a_stream, " -s, --stats          stats of the database\n");
        fprintf(a_stream, " -n, --num            number of keys in the database\n");
        fprintf(a_stream, " -f, --format         parse updated bot json format\n");
        fprintf(a_stream, " -p, --print          print all keys in the database\n");
        exit(a_exit_code);
}
//: ----------------------------------------------------------------------------
//: \details: main
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int main(int argc, char** argv)
{
        struct option l_options[] = 
                {
                { "help",       0, 0, 'h'},
                { "readmode",   0, 0, 'r'},
                { "writemode",  0, 0, 'w'},
                { "load",       0, 0, 'l'},
                { "print",      0, 0, 'p'},
                { "dirpath",    1, 0, 'd'},
                { "memsize",    1, 0, 'm'},
                { "get",        0, 0, 'g'},
                { "json",       1, 0, 'j'},
                { "stats",      0, 0, 's'},
                { "ja3key",     1, 0, 'k'},
                { "num",        0, 0, 'n'},
                { "format",     0, 0, 'f'},
                { 0, 0, 0, 0}, 
                };
        char l_arg_list[] = "k:d:m:j:hnlrwgsf";
        char l_opt;
        int l_option_index = 0;
        std::string l_arg;
        bool l_read_mode = false;
        bool l_write_mode = false;
        bool l_get_key = false;
        bool l_print_keys = false;
        bool l_num_keys = false;
        bool l_get_stats = false;
        bool l_load_db = false;
        bool l_bot_format = false;
        uint64_t l_mem_size = 0;
        uint64_t l_start_time = 0;
        uint64_t l_end_time = 0;
        std::string l_dir_path;
        std::string l_ja3_key;
        std::string l_json_file_path;
        std::string l_new_json_file_path;
        int l_num = 1;
        while ((l_opt = getopt_long_only(argc, argv, l_arg_list, l_options, &l_option_index)) != -1)
        {
                if(optarg)
                {
                        l_arg = std::string(optarg);
                }
                else
                {
                        l_arg.clear();
                }
                switch(l_opt)
                {
                // -----------------------------------------
                // Help
                // -----------------------------------------
                case 'h':
                {
                        print_usage(stdout, 0);
                        break;
                }
                // -----------------------------------------
                // read mode
                // -----------------------------------------
                case 'r':
                {
                        l_read_mode = true;
                        break;
                }
                // -----------------------------------------
                // write mode
                // -----------------------------------------
                case 'w':
                {
                        l_write_mode = true;
                        break;
                }
                // -----------------------------------------
                // get key
                // -----------------------------------------
                case 'g':
                {
                        l_get_key = true;
                        break;
                }
                // -----------------------------------------
                // stats
                // -----------------------------------------
                case 's':
                {
                        l_get_stats = true;
                        break;
                }
                // -----------------------------------------
                // key name - ja3
                // -----------------------------------------
                case 'k':
                {
                        l_ja3_key = l_arg;
                        break;
                }
                // -----------------------------------------
                // dir path
                // -----------------------------------------
                case 'd':
                {
                        l_dir_path = l_arg;
                        break;
                }
                // -----------------------------------------
                // json file path
                // -----------------------------------------
                case 'j':
                {
                        l_json_file_path = l_arg;
                        break;
                }
                // -----------------------------------------
                // memsize
                // -----------------------------------------
                case 'm':
                {
                        l_mem_size = std::stoull(l_arg);
                        break;
                }
                // -----------------------------------------
                // clear keys
                // -----------------------------------------
                case 'p':
                {
                        l_print_keys = true;
                        break;
                }
                // -----------------------------------------
                // load db
                // -----------------------------------------
                case 'l':
                {
                        l_load_db = true;
                        break;
                }
                // -----------------------------------------
                // get num of keys
                // -----------------------------------------
                case 'n':
                {
                        l_num_keys = true;
                        break;
                }
                // -----------------------------------------
                // parse updated bot db json format
                // -----------------------------------------
                case 'f':
                {
                        l_bot_format = true;
                        break;
                }
                default:
                {
                        print_usage(stdout, -1);
                }
                }
        }
        // -------------------------------------------------
        //  create db object
        // -------------------------------------------------
        int32_t l_s;
        ns_waflz::kv_db* l_db = NULL;
        l_db = reinterpret_cast<ns_waflz::kv_db *>(new ns_waflz::lm_db());

        if (!l_read_mode && 
            !l_write_mode)
        {
                NDBG_PRINT("pls mention a mode to init db\n");
                if(l_db) { delete l_db; l_db = NULL; }
                return -1;
        }
        if (l_dir_path.empty())
        {
                NDBG_PRINT("pls provide db path to read/write\n");
                if(l_db) { delete l_db; l_db = NULL; }
                return -1;
        }
        // -------------------------------------------------
        //  read mode - for debugging like print db stats
        //  and print all keys
        // -------------------------------------------------
        if (l_read_mode)
        {
            l_db->set_opt(ns_waflz::lm_db::OPT_LMDB_DIR_PATH, l_dir_path.c_str(), l_dir_path.length());
            l_db->set_opt(ns_waflz::lm_db::OPT_LMDB_READERS, NULL, 6);
            l_db->set_opt(ns_waflz::lm_db::OPT_LMDB_BOT_MODE, NULL, 1);
            l_s = l_db->init_read_mode();
            if (l_s != 0)
            {
                    NDBG_PRINT("init_read_mode failed -%s\n", l_db->get_err_msg());
                    if(l_db) { delete l_db; l_db = NULL; }
                    return -1;
            }
            if (l_print_keys)
            {
                    l_s = l_db->print_all_keys();
                    if(l_s != 0)
                    {
                            NDBG_PRINT("print all key failed - %s\n", l_db->get_err_msg());
                            if(l_db) { delete l_db; l_db = NULL; }
                            return -1;
                    }
            }
            if (l_get_stats)
            {
                    ns_waflz::db_stats_t l_stats;
                    l_s = l_db->get_db_stats(l_stats);
                    if(l_s != 0)
                    {
                            NDBG_PRINT("getting db stats failed\n");
                            if(l_db) { delete l_db; l_db = NULL; }
                            return -1;
                    }
                    printf("readers allocated - %d\n", l_stats.m_max_readers);
                    printf("readers used - %d\n", l_stats.m_readers_used);
                    printf("pages allocated - %d\n", l_stats.m_max_pages);
                    printf("pages used - %lu\n", l_stats.m_pages_used);
                    printf("resident memory used - %lu\n", l_stats.m_res_mem_used);
                    printf("num of entries in db -%lu\n", l_stats.m_num_entries);
            }
            if (l_num_keys)
            {
                    ns_waflz::db_stats_t l_stats;
                    l_s = l_db->get_db_stats(l_stats);
                    if(l_s != 0)
                    {
                            NDBG_PRINT("getting db stats failed\n");
                            if(l_db) { delete l_db; l_db = NULL; }
                            return -1;
                    }
                    printf("num of entries in db:%lu", l_stats.m_num_entries);
            }
        }
        // -------------------------------------------------
        //  write mode is used for creating db from json
        //  file or to get a single key
        // -------------------------------------------------
        else
        {
                if (l_mem_size == 0)
                {
                        NDBG_PRINT("pls provide mem size for db\n");
                        if(l_db) { delete l_db; l_db = NULL; }
                        return -1;
                }
                l_db->set_opt(ns_waflz::lm_db::OPT_LMDB_DIR_PATH, l_dir_path.c_str(), l_dir_path.length());
                l_db->set_opt(ns_waflz::lm_db::OPT_LMDB_MMAP_SIZE, NULL, l_mem_size);
                l_db->set_opt(ns_waflz::lm_db::OPT_LMDB_BOT_MODE, NULL, 1);
                l_s = l_db->init();
                if (l_s != 0)
                {
                        NDBG_PRINT("db init failed\n");
                        if(l_db) { delete l_db; l_db = NULL; }
                        return -1;

                }
                if (l_load_db)
                {
                        if (l_json_file_path.empty())
                        {
                                NDBG_PRINT("please provide a json file to load\n");
                                if(l_db) { delete l_db; l_db = NULL; }
                                return -1;
                        }
                        struct stat l_stat;
                        int32_t l_s = 0;
                        l_s = stat(l_json_file_path.c_str(), &l_stat);
                        if (l_s != 0)
                        {
                                NDBG_PRINT("Error performing stat on file: %s  Reason: %s",
                                            l_json_file_path.c_str(),
                                            strerror(errno));
                                if(l_db) { delete l_db; l_db = NULL; }
                                return WAFLZ_STATUS_ERROR;
                        }
                        if (!(l_stat.st_mode & S_IFREG))
                        {
                                NDBG_PRINT("Error opening file: %s  Reason: is NOT a regular file",
                                            l_json_file_path.c_str());
                                if(l_db) { delete l_db; l_db = NULL; }
                                return WAFLZ_STATUS_ERROR;
                        }
                        //clear db before loading new file
                        l_s = l_db ->clear_keys();
                        if (l_s != 0)
                        {
                                NDBG_PRINT("clearing keys failed. Reason-%s\n", l_db->get_err_msg());
                                if(l_db) { delete l_db; l_db = NULL; }
                                return -1;
                        }
                        l_s = l_db->load_bot_file(l_json_file_path, l_bot_format);
                        if (l_s != 0)
                        {
                                NDBG_PRINT("load bot file to db failed. Reason-%s\n", l_db->get_err_msg());
                                if(l_db) { delete l_db; l_db = NULL; }
                                return -1;
                        }
                }
                // -------------------------------------------------
                //  get key
                // -------------------------------------------------
                if (l_get_key)
                {
                        if (l_ja3_key.empty())
                        {
                                NDBG_PRINT("Pls provide ja3 key in the format ja3:ua\n");
                                if(l_db) { delete l_db; l_db = NULL; }
                                return -1;
                        }
                        uint64_t l_city_hash = 0;
                        uint32_t l_val;
                        l_city_hash = CityHash64(l_ja3_key.c_str(), l_ja3_key.length());     
                        l_s = l_db->get_key(&l_city_hash, sizeof(l_city_hash), l_val);
                        if(l_s != 0)
                        {
                                NDBG_PRINT("get key failed -%s\n", l_db->get_err_msg());
                                if(l_db) { delete l_db; l_db = NULL; }
                                return -1;
                        }
                        printf("score for key %s is %d\n", l_ja3_key.c_str(), l_val);
                }
        }
cleanup:
        if(l_db) { delete l_db; l_db = NULL; }
        return 0;
}

