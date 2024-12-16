// -----------------------------------------------------------------------------
// std includes
// -----------------------------------------------------------------------------
#include <chrono>
#include <iostream>
#include <unistd.h>
#include <algorithm>
#include <vector>
#include <iomanip>
#include <locale>
#include <sstream>
#include <sys/stat.h>
// -----------------------------------------------------------------------------
// waflz includes
// -----------------------------------------------------------------------------
#include "waflz/limit.h"
#include "waflz/enforcer.h"
#include "waflz/rqst_ctx.h"
#include "waflz/lm_db.h"
#include "support/time_util.h"
// -----------------------------------------------------------------------------
// protobuff includes
// -----------------------------------------------------------------------------
#include "limit.pb.h"
// -----------------------------------------------------------------------------
// globals
// -----------------------------------------------------------------------------
static ns_waflz::rqst_ctx_callbacks GS_callbacks = {
    NULL, //ns_waflz_server::get_rqst_ip_cb,
    NULL, // ns_waflz_server::get_rqst_host_cb,
    NULL, // ns_waflz_server::get_rqst_port_cb,
    NULL, // ns_waflz_server::get_rqst_scheme_cb,
    NULL, // ns_waflz_server::get_rqst_protocol_cb,
    NULL, // ns_waflz_server::get_rqst_line_cb,
    NULL, // ns_waflz_server::get_rqst_method_cb,
    NULL, // ns_waflz_server::get_rqst_url_cb,
    NULL, // ns_waflz_server::get_rqst_uri_cb,
    NULL, // ns_waflz_server::get_rqst_path_cb,
    NULL, // ns_waflz_server::get_rqst_query_str_cb,
    NULL, // ns_waflz_server::get_rqst_header_size_cb, 
    NULL, //get_rqst_header_w_key_cb,
    NULL, // ns_waflz_server::get_rqst_header_w_idx_cb,
    NULL, // ns_waflz_server::get_rqst_body_str_cb,
    NULL, //get_rqst_local_addr_cb,
    NULL, //get_rqst_canonical_port_cb,
    NULL, //get_rqst_apparent_cache_status_cb,
    NULL, //get_rqst_bytes_out_cb,
    NULL, //get_rqst_bytes_in_cb,
    NULL, // ns_waflz_server::get_rqst_uuid_cb, //get_rqst_req_id_cb,
    NULL, // ns_waflz_server::get_cust_id_cb, //get_cust_id_cb
    NULL, // ns_waflz_server::get_rqst_ja3_md5,
    NULL, // ns_waflz_server::get_recaptcha_subr_cb,
    NULL, // ns_waflz_server::get_team_id_cb,
    NULL, // env id
    NULL, // ns_waflz_server::get_rqst_backend_port_cb,
};
// -----------------------------------------------------------------------------
//
// -----------------------------------------------------------------------------
static int remove_dir( const std::string a_dir )
{
    // -----------------------------------------------------
    // get stat on a_dir 
    // -----------------------------------------------------
    struct stat l_stats;
    int l_s = stat(a_dir.c_str(), &l_stats);
    // -----------------------------------------------------
    // leave if we cant get stat (ie: doesnt exist) 
    // -----------------------------------------------------
    if (l_s != 0) { return 0; }
    // -----------------------------------------------------
    // unlink the data and lock file 
    // -----------------------------------------------------
    unlink((a_dir + "/data.mdb").c_str());
    unlink((a_dir + "/lock.mdb").c_str());
    // -----------------------------------------------------
    // remove the a_dir 
    // -----------------------------------------------------
    l_s = rmdir(a_dir.c_str());
    // -----------------------------------------------------
    // report error if we were unable to remove the a_dir
    // -----------------------------------------------------
    if (l_s != 0) { return -1; }
    // -----------------------------------------------------
    // report success 
    // -----------------------------------------------------
    return 0;
}
// -----------------------------------------------------------------------------
//
// -----------------------------------------------------------------------------
ns_waflz::kv_db* generate_rl_db( std::string a_dir = "/tmp/test_lmdb" )
{
    // -----------------------------------------------------
    // create lmdb object
    // -----------------------------------------------------
    ns_waflz::kv_db* l_db = reinterpret_cast<ns_waflz::kv_db*>(new ns_waflz::lm_db());
    // -----------------------------------------------------
    // create the lmdb a_dir 
    // -----------------------------------------------------
    int l_s = remove_dir(a_dir);
    if (l_s != WAFLZ_STATUS_OK)
    {
        std::cout << "failed to remove a_dir." << std::endl;
        if (l_db) { delete l_db; l_db = nullptr; }
        return l_db;
    }
    l_s = mkdir(a_dir.c_str(), 0700);
    if (l_s != WAFLZ_STATUS_OK)
    {
        std::cout << "failed to make a_dir." << std::endl;
        if (l_db) { delete l_db; l_db = nullptr; }
        return l_db;
    }
    // -----------------------------------------------------
    // set lmdb options 
    // -----------------------------------------------------
    l_db->set_opt(ns_waflz::lm_db::OPT_LMDB_DIR_PATH, a_dir.c_str(), a_dir.length());
    l_db->set_opt(ns_waflz::lm_db::OPT_LMDB_READERS, NULL, 6);
    l_db->set_opt(ns_waflz::lm_db::OPT_LMDB_MMAP_SIZE, NULL, 10485760);
    // -----------------------------------------------------
    // init l_db
    // -----------------------------------------------------
    l_s = l_db->init();
    if ( l_s != WAFLZ_STATUS_OK )
    {
        const char* l_err_msg = l_db->get_err_msg();
        std::cout << "failed to create l_db: " << std::string(l_err_msg, strlen(l_err_msg)) << std::endl;
        if (l_db) { delete l_db; l_db = nullptr; }
    }
    // -----------------------------------------------------
    // return l_db
    // -----------------------------------------------------
    return l_db;
}
// -----------------------------------------------------------------------------
//
// -----------------------------------------------------------------------------
std::string generate_rand_string( int a_string_size )
{
    // -----------------------------------------------------
    // lambda function to get a random char 
    // -----------------------------------------------------
    auto l_rand_char = []() -> char
    {
        static auto& chars = (
            "0123456789"
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        );
        const size_t max_size = sizeof(chars) - 1;
        return chars[ rand() % max_size ];
    };
    // -----------------------------------------------------
    // create a string of random chars
    // -----------------------------------------------------
    std::string l_rand_str(a_string_size, 0);
    std::generate_n( l_rand_str.begin(), a_string_size, l_rand_char );
    // -----------------------------------------------------
    // return the random string
    // -----------------------------------------------------
    return l_rand_str;
}
// -----------------------------------------------------------------------------
//
// -----------------------------------------------------------------------------
std::string generate_rand_ipv4( )
{
    // -----------------------------------------------------
    // string stream to hold l_ip
    // -----------------------------------------------------
    std::stringstream l_ip;
    // -----------------------------------------------------
    // load 4 octets seperated by "."s
    // -----------------------------------------------------
    for ( int i_index = 0; i_index < 3; i_index++ )
    {
        l_ip << rand() % 256;
        l_ip << ".";
    }
    l_ip << rand() % 256;
    // -----------------------------------------------------
    // return the l_ip
    // -----------------------------------------------------
    return l_ip.str();
}
// -----------------------------------------------------------------------------
//
// -----------------------------------------------------------------------------
std::chrono::nanoseconds measure_cityhash_time( int a_string_size, int a_runs = 100000 )
{
    // -----------------------------------------------------
    // create time counter and test string 
    // -----------------------------------------------------
    std::chrono::nanoseconds ao_total_time = std::chrono::nanoseconds::zero();
    std::string l_key = generate_rand_string( a_string_size );
    // -----------------------------------------------------
    // perform independent a_runs 
    // -----------------------------------------------------
    for ( int i_index = 0; i_index <= a_runs; i_index++ )
    {
        // -------------------------------------------------
        // l_start timer 
        // -------------------------------------------------
        std::chrono::time_point<std::chrono::high_resolution_clock> l_start = std::chrono::high_resolution_clock::now();
        // -------------------------------------------------
        // perform hash
        // -------------------------------------------------
        CityHash64(l_key.c_str(), l_key.length());
        // -------------------------------------------------
        // stop timer 
        // -------------------------------------------------
        std::chrono::time_point<std::chrono::high_resolution_clock> l_end = std::chrono::high_resolution_clock::now();
        // -------------------------------------------------
        // add run time to total elapsed time
        // -------------------------------------------------
        std::chrono::nanoseconds l_run_time = std::chrono::duration_cast<std::chrono::nanoseconds>(l_end - l_start);
        ao_total_time += l_run_time;
    }
    // -----------------------------------------------------
    // return total time elapsed 
    // -----------------------------------------------------
    return ao_total_time;
}
// -----------------------------------------------------------------------------
//
// -----------------------------------------------------------------------------
int count_digits( int a_num )
{
    // -----------------------------------------------------
    // l_count the amount of digits in a number 
    // -----------------------------------------------------
    int l_count = 0;
    while ( a_num != 0 ) {
        a_num = a_num / 10;
        l_count++;
    }
    // -----------------------------------------------------
    // return the digit l_count plus some padding to account
    // for commas when printing the number 
    // -----------------------------------------------------
    return l_count + (l_count / 3);
}
// -----------------------------------------------------------------------------
// locale to print numbers with commas
// -----------------------------------------------------------------------------
class comma_numpunct : public std::numpunct<char>
{
  protected:
    virtual char do_thousands_sep() const
    {
        return ',';
    }

    virtual std::string do_grouping() const
    {
        return "\03";
    }
};
// -----------------------------------------------------------------------------
//
// -----------------------------------------------------------------------------
void test_cityhash( int a_runs = 100000 )
{
    // -----------------------------------------------------
    // print title of test
    // -----------------------------------------------------
    std::cout << "Performance testing for CityHash at different string sizes (100,000 runs):" << std::endl;
    // -----------------------------------------------------
    // create sizes to test
    // -----------------------------------------------------
    static std::vector<int> l_test_sizes{
        5, 10, 100, 1000, 10000,
        64000, 128000, 192000,
        256000, 320000, 384000,
        1000000, 5000000, 10000000,
    };
    static int l_large_degree = count_digits( l_test_sizes.back() );
    static int l_small_degree = l_large_degree - 2;
    // -----------------------------------------------------
    // print table header
    // -----------------------------------------------------
    std::cout << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(l_small_degree) << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::endl;
    std::cout << "|" << std::setw(l_large_degree) << std::setfill(' ') << "bytes"
              << "|" << std::setw(l_small_degree) << std::setfill(' ') << "kb"
              << "|" << std::setw(21)             << std::setfill(' ') << "total nano seconds"
              << "|" << std::setw(21)             << std::setfill(' ') << "average nano seconds"
              << "|" << std::setw(21)             << std::setfill(' ') << "total mili seconds"
              << "|" << std::setw(21)             << std::setfill(' ') << "average mili seconds"
              << "|" << std::endl;
    std::cout << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(l_small_degree) << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::endl;
    // -----------------------------------------------------
    // for each test l_size
    // -----------------------------------------------------
    for ( auto i_it = l_test_sizes.begin(); i_it != l_test_sizes.end(); i_it++ )
    {
        // -------------------------------------------------
        // run each test
        // -------------------------------------------------
        std::chrono::nanoseconds l_elapsed_time = measure_cityhash_time(*i_it, a_runs);
        // -------------------------------------------------
        // calculate l_size in bytes and kilobytes
        // -------------------------------------------------
        int l_size_in_b = ((*i_it) * sizeof(char));
        int l_size_in_kb = ((*i_it) * sizeof(char)) / 1024;
        // -------------------------------------------------
        // calculate test time in nano seconds and average
        // time in nano seconds
        // -------------------------------------------------
        auto l_time_in_ns = l_elapsed_time.count();
        auto l_avg_time_in_ns = (*i_it == 0) ? 0.0 : ((double) l_time_in_ns) / (100000.0);
        // -------------------------------------------------
        // calculate test time in mili seconds and average
        // time in mili seconds
        // -------------------------------------------------
        auto l_time_in_ms = std::chrono::duration_cast<std::chrono::milliseconds>(l_elapsed_time).count();
        auto l_avg_time_in_ms = (*i_it == 0) ? 0.0 : ((double) l_time_in_ms) / (100000.0);
        // -------------------------------------------------
        // print results to stream
        // -------------------------------------------------
        std::cout << "|" << std::setw(l_large_degree) << std::setfill(' ') << l_size_in_b
                  << "|" << std::setw(l_small_degree) << std::setfill(' ') << l_size_in_kb
                  << "|" << std::setw(21)             << std::setfill(' ') << l_time_in_ns
                  << "|" << std::setw(21)             << std::setfill(' ') << l_avg_time_in_ns
                  << "|" << std::setw(21)             << std::setfill(' ') << l_time_in_ms
                  << "|" << std::setw(21)             << std::setfill(' ') << l_avg_time_in_ms
                  << "|" << std::endl;
    }
    // -----------------------------------------------------
    // print l_end of table
    // -----------------------------------------------------
    std::cout << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(l_small_degree) << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::endl;
}
// -----------------------------------------------------------------------------
//
// -----------------------------------------------------------------------------
std::chrono::nanoseconds measure_limit_process( int a_num_of_args, ns_waflz::kv_db* a_db, int a_runs = 100000 )
{
    // -----------------------------------------------------
    // create time counter and l_rqst context
    // -----------------------------------------------------
    std::chrono::nanoseconds ao_total_time = std::chrono::nanoseconds::zero();
    // -----------------------------------------------------
    // create l_rqst context
    // -----------------------------------------------------
    ns_waflz::rqst_ctx* l_rqst = new ns_waflz::rqst_ctx((void*)nullptr, 0, 0, &GS_callbacks, false, false);
    // -----------------------------------------------------
    // create limit proto
    // -----------------------------------------------------
    waflz_pb::limit* l_limit_pb = new waflz_pb::limit();
    l_limit_pb->set_duration_sec(10);
    l_limit_pb->set_id("test:D");
    l_limit_pb->set_num(5);
    // -----------------------------------------------------
    // setup l_rqst context and limit based on run l_size
    //
    // NOTE: maps arent cleared in l_rqst ctx because they 
    // usually only contain values also found in the lists.
    // in this case we didnt populate the list - so we have
    // to clear manually 
    // -----------------------------------------------------
    std::vector<char*> l_cleanup_list;
    if ( a_num_of_args >= 1 )
    {
        l_rqst->m_src_addr = ns_waflz::data_t{"255.255.255.255", strlen("255.255.255.255")};
        l_limit_pb->add_keys("IP");
    }
    if ( a_num_of_args >= 2 )
    {
        std::string l_ua = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36";
        char* l_raw_ua = new char[l_ua.length()];
        strcpy(l_raw_ua, l_ua.c_str());
        l_cleanup_list.push_back(l_raw_ua);
        l_rqst->m_header_map.insert(std::make_pair<ns_waflz::data_t, ns_waflz::data_t>(
            ns_waflz::data_t{"User-Agent", (uint32_t)strlen("User-Agent")},
            ns_waflz::data_t{l_raw_ua, (uint32_t)l_ua.length()}
        ));
        l_limit_pb->add_keys("USER_AGENT");
    }
    if ( a_num_of_args >= 3 )
    {
        l_rqst->m_src_asn_str.m_len = asprintf(
            &(l_rqst->m_src_asn_str.m_data),
            "%s",
            "asn str :D"
        );
        l_limit_pb->add_keys("ASN");
    }
    if ( a_num_of_args >= 4 )
    {
        l_rqst->m_virt_ssl_client_ja3_md5 = ns_waflz::data_t{ "253714f62c0a1e6869fe8ba6a45a0588", strlen("253714f62c0a1e6869fe8ba6a45a0588") };
        l_limit_pb->add_keys("JA3");
    }
    if ( a_num_of_args >= 5 )
    {
        // -------------------------------------------------
        // anything after 4 a_num_of_args is considered a
        // header / cookie / arg
        // -------------------------------------------------
        for ( int i_index = a_num_of_args - 5; i_index >= 0; i_index-- )
        {
            // ---------------------------------------------
            // decide which map this will go in
            // ---------------------------------------------
            int l_location = i_index % 3;
            // ---------------------------------------------
            // create l_key and l_val for entry
            // ---------------------------------------------
            std::string l_key = "test_key_" + std::to_string(i_index);
            char* l_raw_key = new char[l_key.length()];
            strcpy(l_raw_key, l_key.c_str());
            l_cleanup_list.push_back(l_raw_key);
            std::string l_val = generate_rand_string(64000);
            char* l_raw_val = new char[l_val.length()];
            strcpy(l_raw_val, l_val.c_str());
            l_cleanup_list.push_back(l_raw_val);
            // ---------------------------------------------
            // header
            // ---------------------------------------------
            if (l_location == 0)
            {
                l_rqst->m_header_map.insert(std::make_pair<ns_waflz::data_t, ns_waflz::data_t>(
                    ns_waflz::data_t(l_raw_key, (uint32_t)l_key.length()),
                    ns_waflz::data_t{l_raw_val, (uint32_t)l_val.length()}
                ));
                l_limit_pb->add_keys("HEADER:" + l_key);
            }
            // ---------------------------------------------
            // cookie
            // ---------------------------------------------
            else if (l_location == 1)
            {
                l_rqst->m_cookie_map.insert(std::make_pair<ns_waflz::data_t, ns_waflz::data_t>(
                    ns_waflz::data_t(l_raw_key, (uint32_t)l_key.length()),
                    ns_waflz::data_t{l_raw_val, (uint32_t)l_val.length()}
                ));
                l_limit_pb->add_keys("COOKIE:" + l_key);
            }
            // ---------------------------------------------
            // arg
            // ---------------------------------------------
            else if (l_location == 2)
            {
                l_rqst->m_query_arg_map.insert(std::make_pair<ns_waflz::data_t, ns_waflz::data_t>(
                    ns_waflz::data_t(l_raw_key, (uint32_t)l_key.length()),
                    ns_waflz::data_t{l_raw_val, (uint32_t)l_val.length()}
                ));
                l_limit_pb->add_keys("ARGS:" + l_key);
            }
        }
    }
    // -----------------------------------------------------
    // create limit
    // -----------------------------------------------------
    ns_waflz::limit* l_test_limit = new ns_waflz::limit(*a_db);
    if ( l_test_limit->load(l_limit_pb) != WAFLZ_STATUS_OK )
    {
        const char* l_err_msg = l_test_limit->get_err_msg();
        std::cout << "failed to init limit: " << std::string(l_err_msg, strlen(l_err_msg)) << std::endl;
        if (l_limit_pb) { delete l_limit_pb; l_limit_pb = nullptr; }
        if (l_test_limit) { delete l_test_limit; l_test_limit = nullptr; }
        if (l_rqst) { delete l_rqst; l_rqst = nullptr; }
        return ao_total_time;
    }
    // -----------------------------------------------------
    // other stuff for limit run 
    // -----------------------------------------------------
    bool l_exceeds = false;
    const waflz_pb::condition_group *l_cg = NULL;
    const std::string l_s_id = "__na__";
    // -----------------------------------------------------
    // perform independent a_runs 
    // -----------------------------------------------------
    for ( int i_index = 0; i_index <= a_runs; i_index++ )
    {
        // -------------------------------------------------
        // l_start timer 
        // -------------------------------------------------
        std::chrono::time_point<std::chrono::high_resolution_clock> l_start = std::chrono::high_resolution_clock::now();
        // -------------------------------------------------
        // perform process
        // -------------------------------------------------
        int l_s = l_test_limit->process(l_exceeds, &l_cg, l_s_id, l_rqst, true);
        // -------------------------------------------------
        // stop timer 
        // -------------------------------------------------
        std::chrono::time_point<std::chrono::high_resolution_clock> l_end = std::chrono::high_resolution_clock::now();
        // -------------------------------------------------
        // check for error 
        // -------------------------------------------------
        if(l_s != WAFLZ_STATUS_OK)
        {
            const char* l_err_msg = l_test_limit->get_err_msg();
            std::cout << "error processing limit: " << std::string(l_err_msg, strlen(l_err_msg)) << std::endl;
            break;
        }
        // -------------------------------------------------
        // add run time to total elapsed time
        // -------------------------------------------------
        std::chrono::nanoseconds l_run_time = std::chrono::duration_cast<std::chrono::nanoseconds>(l_end - l_start);
        ao_total_time += l_run_time;
    }
    // -----------------------------------------------------
    // delete all entries made in the l_rqst ctx
    // -----------------------------------------------------
    for (auto i_it = l_cleanup_list.begin(); i_it != l_cleanup_list.end(); i_it++)
    {
        if ( *i_it ) { delete[] *i_it; }
    }
    // -----------------------------------------------------
    // return total time elapsed 
    // -----------------------------------------------------
    if (l_limit_pb) { delete l_limit_pb; l_limit_pb = nullptr; }
    if (l_test_limit) { delete l_test_limit; l_test_limit = nullptr; }
    if (l_rqst) { delete l_rqst; l_rqst = nullptr; }
    return ao_total_time;
}
// -----------------------------------------------------------------------------
//
// -----------------------------------------------------------------------------
void test_limit_process(ns_waflz::kv_db* a_db, int a_runs = 100000)
{
    // -----------------------------------------------------
    // print title of test
    // -----------------------------------------------------
    std::cout << "Performance testing for limit.process() with different amount of args (" << a_runs << " runs):" << std::endl;
    // -----------------------------------------------------
    // create sizes to test
    // -----------------------------------------------------
    std::vector<int> l_test_sizes{
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12
    };
    int l_large_degree = count_digits( l_test_sizes.back() ) + 2;
    // -----------------------------------------------------
    // print table header
    // -----------------------------------------------------
    std::cout << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(8)              << std::setfill('-') << "-"
              << "|" << std::setw(8)              << std::setfill('-') << "-"
              << "|" << std::setw(8)              << std::setfill('-') << "-"
              << "|" << std::setw(16)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::endl;
    std::cout << "|" << std::setw(l_large_degree) << std::setfill(' ') << "#"
              << "|" << std::setw(l_large_degree) << std::setfill(' ') << "IP"
              << "|" << std::setw(l_large_degree) << std::setfill(' ') << "UA"
              << "|" << std::setw(l_large_degree) << std::setfill(' ') << "ASN"
              << "|" << std::setw(l_large_degree) << std::setfill(' ') << "JA3"
              << "|" << std::setw(8)              << std::setfill(' ') << "HEADERS"
              << "|" << std::setw(8)              << std::setfill(' ') << "COOKIES"
              << "|" << std::setw(8)              << std::setfill(' ') << "ARGS"
              << "|" << std::setw(16)             << std::setfill(' ') << "total bytes"
              << "|" << std::setw(21)             << std::setfill(' ') << "total nano seconds"
              << "|" << std::setw(21)             << std::setfill(' ') << "average nano seconds"
              << "|" << std::setw(21)             << std::setfill(' ') << "total mili seconds"
              << "|" << std::setw(21)             << std::setfill(' ') << "average mili seconds"
              << "|" << std::endl;
    std::cout << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(8)              << std::setfill('-') << "-"
              << "|" << std::setw(8)              << std::setfill('-') << "-"
              << "|" << std::setw(8)              << std::setfill('-') << "-"
              << "|" << std::setw(16)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::endl;
    // -----------------------------------------------------
    // for each test l_size
    // -----------------------------------------------------
    for ( auto i_it = l_test_sizes.begin(); i_it != l_test_sizes.end(); i_it++ )
    {
        // -------------------------------------------------
        // run each test
        // -------------------------------------------------
        std::chrono::nanoseconds l_elapsed_time = measure_limit_process(*i_it, a_db, a_runs);
        // -------------------------------------------------
        // calculate test time in nano seconds and average
        // time in nano seconds
        // -------------------------------------------------
        auto l_time_in_ns = l_elapsed_time.count();
        auto l_avg_time_in_ns = (*i_it == 0) ? 0.0 : ((double) l_time_in_ns) / (100000.0);
        // -------------------------------------------------
        // calculate test time in mili seconds and average
        // time in mili seconds
        // -------------------------------------------------
        auto l_time_in_ms = std::chrono::duration_cast<std::chrono::milliseconds>(l_elapsed_time).count();
        auto l_avg_time_in_ms = (*i_it == 0) ? 0.0 : ((double) l_time_in_ms) / (100000.0);
        // -------------------------------------------------
        // calculating amount of each type of counting
        // group
        // -------------------------------------------------
        bool l_has_ip = *i_it >= 1;
        bool l_has_ua = *i_it >= 2;
        bool l_has_asn = *i_it >= 3;
        bool l_has_ja3 = *i_it >= 4;
        int  l_amount_of_headers = (*i_it >= 5) ? ((*i_it - 5) / 3) + 1 : 0;
        int  l_amount_of_cookies = (*i_it >= 6) ? ((*i_it - 6) / 3) + 1 : 0;
        int  l_amount_of_args = (*i_it >= 7) ? ((*i_it - 7) / 3) + 1 : 0;
        // -------------------------------------------------
        // calculating total l_size of l_rqst
        // -------------------------------------------------
        uint32_t l_size = 0;
        if (l_has_ip) { l_size += sizeof("255.255.255.255") + 1; }
        if (l_has_ua) { l_size += sizeof("Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36") + 1; }
        if (l_has_asn) { l_size += sizeof("test asn :D") + 1; }
        if (l_has_ja3) { l_size += sizeof("253714f62c0a1e6869fe8ba6a45a0588") + 1; }
        if (*i_it >= 5) { l_size += 64000 * (*i_it - 4); }
        // -------------------------------------------------
        // print l_end of table
        // -------------------------------------------------
        std::cout << "|" << std::setw(l_large_degree) << std::setfill(' ') << *i_it
                  << "|" << std::setw(l_large_degree) << std::setfill(' ') << l_has_ip
                  << "|" << std::setw(l_large_degree) << std::setfill(' ') << l_has_ua
                  << "|" << std::setw(l_large_degree) << std::setfill(' ') << l_has_asn
                  << "|" << std::setw(l_large_degree) << std::setfill(' ') << l_has_ja3
                  << "|" << std::setw(8)              << std::setfill(' ') << l_amount_of_headers
                  << "|" << std::setw(8)              << std::setfill(' ') << l_amount_of_cookies
                  << "|" << std::setw(8)              << std::setfill(' ') << l_amount_of_args
                  << "|" << std::setw(16)             << std::setfill(' ') << l_size
                  << "|" << std::setw(21)             << std::setfill(' ') << l_time_in_ns
                  << "|" << std::setw(21)             << std::setfill(' ') << l_avg_time_in_ns
                  << "|" << std::setw(21)             << std::setfill(' ') << l_time_in_ms
                  << "|" << std::setw(21)             << std::setfill(' ') << l_avg_time_in_ms
                  << "|" << std::endl;
    }
    // -----------------------------------------------------
    // print l_end of table
    // -----------------------------------------------------
    std::cout << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(8)              << std::setfill('-') << "-"
              << "|" << std::setw(8)              << std::setfill('-') << "-"
              << "|" << std::setw(8)              << std::setfill('-') << "-"
              << "|" << std::setw(16)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::endl;
}
// -----------------------------------------------------------------------------
//
// -----------------------------------------------------------------------------
std::chrono::nanoseconds measure_enforcer_process( int a_num_of_args, int a_runs = 100000 )
{
    // -----------------------------------------------------
    // create time counter and l_rqst context
    // -----------------------------------------------------
    std::chrono::nanoseconds ao_total_time = std::chrono::nanoseconds::zero();
    // -----------------------------------------------------
    // create l_rqst context
    // -----------------------------------------------------
    ns_waflz::rqst_ctx* l_rqst = new ns_waflz::rqst_ctx((void*)nullptr, 0, 0, &GS_callbacks, false, false);
    // -----------------------------------------------------
    // create config / limit proto
    // -----------------------------------------------------
    waflz_pb::config* l_config_pb = new waflz_pb::config();
    waflz_pb::limit* l_limit_pb = l_config_pb->add_limits();
    waflz_pb::condition_group* l_cg_pb = l_limit_pb->add_condition_groups();
    l_limit_pb->set_duration_sec(10000);
    l_limit_pb->set_id("test:D");
    l_limit_pb->set_disabled(false);
    l_config_pb->set_id(l_limit_pb->id());
    l_config_pb->set_type(waflz_pb::config_type_t_ENFORCER);
    l_limit_pb->set_num(5);
    // -----------------------------------------------------
    // setup l_rqst context and limit based on run l_size
    //
    // NOTE: maps arent cleared in l_rqst ctx because they 
    // usually only contain values also found in the lists.
    // in this case we didnt populate the list - so we have
    // to clear manually 
    // -----------------------------------------------------
    std::vector<char*> l_cleanup_list;
    if ( a_num_of_args >= 1 )
    {
        l_rqst->m_src_addr = ns_waflz::data_t{"255.255.255.255", strlen("255.255.255.255")};
        l_limit_pb->add_keys("IP");
        waflz_pb::condition* l_c = l_cg_pb->add_conditions();
        waflz_pb::op_t* l_operator = l_c->mutable_op();
        l_operator->set_type(waflz_pb::op_t_type_t_STREQ);
        l_operator->set_value(l_rqst->m_src_addr.m_data, l_rqst->m_src_addr.m_len);
        l_c->mutable_target()->set_type(waflz_pb::condition_target_t_type_t_REMOTE_ADDR);
    }
    if ( a_num_of_args >= 2 )
    {
        std::string l_ua = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36";
        char* l_raw_ua = new char[l_ua.length()];
        strcpy(l_raw_ua, l_ua.c_str());
        l_cleanup_list.push_back(l_raw_ua);
        l_rqst->m_header_map.insert(std::make_pair<ns_waflz::data_t, ns_waflz::data_t>(
            ns_waflz::data_t{"User-Agent", (uint32_t)strlen("User-Agent")},
            ns_waflz::data_t{l_raw_ua, (uint32_t)l_ua.length()}
        ));
        l_limit_pb->add_keys("USER_AGENT");
        waflz_pb::condition* l_c = l_cg_pb->add_conditions();
        waflz_pb::op_t* l_operator = l_c->mutable_op();
        l_operator->set_type(waflz_pb::op_t_type_t_STREQ);
        l_operator->set_value(l_ua);
        auto l_var = l_c->mutable_target();
        l_var->set_type(waflz_pb::condition_target_t_type_t_REQUEST_HEADERS);
        l_var->mutable_value()->assign("User-Agent");
    }
    if ( a_num_of_args >= 3 )
    {
        l_rqst->m_src_asn_str.m_len = asprintf(
            &(l_rqst->m_src_asn_str.m_data),
            "%s",
            "asn str :D"
        );
        l_limit_pb->add_keys("ASN");
        waflz_pb::condition* l_c = l_cg_pb->add_conditions();
        waflz_pb::op_t* l_operator = l_c->mutable_op();
        l_operator->set_type(waflz_pb::op_t_type_t_STREQ);
        l_operator->set_value(l_rqst->m_src_asn_str.m_data, l_rqst->m_src_asn_str.m_len);
        l_c->mutable_target()->set_type(waflz_pb::condition_target_t_type_t_REMOTE_ASN);
    }
    if ( a_num_of_args >= 4 )
    {
        l_rqst->m_virt_ssl_client_ja3_md5 = ns_waflz::data_t{ "253714f62c0a1e6869fe8ba6a45a0588", strlen("253714f62c0a1e6869fe8ba6a45a0588") };
        l_limit_pb->add_keys("JA3");
        waflz_pb::condition* l_c = l_cg_pb->add_conditions();
        waflz_pb::op_t* l_operator = l_c->mutable_op();
        l_operator->set_type(waflz_pb::op_t_type_t_STREQ);
        l_operator->set_value(l_rqst->m_virt_ssl_client_ja3_md5.m_data, l_rqst->m_virt_ssl_client_ja3_md5.m_len);
        l_c->mutable_target()->set_type(waflz_pb::condition_target_t_type_t_REMOTE_JA3);
    }
    if ( a_num_of_args >= 5 )
    {
        // -------------------------------------------------
        // anything after 4 a_num_of_args is considered a
        // header / cookie / arg
        // -------------------------------------------------
        for ( int i_index = a_num_of_args - 5; i_index >= 0; i_index-- )
        {
            // ---------------------------------------------
            // decide which map this will go in
            // ---------------------------------------------
            int l_location = i_index % 3;
            // ---------------------------------------------
            // create l_key and l_val for entry
            // ---------------------------------------------
            std::string l_key = "test_key_" + std::to_string(i_index);
            char* l_raw_key = new char[l_key.length()];
            strcpy(l_raw_key, l_key.c_str());
            l_cleanup_list.push_back(l_raw_key);
            std::string l_val = generate_rand_string(64000);
            char* l_raw_val = new char[l_val.length()];
            strcpy(l_raw_val, l_val.c_str());
            l_cleanup_list.push_back(l_raw_val);
            // ---------------------------------------------
            // create new condition for enforcer
            // ---------------------------------------------
            waflz_pb::condition* l_c = l_cg_pb->add_conditions();
            waflz_pb::op_t* l_operator = l_c->mutable_op();
            l_operator->set_type(waflz_pb::op_t_type_t_STREQ);
            // ---------------------------------------------
            // header
            // ---------------------------------------------
            if (l_location == 0)
            {
                l_rqst->m_header_map.insert(std::make_pair<ns_waflz::data_t, ns_waflz::data_t>(
                    ns_waflz::data_t(l_raw_key, (uint32_t) l_key.length()),
                    ns_waflz::data_t{l_raw_val, (uint32_t) l_val.length()}
                ));
                l_limit_pb->add_keys("HEADER:" + l_key);
                l_operator->set_value(l_raw_val, strlen(l_raw_val));
                auto l_var = l_c->mutable_target();
                l_var->set_type(waflz_pb::condition_target_t_type_t_REQUEST_HEADERS);
                l_var->mutable_value()->assign(l_raw_key);
            }
            // ---------------------------------------------
            // cookie
            // ---------------------------------------------
            else if (l_location == 1)
            {
                l_rqst->m_cookie_map.insert(std::make_pair<ns_waflz::data_t, ns_waflz::data_t>(
                    ns_waflz::data_t(l_raw_key, (uint32_t) l_key.length()),
                    ns_waflz::data_t{l_raw_val, (uint32_t) l_val.length()}
                ));
                l_limit_pb->add_keys("COOKIE:" + l_key);
                l_operator->set_value(l_raw_val, strlen(l_raw_val));
                auto l_var = l_c->mutable_target();
                l_var->set_type(waflz_pb::condition_target_t_type_t_REQUEST_COOKIES);
                l_var->mutable_value()->assign(l_raw_key);
            }
            // ---------------------------------------------
            // arg
            // ---------------------------------------------
            else if (l_location == 2)
            {
                l_rqst->m_query_arg_map.insert(std::make_pair<ns_waflz::data_t, ns_waflz::data_t>(
                    ns_waflz::data_t(l_raw_key, (uint32_t) l_key.length()),
                    ns_waflz::data_t{l_raw_val, (uint32_t) l_val.length()}
                ));
                l_limit_pb->add_keys("ARGS:" + l_key);
                l_operator->set_value(l_raw_val, strlen(l_raw_val));
                auto l_var = l_c->mutable_target();
                l_var->set_type(waflz_pb::condition_target_t_type_t_QUERY_ARG);
                l_var->mutable_value()->assign(l_raw_key);
            }
        }
    }
    // -----------------------------------------------------
    // setup enforcement
    // -----------------------------------------------------
    waflz_pb::enforcement *l_e = l_limit_pb->mutable_action();
    l_e->set_enf_type(waflz_pb::enforcement_type_t::enforcement_type_t_BLOCK_REQUEST);
    l_e->set_percentage(100.0);
    uint32_t l_e_duration_s = (l_e->has_duration_sec()) ? l_e->duration_sec() : l_limit_pb->duration_sec();
    l_e->set_duration_sec(l_e_duration_s);
    // -----------------------------------------------------
    // set duration (so we dont get sweept)
    // -----------------------------------------------------
    uint64_t l_cur_time_ms = ns_waflz::get_time_ms();
    l_e->set_start_time_ms(l_cur_time_ms);
    l_limit_pb->set_start_epoch_msec(l_cur_time_ms);
    l_limit_pb->set_end_epoch_msec(l_cur_time_ms + l_e_duration_s*1000);
    // -----------------------------------------------------
    // make enforcer and add config 
    // -----------------------------------------------------
    auto l_enfx = new ns_waflz::enforcer(false);
    if(l_enfx->merge(*l_config_pb) != WAFLZ_STATUS_OK)
    {
        const char* l_err_msg = l_enfx->get_err_msg();
        std::cout << "error performing merge: " << std::string(l_err_msg, strlen(l_err_msg)) << std::endl;
        return ao_total_time;
    }
    // -----------------------------------------------------
    // other stuff for limit run 
    // -----------------------------------------------------
    const waflz_pb::enforcement *l_enf = NULL;
    // -----------------------------------------------------
    // perform independent a_runs 
    // -----------------------------------------------------
    for ( int i_index = 0; i_index <= a_runs; i_index++ )
    {
        // -------------------------------------------------
        // l_start timer 
        // -------------------------------------------------
        std::chrono::time_point<std::chrono::high_resolution_clock> l_start = std::chrono::high_resolution_clock::now();
        // -------------------------------------------------
        // perform process
        // -------------------------------------------------
        int l_s = l_enfx->process(&l_enf, l_rqst);
        // -------------------------------------------------
        // stop timer 
        // -------------------------------------------------
        std::chrono::time_point<std::chrono::high_resolution_clock> l_end = std::chrono::high_resolution_clock::now();
        // -------------------------------------------------
        // check for error 
        // -------------------------------------------------
        if(l_s != WAFLZ_STATUS_OK)
        {
            const char* l_err_msg = l_enfx->get_err_msg();
            std::cout << "error processing enforcer: " << std::string(l_err_msg, strlen(l_err_msg)) << std::endl;
            break;
        }
        if (!l_enf)
        {
            std::cout << "failed to match enforcer" << std::endl;
            break;
        }
        // -------------------------------------------------
        // add run time to total elapsed time
        // -------------------------------------------------
        std::chrono::nanoseconds l_run_time = std::chrono::duration_cast<std::chrono::nanoseconds>(l_end - l_start);
        ao_total_time += l_run_time;
    }
    // -----------------------------------------------------
    // clean up
    // -----------------------------------------------------
    for (auto i_it = l_cleanup_list.begin(); i_it != l_cleanup_list.end(); i_it++)
    {
        if ( *i_it ) { delete[] *i_it; }
    }
    if (l_enfx) { delete l_enfx; l_enfx = nullptr; }
    if (l_config_pb) { delete l_config_pb; l_config_pb = nullptr; }
    if (l_rqst) { delete l_rqst; l_rqst = nullptr; }
    // -----------------------------------------------------
    // return total time elapsed 
    // -----------------------------------------------------
    return ao_total_time;
}
// -----------------------------------------------------------------------------
//
// -----------------------------------------------------------------------------
void test_enforcer_process(int a_runs = 100000)
{
    // -----------------------------------------------------
    // print title of test
    // -----------------------------------------------------
    std::cout << "Performance testing for enforcer.process() with different amount of args (" << a_runs << " runs):" << std::endl;
    // -----------------------------------------------------
    // create sizes to test
    // -----------------------------------------------------
    std::vector<int> l_test_sizes{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    int l_large_degree = count_digits( l_test_sizes.back() ) + 2;
    // -----------------------------------------------------
    // print table header
    // -----------------------------------------------------
    std::cout << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(8)              << std::setfill('-') << "-"
              << "|" << std::setw(8)              << std::setfill('-') << "-"
              << "|" << std::setw(8)              << std::setfill('-') << "-"
              << "|" << std::setw(16)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::endl;
    std::cout << "|" << std::setw(l_large_degree) << std::setfill(' ') << "#"
              << "|" << std::setw(l_large_degree) << std::setfill(' ') << "IP"
              << "|" << std::setw(l_large_degree) << std::setfill(' ') << "UA"
              << "|" << std::setw(l_large_degree) << std::setfill(' ') << "ASN"
              << "|" << std::setw(l_large_degree) << std::setfill(' ') << "JA3"
              << "|" << std::setw(8)              << std::setfill(' ') << "HEADERS"
              << "|" << std::setw(8)              << std::setfill(' ') << "COOKIES"
              << "|" << std::setw(8)              << std::setfill(' ') << "ARGS"
              << "|" << std::setw(16)             << std::setfill(' ') << "total bytes"
              << "|" << std::setw(21)             << std::setfill(' ') << "total nano seconds"
              << "|" << std::setw(21)             << std::setfill(' ') << "average nano seconds"
              << "|" << std::setw(21)             << std::setfill(' ') << "total mili seconds"
              << "|" << std::setw(21)             << std::setfill(' ') << "average mili seconds"
              << "|" << std::endl;
    std::cout << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(8)              << std::setfill('-') << "-"
              << "|" << std::setw(8)              << std::setfill('-') << "-"
              << "|" << std::setw(8)              << std::setfill('-') << "-"
              << "|" << std::setw(16)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::endl;
    // -----------------------------------------------------
    // for each test l_size
    // -----------------------------------------------------
    for ( auto i_it = l_test_sizes.begin(); i_it != l_test_sizes.end(); i_it++ )
    {
        // -------------------------------------------------
        // run each test
        // -------------------------------------------------
        std::chrono::nanoseconds l_elapsed_time = measure_enforcer_process(*i_it, a_runs);
        // -------------------------------------------------
        // calculate test time in nano seconds and average
        // time in nano seconds
        // -------------------------------------------------
        auto l_time_in_ns = l_elapsed_time.count();
        auto l_avg_time_in_ns = (*i_it == 0) ? 0.0 : ((double) l_time_in_ns) / (100000.0);
        // -------------------------------------------------
        // calculate test time in mili seconds and average
        // time in mili seconds
        // -------------------------------------------------
        auto l_time_in_ms = std::chrono::duration_cast<std::chrono::milliseconds>(l_elapsed_time).count();
        auto l_avg_time_in_ms = (*i_it == 0) ? 0.0 : ((double) l_time_in_ms) / (100000.0);
        // -------------------------------------------------
        // calculating amount of each type of counting
        // group
        // -------------------------------------------------
        bool l_has_ip = *i_it >= 1;
        bool l_has_ua = *i_it >= 2;
        bool l_has_asn = *i_it >= 3;
        bool l_has_ja3 = *i_it >= 4;
        int  l_amount_of_headers = (*i_it >= 5) ? ((*i_it - 5) / 3) + 1 : 0;
        int  l_amount_of_cookies = (*i_it >= 6) ? ((*i_it - 6) / 3) + 1 : 0;
        int  l_amount_of_args = (*i_it >= 7) ? ((*i_it - 7) / 3) + 1 : 0;
        // -------------------------------------------------
        // calculating total l_size of l_rqst
        // -------------------------------------------------
        uint32_t l_size = 0;
        if (l_has_ip) { l_size += sizeof("255.255.255.255") + 1; }
        if (l_has_ua) { l_size += sizeof("Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36") + 1; }
        if (l_has_asn) { l_size += sizeof("test asn :D") + 1; }
        if (l_has_ja3) { l_size += sizeof("253714f62c0a1e6869fe8ba6a45a0588") + 1; }
        if (*i_it >= 5) { l_size += 64000 * (*i_it - 4); }
        // -------------------------------------------------
        // print l_end of table
        // -------------------------------------------------
        std::cout << "|" << std::setw(l_large_degree) << std::setfill(' ') << *i_it
                  << "|" << std::setw(l_large_degree) << std::setfill(' ') << l_has_ip
                  << "|" << std::setw(l_large_degree) << std::setfill(' ') << l_has_ua
                  << "|" << std::setw(l_large_degree) << std::setfill(' ') << l_has_asn
                  << "|" << std::setw(l_large_degree) << std::setfill(' ') << l_has_ja3
                  << "|" << std::setw(8)              << std::setfill(' ') << l_amount_of_headers
                  << "|" << std::setw(8)              << std::setfill(' ') << l_amount_of_cookies
                  << "|" << std::setw(8)              << std::setfill(' ') << l_amount_of_args
                  << "|" << std::setw(16)             << std::setfill(' ') << l_size
                  << "|" << std::setw(21)             << std::setfill(' ') << l_time_in_ns
                  << "|" << std::setw(21)             << std::setfill(' ') << l_avg_time_in_ns
                  << "|" << std::setw(21)             << std::setfill(' ') << l_time_in_ms
                  << "|" << std::setw(21)             << std::setfill(' ') << l_avg_time_in_ms
                  << "|" << std::endl;
    }
    // -----------------------------------------------------
    // print l_end of table
    // -----------------------------------------------------
    std::cout << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(l_large_degree) << std::setfill('-') << "-"
              << "|" << std::setw(8)              << std::setfill('-') << "-"
              << "|" << std::setw(8)              << std::setfill('-') << "-"
              << "|" << std::setw(8)              << std::setfill('-') << "-"
              << "|" << std::setw(16)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::setw(21)             << std::setfill('-') << "-"
              << "|" << std::endl;
}
// -----------------------------------------------------------------------------
//
// -----------------------------------------------------------------------------
int main(int argc, char** argv)
{
    // -----------------------------------------------------
    // set random seed
    // -----------------------------------------------------
    srand((unsigned)time(NULL) * getpid());
    // -----------------------------------------------------
    // setup cout format stream
    // -----------------------------------------------------
    std::cout.imbue( std::locale(std::locale(), new comma_numpunct) );
    std::cout.precision(3);
    std::cout << std::fixed;
    // -----------------------------------------------------
    // test cityhash
    // -----------------------------------------------------
    test_cityhash();
    // -----------------------------------------------------
    // create rl l_db and test limits
    // -----------------------------------------------------
    ns_waflz::kv_db* l_db = generate_rl_db();
    test_limit_process( l_db );
    // -----------------------------------------------------
    // create rl l_db and test limits
    // -----------------------------------------------------
    test_enforcer_process( );
    // -----------------------------------------------------
    // cleanup and leave
    // -----------------------------------------------------
    if (l_db) { delete l_db; l_db = nullptr; }
    return 0;
}