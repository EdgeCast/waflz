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
#include "waflz/rqst_ctx.h"
#include "waflz/api_gw.h"
#include "waflz/engine.h"
#include "support/time_util.h"
// -----------------------------------------------------------------------------
// protobuff includes
// -----------------------------------------------------------------------------
#include "api_gw.pb.h"
#include "event.pb.h"
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
std::chrono::nanoseconds measure_jwt_time( ns_waflz::api_gw* a_api_gw, int a_runs, std::string a_auth_string, bool a_expect_event = false)
{
    // -----------------------------------------------------
    // create time counter
    // -----------------------------------------------------
    std::chrono::nanoseconds ao_total_time = std::chrono::nanoseconds::zero();
    // -----------------------------------------------------
    // create l_rqst context
    // -----------------------------------------------------
    ns_waflz::rqst_ctx* l_rqst = new ns_waflz::rqst_ctx((void*)nullptr, 0, 0, &GS_callbacks, false, false);
    l_rqst->m_method.m_data = "GET";
    l_rqst->m_method.m_len = strlen("GET");
    
    std::string l_jwt = "Bearer " + a_auth_string;
    l_rqst->m_header_map.insert(std::make_pair<ns_waflz::data_t, ns_waflz::data_t>(
        ns_waflz::data_t{"Authorization", (uint32_t)strlen("Authorization")},
        ns_waflz::data_t{l_jwt.c_str(), (uint32_t)l_jwt.length()}
    ));
    // -----------------------------------------------------
    // perform independent a_runs 
    // -----------------------------------------------------
    waflz_pb::event* l_event = NULL;
    auto l_status = WAFLZ_STATUS_OK;
    for ( int i_index = 0; i_index <= a_runs; i_index++ )
    {
        // -------------------------------------------------
        // l_start timer 
        // -------------------------------------------------
        std::chrono::time_point<std::chrono::high_resolution_clock> l_start = std::chrono::high_resolution_clock::now();
        // -------------------------------------------------
        // perform hash
        // -------------------------------------------------
        l_status = a_api_gw->process(&l_event, nullptr, &l_rqst);
        // -------------------------------------------------
        // stop timer 
        // -------------------------------------------------
        std::chrono::time_point<std::chrono::high_resolution_clock> l_end = std::chrono::high_resolution_clock::now();
        if(l_status != WAFLZ_STATUS_OK)
        {
            const char* l_err_msg = a_api_gw->get_err_msg();
            std::cout << "error processing: " << std::string(l_err_msg, strlen(l_err_msg)) << std::endl;
            break;
        }
        // -------------------------------------------------
        // add run time to total elapsed time
        // -------------------------------------------------
        std::chrono::nanoseconds l_run_time = std::chrono::duration_cast<std::chrono::nanoseconds>(l_end - l_start);
        ao_total_time += l_run_time;
        // -------------------------------------------------
        // add run time to total elapsed time
        // -------------------------------------------------
        if (l_event && !a_expect_event)
        {
            std::cout << "i have an event when one was not expected!" << std::endl;
            std::cout << l_event->DebugString() << std::endl;
            break;
        }
    }
    // -----------------------------------------------------
    // return total time elapsed 
    // -----------------------------------------------------
    return ao_total_time;
}
// -----------------------------------------------------------------------------
//
// -----------------------------------------------------------------------------
void test_jwt_parse( char* a_good_auth, int a_runs = 100000 )
{
    // -----------------------------------------------------
    // print title of test
    // -----------------------------------------------------
    std::cout << "Performance testing for jwt auth at different string sizes (" << a_runs << " runs):" << std::endl;
    // -----------------------------------------------------
    // create api_gw
    // -----------------------------------------------------
    ns_waflz::engine* l_engine = new ns_waflz::engine();
    if ( l_engine->init() != WAFLZ_STATUS_OK )
    {
        std::cout << "oh no!" << std::endl;
        if (l_engine) { delete l_engine; l_engine = NULL; }
        return;
    }
    // -----------------------------------------------------
    // make an api_gw proto
    // -----------------------------------------------------
    auto l_api_gw_proto = waflz_pb::api_gw();
    auto l_api_gw_proto_rule = l_api_gw_proto.add_rules();
    l_api_gw_proto_rule->add_methods("GET");
    l_api_gw_proto_rule->set_id("banana");
    auto l_api_gw_proto_rule_token = l_api_gw_proto_rule->mutable_token();
    l_api_gw_proto_rule_token->set_token_type(waflz_pb::JWT);
    auto l_api_gw_proto_rule_token_jwks = l_api_gw_proto_rule_token->mutable_jwks()->add_keys();
    l_api_gw_proto_rule_token_jwks->set_kty("RSA");
    l_api_gw_proto_rule_token_jwks->set_use("sig");
    l_api_gw_proto_rule_token_jwks->set_kid("174EFCA3923B25163F581A0CB71CAD97B036E0B8");
    l_api_gw_proto_rule_token_jwks->set_e("AQAB");
    l_api_gw_proto_rule_token_jwks->set_n("n1x3isqbPYjG2dUm5d5NAYM4KbmANTstxv93YfzLb7ZbGf-5ml5378sTXAVrJrsMjoGHv6f6DwjReIc1vsXuZpfcCw8ggdvoFgSqXC8yxXRbZLRRgWO2yX1qxSEeB2XOGTZnH6R-k0MIsUtgGzl5uhsE3aB3enpWdAa9tIi1cJ3FLLJruy4UPR_ZA9-hY9bgqvHTGq_DrAes4bhgcwvoCJxyZFt-NEfL3FGJ2qUaHexcvBG-oAhP6bKcwd8KXQFE_8fT6uNVlt_DbsJx81nCWbMckGzKbQXk8QoXonkB9waAUJl81MBk9zKHt5LujgFXJODZWmyR4oHhLw4UySKCow");
    l_api_gw_proto_rule_token_jwks->set_alg(waflz_pb::RS256);
    l_api_gw_proto_rule_token_jwks->set_x5t("F078o5I7JRY_WBoMtxytl7A24Lg");
    l_api_gw_proto_rule_token_jwks->add_x5c("MIIEWzCCA0OgAwIBAgIJAPzw5pQEyIL4MA0GCSqGSIb3DQEBCwUAMIHDMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1BsYXlhIFZpc3RhMScwJQYDVQQKDB5WZXJpem9uIERpZ2l0YWwgTWVkaWEgU2VydmljZXMxHDAaBgNVBAsME0lkZW50aXR5IE1hbmFnZW1lbnQxEzARBgNVBAMMCmlkLnZkbXMuaW8xNTAzBgkqhkiG9w0BCQEWJmFyZGFsYW4uc2FlaWRpQHZlcml6b25kaWdpdGFsbWVkaWEuY29tMB4XDTE3MDQyOTAzNDQ0MVoXDTE3MDUyOTAzNDQ0MVowgcMxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLUGxheWEgVmlzdGExJzAlBgNVBAoMHlZlcml6b24gRGlnaXRhbCBNZWRpYSBTZXJ2aWNlczEcMBoGA1UECwwTSWRlbnRpdHkgTWFuYWdlbWVudDETMBEGA1UEAwwKaWQudmRtcy5pbzE1MDMGCSqGSIb3DQEJARYmYXJkYWxhbi5zYWVpZGlAdmVyaXpvbmRpZ2l0YWxtZWRpYS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCfXHeKyps9iMbZ1Sbl3k0BgzgpuYA1Oy3G/3dh/MtvtlsZ/7maXnfvyxNcBWsmuwyOgYe/p/oPCNF4hzW+xe5ml9wLDyCB2+gWBKpcLzLFdFtktFGBY7bJfWrFIR4HZc4ZNmcfpH6TQwixS2AbOXm6GwTdoHd6elZ0Br20iLVwncUssmu7LhQ9H9kD36Fj1uCq8dMar8OsB6zhuGBzC+gInHJkW340R8vcUYnapRod7Fy8Eb6gCE/pspzB3wpdAUT/x9Pq41WW38NuwnHzWcJZsxyQbMptBeTxCheieQH3BoBQmXzUwGT3Moe3ku6OAVck4NlabJHigeEvDhTJIoKjAgMBAAGjUDBOMB0GA1UdDgQWBBQcdexTJwVKoEmS4yYYS+kMqiqJUTAfBgNVHSMEGDAWgBQcdexTJwVKoEmS4yYYS+kMqiqJUTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAkN65cWDRvdXOW7QvSbeSN+WFrlE4qB9w1GvxK6xnyhysuFJzPKJBS4Zk+4SJcdLCIcUIu/MS+q3QAevCJFoAdy/Iy9APIYCce09dHK7bywj0FVYP7Xpnb0/iskKR7yDjXLxUEdsd6NNWMlYGpBSxjD+L1ohyYnmt+RySqtocSV/T4rbgMVQBB4chX/5aOQslVUvhOArbkITS/Jf8cUbcI6fqTreNsRrbf0mT1C/1qfblGaqGql9mbFsZW/iDcXZdgxU9j6aZdhgoBBx0ro6evPkVCfp/3LyJ1EogZfIwQFTXJNGSzbYy8tBGSZI22rYtkz2rvVXTGFNX2HglofS0v"); 
    ns_waflz::api_gw* l_api_gw = new ns_waflz::api_gw(*l_engine);
    // -----------------------------------------------------
    // load api_gw
    // -----------------------------------------------------
    auto l_status = l_api_gw->load(&l_api_gw_proto, std::string(""));
    if (l_status != WAFLZ_STATUS_OK)
    {
        std::cout << "Error: " << std::string(l_api_gw->get_err_msg()) << std::endl;
        if (l_api_gw) { delete l_api_gw; l_api_gw = NULL; }
        if (l_engine) { delete l_engine; l_engine = NULL; }
        return;
    }
    // -----------------------------------------------------
    // print table header
    // -----------------------------------------------------
    std::cout << "|" << std::setw(21) << std::setfill('-') << "-"
              << "|" << std::setw(21) << std::setfill('-') << "-"
              << "|" << std::setw(21) << std::setfill('-') << "-"
              << "|" << std::setw(21) << std::setfill('-') << "-"
              << "|" << std::setw(21) << std::setfill('-') << "-"
              << "|" << std::endl;
    std::cout << "|" << std::setw(21) << std::setfill(' ') << "Runs"
              << "|" << std::setw(21) << std::setfill(' ') << "Total nano seconds"
              << "|" << std::setw(21) << std::setfill(' ') << "average nano seconds"
              << "|" << std::setw(21) << std::setfill(' ') << "Total mili seconds"
              << "|" << std::setw(21) << std::setfill(' ') << "average mili seconds"
              << "|" << std::endl;
    std::cout << "|" << std::setw(21) << std::setfill('-') << "-"
              << "|" << std::setw(21) << std::setfill('-') << "-"
              << "|" << std::setw(21) << std::setfill('-') << "-"
              << "|" << std::setw(21) << std::setfill('-') << "-"
              << "|" << std::setw(21) << std::setfill('-') << "-"
              << "|" << std::endl;
    // -------------------------------------------------
    // run each test
    // -------------------------------------------------
    if (a_good_auth)
    {
        std::chrono::nanoseconds l_good_elapsed_time = measure_jwt_time(l_api_gw, a_runs, std::string(a_good_auth));
        // -------------------------------------------------
        // calculate test time in nano seconds and average
        // time in nano seconds
        // -------------------------------------------------
        auto l_time_in_ns = l_good_elapsed_time.count();
        auto l_avg_time_in_ns = ((double) l_time_in_ns) / (100000.0);
        // -------------------------------------------------
        // calculate test time in mili seconds and average
        // time in mili seconds
        // -------------------------------------------------
        auto l_time_in_ms = std::chrono::duration_cast<std::chrono::milliseconds>(l_good_elapsed_time).count();
        auto l_avg_time_in_ms = ((double) l_time_in_ms) / (100000.0);
        // -------------------------------------------------
        // print results to stream
        // -------------------------------------------------
        std::cout << "|" << std::setw(14) << std::setfill(' ') << a_runs <<  std::setw(7) << "(good)"
                << "|" << std::setw(21) << std::setfill(' ') << l_time_in_ns
                << "|" << std::setw(21) << std::setfill(' ') << l_avg_time_in_ns
                << "|" << std::setw(21) << std::setfill(' ') << l_time_in_ms
                << "|" << std::setw(21) << std::setfill(' ') << l_avg_time_in_ms
                << "|" << std::endl;
    }
    // -------------------------------------------------
    // bad test (bad header json)
    // -------------------------------------------------
    std::chrono::nanoseconds l_bad_elapsed_time = measure_jwt_time(l_api_gw, a_runs, "asdaweyJhbGciOiJSUzI1NiIsImtpZCI6IjE3NEVGQ0EzOTIzQjI1MTYzRjU4MUEwQ0I3MUNBRDk3QjAzNkUwQjgiLCJ0eXAiOiJKV1QiLCJ4NXQiOiJGMDc4bzVJN0pSWV9XQm9NdHh5dGw3QTI0TGcifQ.eyJuYmYiOjE3MTU4NzUxNDYsImV4cCI6MTcxNTk2MTU0NiwiaXNzIjoiaHR0cHM6Ly9pZC52ZG1zLmlvIiwiYXVkIjpbIldBRiIsImVjLndhZi5jYXMiLCJodHRwczovL2lkLnZkbXMuaW8vcmVzb3VyY2VzIl0sImNsaWVudF9pZCI6IjM0MmU0YzNmLTFkNzYtNGQzOC1hZWZlLWE1MTFlODM3ZWU3MyIsImNsaWVudF90ZW5hbnRfaWQiOiI4MWVjMTdmNC0wNjIyLTQzYmItODRkMy1iZGM4NWM2OGM2OWUiLCJqdGkiOiIzODdDOUFENkZEMDQ0RkNDNTc5QUQ1RUI3MjUxMjk3MCIsImlhdCI6MTcxNTg3NTE0Niwic2NvcGUiOlsiZWMud2FmIl19.KMsGDlPDtuiccDXsixJ1KmnLjsBJDjm4M6Q2yMrrJkIVlp0MPFa6mpaPrWqkUxeH6d6EtGjnPMV7yI4zOWXSQFQS2DbgM3nI3CohDZqec8qch9yswZ1De1meXcPdzzuIaLhyMrf0-6XE7oRZT2mzXY8qqCZzQwVF5BqyDQ2VGoOwEdtow4dHikjGFI1pJaUHzDC3sP2F4FABvRP3iIOD3AubliSGXZQUtuhb4vY4LEWvrYBiZievWk_3WwEfIOBH_Q8QTvy477kfUB83JCmuySalOS6yH0SE7w_cDEocDy-x7P26jLHipTLBfm1So4QeZjBSHs56pVUknFgOZ9BnOA", true);
    auto l_time_in_ns = l_bad_elapsed_time.count();
    auto l_avg_time_in_ns = ((double) l_time_in_ns) / (100000.0);
    // -------------------------------------------------
    // calculate test time in mili seconds and average
    // time in mili seconds
    // -------------------------------------------------
    auto l_time_in_ms = std::chrono::duration_cast<std::chrono::milliseconds>(l_bad_elapsed_time).count();
    auto l_avg_time_in_ms = ((double) l_time_in_ms) / (100000.0);
    // -------------------------------------------------
    // print results to stream
    // -------------------------------------------------
    std::cout << "|" << std::setw(14) << std::setfill(' ') << a_runs <<  std::setw(7) << "(bad)"
              << "|" << std::setw(21) << std::setfill(' ') << l_time_in_ns
              << "|" << std::setw(21) << std::setfill(' ') << l_avg_time_in_ns
              << "|" << std::setw(21) << std::setfill(' ') << l_time_in_ms
              << "|" << std::setw(21) << std::setfill(' ') << l_avg_time_in_ms
              << "|" << std::endl;
    // -------------------------------------------------
    // bad test (bad signature)
    // -------------------------------------------------
    std::chrono::nanoseconds l_bad_sign_elapsed_time = measure_jwt_time(l_api_gw, a_runs, "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE3NEVGQ0EzOTIzQjI1MTYzRjU4MUEwQ0I3MUNBRDk3QjAzNkUwQjgiLCJ0eXAiOiJKV1QiLCJ4NXQiOiJGMDc4bzVJN0pSWV9XQm9NdHh5dGw3QTI0TGcifQ.eyJuYmYiOjE3MTU4NzUxNDYsImV4cCI6MTcxNTk2MTU0NiwiaXNzIjoiaHR0cHM6Ly9pZC52ZG1zLmlvIiwiYXVkIjpbIldBRiIsImVjLndhZi5jYXMiLCJodHRwczovL2lkLnZkbXMuaW8vcmVzb3VyY2VzIl0sImNsaWVudF9pZCI6IjM0MmU0YzNmLTFkNzYtNGQzOC1hZWZlLWE1MTFlODM3ZWU3MyIsImNsaWVudF90ZW5hbnRfaWQiOiI4MWVjMTdmNC0wNjIyLTQzYmItODRkMy1iZGM4NWM2OGM2OWUiLCJqdGkiOiIzODdDOUFENkZEMDQ0RkNDNTc5QUQ1RUI3MjUxMjk3MCIsImlhdCI6MTcxNTg3NTE0Niwic2NvcGUiOlsiZWMud2FmIiwgInRlc3QiXX0K.KMsGDlPDtuiccDXsixJ1KmnLjsBJDjm4M6Q2yMrrJkIVlp0MPFa6mpaPrWqkUxeH6d6EtGjnPMV7yI4zOWXSQFQS2DbgM3nI3CohDZqec8qch9yswZ1De1meXcPdzzuIaLhyMrf0-6XE7oRZT2mzXY8qqCZzQwVF5BqyDQ2VGoOwEdtow4dHikjGFI1pJaUHzDC3sP2F4FABvRP3iIOD3AubliSGXZQUtuhb4vY4LEWvrYBiZievWk_3WwEfIOBH_Q8QTvy477kfUB83JCmuySalOS6yH0SE7w_cDEocDy-x7P26jLHipTLBfm1So4QeZjBSHs56pVUknFgOZ9BnOA", true);
    l_time_in_ns = l_bad_sign_elapsed_time.count();
    l_avg_time_in_ns = ((double) l_time_in_ns) / (100000.0);
    // -------------------------------------------------
    // calculate test time in mili seconds and average
    // time in mili seconds
    // -------------------------------------------------
    l_time_in_ms = std::chrono::duration_cast<std::chrono::milliseconds>(l_bad_sign_elapsed_time).count();
    l_avg_time_in_ms = ((double) l_time_in_ms) / (100000.0);
    // -------------------------------------------------
    // print results to stream
    // -------------------------------------------------
    std::cout << "|" << std::setw(14) << std::setfill(' ') << a_runs <<  std::setw(7) << "(bad)"
              << "|" << std::setw(21) << std::setfill(' ') << l_time_in_ns
              << "|" << std::setw(21) << std::setfill(' ') << l_avg_time_in_ns
              << "|" << std::setw(21) << std::setfill(' ') << l_time_in_ms
              << "|" << std::setw(21) << std::setfill(' ') << l_avg_time_in_ms
              << "|" << std::endl;
    // -------------------------------------------------
    // next bad test (missing kid)
    // -------------------------------------------------
    std::chrono::nanoseconds l_bad_kid_elapsed_time = measure_jwt_time(l_api_gw, a_runs, "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE3NEVGQ0EzOTIzQjI1MTYzRjU4MUEwQ0I3MUNhZGF1ZDdCMDM2RXNzIiwidHlwIjoiSldUIiwieDV0IjoiRjA3OG81STdKUllfV0JvTXR4eXRsN0EyNExnIn0K.eyJuYmYiOjE3MTU4NzUxNDYsImV4cCI6MTcxNTk2MTU0NiwiaXNzIjoiaHR0cHM6Ly9pZC52ZG1zLmlvIiwiYXVkIjpbIldBRiIsImVjLndhZi5jYXMiLCJodHRwczovL2lkLnZkbXMuaW8vcmVzb3VyY2VzIl0sImNsaWVudF9pZCI6IjM0MmU0YzNmLTFkNzYtNGQzOC1hZWZlLWE1MTFlODM3ZWU3MyIsImNsaWVudF90ZW5hbnRfaWQiOiI4MWVjMTdmNC0wNjIyLTQzYmItODRkMy1iZGM4NWM2OGM2OWUiLCJqdGkiOiIzODdDOUFENkZEMDQ0RkNDNTc5QUQ1RUI3MjUxMjk3MCIsImlhdCI6MTcxNTg3NTE0Niwic2NvcGUiOlsiZWMud2FmIiwgInRlc3QiXX0K.KMsGDlPDtuiccDXsixJ1KmnLjsBJDjm4M6Q2yMrrJkIVlp0MPFa6mpaPrWqkUxeH6d6EtGjnPMV7yI4zOWXSQFQS2DbgM3nI3CohDZqec8qch9yswZ1De1meXcPdzzuIaLhyMrf0-6XE7oRZT2mzXY8qqCZzQwVF5BqyDQ2VGoOwEdtow4dHikjGFI1pJaUHzDC3sP2F4FABvRP3iIOD3AubliSGXZQUtuhb4vY4LEWvrYBiZievWk_3WwEfIOBH_Q8QTvy477kfUB83JCmuySalOS6yH0SE7w_cDEocDy-x7P26jLHipTLBfm1So4QeZjBSHs56pVUknFgOZ9BnOA", true);
    l_time_in_ns = l_bad_kid_elapsed_time.count();
    l_avg_time_in_ns = ((double) l_time_in_ns) / (100000.0);
    // -------------------------------------------------
    // calculate test time in mili seconds and average
    // time in mili seconds
    // -------------------------------------------------
    l_time_in_ms = std::chrono::duration_cast<std::chrono::milliseconds>(l_bad_kid_elapsed_time).count();
    l_avg_time_in_ms = ((double) l_time_in_ms) / (100000.0);
    // -------------------------------------------------
    // print results to stream
    // -------------------------------------------------
    std::cout << "|" << std::setw(14) << std::setfill(' ') << a_runs <<  std::setw(7) << "(bad)"
              << "|" << std::setw(21) << std::setfill(' ') << l_time_in_ns
              << "|" << std::setw(21) << std::setfill(' ') << l_avg_time_in_ns
              << "|" << std::setw(21) << std::setfill(' ') << l_time_in_ms
              << "|" << std::setw(21) << std::setfill(' ') << l_avg_time_in_ms
              << "|" << std::endl;
    // -----------------------------------------------------
    // print l_end of table
    // -----------------------------------------------------
    std::cout << "|" << std::setw(21) << std::setfill('-') << "-"
              << "|" << std::setw(21) << std::setfill('-') << "-"
              << "|" << std::setw(21) << std::setfill('-') << "-"
              << "|" << std::setw(21) << std::setfill('-') << "-"
              << "|" << std::setw(21) << std::setfill('-') << "-"
              << "|" << std::endl;
    // -----------------------------------------------------
    // cleanup and leave
    // -----------------------------------------------------
    if (l_api_gw) { delete l_api_gw; l_api_gw = NULL; }
    if (l_engine) { delete l_engine; l_engine = NULL; }
    return;
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
int main(int argc, char** argv)
{
    // -----------------------------------------------------
    // check to see if a good auth token was passed
    // -----------------------------------------------------
    if (argc < 2)
    {
        std::cout << "no good auth token passed - skipping good test" << std::endl;
    }
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
    // test jwt parsing
    // -----------------------------------------------------
    test_jwt_parse( argv[1] );
    // -----------------------------------------------------
    // done-zo
    // -----------------------------------------------------
    return 0;
}