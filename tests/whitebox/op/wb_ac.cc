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
//! Includes
//! ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "waflz/def.h"
#include "waflz/ac.h"
#include "support/ndebug.h"
#include <string.h>
//! ----------------------------------------------------------------------------
//! macros
//! ----------------------------------------------------------------------------
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif
//! ----------------------------------------------------------------------------
//! user agent list
//! ----------------------------------------------------------------------------
const char * const G_SMALL_LIST[] = {
        "cat",
        "car",
        "cot",
        "fox",
        "fix",
        "fax"
};
//! ----------------------------------------------------------------------------
//! user agent list
//! ----------------------------------------------------------------------------
const char * const G_USER_AGENT_LIST[] = {
        "Amazon CloudFront",
        "AppleCoreMedia/1.0.0.12H606 (Apple TV; U; CPU OS 8_4_2 like Mac OS X; en_us)",
        "AppleCoreMedia/1.0.0.14G60 (iPhone; U; CPU OS 10_3_3 like Mac OS X; ar)",
        "AppleCoreMedia/1.0.0.14G60 (iPhone; U; CPU OS 10_3_3 like Mac OS X; en_us)",
        "AppleCoreMedia/1.0.0.15A432 (iPhone; U; CPU OS 11_0_3 like Mac OS X; ar)",
        "AppleCoreMedia/1.0.0.15A432 (iPhone; U; CPU OS 11_0_3 like Mac OS X; en_us)",
        "AppleCoreMedia/1.0.0.15B150 (iPhone; U; CPU OS 11_1_1 like Mac OS X; en_us)",
        "AppleCoreMedia/1.0.0.15B202 (iPhone; U; CPU OS 11_1_2 like Mac OS X; en_us)",
        "AppleCoreMedia/1.0.0.15J582 (Apple TV; U; CPU OS 11_1 like Mac OS X; en_us)",
        "CDN-ECST",
        "downloader 3.0.4.140;Bitdefender2015 (WSLib 1.4 [3, 0, 0, 155])",
        "downloader 3.0.4.171; (WSLib 1.4 [3, 0, 0, 168])",
        "ECPurge/2.0.4432",
        "EdgeDirector/1.0",
        "GOGGalaxyClient/1.2.29.28 (Windows 10 10.0 (Build 15063)IA32)",
        "Lavf53.32.100",
        "libwww-perl/6.05",
        "local-perf-checker/$Revision$",
        "Microsoft BITS/7.8",
        "Microsoft-CryptoAPI/10.0",
        "Microsoft-CryptoAPI/6.1",
        "Microsoft-CryptoAPI/6.3",
        "Microsoft-Delivery-Optimization/10.0",
        "Microsoft-WNS/10.0",
        "Mozilla/4.0 (Windows 98; US) Opera 12.16 [en]",
        "Mozilla/5.0 (iPad; CPU OS 10_3_3 like Mac OS X) AppleWebKit/603.3.8 (KHTML, like Gecko) Version/10.0 Mobile/14G60 Safari/602.1",
        "Mozilla/5.0 (iPad; CPU OS 11_0_3 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A432 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 11_1_1 like Mac OS X) AppleWebKit/604.3.5 (KHTML, like Gecko) Version/11.0 Mobile/15B150 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 11_1_2 like Mac OS X) AppleWebKit/604.3.5 (KHTML, like Gecko) Version/11.0 Mobile/15B202 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 9_3_5 like Mac OS X) AppleWebKit/601.1.46 (KHTML, like Gecko) Version/9.0 Mobile/13G36 Safari/601.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 10_2_1 like Mac OS X) AppleWebKit/602.4.6 (KHTML, like Gecko) Version/10.0 Mobile/14D27 Safari/602.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_2 like Mac OS X) AppleWebKit/603.2.4 (KHTML, like Gecko) Version/10.0 Mobile/14F89 Safari/602.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_3 like Mac OS X) AppleWebKit/603.3.8 (KHTML, like Gecko) Version/10.0 Mobile/14G60 Safari/602.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 11_0_2 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A421 Safari/604.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 11_0_3 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Mobile/15A432",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 11_0_3 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A432 Safari/604.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 11_1_1 like Mac OS X) AppleWebKit/604.3.5 (KHTML, like Gecko) Mobile/15B150",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 11_1_1 like Mac OS X) AppleWebKit/604.3.5 (KHTML, like Gecko) Version/11.0 Mobile/15B150 Safari/604.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 11_1_2 like Mac OS X) AppleWebKit/604.3.5 (KHTML, like Gecko) Mobile/15B202",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 11_1_2 like Mac OS X) AppleWebKit/604.3.5 (KHTML, like Gecko) Version/11.0 Mobile/15B202 Safari/604.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 11_1 like Mac OS X) AppleWebKit/604.3.5 (KHTML, like Gecko) Version/11.0 Mobile/15B93 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 4.4; MI 2 Build/KRT16M) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/30.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/603.3.8 (KHTML, like Gecko) Version/10.1.2 Safari/603.3.8",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/604.3.5 (KHTML, like Gecko) Version/11.0.1 Safari/604.3.5",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/604.3.5 (KHTML, like Gecko) Version/11.0.1 Safari/604.3.5",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/604.3.5 (KHTML, like Gecko) Version/11.0.1 Safari/604.3.5",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/601.7.8 (KHTML, like Gecko) Version/9.1.3 Safari/537.86.7",
        "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36 Edge/15.15063",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36",
        "Mozilla/5.0 (Windows NT 5.1; rv:52.0) Gecko/20100101 Firefox/52.0",
        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; rv:57.0) Gecko/20100101 Firefox/57.0",
        "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0",
        "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows; U; Windows NT 10.0; en-US; Valve Steam Client/default/1509425745; ) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36",
        "Mozilla/5.0 (X11; CrOS x86_64 9901.66.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.82 Safari/537.36",
        "Mozilla/5.0 (X11; Linux armv7l) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.17 Safari/537.36 CrKey/1.28.100555",
        "__na__",
        "okhttp/2.7.5",
        "okhttp/3.2.0",
        "okhttp/3.9.0-twitter-201709221",
        "Roku/DVP-7.70 (047.70E04135A)",
        "Roku/DVP-8.0 (248.00E04108A)",
        "Roku/DVP-8.0 (248.00E04128A)",
        "Roku/DVP-8.0 (288.00E04108A)",
        "Roku/DVP-8.0 (288.00E04128A)",
        "Roku/DVP-8.0 (298.00E04108A)",
        "Syabas/J3S-01-01-150121-02-POP-890-999 Mozilla/4.0",
        "trustd (unknown version) CFNetwork/889.9 Darwin/17.2.0",
        "Twitter/7.11 CFNetwork/889.9 Darwin/17.2.0",
        "Twitter/7.12 CFNetwork/811.5.4 Darwin/16.7.0",
        "Twitter/7.12 CFNetwork/887 Darwin/17.0.0",
        "Twitter/7.12 CFNetwork/889.9 Darwin/17.2.0",
        "Valve/Steam HTTP Client 1.0",
        "Windows-Update-Agent",
        "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/1.58",
        "X-EC-Precache"
};
//! ----------------------------------------------------------------------------
//! \details: TODO
//! \return:  TODO
//! \param:   TODO
//! ----------------------------------------------------------------------------
static int match_handler(ns_waflz::ac *a_ac, ns_waflz::node_t* a_current_node, void** a_data)
{
        if(*a_data)
        {
                uint32_t *l_count = (uint32_t *)*a_data;
                *l_count = *l_count + 1;
        }
        //NDBG_OUTPUT("position: %u found: ", ao_match->m_pos);
#ifdef PM_DEBUG
        for(uint32_t i_m = 0; i_m < ao_match->m_size; i_m++)
        {
                NDBG_OUTPUT("#%ld \"%.*s\", ",
                            ao_match->m_patterns[i_m].m_id.m_u.m_number,
                            (int)ao_match->m_patterns[i_m].m_text.m_len,
                            ao_match->m_patterns[i_m].m_text.m_str);
        }
#endif
        //NDBG_OUTPUT("\n");
#if 0
        ac::match_t *l_m = (ac::match_t *)a_data;
        l_m->m_pos = ao_match->m_pos;
#ifdef PM_DEBUG
        l_m->m_patterns = ao_match->m_patterns;
        l_m->m_size = ao_match->m_size;
#endif
#endif
        // -------------------------------------------------
        // zero return value will continue search
        // non-zero return value will stop search
        // eg.
        // if enough results, stop search with non-zero return
        // or to find all matches always return 0
        // -------------------------------------------------
        return 0;
}
//! ----------------------------------------------------------------------------
//! ac test
//! ----------------------------------------------------------------------------
TEST_CASE( "ac basic test", "[ac_basic]" ) {
        // -------------------------------------------------
        // basic test
        // -------------------------------------------------
        SECTION("ac basic insert") {
                ns_waflz::ac *l_ac = NULL;
                l_ac = new ns_waflz::ac();
                REQUIRE((l_ac != NULL));
                uint32_t l_size = ARRAY_SIZE(G_SMALL_LIST);
                for(uint32_t i_p = 0; i_p < l_size; ++i_p)
                {
                        int32_t l_s;
                        l_s = l_ac->add(G_SMALL_LIST[i_p], strlen(G_SMALL_LIST[i_p]));
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                }
                l_ac->finalize();
                //l_ac->display();
                bool l_s;
                std::string l_match_str;
                l_s = l_ac->find_first("cat", strlen("cat"), l_match_str);
                REQUIRE((l_s == true));
                l_s = l_ac->find_first("ca", strlen("ca"), l_match_str);
                REQUIRE((l_s == false));
                l_s = l_ac->find_first("cax", strlen("cax"), l_match_str);
                REQUIRE((l_s == false));
                l_s = l_ac->find_first("car", strlen("car"), l_match_str);
                REQUIRE((l_s == true));
                l_s = l_ac->find_first("fox", strlen("fox"), l_match_str);
                REQUIRE((l_s == true));
                l_s = l_ac->find_first("fex", strlen("fex"), l_match_str);
                REQUIRE((l_s == false));
                // clean up
                if(l_ac)
                {
                        delete l_ac;
                }
        }
        // -------------------------------------------------
        // basic test
        // -------------------------------------------------
        SECTION("ac multi match") {
                ns_waflz::ac *l_ac = NULL;
                l_ac = new ns_waflz::ac();
                REQUIRE((l_ac != NULL));
                uint32_t l_size = ARRAY_SIZE(G_SMALL_LIST);
                for(uint32_t i_p = 0; i_p < l_size; ++i_p)
                {
                        int32_t l_s;
                        l_s = l_ac->add(G_SMALL_LIST[i_p], strlen(G_SMALL_LIST[i_p]));
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                }
                l_ac->finalize();
                //l_ac->display();
                bool l_s;
                uint32_t l_match_count = 0;
                void* l_match_count_ptr = static_cast<void*>(&l_match_count);
                std::string l_match_str;
                l_s = l_ac->find("cat and dog and fart and foxes are cool faxes",
                                 strlen("cat and dog and fart and foxes are cool faxes"),
                                 l_match_str,
                                 match_handler,
                                 &l_match_count_ptr);
                REQUIRE((l_s == true));
                REQUIRE((l_match_count == 3));
                // clean up
                if(l_ac)
                {
                        delete l_ac;
                }
        }
        // -------------------------------------------------
        // nullptr check
        // -------------------------------------------------
        SECTION("ac empty buffer test") {
                ns_waflz::ac *l_ac = NULL;
                l_ac = new ns_waflz::ac();
                REQUIRE((l_ac != NULL));
                uint32_t l_size = ARRAY_SIZE(G_USER_AGENT_LIST);
                for(uint32_t i_p = 0; i_p < l_size; ++i_p)
                {
                        int32_t l_s;
                        l_s = l_ac->add(G_USER_AGENT_LIST[i_p], strlen(G_USER_AGENT_LIST[i_p]));
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                }
                l_ac->finalize();
                std::string l_match_str;
                REQUIRE((l_ac->find_first(nullptr, 0, l_match_str ) == WAFLZ_STATUS_OK));
                REQUIRE((l_ac->find_first(nullptr, 20, l_match_str ) == WAFLZ_STATUS_OK));
                // clean up
                if(l_ac)
                {
                        delete l_ac;
                }
        }
        // -------------------------------------------------
        // data package check
        // -------------------------------------------------
        SECTION("ac data package") {
                std::vector<uint32_t> l_random_data;
                ns_waflz::ac *l_ac = new ns_waflz::ac();
                REQUIRE((l_ac != NULL));
                uint32_t l_size = ARRAY_SIZE(G_USER_AGENT_LIST);
                for(uint32_t i_p = 0; i_p < l_size; ++i_p)
                {
                        l_random_data.emplace_back(i_p);
                }
                for(uint32_t i_p = 0; i_p < l_size; ++i_p)
                {
                        int32_t l_s;
                        l_s = l_ac->add(G_USER_AGENT_LIST[i_p], strlen(G_USER_AGENT_LIST[i_p]), (void*) &l_random_data[i_p]);
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                }
                l_ac->finalize();
                std::string l_match_str;
                uint32_t* l_num_for_ua = nullptr;
                int32_t l_s = l_ac->find_with_data(G_USER_AGENT_LIST[23], strlen(G_USER_AGENT_LIST[23]), l_match_str, (void**) &l_num_for_ua);
                REQUIRE(l_s == true);
                REQUIRE(l_match_str == G_USER_AGENT_LIST[23]);
                REQUIRE((*l_num_for_ua) == 23);
                // clean up
                if(l_ac)
                {
                        delete l_ac;
                }
        }
        // -------------------------------------------------
        // user agent test
        // -------------------------------------------------
        SECTION("ac user-agent") {
                ns_waflz::ac *l_ac = NULL;
                l_ac = new ns_waflz::ac();
                REQUIRE((l_ac != NULL));
                uint32_t l_size = ARRAY_SIZE(G_USER_AGENT_LIST);
                for(uint32_t i_p = 0; i_p < l_size; ++i_p)
                {
                        int32_t l_s;
                        l_s = l_ac->add(G_USER_AGENT_LIST[i_p], strlen(G_USER_AGENT_LIST[i_p]));
                        REQUIRE((l_s == WAFLZ_STATUS_OK));
                }
                l_ac->finalize();
                //l_ac->display();
                bool l_s;
                std::string l_match_str;
                l_s = l_ac->find_first(G_USER_AGENT_LIST[23], strlen(G_USER_AGENT_LIST[23]), l_match_str);
                REQUIRE(l_s == true);
                REQUIRE(l_match_str == G_USER_AGENT_LIST[23]);
                l_s = l_ac->find_first("X-EC-Precache", strlen("X-EC-Precache"), l_match_str);
                REQUIRE(l_s == true);
                REQUIRE(l_match_str == "X-EC-Precache");
                l_s = l_ac->find_first("X-EC-Precachd", strlen("X-EC-Precachd"), l_match_str);
                REQUIRE(l_s == false);
                l_s = l_ac->find_first("Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
                                strlen("Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36"),
                                l_match_str);
                REQUIRE(l_s == true);
                REQUIRE(l_match_str == "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36");
                l_s = l_ac->find_first("Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3203.94 Safari/537.36",
                                strlen("Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3203.94 Safari/537.36"),
                                l_match_str);
                REQUIRE(l_s == false);
                l_s = l_ac->find_first("I'm cool CDN-ECST blahblahblah HI MOM!",
                                strlen("I'm cool CDN-ECST blahblahblah HI MOM!"),
                                l_match_str);
                REQUIRE(l_s == true);
                REQUIRE(l_match_str == "CDN-ECST");
                l_s = l_ac->find_first("I'm pretending to be Amazon CloudFront :)",
                                strlen("I'm pretending to be Amazon CloudFront :)"),
                                l_match_str);
                REQUIRE(l_s == true);
                REQUIRE(l_match_str == "Amazon CloudFront");
                // clean up
                if(l_ac)
                {
                        delete l_ac;
                }
        }
}
