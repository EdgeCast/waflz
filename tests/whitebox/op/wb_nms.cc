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
#include "waflz/nms.h"
//! ----------------------------------------------------------------------------
//! read_file
//! ----------------------------------------------------------------------------
TEST_CASE( "nms basic test", "[nms_basic]" ) {
        SECTION("ipv4 basic insert") {
                int32_t l_s;
                ns_waflz::nms *l_nms = new ns_waflz::nms();
                l_s = l_nms->add("127.0.0.1", sizeof("127.0.0.1"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_nms->add("192.168.100.0/24", sizeof("192.168.100.0/24"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                bool l_m;
                l_s = l_nms->contains(l_m, "127.0.0.1", sizeof("127.0.0.1"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_m == true));
                l_s = l_nms->contains(l_m, "192.168.100.1", sizeof("192.168.100.1"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_m == true));
                l_s = l_nms->contains(l_m, "192.168.100.12", sizeof("192.168.100.12"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_m == true));
                // captures buffer overflow
                l_s = l_nms->contains(l_m, "192.168.100.0", sizeof("192.168.100.0"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_m == true));
                l_s = l_nms->contains(l_m, "193.164.100.12", sizeof("193.164.100.12"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_m == false));
                l_s = l_nms->add("33.239.70.98/31", sizeof("33.239.70.98/31"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_nms->add("33.239.70.96/31", sizeof("33.239.70.96/31"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_nms->contains(l_m, "33.239.70.99", sizeof("33.239.70.99"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_m == true));
                l_s = l_nms->contains(l_m, "33.239.70.97", sizeof("33.239.70.97"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_m == true));
                if(l_nms) { delete l_nms; l_nms = NULL;}
        }
        SECTION("ipv6 basic insert") {
                int32_t l_s;
                ns_waflz::nms *l_nms = new ns_waflz::nms();
                l_s = l_nms->add("2001:0db8:85a3:0000:0000:8a2e:0370:7334", sizeof("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_nms->add("2222:0db8:85a3:0001:0001:8a2e:0370::/112", sizeof("2222:0db8:85a3:0001:0001:8a2e:0370::/112"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                void *l_node;
                bool l_m;
                l_s = l_nms->contains(l_m, "2001:0db8:85a3:0000:0000:8a2e:0370:7334", sizeof("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_m == true));
                l_s = l_nms->contains(l_m, "2001:0db8:85a3:0000:0000:8a2f:0370:7334", sizeof("2001:0db8:85a3:0000:0000:8a2f:0370:7334"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_m == false));
                l_s = l_nms->contains(l_m, "2222:0db8:85a3:0001:0001:8a2e:0370:0001", sizeof("2222:0db8:85a3:0001:0001:8a2e:0370:0001"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_m == true));
                l_s = l_nms->contains(l_m, "2222:0db8:85a3:0001:0001:8a2e:0370:0000", sizeof("2222:0db8:85a3:0001:0001:8a2e:0370:0000"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_m == true));
                l_s = l_nms->contains(l_m, "2222:0db8:85a3:0001:0001:8a2e:0371:0001", sizeof("2222:0db8:85a3:0001:0001:8a2e:0371:0001"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_m == false));
                l_s = l_nms->add("72c6:c04:bf2e:a6c6:6b90:2a94:42de:6ab7/113", sizeof("72c6:c04:bf2e:a6c6:6b90:2a94:42de:6ab7/113"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_nms->add("72c6:c04:bf2e:a6c6:6b90:2a94:42de:eab7/113", sizeof("72c6:c04:bf2e:a6c6:6b90:2a94:42de:eab7/113"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_nms->contains(l_m, "72c6:c04:bf2e:a6c6:6b90:2a94:42de:8000", sizeof("72c6:c04:bf2e:a6c6:6b90:2a94:42de:8000"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_m == true));
                l_s = l_nms->contains(l_m, "72c6:c04:bf2e:a6c6:6b90:2a94:42de:0", sizeof("72c6:c04:bf2e:a6c6:6b90:2a94:42de:0"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_m == true));
                if(l_nms) { delete l_nms; l_nms = NULL;}
        }
}
