Overview
--------

What is it?
===========
An implementation of a WAF engine in c/c++ supporting processing a subset of ModSecurity rules functionalties, configurable with either json or ModSecurity rules.  waflz is optimized to support running many WAF profiles side by side, by using faster/smaller internal data types and sharing common ruleset data between the profiles.  E.g, if multiple WAF profiles refer to the same ruleset(s), the ruleset(s) are loaded only once for all and shared in memory.

Why another ModSecurity engine?
===============================
The open source standard implementation of the `ModSecurity Rules Engine <https://github.com/SpiderLabs/ModSecurity/>`_ -while excellent, and extremely flexible for individuals' use-cases, could be problematic in a CDN, where performance is the product.  One of the principle technical challenges in a CDN is "multi-tenancy", where any given single physical server on our edge is servicing client requests for any given customer configuration.  Mechanically, on the edge customer configuration is "patched" in at run-time while the client request is being serviced.

.. figure:: _images/patching.svg
    :alt: patching
    :align: center
    :figclass: align-center
    :width: 500px
    :height: 150px

    customer config patching on an edge server

The resource implications of being able to "patch" in any given customer configuration from any given edge server means configuration must be lightweight and servicing the request must be done as fast as possible.  One customer configuration using too much memory crowds out the others (memory being finite).  Performance wise, client requests taking too long to service eventually affect other client requests (including other customers).

Development from this perspective changes many of the engineering trade-offs.  Determinism, more restrictive memory and cpu constraints tend to trump flexibility, so `waflz <https://github.com/edgioinc/waflz>`_ was developed specifically to suit the needs of a CDN.

Architecture
============

Input/Output Formats
********************
We thought one of the biggest candidates for improvement in developing our own engine was the representation of rule language in code.  A more rigid schema might lead to simpler, easier to reason about implementations.  We settled on defining the rules in `protocol buffers <https://developers.google.com/protocol-buffers/>`_ schema -see:  `definitions <https://github.com/edgioinc/waflz/blob/master/proto/rule.proto>`_.  Some of the benefits to this approach included:

* Protocol buffers are interoperable with json, ideal for working with API's.  Translation between the protocol buffers and ModSecurity format was added by us, allowing for interoperability between the 3 formats (json/protocol buffers/ModSecurity).  `waflz_dump <https://github.com/edgioinc/waflz/tree/master/util/waflz_dump>`_ is a utility for converting between the 3 formats.
* The parsed protocol buffer representation can be used in the code, circumventing duplication in redefining internal data structures to mirror the data definitions.

Server Shims
************
Another interesting detail is how to write a library that plugs into HTTP server applications like nginx, apache, or "Sailfish" (the Edgio HTTP server application).  The library shouldn't expose its internal complexity, but for a WAF quite a bit of request context information has to be passed between the HTTP server and the library.  To write a plugin for waflz, server specific callbacks are defined along with the "request context pointer", to extract various parts of the HTTP request and provide them back to the waflz library.

An example using the `is2 <https://github.com/Edgio/is2>`_ embedded http server library:

.. code-block:: c

  // get request method callback
  static int32_t get_rqst_method_cb(const char **a_data,
                                    uint32_t &a_len,
                                    void *a_ctx)
  {
          // cast in request context
          ns_is2::rqst *l_rqst = ((ns_is2::session *)a_ctx)->m_rqst;

          // extract request method
          *a_data = l_rqst->get_method_str();
          a_len = strlen(l_rqst->get_method_str());

          // return status OK == 0
          return 0;
  }

The list of user definable callbacks is `here <https://github.com/edgioinc/waflz/blob/master/include/waflz/rqst_ctx.h#L68>`_ -*NOTE*: *we're working to reducing the number of required callback definitions for waflz server integration.  Many of these can be collapsed*

Server-less Testing
*******************
A benefit of defining a plugin this way with callbacks to get the HTTP request data, is it allows for "server-less testing" in whitebox tests.  There's few examples of `this <https://github.com/edgioinc/waflz/blob/master/tests/whitebox/core/wb_profile_acl.cc#L99>`_ in our whitebox testing framework in the access control list (ACL) tests, where the server callbacks are stubbed out, and the library runs and tests as if it was embedded in and actual HTTP server application.

.. code-block:: c

  // spoof a request uri/path with a callback
  static int32_t get_rqst_uri_bananas_cb(const char **a_data, uint32_t &a_len, void *a_ctx)
  {
         static const char s_uri[] = "/bananas/monkey";
         *a_data = s_uri;
         a_len = sizeof(s_uri);
         return 0;
  }

  ...

   // write a catch.hpp to test waflz processing w/ spoofed server callback
   SECTION("verify simple URI match") {

           // set callbacks...
           ns_waflz::rqst_ctx::s_get_rqst_uri_cb = get_rqst_uri_bananas_cb;
           ...
           // waflz processing...
           void *l_ctx = NULL;
           waflz_pb::event *l_event = NULL;
           int l_s;
           l_s = l_profile->process(&l_event, l_ctx);
           REQUIRE((l_s == WAFLZ_STATUS_OK));
           REQUIRE((l_event != NULL));
           ...
  ...

"Muti-tenancy" Concerns
***********************
Running a WAF in a CDN, the principle resource issue can be many customer configurations loading the same 3 or 4 WAF ruleset definitions (100's to 1000's of rules) into a server process's memory.  The obvious optimization is to load rulesets only once and share read-only copies internally between the customer configurations.  One challenge with this approach, however, is custom configurable rule modifications like `SecRuleUpdateTargetById <https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#SecRuleUpdateTargetById>`_ complicate the implementation of sharing ruleset data.  waflz dedupes rulesets loaded previously, saving precious process memory in production.

Performance Tweaks
******************
There are a few critical data structures in a ModSecurity-compatible WAF, besides the usual strings, and regex patterns.  Here's a list of a few we strived to improve for our specific use-cases:

* **Aho-Corasick**: For operators like `PM <https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#pm>`_/`PMFROMFILE <https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#pmfromfile>`_ (multiple substring matching like "grep -F/fgrep"), an `Aho-Corasick <https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm>`_ data structure is constructed for faster parallel searching of substrings.  `Our construction <https://github.com/edgioinc/waflz/blob/master/src/op/ac.h>`_ is similar to the `acmp <https://github.com/SpiderLabs/ModSecurity/blob/v2/master/apache2/acmp.h>`_ object in the standard implementation but more space efficient, as it prunes node meta information.  Search performance is similar as the tree is traversed similarly in both implementations.
* **IP Tree**: We've had an internal `IP Tree <https://github.com/edgioinc/waflz/blob/master/include/waflz/nms.h>`_ kicking around our internal repos, that's performed well for us and seems to be faster than the `msc_tree <https://github.com/SpiderLabs/ModSecurity/blob/v2/master/apache2/msc_tree.h>`_ in the standard implementation -see: :ref:`appendix-iptrie`.  It's reusable as well outside of our library.
* **XPath**: For `"XML:<path>" <https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#XML>`_ targets in the rules to mitigate the performance overhead of recalculating the same expression in the rules during request processing, we built in XPath cache-ing. For example *grep* how many times the expression "XML:/\*" appears in the OWASP CRS ruleset to see how many times an XPath could be recomputed in the processing of a single request without a cache-ing layer.
