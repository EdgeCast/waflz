Appendix
========

ACL Rule ID mapping
-------------------
waflz internal access control lists' (ACLs') use 80XXX rule prefixes for alerts (ip/content-type/etc) -see also: :ref:`profiles-acls`

.. List-table:: OWASP CRS 2.2.9 to waflz ACL rule-id mapping
	:widths: 30 25 25
	:header-rows: 1

	* - ACL Setting
	  - OWASP CRS 2.2.9
	  - waflz
	* - ASN
	  - 430001
	  - 80001
	* - Allowed content-types
	  - 960010
	  - 80002
	* - Cookie
	  - 430004
	  - 80003
	* - Country
	  - 430425
	  - 80004
	* - Disallowed file extensions
	  - 960035
	  - 80005
	* - Disallowed headers
	  - 960038
	  - 80007
	* - IP
	  - 430108
	  - 80008
	* - Allowed methods
	  - 960032
	  - 80009
	* - Referer
	  - 430003
	  - 80010
	* - URL
	  - 430002
	  - 80011
	* - User-Agent
	  - 430614
	  - 80012
	* - HTTP version
	  - 960034
	  - 80013


.. _appendix-iptrie:

IP Trie Performance
-------------------

Comparing memory and query performance between the waflz `IP Tree <https://github.com/edgioinc/waflz/blob/master/include/waflz/nms.h>`_ and ModSecurity `msc_tree <https://github.com/SpiderLabs/ModSecurity/blob/v2/master/apache2/msc_tree.h>`_ implementations.

.. figure:: _images/mem_usage_ipv4.svg
    :alt: Memory Usage IPv4
    :align: center
    :figclass: align-center

    Comparing ModSecurity vs waflz iptrie Memory Usage (IPv4)

.. figure:: _images/mem_usage_ipv6.svg
    :alt: Memory Usage IPv6
    :align: center
    :figclass: align-center

    Comparing ModSecurity vs waflz iptrie Memory Usage (IPv6)

.. figure:: _images/query_perf_ipv4.svg
    :alt: Search Performance IPv4
    :align: center
    :figclass: align-center

    Comparing ModSecurity vs waflz iptrie Search Performance (IPv4)

.. figure:: _images/query_perf_ipv6.svg
    :alt: Search Performance IPv6
    :align: center
    :figclass: align-center

    Comparing ModSecurity vs waflz iptrie Search Performance (IPv6)


