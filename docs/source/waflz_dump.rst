Format Conversions with waflz_dump
----------------------------------
`waflz <https://github.com/edgioinc/waflz>`_ can interoperate with ModSecurity rules in 3 format: json, protocol buffers (binary), and ModSecurity rules format.  `waflz_dump <https://github.com/edgioinc/waflz/tree/master/util/waflz_dump>`_ is a utility to convert between the 3 formats.  waflz_dump is more than a curiosity, however.  It has practical uses at Edgio for exposing ruleset information via API's, as ModSecurity Rule format is not conducive to HTTP API usage.

A Little Conversion Example (`ShellShock <https://en.wikipedia.org/wiki/Shellshock_(software_bug)>`_)
=====================================================================================================

A ModSecurity Rule file
***********************

.. code-block:: sh

    >cat modsecurity_shellshock_1.conf

    SecRule REQUEST_HEADERS|REQUEST_LINE|REQUEST_BODY|REQUEST_HEADERS_NAMES \
            "@contains () {" "phase:2,rev:'1',\
            ver:'EC/1.0.0',\
            maturity:'1',accuracy:'8',\
            t:none,t:urlDecodeUni,t:Utf8toUnicode,\
            id:'431000',\
            msg:'Bash shellshock attack detected',\
            tag:'CVE-2014-6271',block"

Convert to json
***************

.. code-block:: sh

    >waflz_dump --input=./modsecurity_shellshock_1.conf --input_modsec --json | jq '.'

    {
      "ruleset_id": "__na__",
      "ruleset_version": "__na__",
      "directive": [
        {
          "sec_rule": {
            "variable": [
              {
                "type": "REQUEST_HEADERS",
                "match": [
                  {
                    "is_negated": false,
                    "is_regex": false
                  }
                ],
                "is_count": false
              },
              {
                "type": "REQUEST_LINE",
                "match": [
                  {
                    "is_negated": false,
                    "is_regex": false
                  }
                ],
                "is_count": false
              },
              {
                "type": "REQUEST_BODY",
                "match": [
                  {
                    "is_negated": false,
                    "is_regex": false
                  }
                ],
                "is_count": false
              },
              {
                "type": "REQUEST_HEADERS_NAMES",
                "match": [
                  {
                    "is_negated": false,
                    "is_regex": false
                  }
                ],
                "is_count": false
              }
            ],
            "operator": {
              "type": "CONTAINS",
              "value": "() {",
              "is_regex": false,
              "is_negated": false
            },
            "action": {
              "id": "431000",
              "msg": "Bash shellshock attack detected",
              "action_type": "BLOCK",
              "accuracy": "8",
              "maturity": "1",
              "phase": 2,
              "rev": "1",
              "ver": "EC/1.0.0",
              "file": "modsecurity_shellshock_1.conf",
              "tag": [
                "CVE-2014-6271"
              ],
              "t": [
                "NONE",
                "URLDECODEUNI",
                "UTF8TOUNICODE"
              ]
            },
            "hidden": false
          }
        }
      ]
    }


Convert to protocol buffers
***************************

.. code-block:: sh

    >waflz_dump --input=./modsecurity_shellshock_1.conf --input_modsec --pbuf | xxd

    00000000: a206 065f 5f6e 615f 5faa 0606 5f5f 6e61  ...__na__...__na
    00000010: 5f5f 82f7 02cb 0112 c801 c23e 0a08 1612  __.........>....
    00000020: 0450 0058 0018 00c2 3e0a 0818 1204 5000  .P.X....>.....P.
    00000030: 5800 1800 c23e 0a08 1212 0450 0058 0018  X....>.....P.X..
    00000040: 00c2 3e0a 0817 1204 5000 5800 1800 ca3e  ..>.....P.X....>
    00000050: 0c08 0212 0428 2920 7b18 0050 00d2 3e7e  .....() {..P..>~
    00000060: 0a06 3433 3130 3030 121f 4261 7368 2073  ..431000..Bash s
    00000070: 6865 6c6c 7368 6f63 6b20 6174 7461 636b  hellshock attack
    00000080: 2064 6574 6563 7465 6450 02a2 0601 38aa   detectedP....8.
    00000090: 0601 31b0 0602 ba06 0131 c206 0845 432f  ..1......1...EC/
    000000a0: 312e 302e 30ca 061d 6d6f 6473 6563 7572  1.0.0...modsecur
    000000b0: 6974 795f 7368 656c 6c73 686f 636b 5f31  ity_shellshock_1
    000000c0: 2e63 6f6e 66e2 120d 4356 452d 3230 3134  .conf...CVE-2014
    000000d0: 2d36 3237 31a0 1f0b a01f 12a0 1f13 80fa  -6271...........
    000000e0: 0100                                     ..

Converting to json and back to ModSecurity
******************************************
*note the action ordering in the rule becomes slightly mangled albeit still correct*

.. code-block:: sh

    # modsecurity rules file
    >cat ./modsecurity_shellshock_1.conf

    SecRule REQUEST_HEADERS|REQUEST_LINE|REQUEST_BODY|REQUEST_HEADERS_NAMES \
            "@contains () {" "phase:2,rev:'1',\
            ver:'EC/1.0.0',\
            maturity:'1',accuracy:'8',\
            t:none,t:urlDecodeUni,t:Utf8toUnicode,\
            id:'431000',\
            msg:'Bash shellshock attack detected',\
            tag:'CVE-2014-6271',block"
    
    # convert to json
    >waflz_dump --input=./modsecurity_shellshock_1.conf --input_modsec --json --output=./modsecurity_shellshock_1.json

    # convert back to ModSecurity format
    >waflz_dump --input=./modsecurity_shellshock_1.json --input_json --modsec

    SecRule REQUEST_HEADERS|REQUEST_LINE|REQUEST_BODY|REQUEST_HEADERS_NAMES "@contains () {" "phase:2,block,rev:'1',ver:'EC/1.0.0',maturity:'1',accuracy:'8',t:none,t:urlDecodeUni,t:utf8tounicode,id:431000,msg:'Bash shellshock attack detected',tag:'CVE-2014-6271'"

