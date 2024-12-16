![waflz-ci](https://github.com/edgioinc/waflz/workflows/waflz-ci/badge.svg)

<p align="center">
<img src="/docs/_images/waflz_white.svg" title="waflz" width="200"/>
</p>

# waflz
> _A multitenant ModSecurity compatible WAF engine. [Docs](https://edgio.github.io/waflz/ "waflz docs")_

## Table of Contents

- [Background](#background)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [License](#license)

## Background
An implementation of a WAF engine in c/c++ supporting processing a subset of ModSecurity rules functionalties, configurable with either json or ModSecurity rules.  waflz is optimized to support running many WAF profiles side by side, by using [faster](https://github.com/edgioinc/waflz/blob/master/include/waflz/nms.h "IP tree")/[smaller](https://github.com/edgioinc/waflz/blob/master/include/waflz/ac.h "Aho–Corasick") internal data types and sharing common ruleset data between the profiles -ie if multiple WAF profiles refer to the same ruleset(s), the ruleset(s) are loaded only once for all and shared in memory.

### Rationale
The Edgio global edge platform is a multitenant CDN supporting our hundreds of thousands individual customer configurations from any given location.  The Edgio WAF supports running OWASP Core Rulesets as well as some third-party rulesets.  The performance and resource allocation of any given customer configuration has the potential of impacting others -ie eventually all configurations live in memory on a physical server in a "Point of Presence" (POP) in a datacenter.  It was important then to the Edgio CDN the WAF be as high performant, memory constrained, and deterministic as possible.

### Capabilities
The open source standard implementation of the [ModSecurity Rules Engine](https://github.com/SpiderLabs/ModSecurity "ModSecurity") -while excellent, and extremely flexible for individuals' use-cases, could be problematic in a CDN, where performance is the product.  Several ModSecurity capabilities eg [SecRemoteRules](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#SecRemoteRules "SecRemoteRules") and [inspectFile](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#inspectFile "inspectFile"), were intentionally ommitted, due to potential performance impacts in a multitenant environment.  A list of currently supported variables, operators and transforms are listed in the [capabilities section of the docs](https://edgioinc.github.io/waflz/capabilities "waflz capabilities")


## Install

### Building

#### Ubuntu (18.04/20.04)

##### Package Requirements

```sh
$ sudo apt-get install -y libssl-dev libpcre3-dev libxml2-dev libicu-dev protobuf-compiler libprotobuf-dev liblzma-dev python3-pip
```

##### Python Package Requirements
```sh
$ pip3 install -r requirements.txt
```

##### Build
This script will build, run tests, and create packages

```sh
$ ./build.sh
```

##### Install (optional)
```sh
cd ./build
sudo make install
```

### Source Code Layout
The waflz root directory contains this README, the build.sh script which automates building/testing/packaging, and other files related to CI/CD.

Inside the root are the following important directories:

- `docs`: Contains everything necessary to generate documentation.  Changes should be made inside the source subdirectory.
- `ext`: External libraries that are compiled and used by waflz
- `include/waflz`: The core C/C++ header files
- `proto`: The Protocol Buffer definition files used by waflz
- `src`: The core C/C++ source files, organized by functionality
- `sub`: Contains the submodules used by waflz
- `tests`: Contains the waflz test suite, which includes blackbox, whitebox, and stress testing
- `util`: Utility applications that are useful for testing and validation of the waflz library

## Usage

### Running standalone waflz_server for testing WAF rules

```sh
$ cat rule.conf
  SecRule &REQUEST_HEADERS:Host "@eq 0" \
        "phase:2,\
        rev:'2',\
        ver:'OWASP_CRS/2.2.9',\
        t:none,block,\
        msg:'Request Missing a Host Header',\
        id:'960008',\
        severity:'4',\
        setvar:'tx.msg=%{rule.msg}',\
        setvar:tx.anomaly_score=+%{tx.warning_anomaly_score},\
        setvar:tx.%{rule.id}-OWASP_CRS/PROTOCOL_VIOLATION/MISSING_HEADER-%{matched_var_name}=%{matched_var}"

$ ./build/util/waflz_server/waflz_server --modsecurity=rule.conf

```

### curl'ing waflz_server

```sh
$ curl -s "http://localhost:12345/index.html" -H"Host:" | jq '.'
{
  "matched_var": {
    "name": "REQUEST_HEADERS",
    "value": "MA=="
  },
  "rule_msg": "Inbound Anomaly Score Exceeded (Total Score: 3): Last Matched Message: Request Missing a Host Header",
  "rule_op_name": "gt",
  "rule_op_param": "0",
  "rule_tag": [
    "OWASP_CRS/ANOMALY/EXCEEDED"
  ],
  "rule_target": [
    {
      "name": "TX",
      "param": "ANOMALY_SCORE"
    }
  ],
  "sub_event": [
    {
      "matched_var": {
        "name": "REQUEST_HEADERS",
        "value": "MA=="
      },
      "rule_id": 960008,
      "rule_intercept_status": 403,
      "rule_msg": "Request Missing a Host Header",
      "rule_op_name": "EQ",
      "rule_op_param": "0",
      "rule_target": [
        {
          "is_counting": true,
          "name": "REQUEST_HEADERS",
          "param": "Host"
        }
      ],
      "total_anomaly_score": 3,
      "waf_profile_id": "__na__",
      "waf_profile_name": "__na__"
    }
  ],
  "total_anomaly_score": 3,
  "waf_profile_id": "__na__",
  "waf_profile_name": "__na__"
}
```

## Contribute

- We welcome issues, questions and pull requests.

