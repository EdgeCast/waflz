include_directories(/opt/local/include)
# ------------------------------------------------------------------------------
# Can't add for now...
# ------------------------------------------------------------------------------
add_definitions(-DHAVE_CONFIG_H)
# ------------------------------------------------------------------------------
# header files to install
# ------------------------------------------------------------------------------
LIST(APPEND INST_HDRS ${HDRS})
# ------------------------------------------------------------------------------
# include paths
# ------------------------------------------------------------------------------
include_directories(
    #${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    # ------------------------------------------------------
    # proto
    # ------------------------------------------------------
    ${CMAKE_BINARY_DIR}/proto
    # ------------------------------------------------------
    # yajl
    # ------------------------------------------------------
    ${CMAKE_BINARY_DIR}/ext_yajl-prefix/src/yajl-2.1.1/include
    # ------------------------------------------------------
    # waflz include
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    # ------------------------------------------------------
    # cityhash libs
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/cityhash
    # ------------------------------------------------------
    # libinjection
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/libinjection/src
    # ------------------------------------------------------
    # libmaxminddb
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/libmaxminddb/src
    # ------------------------------------------------------
    # lmdb
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/liblmdb/src
    # ------------------------------------------------------
    # jwt
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/jwt-cpp
    # ------------------------------------------------------
    # external libs
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext
    ${CMAKE_SOURCE_DIR}/ext/yajl
    /usr/include/libxml2
    # OS X hack to support /usr/local/include
    # ref: https://gitlab.kitware.com/cmake/cmake/-/issues/19120
    /usr/local/include
)
# ------------------------------------------------------------------------------
# source files
# ------------------------------------------------------------------------------
SET(SRCS
    # ------------------------------------------------------
    # libmaxminddb
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/libmaxminddb/src/data-pool.c
    ${CMAKE_SOURCE_DIR}/ext/libmaxminddb/src/maxminddb.c
    # ------------------------------------------------------
    # lmdb
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/liblmdb/mdb.c
    ${CMAKE_SOURCE_DIR}/ext/liblmdb/midl.c
    # ------------------------------------------------------
    # yajl
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_alloc.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_gen.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_parser.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_version.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_buf.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_encode.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_lex.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_tree.c
    # ------------------------------------------------------
    # base64
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/base64/base64.cc
    # ------------------------------------------------------
    # json protobuf
    # ------------------------------------------------------
    jspb/jspb.cc
    # ------------------------------------------------------
    # ectoken
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/ectoken/ectoken_v3.cc
    ${CMAKE_SOURCE_DIR}/ext/ectoken/base64.cc
    # ------------------------------------------------------
    # support
    # ------------------------------------------------------
    support/city.cc
    support/time_util.cc
    support/geoip2_mmdb.cc
    support/file_util.cc
    support/string_util.cc
    support/trace.cc
    support/ndebug.cc
    support/base64.cc
    support/curl_util.cc
    # ------------------------------------------------------
    # db
    # ------------------------------------------------------
    db/lm_db.cc
    # ------------------------------------------------------
    # libinjection
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/libinjection/src/libinjection_html5.c
    ${CMAKE_SOURCE_DIR}/ext/libinjection/src/libinjection_sqli.c
    ${CMAKE_SOURCE_DIR}/ext/libinjection/src/libinjection_xss.c
    # ------------------------------------------------------
    # modsecurity
    # ------------------------------------------------------
    modsecurity/config_parser.cc
    # ------------------------------------------------------
    # parsers
    # ------------------------------------------------------
    parser/parser_url_encoded.cc
    parser/parser_xml.cc
    parser/parser_json.cc
    # ------------------------------------------------------
    # operators
    # ------------------------------------------------------
    op/regex.cc
    op/luhn.cc
    op/nms.cc
    op/ac.cc
    op/byte_range.cc
    # ------------------------------------------------------
    # core
    # ------------------------------------------------------
    core/waf.cc
    core/acl.cc
    core/api_gw.cc
    core/client_waf.cc
    core/schema.cc
    core/engine.cc
    core/profile.cc
    core/decode.cc
    core/rqst_ctx.cc
    core/var.cc
    core/tx.cc
    core/op.cc
    core/macro.cc
    core/render.cc
    core/scopes.cc
    core/scopes_configs.cc
    core/rules.cc
    core/bots.cc
    core/bot_manager.cc
    core/challenge.cc
    core/captcha.cc
    core/resp_ctx.cc
    core/render_resp.cc
    core/jwt_parser.cc
    # ------------------------------------------------------
    # limit
    # ------------------------------------------------------
    limit/rl_obj.cc
    limit/enforcer.cc
    limit/limit.cc
)
if(BUILD_REDIS)
  list(APPEND SRCS
    db/redis_db.cc
  )
endif()
# ------------------------------------------------------------------------------
# c source
# ------------------------------------------------------------------------------
SET_SOURCE_FILES_PROPERTIES(
    # ------------------------------------------------------
    # libmaxminddb
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/libmaxminddb/src/data-pool.c
    ${CMAKE_SOURCE_DIR}/ext/libmaxminddb/src/maxminddb.c
    # ------------------------------------------------------
    # yajl
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_alloc.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_gen.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_parser.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_version.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_buf.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_encode.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_lex.c
    ${CMAKE_SOURCE_DIR}/ext/yajl/yajl_tree.c
    # ------------------------------------------------------
    # libinjection
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/ext/libinjection/src/libinjection_html5.c
    ${CMAKE_SOURCE_DIR}/ext/libinjection/src/libinjection_sqli.c
    ${CMAKE_SOURCE_DIR}/ext/libinjection/src/libinjection_xss.c
    # ------------------------------------------------------
    # properties
    # ------------------------------------------------------
    PROPERTIES LANGUAGE C
)
set(CMAKE_C_FLAGS "-std=c99")
set(CMAKE_CXX_FLAGS "-Wall -Weffc++ -Werror -std=c++17")
# ------------------------------------------------------------------------------
# headers
# ------------------------------------------------------------------------------
SET(HDRS
    ${CMAKE_SOURCE_DIR}/include/waflz/acl.h
    ${CMAKE_SOURCE_DIR}/include/waflz/api_gw.h
    ${CMAKE_SOURCE_DIR}/include/waflz/client_waf.h
    ${CMAKE_SOURCE_DIR}/include/waflz/schema.h
    ${CMAKE_SOURCE_DIR}/include/waflz/arg.h
    ${CMAKE_SOURCE_DIR}/include/waflz/atomic.h
    ${CMAKE_SOURCE_DIR}/include/waflz/challenge.h
    ${CMAKE_SOURCE_DIR}/include/waflz/captcha.h
    ${CMAKE_SOURCE_DIR}/include/waflz/city.h
    ${CMAKE_SOURCE_DIR}/include/waflz/config_parser.h
    ${CMAKE_SOURCE_DIR}/include/waflz/def.h
    ${CMAKE_SOURCE_DIR}/include/waflz/engine.h
    ${CMAKE_SOURCE_DIR}/include/waflz/geoip2_mmdb.h
    ${CMAKE_SOURCE_DIR}/include/waflz/parser.h
    ${CMAKE_SOURCE_DIR}/include/waflz/profile.h
    ${CMAKE_SOURCE_DIR}/include/waflz/render.h
    ${CMAKE_SOURCE_DIR}/include/waflz/rqst_ctx.h
    ${CMAKE_SOURCE_DIR}/include/waflz/rules.h
    ${CMAKE_SOURCE_DIR}/include/waflz/bots.h
    ${CMAKE_SOURCE_DIR}/include/waflz/bot_manager.h
    ${CMAKE_SOURCE_DIR}/include/waflz/scopes_configs.h
    ${CMAKE_SOURCE_DIR}/include/waflz/scopes.h
    ${CMAKE_SOURCE_DIR}/include/waflz/trace.h
    ${CMAKE_SOURCE_DIR}/include/waflz/waf.h
    ${CMAKE_SOURCE_DIR}/include/waflz/waflz.h
    ${CMAKE_SOURCE_DIR}/include/waflz/string_util.h
    ${CMAKE_SOURCE_DIR}/include/waflz/resp_ctx.h
    ${CMAKE_SOURCE_DIR}/include/waflz/render_resp.h
    # ------------------------------------------------------
    # db
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/include/waflz/kv_db.h
    ${CMAKE_SOURCE_DIR}/include/waflz/lm_db.h
    # ------------------------------------------------------
    # limit
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/include/waflz/enforcer.h
    ${CMAKE_SOURCE_DIR}/include/waflz/limit.h
    ${CMAKE_SOURCE_DIR}/include/waflz/rl_obj.h
    # ------------------------------------------------------
    # protocol buffers
    # ------------------------------------------------------
    ${CMAKE_BINARY_DIR}/proto/acl.pb.h
    ${CMAKE_BINARY_DIR}/proto/action.pb.h
    ${CMAKE_BINARY_DIR}/proto/bot_manager.pb.h
    ${CMAKE_BINARY_DIR}/proto/event.pb.h
    ${CMAKE_BINARY_DIR}/proto/limit.pb.h
    ${CMAKE_BINARY_DIR}/proto/profile.pb.h
    ${CMAKE_BINARY_DIR}/proto/request_info.pb.h
    ${CMAKE_BINARY_DIR}/proto/rule.pb.h
    ${CMAKE_BINARY_DIR}/proto/scope.pb.h
    ${CMAKE_BINARY_DIR}/proto/api_gw.pb.h
    ${CMAKE_BINARY_DIR}/proto/client_waf.pb.h
    # ------------------------------------------------------
    # op
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/include/waflz/ac.h
    ${CMAKE_SOURCE_DIR}/include/waflz/nms.h
    # ------------------------------------------------------
    # support
    # ------------------------------------------------------
    ${CMAKE_SOURCE_DIR}/src/support/file_util.h
    ${CMAKE_SOURCE_DIR}/src/support/curl_util.h
)
if(BUILD_REDIS)
  list(APPEND HDRS
    ${CMAKE_SOURCE_DIR}/include/waflz/redis_db.h
  )
endif()
# ------------------------------------------------------------------------------
# Tell the build system protobuf files are automatically generated
# ------------------------------------------------------------------------------
SET(PB_SRCS
    ${WAFLZ_PROTO_HDRS} ${WAFLZ_PROTO_SRCS}
)
set_source_files_properties(${PB_SRCS} PROPERTIES GENERATED TRUE)
set_source_files_properties(${PB_SRCS} PROPERTIES COMPILE_FLAGS '-Wno-effc++')
# ------------------------------------------------------------------------------
#  JWT third party lib is not build with -effc++.
# ------------------------------------------------------------------------------
set_source_files_properties(core/jwt_parser.h PROPERTIES COMPILE_FLAGS '-Wno-effc++')
set_source_files_properties(core/jwt_parser.cc PROPERTIES COMPILE_FLAGS '-Wno-effc++')
# ------------------------------------------------------------------------------
# library
# ------------------------------------------------------------------------------
add_library(waflz_obj OBJECT ${SRCS} ${PB_SRCS})
add_library(waflzcore STATIC $<TARGET_OBJECTS:waflz_obj>)
add_library(waflz SHARED $<TARGET_OBJECTS:waflz_obj>)
# ------------------------------------------------------------------------------
# lib settings
# ------------------------------------------------------------------------------
target_include_directories(waflzcore PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_BINARY_DIR}/proto
    ${CMAKE_BINARY_DIR}
)
target_link_libraries(waflz
    curl
    ssl
    crypto
    pcre
    protobuf
    xml2
)
if(BUILD_REDIS)
  target_link_libraries(waflz
    hiredis
  )
endif()
# ------------------------------------------------------------------------------
# properties
# ------------------------------------------------------------------------------
SET_TARGET_PROPERTIES(waflz_obj
    PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)
# ------------------------------------------------------------------------------
# Create symlink for libwaflz.so.<soversion>
# ------------------------------------------------------------------------------
SET_TARGET_PROPERTIES(waflz
    PROPERTIES
    SOVERSION 0
)
# ------------------------------------------------------------------------------
# install
# ------------------------------------------------------------------------------
# Add install target for the library
install(TARGETS waflzcore
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    COMPONENT Libraries
)
# Add install target for the shared library
install(TARGETS waflz
  LIBRARY DESTINATION lib
  COMPONENT Libraries
)
# Add install target for header files
install(FILES ${HDRS}
    DESTINATION include/waflz
    COMPONENT Headers
)

