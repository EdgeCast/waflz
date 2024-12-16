# ------------------------------------------------------------------------------
# Project setup
# ------------------------------------------------------------------------------
project(waflz)
cmake_minimum_required(VERSION 3.5)
# ------------------------------------------------------------------------------
# Build options
# ------------------------------------------------------------------------------
option(GCC_OPTIONS                "Command line options passed to gcc or 'native' to compile for this hardware" OFF)
option(DEBUG_MODE                 "Compile in debug mode." OFF)
option(FORTIFY                    "Fortify source." OFF)
option(BUILD_SYMBOLS              "Build with Symbols" OFF)
option(BUILD_TCMALLOC             "Build with tcmalloc" OFF)
option(BUILD_PROFILER             "Enable google cpu and heap profiler support" OFF)
option(BUILD_ASAN                 "Build with Address Sanitizer" OFF)
option(BUILD_UBSAN                "Build with Undefined Behavior Sanitizer" OFF)
option(BUILD_TESTS                "Build the unit tests." ON)
option(BUILD_PERFORMANCE_MEASURE  "Builds performance measures." ON)
option(BUILD_APPS                 "Build the apps." OFF)
option(BUILD_REDIS                "Build support for redis" OFF)
option(BUILD_UBUNTU               "Build for Ubuntu" OFF)
option(BUILD_CUSTOM_OPENSSL       "Build for openssl" OFF)
option(BUILD_REDHAT               "Build for Red Hat" OFF)
# ------------------------------------------------------------------------------
# Add the corrent -std flag, whatever it is
# ------------------------------------------------------------------------------
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG(-Wno-error=misleading-indentation COMPILER_SUPPORTS_MISIDENT)
CHECK_CXX_COMPILER_FLAG(-Wno-error=nonnull-compare COMPILER_SUPPORTS_NONNULL)
CHECK_CXX_COMPILER_FLAG(-std=c++17 COMPILER_SUPPORTS_CXX17)
CHECK_CXX_COMPILER_FLAG(-std=c++14 COMPILER_SUPPORTS_CXX14)
CHECK_CXX_COMPILER_FLAG(-std=c++11 COMPILER_SUPPORTS_CXX11)
CHECK_CXX_COMPILER_FLAG(-std=c++0x COMPILER_SUPPORTS_CXX0X)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(COMPILER_SUPPORTS_CXX14)
  if(COMPILER_SUPPORTS_MISIDENT)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-error=misleading-indentation")
  endif()
  if(COMPILER_SUPPORTS_NONNULL)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-error=nonnull-compare")
  endif()
endif()
# ------------------------------------------------------------------------------
# find protobuf package
# ------------------------------------------------------------------------------
find_package(Protobuf REQUIRED)
# ------------------------------------------------------------------------------
# Display the current settings
# ------------------------------------------------------------------------------
message(STATUS "Build Configuration:")
message("")
message("    Build Option                               Variable                     Value            ")
message("    -----------------------------------------------------------------------------------------")
message("    Debug mode:                                " "DEBUG_MODE                   " ${DEBUG_MODE})
message("    Fortify Source:                            " "FORTIFY                      " ${FORTIFY})
message("    Install path:                              " "INSTALL_PREFIX               " ${CMAKE_INSTALL_PREFIX})
message("    Build Symbols                              " "BUILD_SYMBOLS                " ${BUILD_SYMBOLS})
message("    Build with tcmalloc:                       " "BUILD_TCMALLOC               " ${BUILD_TCMALLOC})
message("    Enable google cpu/heap profiler support:   " "BUILD_PROFILER               " ${BUILD_PROFILER})
message("    Build with Address Sanitizer:              " "BUILD_ASAN                   " ${BUILD_ASAN})
message("    Build with Undefined Behavior Sanitizer:   " "BUILD_UBSAN                  " ${BUILD_UBSAN})
message("    Build unit tests:                          " "BUILD_TESTS                  " ${BUILD_TESTS})
message("    Build performance measures:                " "BUILD_PERFORMANCE_MEASURE    " ${BUILD_PERFORMANCE_MEASURE})
message("    Build applications:                        " "BUILD_APPS                   " ${BUILD_APPS})
message("    Build support for redis:                   " "BUILD_REDIS                  " ${BUILD_REDIS})
message("    Build for Ubuntu (adds package help):      " "BUILD_UBUNTU                 " ${BUILD_UBUNTU})
message("    Build for custom OpenSSL:                  " "BUILD_CUSTOM_OPENSSL         " ${BUILD_CUSTOM_OPENSSL})
message("    Build for Red Hat:                         " "BUILD_REDHAT                 " ${BUILD_REDHAT})
message("")
# ------------------------------------------------------------------------------
# Fortify Options
# ------------------------------------------------------------------------------
if(FORTIFY)
  add_definitions(-D_FORTIFY_SOURCE=2 -O1 -Wl,-z,relro,-z,now)
endif()
# ------------------------------------------------------------------------------
# redis
# ------------------------------------------------------------------------------
if(BUILD_REDIS)
  add_definitions(-DWAFLZ_KV_DB_REDIS)
endif()
# ------------------------------------------------------------------------------
# fail if not found
# ------------------------------------------------------------------------------
macro(fail_if_not_found_library a_lib)
  find_library(${a_lib}_LIBRARY
               NAME ${a_lib}
               PATH_SUFFIXES ${CMAKE_LIBRARY_ARCHITECTURE})
  if(NOT ${a_lib}_LIBRARY)
    message(FATAL_ERROR "${a_lib} library not found")
  endif()
  set(LIBRARIES ${LIBRARIES} ${a_lib})
endmacro(fail_if_not_found_library)
# ------------------------------------------------------------------------------
# special build case for OPENSSL
# ------------------------------------------------------------------------------
if(BUILD_CUSTOM_OPENSSL)
  INCLUDE_DIRECTORIES("${BUILD_CUSTOM_OPENSSL}/include")
  LINK_DIRECTORIES("${BUILD_CUSTOM_OPENSSL}")
  LINK_DIRECTORIES("${BUILD_CUSTOM_OPENSSL}/lib")
endif()
if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  set(LIBRARIES ${LIBRARIES} pthread ssl crypto pcre protobuf xml2 curl)
endif()
if(BUILD_REDHAT)
  set(LIBRARIES ${LIBRARIES} ssl crypto pcre protobuf xml2 curl)
  add_definitions(-DWAFLZ_PCRE_INFO_FLAGS_MISSING)
endif()
# ------------------------------------------------------------------------------
# Mac OS X
# ------------------------------------------------------------------------------
if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  # --------------------------------------------------------
  # Mac OS X specific code
  # --------------------------------------------------------
  SET(OperatingSystem "Mac OS X")
  # --------------------------------------------------------
  # Add MacPorts
  # --------------------------------------------------------
  INCLUDE_DIRECTORIES(/usr/local/opt/openssl/include)
  INCLUDE_DIRECTORIES(/usr/local/opt/protobuf/include)
  INCLUDE_DIRECTORIES(/usr/local/opt/pcre/include)
  INCLUDE_DIRECTORIES(/usr/local/opt/libxml2/include)
  INCLUDE_DIRECTORIES(/usr/local/opt/rapidjson/include)
  # --------------------------------------------------------
  # link dirs
  # --------------------------------------------------------
  LINK_DIRECTORIES(/usr/local/opt/openssl/lib)
  LINK_DIRECTORIES(/usr/local/opt/protobuf/lib)
  LINK_DIRECTORIES(/usr/local/opt/pcre/lib)
  LINK_DIRECTORIES(/usr/local/opt/libxml2/lib)
  # --------------------------------------------------------
  # if redis
  # --------------------------------------------------------
  if(BUILD_REDIS)
    INCLUDE_DIRECTORIES(/usr/local/opt/hiredis/include)
    LINK_DIRECTORIES(/usr/local/opt/hiredis/lib)
    LIST(APPEND LIBRARIES hiredis)
  endif()
  # --------------------------------------------------------
  # cc flags
  # --------------------------------------------------------
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
endif(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
# ------------------------------------------------------------------------------
# ASAN
# ------------------------------------------------------------------------------
if(BUILD_ASAN)
  set(DEBUG_LIBRARIES asan ${DEBUG_LIBRARIES})
  add_definitions(-g3 -fno-omit-frame-pointer -fsanitize=address)
  set(DEBUG_MODE ON)
  set(BUILD_PROFILER OFF)
  set(BUILD_TCMALLOC OFF)
# ------------------------------------------------------------------------------
# UBSAN
# ------------------------------------------------------------------------------
elseif(BUILD_UBSAN)
  set(DEBUG_LIBRARIES ubsan ${DEBUG_LIBRARIES})
  add_definitions(-g3 -fno-omit-frame-pointer -fsanitize=undefined -fno-sanitize-recover)
  set(DEBUG_MODE ON)
  set(BUILD_PROFILER OFF)
  set(BUILD_TCMALLOC OFF)
endif()
# ------------------------------------------------------------------------------
# Build PROFILER
# ------------------------------------------------------------------------------
if(BUILD_PROFILER)
  add_definitions(-DENABLE_PROFILER=1)
  if(BUILD_UBUNTU)
    fail_if_not_found_library(libprofiler.a)
    set(LIBRARIES ${LIBRARIES} unwind)
  else()
    set(LIBRARIES ${LIBRARIES} tcmalloc profiler)
  endif()
endif()
# ------------------------------------------------------------------------------
# Build TCMALLOC
# ------------------------------------------------------------------------------
if(BUILD_TCMALLOC)
  if(BUILD_UBUNTU)
    fail_if_not_found_library(libtcmalloc.a)
    fail_if_not_found_library(libunwind.a)
    LIST(APPEND LIBRARIES pthread)
  endif()
endif()
# ------------------------------------------------------------------------------
# Build UBUNTU
# ------------------------------------------------------------------------------
if(BUILD_UBUNTU)
  if(BUILD_APPS)
    fail_if_not_found_library(libssl.a)
  endif()
  fail_if_not_found_library(libcrypto.a)
  fail_if_not_found_library(libpcre.a)
  fail_if_not_found_library(libprotobuf.a)
  # --------------------------------------------------------
  # if rate-limiting check for kv db libs
  # --------------------------------------------------------  
  if(BUILD_REDIS)
    fail_if_not_found_library(libhiredis.a)
  endif()
  # --------------------------------------------------------
  # xml2 -brings in a lot...
  # --------------------------------------------------------
  fail_if_not_found_library(libxml2.a)
  fail_if_not_found_library(libz.a)
  fail_if_not_found_library(liblzma.a)
  fail_if_not_found_library(libicuuc.a)
  fail_if_not_found_library(libicudata.a)
  fail_if_not_found_library(libicui18n.a)
endif()
# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
if(FAILED_PACKAGES)
  LIST(REMOVE_DUPLICATES MISSING_UBUNTU_PACKAGES)
  string(REPLACE ";" " " MISSING_UBUNTU_PACKAGES_STR "${MISSING_UBUNTU_PACKAGES}")
  message(FATAL_ERROR "  Please install suggested packages:   sudo apt-get install ${MISSING_UBUNTU_PACKAGES_STR}   and try again.")
endif()
# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
set(LIBRARIES ${LIBRARIES} dl)
set(LIBRARIES ${LIBRARIES} pthread)
set(LIBRARIES ${LIBRARIES} curl)
if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(LIBRARIES ${LIBRARIES} rt)
endif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
set(LIBRARIES ${LIBRARIES} m)
message(STATUS "Libraries: ${LIBRARIES}")
# ------------------------------------------------------------------------------
# Optional flags
# ------------------------------------------------------------------------------
if(DEBUG_MODE)
    add_definitions(-O0 -g3)
else()
    add_definitions(-O2)
endif()
if(BUILD_SYMBOLS)
    add_definitions(-g3)
endif()
# ------------------------------------------------------------------------------
# Build is2
# ------------------------------------------------------------------------------
include(ExternalProject)
if(BUILD_APPS)
  ExternalProject_Add(submodule_is2
    CMAKE_ARGS -DBUILD_TLS=ON
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/sub/is2
    INSTALL_COMMAND ""
  )
endif()
# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
# make the cmake list variables into .deb-compatible strings
string(REPLACE ";" ", " CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS_LIST}")
string(REPLACE ";" ", " CPACK_DEBIAN_PACKAGE_BUILDS_DEPENDS "${CPACK_DEBIAN_PACKAGE_BUILDS_DEPENDS_LIST}")
# ------------------------------------------------------------------------------
# Version
# ------------------------------------------------------------------------------
EXECUTE_PROCESS(COMMAND git -C ${CMAKE_SOURCE_DIR} describe --tags OUTPUT_VARIABLE VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)
add_definitions(-DWAFLZ_VERSION="${VERSION}")
# ------------------------------------------------------------------------------
# Debian Package Support
# ------------------------------------------------------------------------------
if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  SET(DISTRIBUTION "macOS")
else()
  EXECUTE_PROCESS(COMMAND lsb_release -cs OUTPUT_VARIABLE DISTRIBUTION OUTPUT_STRIP_TRAILING_WHITESPACE)
endif()
SET(CPACK_GENERATOR "DEB")
SET(CPACK_DEBIAN_PACKAGE_VERSION "${VERSION}-${DISTRIBUTION}")
SET(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
if(BUILD_ASAN)
    SET(CPACK_PACKAGE_FILE_NAME "waflz_${CPACK_DEBIAN_PACKAGE_VERSION}_${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}-debug")
else()
    SET(CPACK_PACKAGE_FILE_NAME "waflz_${CPACK_DEBIAN_PACKAGE_VERSION}_${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}")
endif()
SET(CPACK_DEBIAN_PACKAGE_NAME "waflz")
SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "Reed Morrison, Devender Singh, Revathi Sabanayagam, Raymond Mintz, Thomas Ahn")
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Waflz Libraries and tools")
SET(CPACK_PACKAGE_DESCRIPTION "Waflz Libraries and tools")
message(STATUS "Package Configuration:")
message("")
message("    Option                                     Value                     ")
message("    ---------------------------------------------------------------------")
message("    Package Version:                           ${CPACK_DEBIAN_PACKAGE_VERSION}")
message("")
INCLUDE(CPack)
# ------------------------------------------------------------------------------
# include source/test directories
# ------------------------------------------------------------------------------
add_subdirectory(proto)
add_subdirectory(src)
if(BUILD_APPS)
  add_subdirectory(util)
endif()
if(BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
if(BUILD_PERFORMANCE_MEASURE)
  enable_testing()
  add_subdirectory(performance)
endif()
# ------------------------------------------------------------------------------
# release target
# NOTE deb has to exist in order to create tar.gz
# ------------------------------------------------------------------------------
if(BUILD_ASAN)
    SET(RELEASE_PACKAGE_FILE_NAME "waflz_${CPACK_DEBIAN_PACKAGE_VERSION}_${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}-debug.deb")
else()
    SET(RELEASE_PACKAGE_FILE_NAME "waflz_${CPACK_DEBIAN_PACKAGE_VERSION}_${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}.deb")
endif()
add_custom_target(release
    COMMAND ${CMAKE_SOURCE_DIR}/support/deb2tar.sh -d ${CMAKE_BINARY_DIR}/${RELEASE_PACKAGE_FILE_NAME}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
# ------------------------------------------------------------------------------
# docs
# ------------------------------------------------------------------------------
add_custom_target(docs
    COMMAND doxygen ${CMAKE_CURRENT_SOURCE_DIR}/doxygen.conf WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
)
