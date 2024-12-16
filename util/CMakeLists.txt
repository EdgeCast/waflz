# ------------------------------------------------------------------------------
# apps
# ------------------------------------------------------------------------------
include_directories(${CMAKE_SOURCE_DIR}/sub/is2)
add_subdirectory(wjc)
add_subdirectory(waflz_dump)
add_subdirectory(waflz_server)
add_subdirectory(lmdb_util)