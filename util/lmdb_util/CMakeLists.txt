# ------------------------------------------------------------------------------
# header files to install
# ------------------------------------------------------------------------------
LIST(APPEND INST_HDRS ${HDRS})
# ------------------------------------------------------------------------------
# include paths
# ------------------------------------------------------------------------------
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_SOURCE_DIR}/ext
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src
)
# ------------------------------------------------------------------------------
# source files
# ------------------------------------------------------------------------------
SET(SRCS lmdb_util.cc)

# ------------------------------------------------------------------------------
# Headers
# ------------------------------------------------------------------------------
SET(HDRS
)
# ------------------------------------------------------------------------------
# build and install lmdb_util
# ------------------------------------------------------------------------------
add_executable(lmdb_util ${HDRS} ${SRCS})
add_dependencies(lmdb_util waflzcore)
SET_TARGET_PROPERTIES(lmdb_util PROPERTIES OUTPUT_NAME "lmdb_util")
target_link_libraries(lmdb_util
  ${DEBUG_LIBRARIES}
  ${CMAKE_BINARY_DIR}/src/libwaflzcore.a
  ${LIBRARIES}
)
install(TARGETS lmdb_util
  DESTINATION ${CMAKE_INSTALL_PREFIX}/bin/
  COMPONENT Executables
)

