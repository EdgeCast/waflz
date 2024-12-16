# ------------------------------------------------------------------------------
# macro to compile perft tests
# ------------------------------------------------------------------------------
macro (add_waflz_perf_test test_name)
    add_executable("perf_${test_name}" "perf_${test_name}.cc")
    target_link_libraries("perf_${test_name}" ${DEBUG_LIBRARIES} waflz_compiled_catch waflzcore ${LIBRARIES})
endmacro()
# ------------------------------------------------------------------------------
# add perf tests
# ------------------------------------------------------------------------------
add_waflz_perf_test(jwt)
add_waflz_perf_test(limit_hash)