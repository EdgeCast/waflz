#!/bin/bash
# ------------------------------------------------------------------------------
# Requirements to build...
# ------------------------------------------------------------------------------
which cmake g++ make || {
    echo "Failed to find required build packages. Please install with: sudo apt-get install cmake make g++"
    exit 1
}
# This is necessary in scenarios where the URL of the remote for a given submodule has changed.
git submodule sync || {
    echo "FAILED TO SYNC IS2 LIB"
    exit 1
}
git submodule update -f --init || {
    echo "FAILED TO UPDATE TO LATEST IS2 LIB"
    exit 1
}
# ------------------------------------------------------------------------------
# Build waflz
# ------------------------------------------------------------------------------
main() {

    build_asan=0
    while getopts ":a" opt; do
        case "${opt}" in
            a)
                build_asan=1
            ;;

            \?)
                echo "Invalid option: -$OPTARG" >&2
                exit $?
            ;;
        esac
    done

    if [ "$(uname)" == "Darwin" ]; then
        BUILD_UBUNTU=OFF
        NPROC=$(sysctl -n hw.ncpu)
    else
        BUILD_UBUNTU=ON
        NPROC=$(nproc)
    fi

    mkdir -p build
    pushd build

    if [[ "${build_asan}" -eq 1 ]]; then
        cmake ../ \
        -DBUILD_ASAN=ON\
        -DBUILD_SYMBOLS=ON \
        -DBUILD_APPS=ON \
        -DBUILD_UBUNTU=${BUILD_UBUNTU} \
        -DCMAKE_INSTALL_PREFIX=/usr
    else
        cmake ../ \
        -DBUILD_SYMBOLS=ON \
        -DBUILD_APPS=ON \
        -DBUILD_UBUNTU=${BUILD_UBUNTU} \
        -DCMAKE_INSTALL_PREFIX=/usr
    fi

    make -j${NPROC} && \
    make CTEST_OUTPUT_ON_FAILURE=1 test && \
    umask 0022 && chmod -R a+rX . && \
    make package && \
    make release && \
    popd && \
    exit $?
}

main "${@}"
