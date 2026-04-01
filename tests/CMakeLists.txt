cmake_minimum_required(VERSION 3.15)

# Find GTest
find_package(GTest QUIET)

if(GTest_FOUND)
    message(STATUS "GTest found, building C++ tests")

    add_executable(tls_fingerprint_test
        cpp/tls_fingerprint_test.cpp
    )

    target_include_directories(tls_fingerprint_test
        PRIVATE
            ${CMAKE_SOURCE_DIR}/include
    )

    target_link_libraries(tls_fingerprint_test
        PRIVATE
            tls_fingerprint_static
            GTest::gtest
            GTest::gtest_main
    )

    # Add test
    add_test(NAME TLSFingerprintTest COMMAND tls_fingerprint_test)
else()
    message(STATUS "GTest not found, skipping C++ tests")
endif()
