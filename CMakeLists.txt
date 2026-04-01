cmake_minimum_required(VERSION 3.15)
project(tls_fingerprint VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Options
option(BUILD_PYTHON_BINDINGS "Build Python bindings" ON)
option(BUILD_TESTS "Build tests" ON)

# Platform-specific settings
if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DNOMINMAX)
elseif(APPLE)
    set(CMAKE_MACOSX_RPATH ON)
endif()

# BoringSSL (optional - only needed for actual TLS connections)
set(BORINGSSL_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/boringssl")
if(EXISTS "${BORINGSSL_ROOT}/CMakeLists.txt")
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
    # Don't add_subdirectory BoringSSL - we use standalone implementation
    # add_subdirectory(${BORINGSSL_ROOT} boringssl EXCLUDE_FROM_ALL)
    message(STATUS "BoringSSL found at ${BORINGSSL_ROOT}")
else()
    message(STATUS "BoringSSL not found - using standalone implementation")
endif()

# Core library sources (standalone implementation)
set(TLS_FINGERPRINT_SOURCES
    src/tls_fingerprint_config.cc
    src/tls_fingerprint_generator.cc
)

set(TLS_FINGERPRINT_HEADERS
    include/tls_fingerprint/tls_fingerprint_config.h
    include/tls_fingerprint/tls_fingerprint_generator.h
)

# Create core static library
add_library(tls_fingerprint_static STATIC ${TLS_FINGERPRINT_SOURCES})
target_include_directories(tls_fingerprint_static
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Python bindings
if(BUILD_PYTHON_BINDINGS)
    find_package(Python3 REQUIRED COMPONENTS Interpreter Development)

    # Try to find pybind11
    find_package(pybind11 CONFIG QUIET)
    if(pybind11_FOUND)
        message(STATUS "Found pybind11: ${pybind11_VERSION}")
    else()
        # Try to get pybind11 via pip
        execute_process(
            COMMAND ${Python3_EXECUTABLE} -c "import pybind11; print(pybind11.get_cmake_dir())"
            OUTPUT_VARIABLE PYBIND11_CMAKE_DIR
            OUTPUT_STRIP_TRAILING_WHITESPACE
            RESULT_VARIABLE PYBIND11_RESULT
        )
        if(PYBIND11_RESULT EQUAL 0)
            list(APPEND CMAKE_PREFIX_PATH "${PYBIND11_CMAKE_DIR}")
            find_package(pybind11 CONFIG REQUIRED)
        endif()
    endif()

    if(pybind11_FOUND)
        pybind11_add_module(_tls_fingerprint
            python/tls_fingerprint/_bindings.cc
        )
        target_include_directories(_tls_fingerprint PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(_tls_fingerprint PRIVATE tls_fingerprint_static)
        set_target_properties(_tls_fingerprint PROPERTIES
            LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/python/tls_fingerprint
        )
        message(STATUS "Python bindings will be built")
    else()
        message(WARNING "pybind11 not found. Python bindings will not be built.")
    endif()
else()
    message(STATUS "Python bindings disabled")
endif()

# Tests
if(BUILD_TESTS)
    enable_testing()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt")
        add_subdirectory(tests)
    endif()
endif()

# Install rules
install(TARGETS tls_fingerprint_static
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(FILES ${TLS_FINGERPRINT_HEADERS}
    DESTINATION include/tls_fingerprint
)

# Print configuration summary
message(STATUS "")
message(STATUS "TLS Fingerprint Library Configuration:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build Python Bindings: ${BUILD_PYTHON_BINDINGS}")
message(STATUS "  Build Tests: ${BUILD_TESTS}")
message(STATUS "")
