cmake_minimum_required (VERSION 3.16)

# Back compatibility for VERSION range
if (${CMAKE_VERSION} VERSION_LESS 3.12)
  cmake_policy (VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
endif ()

include (GoogleTest)

add_executable (
    unit_tests

    # write
    write.cpp

    # hash
    hash.cpp
    internal.cpp

    # key derivation
    key_derivation.cpp

    # symmetric crypto
    key_derivation.cpp
    NIST_DRBG.cpp
    secret_share.cpp

    elliptic_curve.cpp
)

target_link_libraries (unit_tests PRIVATE crypto Data::numbers gtest_main gmock)

gtest_discover_tests (unit_tests)

if (OPTIONAL_TESTS)
    add_subdirectory (optional)
endif ()

target_compile_options (unit_tests PRIVATE
    $<$<CXX_COMPILER_ID:GNU>:-ftemplate-depth=2048>
    $<$<CXX_COMPILER_ID:Clang>:-ftemplate-depth=2048>
    $<$<CXX_COMPILER_ID:AppleClang>:-ftemplate-depth=2048>
    $<$<CXX_COMPILER_ID:MSVC>:/constexpr:depth2048>
)
