cmake_minimum_required(VERSION 3.15)

include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
# Prevent gtest from overriding our compiler settings
# Prevent GoogleTest from dumping its headers and libs into our install prefix
set(INSTALL_GTEST OFF CACHE BOOL "Disable installation of googletest" FORCE)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Test executable
add_executable(cryptofs_tests
    test_bitstream.cpp
    test_compression.cpp
#    test_cryptofs.cpp
    test_chacha20.cpp
#    test_fileio.cpp
    test_error_correction.cpp
#    test_fileio_ecc.cpp
)

# Link against our raw object files and GoogleTest
target_link_libraries(cryptofs_tests
    PRIVATE
        $<TARGET_OBJECTS:cryptofs_obj> # Raw objects for white-box testing
        cryptofs_compiler_flags   
        GTest::gtest     
        GTest::gtest_main
)

target_include_directories(cryptofs_tests
    PRIVATE
        ${googletest_SOURCE_DIR}/googletest/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../include  # Public headers
        ${CMAKE_CURRENT_SOURCE_DIR}/../src      # Internal headers
)

include(GoogleTest)
gtest_discover_tests(cryptofs_tests)
