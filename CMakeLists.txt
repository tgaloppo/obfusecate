cmake_minimum_required(VERSION 3.20)
project(cryptofs VERSION 1.0.0 LANGUAGES CXX)

# Default to Release if no build type is specified
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Setting build type to 'Release' as none was specified.")
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build (Debug, Release, RelWithDebInfo, MinSizeRel)." FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "RelWithDebInfo" "MinSizeRel")
endif()

# Build Options
option(CRYPTOFS_BUILD_TESTS  "Build the GoogleTest unit test suite" ON)
option(CRYPTOFS_BUILD_SHARED "Build as a shared library (.so)" ON)
option(CRYPTOFS_ENABLE_ASAN  "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(CRYPTOFS_MARCH_NATIVE "Optimize for the host CPU architecture (-march=native)" OFF)

# Global C++ Standard & Position Independent Code
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(FUSE3 REQUIRED IMPORTED_TARGET fuse3)

# Internal Target for Strict Project Warnings & Optimization Flags
add_library(cryptofs_compiler_flags INTERFACE)

target_compile_definitions(cryptofs_compiler_flags INTERFACE _FILE_OFFSET_BITS=64)

target_compile_options(cryptofs_compiler_flags INTERFACE
    # Strict warning suite
    -Wall
    -Wextra
    -Wpedantic
    -Werror
    -Wconversion
    -Wsign-conversion
    -Wshadow
    -Wnon-virtual-dtor
    -Wold-style-cast
    -Wcast-align
    -Wunused
    -Woverloaded-virtual
    -Wnull-dereference
    -Wformat=2

    # Configuration-specific optimization & debug flags
    $<$<CONFIG:Debug>:-O0 -g3 -fno-omit-frame-pointer>
    $<$<CONFIG:Release>:-O3 -DNDEBUG -funroll-loops>
    $<$<CONFIG:RelWithDebInfo>:-O2 -g -DNDEBUG -fno-omit-frame-pointer>
)

if(CRYPTOFS_MARCH_NATIVE)
    target_compile_options(cryptofs_compiler_flags INTERFACE
        $<$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>>:-march=native>
    )
endif()

# Sanitizer Instrumentation (Debug / Verification)
if(CRYPTOFS_ENABLE_ASAN)
    target_compile_options(cryptofs_compiler_flags INTERFACE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(cryptofs_compiler_flags INTERFACE -fsanitize=address,undefined)
endif()

# Core Library Target
set(CRYPTOFS_SOURCES
    src/bitstream.cpp
    src/symbol_frequency.cpp
    src/arithmetic_encoder.cpp
    src/arithmetic_decoder.cpp
    src/cryptofs.cpp
    src/chacha20.cpp
    src/poly1305.cpp
    src/error_correction.cpp
)

# Build the raw object files first, so tests can access internal symbols
add_library(cryptofs_obj OBJECT ${CRYPTOFS_SOURCES})
target_include_directories(cryptofs_obj PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(cryptofs_obj PRIVATE cryptofs_compiler_flags)
set_property(TARGET cryptofs_obj PROPERTY POSITION_INDEPENDENT_CODE ON)

# Now build the actual library (STATIC or SHARED) using those objects
if(CRYPTOFS_BUILD_SHARED)
    add_library(cryptofs SHARED $<TARGET_OBJECTS:cryptofs_obj>)
else()
    add_library(cryptofs STATIC $<TARGET_OBJECTS:cryptofs_obj>)
endif()

add_library(cryptofs::cryptofs ALIAS cryptofs)

# Hide internal symbols only on the final packaged library
set_target_properties(cryptofs PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

target_include_directories(cryptofs
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(cryptofs
    PRIVATE cryptofs_compiler_flags
)

# Link-Time Optimization (LTO / IPO) for Release Builds
include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_supported OUTPUT ipo_error)
if(ipo_supported)
    set_target_properties(cryptofs PROPERTIES
        INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE
        INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO TRUE
    )
endif()

# FUSE Daemon Executable
add_executable(cryptofs_daemon src/main.cpp)

target_link_libraries(cryptofs_daemon 
    PRIVATE 
        cryptofs::cryptofs 
        PkgConfig::FUSE3 
        cryptofs_compiler_flags
)

# Unit Tests
if(CRYPTOFS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()
