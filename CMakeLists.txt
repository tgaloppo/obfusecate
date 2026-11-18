cmake_minimum_required(VERSION 3.20)
project(obfusecate VERSION 1.0.0 LANGUAGES CXX)

# Default to Release if no build type is specified
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Setting build type to 'Release' as none was specified.")
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build (Debug, Release, RelWithDebInfo, MinSizeRel)." FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "RelWithDebInfo" "MinSizeRel")
endif()

# Build Options
option(OBFUSECATE_BUILD_TESTS  "Build the GoogleTest unit test suite" OFF)
option(OBFUSECATE_ENABLE_ASAN  "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(OBFUSECATE_MARCH_NATIVE "Optimize for the host CPU architecture (-march=native)" OFF)

# Global C++ Standard & Position Independent Code
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(FUSE3 REQUIRED IMPORTED_TARGET fuse3)

# Internal Target for Strict Project Warnings & Optimization Flags
add_library(compiler_flags INTERFACE)

target_compile_definitions(compiler_flags INTERFACE _FILE_OFFSET_BITS=64)

target_compile_options(compiler_flags INTERFACE
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
    -Wno-psabi

    # Configuration-specific optimization & debug flags
    $<$<CONFIG:Debug>:-O0 -g3 -fno-omit-frame-pointer>
    $<$<CONFIG:Release>:-O3 -DNDEBUG -funroll-loops>
    $<$<CONFIG:RelWithDebInfo>:-O2 -g -DNDEBUG -fno-omit-frame-pointer>
)

if(OBFUSECATE_MARCH_NATIVE)
    target_compile_options(compiler_flags INTERFACE
        $<$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>>:-march=native>
    )
endif()

# Sanitizer Instrumentation (Debug / Verification)
if(OBFUSECATE_ENABLE_ASAN)
    target_compile_options(compiler_flags INTERFACE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(compiler_flags INTERFACE -fsanitize=address,undefined)
endif()

# Core Library Target
set(OBFUSECATE_SOURCES
    src/bitstream.cpp
    src/symbol_frequency.cpp
    src/arithmetic_encoder.cpp
    src/arithmetic_decoder.cpp
    src/block_device.cpp
    src/chacha20.cpp
    src/poly1305.cpp
    src/error_correction.cpp
    src/fileio.cpp
    src/crypto.cpp
)

# Build the raw object files first, so tests can access internal symbols
add_library(obfusecate_obj OBJECT ${OBFUSECATE_SOURCES})
target_include_directories(obfusecate_obj PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(obfusecate_obj PRIVATE compiler_flags)
set_property(TARGET obfusecate_obj PROPERTY POSITION_INDEPENDENT_CODE ON)

# Now build the actual library (STATIC or SHARED) using those objects
add_library(obfusecate STATIC $<TARGET_OBJECTS:obfusecate_obj>)

add_library(obfusecate::obfusecate ALIAS obfusecate)

# Hide internal symbols only on the final packaged library
set_target_properties(obfusecate PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

target_include_directories(obfusecate
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(obfusecate
    PRIVATE compiler_flags
)

# Link-Time Optimization (LTO / IPO) for Release Builds
include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_supported OUTPUT ipo_error)
if(ipo_supported)
    set_target_properties(obfusecate PROPERTIES
        INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE
        INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO TRUE
    )
endif()

# FUSE Daemon Executable
add_executable(obfusecate_daemon src/main.cpp)

target_link_libraries(obfusecate_daemon 
    PRIVATE 
        obfusecate::obfusecate 
        PkgConfig::FUSE3 
        compiler_flags
)

install(TARGETS obfusecate_daemon
        DESTINATION bin)
        
# make sure the interface script makes its way to the bin directory
install(PROGRAMS scripts/obfusecate.sh
        DESTINATION bin
        RENAME obfusecate)

# Unit Tests
if(OBFUSECATE_BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()
