// ==============================================================================
// ObFUSEcate
// endian.hpp
// 
// Author: Travis J. Galoppo (tgaloppo@gmail.com)
// Description: Read / Write unsigned integers to buffers in little endian format
// 
// SPDX-License-Identifier: MIT
// ==============================================================================
#pragma once

#include <cstdint>

// These functons read and write integer data types
// to memory locations in little-endian format.

namespace endian
{

inline void write_u8(uint8_t* buf, uint8_t val)
{
    buf[0] = val;
}

inline void write_u16(uint8_t* buf, uint16_t val)
{
    buf[0] = static_cast<uint8_t>((val >> 0) & 0xFF);
    buf[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
}

inline void write_u32(uint8_t* buf, uint32_t val)
{
    buf[0] = static_cast<uint8_t>((val >>  0) & 0xFF);
    buf[1] = static_cast<uint8_t>((val >>  8) & 0xFF);
    buf[2] = static_cast<uint8_t>((val >> 16) & 0xFF);
    buf[3] = static_cast<uint8_t>((val >> 24) & 0xFF);
}

inline void write_u64(uint8_t* buf, uint64_t val)
{
    buf[0] = static_cast<uint8_t>((val >>  0) & 0xFF);
    buf[1] = static_cast<uint8_t>((val >>  8) & 0xFF);
    buf[2] = static_cast<uint8_t>((val >> 16) & 0xFF);
    buf[3] = static_cast<uint8_t>((val >> 24) & 0xFF);
    buf[4] = static_cast<uint8_t>((val >> 32) & 0xFF);
    buf[5] = static_cast<uint8_t>((val >> 40) & 0xFF);
    buf[6] = static_cast<uint8_t>((val >> 48) & 0xFF);
    buf[7] = static_cast<uint8_t>((val >> 56) & 0xFF);
}

inline uint8_t read_u8(const uint8_t* buf)
{
    return buf[0];
}

inline uint16_t read_u16(const uint8_t* buf)
{
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(buf[0]) << 0) |
        (static_cast<uint16_t>(buf[1]) << 8));
}

inline uint32_t read_u32(const uint8_t* buf)
{
    return (static_cast<uint32_t>(buf[0]) <<  0) |
           (static_cast<uint32_t>(buf[1]) <<  8) |
           (static_cast<uint32_t>(buf[2]) << 16) |
           (static_cast<uint32_t>(buf[3]) << 24);
}

inline uint64_t read_u64(const uint8_t* buf)
{
    return (static_cast<uint64_t>(buf[0]) <<  0) |
           (static_cast<uint64_t>(buf[1]) <<  8) |
           (static_cast<uint64_t>(buf[2]) << 16) |
           (static_cast<uint64_t>(buf[3]) << 24) |
           (static_cast<uint64_t>(buf[4]) << 32) |
           (static_cast<uint64_t>(buf[5]) << 40) |
           (static_cast<uint64_t>(buf[6]) << 48) |
           (static_cast<uint64_t>(buf[7]) << 56);
}

} // namespace endian

