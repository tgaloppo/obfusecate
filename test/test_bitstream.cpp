// ==============================================================================
// ObFUSEcate
// test_bitstream.cpp
// 
// Author: Travis J. Galoppo (tgaloppo@gmail.com)
// 
// SPDX-License-Identifier: MIT
// ==============================================================================
#include <gtest/gtest.h>
#include "bitstream.hpp"

using namespace bitstream;

TEST(BitstreamTest, BasicTypesIO) {
    writer out;
    
    out << bit_t{1} 
        << uint8_t{0x81} 
        << uint16_t{0x1234} 
        << uint32_t{0x12345678} 
        << uint64_t{0x0123456789ABCDEF} 
        << bit_t{0} 
        << bit_t{1} 
        << uint16_t{15};

    EXPECT_EQ(out.size_in_bits(), 1 + 8 + 16 + 32 + 64 + 1 + 1 + 16);

    reader in(out.data(), out.size_in_bits());

    bit_t    _1bit, _1bit_2, _1bit_3;
    uint8_t  _8bit;
    uint16_t _16bit, _16bit_2;
    uint32_t _32bit;
    uint64_t _64bit;

    in >> _1bit >> _8bit >> _16bit >> _32bit >> _64bit >> _1bit_2 >> _1bit_3 >> _16bit_2;

    EXPECT_EQ(_1bit.bit, 1);
    EXPECT_EQ(_8bit, 0x81);
    EXPECT_EQ(_16bit, 0x1234);
    EXPECT_EQ(_32bit, 0x12345678);
    EXPECT_EQ(_64bit, 0x0123456789ABCDEF);
    EXPECT_EQ(_1bit_2.bit, 0);
    EXPECT_EQ(_1bit_3.bit, 1);
    EXPECT_EQ(_16bit_2, 15);
}

TEST(BitstreamTest, ArbitraryBitLengths) {
    writer out;
    
    // Write odd, unaligned bit lengths to test spanning logic
    out.append(0b101, 3);
    out.append(0x7F, 7);           // 7 bits
    out.append(0xBCDEF, 20);     // 20 bits
    out.append(0xFFFFFFFFFFFFFFFF, 63); // 63 bits (tests maximum shift without overflow)
    
    EXPECT_EQ(out.size_in_bits(), 3 + 7 + 20 + 63);

    reader in(out.data(), out.size_in_bits());
    
    uint64_t val1, val2, val3, val4;
    
    in.extract(val1, 3);
    in.extract(val2, 7);
    in.extract(val3, 20);
    in.extract(val4, 63);

    EXPECT_EQ(val1, 0b101);
    EXPECT_EQ(val2, 0x7F);
    EXPECT_EQ(val3, 0xBCDEF);
    EXPECT_EQ(val4, 0x7FFFFFFFFFFFFFFF); // 63 bits of 1s
}

TEST(BitstreamTest, DataBleedMasking) {
    writer out;
    
    // out.append(value, n_bits)
    // 0xAF is 1010 1111. We only want 4 bits (1111 / 0xF). 
    // If it bleeds, 1010 (0xA) will pollute bits 4-7.
    out.append(0xAF, 4); 
    
    // Write 4 bits of explicit zeros into bits 4-7.
    // If the previous write bled, the |= operator will leave the 1010 intact,
    // and reading this back will yield 0xA instead of 0x0.
    out.append(0x00, 4); 
    
    reader in(out.data(), out.size_in_bits());
    
    uint64_t val1, val2;
    in.extract(val1, 4);
    in.extract(val2, 4);
    
    EXPECT_EQ(val1, 0x0F);
    EXPECT_EQ(val2, 0x00);
}

TEST(BitstreamTest, CapacityExpansion) {
    // Start with a very small buffer to force immediate reallocations
    writer out(16); 
    
    const int num_iterations = 1000;
    for (int i = 0; i < num_iterations; ++i) {
        out << static_cast<uint64_t>(i);
    }
    
    EXPECT_EQ(out.size_in_bits(), num_iterations * 64);
    
    reader in(out.data(), out.size_in_bits());
    
    for (int i = 0; i < num_iterations; ++i) {
        uint64_t val;
        in >> val;
        EXPECT_EQ(val, static_cast<uint64_t>(i));
    }
}

TEST(BitstreamTest, ResetClearsMemory) {
    writer out;
    
    // Write some all-1s data
    out << uint64_t{0xFFFFFFFFFFFFFFFF} << uint64_t{0xFFFFFFFFFFFFFFFF};
    
    out.reset();
    
    EXPECT_EQ(out.size_in_bits(), 0);
    EXPECT_EQ(out.size_in_bytes(), 0);
    
    // Write new data
    out << uint16_t{0xAAAA};
    
    reader in(out.data(), out.size_in_bits());
    uint16_t val;
    in >> val;
    
    // If reset() did not std::fill with 0, the |= operator would collide 
    // with the old 0xFFs, and val would be 0xFFFF.
    EXPECT_EQ(val, 0xAAAA);
}

TEST(BitstreamTest, OutOfBoundsExtraction) {
    writer out;
    out << uint8_t{0x55}; // Write exactly 8 bits
    
    reader in(out.data(), out.size_in_bits());
    
    uint64_t val1, val2;
    in.extract(val1, 4);  // Valid
    EXPECT_EQ(val1, 0x05); 
    
    in.extract(val2, 8);  // 4 bits left, trying to read 8. Should fail safely.
    EXPECT_EQ(val2, 0);   // Fallback to 0 per reader::extract logic
}
