// ==============================================================================
// ObFUSEcate
// test_block_device.cpp
// 
// Author: Travis J. Galoppo (tgaloppo@gmail.com)
// 
// SPDX-License-Identifier: MIT
// ==============================================================================
#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <random>
#include "block_device.hpp" // Assuming this is where create_compressed_block is declared

using namespace obfusecate;

TEST(BlockIntegrationTest, BasicTextRoundTrip) {
    std::string text = "Integrating the frequency table and the payload into a single block.";
    std::vector<uint8_t> input(text.begin(), text.end());

    compressed_block block = create_compressed_block(input.data(), input.size());
    
    // The frequency table should be relatively small, but > 0
    EXPECT_GT(block.frequency_table.size(), 0);
    EXPECT_GT(block.compressed_data.size(), 0);
    EXPECT_EQ(block.payload_bytes, input.size());

    std::vector<uint8_t> output = decompress_block(block);
    
    EXPECT_EQ(input, output);
}

TEST(BlockIntegrationTest, FullFuseChunkRandomData) {
    std::size_t chunk_size = 65536; // 64KB
    std::vector<uint8_t> input(chunk_size);
    
    std::mt19937 rng(42); 
    std::uniform_int_distribution<int> dist(0, 255);
    for (std::size_t i = 0; i < chunk_size; ++i) {
        input[i] = static_cast<uint8_t>(dist(rng));
    }

    compressed_block block = create_compressed_block(input.data(), input.size());

    // Highly entropic data should result in all 256 symbols being present.
    // Double-flag size: 256 * 18 bits = 576 bytes.
    EXPECT_EQ(block.frequency_table.size(), 576);
    
    std::vector<uint8_t> output = decompress_block(block);
    
    EXPECT_EQ(input, output);
}

TEST(BlockIntegrationTest, ZeroEntropyEdgeCase) {
    std::size_t chunk_size = 65536; // 64KB
    std::vector<uint8_t> input(chunk_size, 0x77); // All 'w's
    
    compressed_block block = create_compressed_block(input.data(), input.size());

    // 255 absent symbols (1 bit each) + 1 present symbol requiring 32-bit count (1 + 1 + 32 bits)
    // Total: 255 + 34 = 289 bits. Padded to bytes = 37 bytes.
    EXPECT_EQ(block.frequency_table.size(), 37);
    
    // The compressed payload itself should be mathematically tiny 
    // because the probability is 1.0. Just the flushed bits.
    EXPECT_LT(block.compressed_data.size(), 16);

    std::vector<uint8_t> output = decompress_block(block);
    
    EXPECT_EQ(input, output);
}

TEST(BlockIntegrationTest, EmptyPayload) {
    std::vector<uint8_t> input; // 0 bytes
    
    compressed_block block = create_compressed_block(input.data(), input.size());
    
    EXPECT_EQ(block.payload_bytes, 0);
    // Table should just be 256 '0' bits (32 bytes)
    EXPECT_EQ(block.frequency_table.size(), 32); 

    std::vector<uint8_t> output = decompress_block(block);
    
    EXPECT_TRUE(output.empty());
}
