#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <random>
#include <algorithm>
#include "arithmetic_encoder.hpp"
#include "arithmetic_decoder.hpp"
#include "bitstream.hpp"

using namespace compression;

// --------------------------------------------------------------------------
// 1. Frequency Model Verification
// --------------------------------------------------------------------------
TEST(ArithmeticCodingTest, FrequencyModelLogic) {
    // 3 'A's, 2 'B's, 1 'C'
    std::vector<uint8_t> data = {'A', 'A', 'A', 'B', 'B', 'C'};
    symbol_frequency freq(data.data(), data.size());

    EXPECT_EQ(freq.get_total(), 6);
    
    // 'A' is 65 (0x41). Cumulative should be 0, upper should be 3
    EXPECT_EQ(freq.get_lower('A'), 0);
    EXPECT_EQ(freq.get_upper('A'), 3);

    // 'B' is 66. Cumulative should be 3, upper should be 5
    EXPECT_EQ(freq.get_lower('B'), 3);
    EXPECT_EQ(freq.get_upper('B'), 5);

    // 'C' is 67. Cumulative should be 5, upper should be 6
    EXPECT_EQ(freq.get_lower('C'), 5);
    EXPECT_EQ(freq.get_upper('C'), 6);

    // Reverse lookup testing
    EXPECT_EQ(freq.get_symbol(0), 'A');
    EXPECT_EQ(freq.get_symbol(2), 'A');
    EXPECT_EQ(freq.get_symbol(3), 'B');
    EXPECT_EQ(freq.get_symbol(4), 'B');
    EXPECT_EQ(freq.get_symbol(5), 'C');
}

// --------------------------------------------------------------------------
// 2. Basic Round-Trip (Short String)
// --------------------------------------------------------------------------
TEST(ArithmeticCodingTest, ShortStringRoundTrip) {
    std::string text = "Arithmetic coding is mathematically elegant.";
    std::vector<uint8_t> input(text.begin(), text.end());
    
    symbol_frequency freq(input.data(), input.size());
    bitstream::writer out;
    arithmetic_coder encoder(out, freq);
    
    encoder.encode(input.data(), input.size());
    encoder.flush();

    bitstream::reader in(out.data(), out.size_in_bits());
    arithmetic_decoder decoder(in, freq);
    
    std::vector<uint8_t> output(input.size());
    decoder.decode(output.data(), output.size());

    EXPECT_EQ(input, output);
}

// --------------------------------------------------------------------------
// 3. FUSE Chunk Size (64KB Random Data)
// --------------------------------------------------------------------------
TEST(ArithmeticCodingTest, FullChunkRandomData) {
    std::size_t chunk_size = 65536; // 64KB
    std::vector<uint8_t> input(chunk_size);
    
    std::mt19937 rng(42); // Seeded for determinism
    std::uniform_int_distribution<int> dist(0, 255);
    for (std::size_t i = 0; i < chunk_size; ++i) {
        input[i] = static_cast<uint8_t>(dist(rng));
    }

    symbol_frequency freq(input.data(), input.size());
    bitstream::writer out;
    arithmetic_coder encoder(out, freq);
    
    encoder.encode(input.data(), input.size());
    encoder.flush();

    bitstream::reader in(out.data(), out.size_in_bits());
    arithmetic_decoder decoder(in, freq);
    
    std::vector<uint8_t> output(chunk_size);
    decoder.decode(output.data(), output.size());

    EXPECT_EQ(input, output);
}

// --------------------------------------------------------------------------
// 4. Zero Entropy (Single Repeating Byte)
// --------------------------------------------------------------------------
// This aggressively tests the std::upper_bound logic in get_symbol() 
// because 255 out of 256 bins will have a frequency width of 0.
TEST(ArithmeticCodingTest, ZeroEntropy) {
    std::size_t chunk_size = 10000;
    std::vector<uint8_t> input(chunk_size, 0x42); // All 'B's
    
    symbol_frequency freq(input.data(), input.size());
    bitstream::writer out;
    arithmetic_coder encoder(out, freq);
    
    encoder.encode(input.data(), input.size());
    encoder.flush();

    // Since entropy is 0, the compressed size should be practically nonexistent
    // (just the flushed bits, usually < 64 bits total)
    EXPECT_LT(out.size_in_bytes(), 16); 

    bitstream::reader in(out.data(), out.size_in_bits());
    arithmetic_decoder decoder(in, freq);
    
    std::vector<uint8_t> output(chunk_size);
    decoder.decode(output.data(), output.size());

    EXPECT_EQ(input, output);
}

// --------------------------------------------------------------------------
// 5. Deep Underflow Stress Test (Skewed Distribution)
// --------------------------------------------------------------------------
// A highly skewed distribution forces the registers to frequently straddle 
// the 0.5 midpoint, heavily exercising the mUnderflow logic and mValue shifts.
TEST(ArithmeticCodingTest, DeepUnderflowStraddle) {
    std::vector<uint8_t> input;
    
    // 90% 'A', 9% 'B', 1% 'C'
    for (int i = 0; i < 9000; ++i) input.push_back('A');
    for (int i = 0; i < 900; ++i)  input.push_back('B');
    for (int i = 0; i < 100; ++i)  input.push_back('C');

    // Shuffle so it's not monotone
    std::mt19937 rng(1337);
    std::shuffle(input.begin(), input.end(), rng);

    symbol_frequency freq(input.data(), input.size());
    bitstream::writer out;
    arithmetic_coder encoder(out, freq);
    
    encoder.encode(input.data(), input.size());
    encoder.flush();

    bitstream::reader in(out.data(), out.size_in_bits());
    arithmetic_decoder decoder(in, freq);
    
    std::vector<uint8_t> output(input.size());
    decoder.decode(output.data(), output.size());

    EXPECT_EQ(input, output);
}
