// ==============================================================================
// ObFUSEcate
// test_error_correction.cpp
// 
// Author: Travis J. Galoppo (tgaloppo@gmail.com)
// 
// SPDX-License-Identifier: MIT
// ==============================================================================
#include <gtest/gtest.h>
#include <vector>
#include <array>
#include <random>
#include <cstring>
#include "error_correction.hpp"

using namespace ecc;

class ECCTest : public ::testing::Test 
{
protected:
    std::vector<uint8_t> generate_random_payload(std::size_t size) 
    {
        std::vector<uint8_t> data(size);
        std::mt19937 gen(1337); 
        std::uniform_int_distribution<uint16_t> dist(0, 255);
        for (std::size_t i = 0; i < size; ++i) 
        {
            data[i] = static_cast<uint8_t>(dist(gen));
        }
        return data;
    }
};

TEST_F(ECCTest, CRC8Consistency) 
{
    std::vector<uint8_t> data(ecc::ECC_SHARD_SIZE, 0xAB);
    std::vector<uint8_t> crcs1, crcs2;
    
    calculate_crc8_vector(data.data(), data.size(), crcs1);
    calculate_crc8_vector(data.data(), data.size(), crcs2);

    ASSERT_EQ(crcs1.size(), 1);
    EXPECT_EQ(crcs1[0], crcs2[0]);
}

TEST_F(ECCTest, ParityVectorGeneration) 
{
    // 3 shards of data. 
    // Shard 0: 0x11, Shard 1: 0x22, Shard 2: 0x44
    // Parity should be 0x11 ^ 0x22 ^ 0x44 = 0x77
    std::vector<uint8_t> data;
    data.insert(data.end(), ecc::ECC_SHARD_SIZE, 0x11);
    data.insert(data.end(), ecc::ECC_SHARD_SIZE, 0x22);
    data.insert(data.end(), ecc::ECC_SHARD_SIZE, 0x44);

    std::array<uint8_t, ecc::ECC_SHARD_SIZE> parity;
    calculate_parity_vector(data.data(), data.size(), parity);

    for (std::size_t i = 0; i < ecc::ECC_SHARD_SIZE; ++i)
    {
        EXPECT_EQ(parity[i], 0x77);
    }
}

TEST_F(ECCTest, RecoverFullShard) 
{
    std::size_t payload_size = 512; // 4 full shards
    std::vector<uint8_t> original_data = generate_random_payload(payload_size);
    std::vector<uint8_t> working_data = original_data;

    std::vector<uint8_t> crc_vec;
    calculate_crc8_vector(original_data.data(), original_data.size(), crc_vec);

    std::array<uint8_t, ecc::ECC_SHARD_SIZE> parity;
    calculate_parity_vector(original_data.data(), original_data.size(), parity);

    // Corrupt the second shard (index 1)
    std::size_t target_shard = 1;
    for (std::size_t i = 0; i < ecc::ECC_SHARD_SIZE; ++i) 
    {
        working_data[target_shard * ecc::ECC_SHARD_SIZE + i] = 0x00; 
    }

    EXPECT_NE(working_data, original_data);

    // Attempt recovery
    bool success = recover_damaged_shard(
        working_data.data(), 
        working_data.size(), 
        target_shard, 
        parity, 
        crc_vec[target_shard]
    );

    EXPECT_TRUE(success);
    EXPECT_EQ(working_data, original_data);
}

TEST_F(ECCTest, RecoverPartialFinalShard) 
{
    // 300 bytes = 2 full shards (256 bytes) + 1 partial shard (44 bytes)
    std::size_t payload_size = 300; 
    std::vector<uint8_t> original_data = generate_random_payload(payload_size);
    std::vector<uint8_t> working_data = original_data;

    std::vector<uint8_t> crc_vec;
    calculate_crc8_vector(original_data.data(), original_data.size(), crc_vec);

    std::array<uint8_t, ecc::ECC_SHARD_SIZE> parity;
    calculate_parity_vector(original_data.data(), original_data.size(), parity);

    // Corrupt the final partial shard (index 2)
    std::size_t target_shard = 2;
    for (std::size_t i = target_shard * ecc::ECC_SHARD_SIZE; i < payload_size; ++i) 
    {
        working_data[i] ^= 0xFF; // flip bits
    }

    EXPECT_NE(working_data, original_data);

    // Attempt recovery
    bool success = recover_damaged_shard(
        working_data.data(), 
        working_data.size(), 
        target_shard, 
        parity, 
        crc_vec[target_shard]
    );

    EXPECT_TRUE(success);
    EXPECT_EQ(working_data, original_data);
}

TEST_F(ECCTest, RecoveryFailsOnWrongParity) 
{
    std::size_t payload_size = 256;
    std::vector<uint8_t> data = generate_random_payload(payload_size);
    
    std::vector<uint8_t> crc_vec;
    calculate_crc8_vector(data.data(), data.size(), crc_vec);

    std::array<uint8_t, ecc::ECC_SHARD_SIZE> parity;
    calculate_parity_vector(data.data(), data.size(), parity);

    // Corrupt Shard 0
    std::memset(data.data(), 0, ecc::ECC_SHARD_SIZE);

    // Sabotage the parity shard
    parity[0] ^= 0x01;

    // Recovery should fail the CRC check because the reconstructed 
    // data will be mathematically incorrect due to the bad parity.
    bool success = recover_damaged_shard(
        data.data(), 
        data.size(), 
        0, 
        parity, 
        crc_vec[0]
    );

    EXPECT_FALSE(success);
}
