// ==============================================================================
// ObFUSEcate
// test_fileio.cpp
// 
// Author: Travis J. Galoppo (tgaloppo@gmail.com)
// 
// SPDX-License-Identifier: MIT
// ==============================================================================
#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <random>
#include <cstring>
#include "block_device.hpp"
#include "chacha20.hpp"
#include "poly1305.hpp"

using namespace obfusecate;

class CryptfsVolumeTest : public ::testing::Test 
{
protected:
    std::string m_test_file = "test_volume.ofs";
    crypto::chacha20::Key m_test_key;

    void SetUp() override 
    {
        if (std::filesystem::exists(m_test_file)) 
        {
            std::filesystem::remove(m_test_file);
        }
        for (std::size_t i = 0; i < m_test_key.size(); ++i) 
        {
            m_test_key[i] = static_cast<uint8_t>(i ^ 0xAA);
        }
    }

    void TearDown() override 
    {
        if (std::filesystem::exists(m_test_file)) 
        {
            std::filesystem::remove(m_test_file);
        }
    }

    std::vector<uint8_t> generate_random_payload(std::size_t size) 
    {
        std::vector<uint8_t> data(size);
        std::mt19937 gen(42); // deterministic for tests
        std::uniform_int_distribution<uint16_t> dist(0, 255);
        for (std::size_t i = 0; i < size; ++i) 
        {
            data[i] = static_cast<uint8_t>(dist(gen));
        }
        return data;
    }
};

TEST_F(CryptfsVolumeTest, FormatsNewVolumeAndMountsExisting) 
{
    // 1. Format new volume
    {
        block_device fs(m_test_file, m_test_key);
        fs.set_logical_size(4096 * 4);
        EXPECT_EQ(fs.get_logical_size(), 4096 * 4);
    } // fs goes out of scope, descriptor closes

    // 2. Verify magic bytes on disk
    std::ifstream raw_file(m_test_file, std::ios::binary);
    char magic[8];
    raw_file.read(magic, 8);
    EXPECT_EQ(std::memcmp(magic, obfusecate::FILE_HEADER_MAGIC, 8), 0);
    raw_file.close();

    // 3. Mount existing volume
    {
        block_device fs(m_test_file, m_test_key);
        EXPECT_EQ(fs.get_logical_size(), 4096 * 4);
    }
}

TEST_F(CryptfsVolumeTest, SingleBlockRoundTrip) 
{
    block_device fs(m_test_file, m_test_key);
    uint64_t block_size = fs.get_logical_block_size();
    fs.set_logical_size(block_size);
    std::vector<uint8_t> write_buf = generate_random_payload(block_size);
    
    EXPECT_NO_THROW(fs.write_logical_block(0, write_buf));
    EXPECT_EQ(fs.get_logical_size(), block_size);

    std::vector<uint8_t> read_buf;
    EXPECT_NO_THROW(fs.read_logical_block(0, read_buf));
    
    EXPECT_EQ(write_buf.size(), read_buf.size());
    EXPECT_EQ(std::memcmp(write_buf.data(), read_buf.data(), block_size), 0);
}

TEST_F(CryptfsVolumeTest, ShiftOnOverwrite) 
{
    block_device fs(m_test_file, m_test_key);
    fs.set_logical_size(1024 * 64);

    // Write Block 0 (Highly incompressible random data -> larger physical footprint)
    std::vector<uint8_t> random_data = generate_random_payload(fs.get_logical_block_size());
    EXPECT_NO_THROW(fs.write_logical_block(0, random_data));
    
    // Write Block 1 (Predictable payload)
    std::vector<uint8_t> block1_data(fs.get_logical_block_size(), 0xBB);
    EXPECT_NO_THROW(fs.write_logical_block(1, block1_data));

    // Overwrite Block 0 (Highly compressible zeros -> shrinks physical size)
    std::vector<uint8_t> zero_data(fs.get_logical_block_size(), 0x00);
    EXPECT_NO_THROW(fs.write_logical_block(0, zero_data));

    // Assert Block 1 shifted correctly and remains intact
    std::vector<uint8_t> read_buf;
    EXPECT_NO_THROW(fs.read_logical_block(1, read_buf));
    EXPECT_EQ(std::memcmp(block1_data.data(), read_buf.data(), fs.get_logical_block_size()), 0);
}

TEST_F(CryptfsVolumeTest, KillSwitchTriggersOnTampering) 
{
    std::vector<uint8_t> write_buf = generate_random_payload(16 * 1024);

    {
        block_device fs(m_test_file, m_test_key);
        fs.set_logical_size(1024*16);
        EXPECT_NO_THROW(fs.write_logical_block(0, write_buf));
    }

    // Maliciously modify the raw ciphertext on disk
    {
        std::fstream raw_file(m_test_file, std::ios::in | std::ios::out | std::ios::binary);
        size_t offset = static_cast<size_t>(sizeof(block_header) + 2 + 256 + 10);
        char tampered_byte;
        raw_file.seekp(static_cast<long int>(sizeof(file_header) + offset)); // Offset into block 0's payload
        raw_file.read(&tampered_byte, 1);
        tampered_byte = static_cast<char>(~tampered_byte);
        raw_file.seekp(static_cast<long int>(sizeof(file_header) + offset)); // Offset into block 0's payload
        raw_file.write(&tampered_byte, 1);

        raw_file.seekp(static_cast<long int>(sizeof(file_header) + offset + 128)); // need to corrupt two shards
        raw_file.read(&tampered_byte, 1);
        tampered_byte = static_cast<char>(~tampered_byte);
        raw_file.seekp(static_cast<long int>(sizeof(file_header) + offset + 128)); // need to corrupt two shards
        raw_file.write(&tampered_byte, 1);
    }

    // Remount and attempt read
    block_device fs(m_test_file, m_test_key);
    std::vector<uint8_t> read_buf;
    
    // Poly1305 MAC check must fail and throw
    EXPECT_THROW(fs.read_logical_block(0, read_buf), std::runtime_error);
}
