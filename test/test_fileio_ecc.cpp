#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <random>
#include <cstring>
#include "cryptofs.hpp"
#include "error_correction.hpp"

using namespace cryptofs;

class CryptfsECCTest : public ::testing::Test 
{
protected:
    std::string m_test_file = "ecc_test_volume.arcane";
    crypto::chacha20::key m_test_key;

    void SetUp() override 
    {
        if (std::filesystem::exists(m_test_file)) 
        {
            std::filesystem::remove(m_test_file);
        }
        for (std::size_t i = 0; i < m_test_key.size(); ++i) 
        {
            m_test_key[i] = static_cast<uint8_t>(i ^ 0xCC);
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
        std::mt19937 gen(42);
        std::uniform_int_distribution<uint16_t> dist(0, 255);
        for (std::size_t i = 0; i < size; ++i) 
        {
            data[i] = static_cast<uint8_t>(dist(gen));
        }
        return data;
    }
    
    // Helper to calculate the exact offset to the encrypted payload on disk
    size_t get_payload_offset(size_t crc_size)
    {
        // superblock + block_header(28) + crc_size_marker(2) + crc_array + parity(64)
        return sizeof(file_superblock) + 28 + 2 + crc_size + ecc::ECC_SHARD_SIZE;
    }
};

TEST_F(CryptfsECCTest, RecoverSingleByteCorruption) 
{
    std::vector<uint8_t> write_buf = generate_random_payload(4096);
    
    {
        cryptofs_file fs(m_test_file, m_test_key);
        fs.set_logical_size(4096);
        EXPECT_TRUE(fs.write_logical_block(0, write_buf));
    }

    // Determine the CRC size for a highly entropic 4096 byte payload.
    // Compressed size + table size will be slightly over 4096.
    // Shards = 4096 / 64 = 64 shards (approx)
    size_t approximate_crc_size = 129; 
    size_t payload_offset = get_payload_offset(approximate_crc_size);

    // Corrupt a single byte in the first shard (index 0)
    {
        std::fstream raw_file(m_test_file, std::ios::in | std::ios::out | std::ios::binary);
        raw_file.seekp(static_cast<long int>(payload_offset + 5)); 
        char tampered_byte = 0x00;
        raw_file.write(&tampered_byte, 1);
    }

    // Remount and attempt read. ECC should silently repair it.
    cryptofs_file fs(m_test_file, m_test_key);
    std::vector<uint8_t> read_buf;
    
    EXPECT_NO_THROW(fs.read_logical_block(0, read_buf));
    EXPECT_EQ(write_buf, read_buf);
}

TEST_F(CryptfsECCTest, UnrecoverableMultiShardCorruption) 
{
    std::vector<uint8_t> write_buf = generate_random_payload(1024 * 16);
    
    {
        cryptofs_file fs(m_test_file, m_test_key);
        fs.set_logical_size(1024 * 32);
        EXPECT_TRUE(fs.write_logical_block(0, write_buf));
    }

    size_t approximate_crc_size = 129; 
    size_t payload_offset = get_payload_offset(approximate_crc_size);

    // Corrupt one byte in shard 0, and one byte in shard 1 (64 bytes later)
    {
        std::fstream raw_file(m_test_file, std::ios::in | std::ios::out | std::ios::binary);
        char tampered_byte = 0x00;
        
        raw_file.seekp(static_cast<long int>(payload_offset + 5)); 
        raw_file.write(&tampered_byte, 1);
        
        raw_file.seekp(static_cast<long int>(payload_offset + 270)); 
        raw_file.write(&tampered_byte, 1);
    }

    // Remount and attempt read. 
    // ECC will detect multiple CRC failures and throw "Unrecoverable corruption"
    cryptofs_file fs(m_test_file, m_test_key);
    std::vector<uint8_t> read_buf;
    
    EXPECT_THROW(
    {
        try {
            fs.read_logical_block(0, read_buf);
        } catch( const std::runtime_error& e ) {
            EXPECT_STREQ( "Unrecoverable corruption", e.what() );
            throw;
        }
    }, std::runtime_error);
}

TEST_F(CryptfsECCTest, HeaderTamperingBypassesECC) 
{
    std::vector<uint8_t> write_buf = generate_random_payload(4096);
    
    {
        cryptofs_file fs(m_test_file, m_test_key);
        fs.set_logical_size(4096);
        EXPECT_TRUE(fs.write_logical_block(0, write_buf));
    }

    // Corrupt the ChaCha20 MAC in the block header. 
    // This leaves the payload pristine, but the AEAD orchestrator MUST fail.
    {
        std::fstream raw_file(m_test_file, std::ios::in | std::ios::out | std::ios::binary);
        raw_file.seekp(static_cast<long int>(sizeof(file_superblock) + 2)); 
        char tampered_byte = 0x00;
        raw_file.write(&tampered_byte, 1);
    }

    // Remount and attempt read. 
    // ECC checks will pass (payload is fine), but Poly1305 will throw.
    cryptofs_file fs(m_test_file, m_test_key);
    std::vector<uint8_t> read_buf;
    
    EXPECT_THROW(
    {
        try {
            fs.read_logical_block(0, read_buf);
        } catch( const std::runtime_error& e ) {
            EXPECT_STREQ( "Decryption Failure", e.what() );
            throw;
        }
    }, std::runtime_error);
}
