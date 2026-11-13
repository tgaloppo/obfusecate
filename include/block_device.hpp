// ==============================================================================
// ObFUSEcate
// block_device.hpp
// 
// Author: Travis J. Galoppo (tgaloppo@gmail.com)
// Description: Compressed, encrypted file backed virtual block device
// 
// SPDX-License-Identifier: MIT
// ==============================================================================
#pragma once

#include <cstdint>
#include <cstring>
#include <vector>
#include <filesystem>
#include <optional>
#include <unistd.h>

#include "endian.hpp"
#include "chacha20.hpp"
#include "error_correction.hpp"

namespace obfusecate
{

constexpr const char* FILE_HEADER_MAGIC   = "OBFUSCTE";
constexpr uint32_t    FILE_HEADER_VERSION = 1;
constexpr uint32_t    LOGICAL_BLOCK_SIZE  = 1024 * 16;

#pragma pack(push, 1)

// header structure for volume file
struct file_header
{
    char     magic[8];              // identifier
    uint32_t version;               // version; for future use
    uint32_t logical_block_size;    // volume block size
    uint64_t total_logical_blocks;  // total blocks in volume
    uint64_t bat_offset;            // location of block access table

    std::array<uint8_t, 12> bat_nonce;  // nonce for BAT 
    std::array<uint8_t, 16> bat_mac;    // Poly1305 MAC for the BAT

    std::array<uint8_t, 12> hdr_nonce;  // nonce for this header
    std::array<uint8_t, 16> hdr_mac;    // Poly1305 MAC over the first 60 bytes of this header

    static constexpr size_t SERIALIZED_SIZE = 88; 

    std::array<uint8_t, SERIALIZED_SIZE> serialize()
    {
        std::array<uint8_t, SERIALIZED_SIZE> buf;
        std::memset(buf.data(), 0, SERIALIZED_SIZE);
        std::memcpy(buf.data(), magic, 8);
        endian::write_u32(buf.data() + 8,  version);
        endian::write_u32(buf.data() + 12, logical_block_size);
        endian::write_u64(buf.data() + 16, total_logical_blocks);
        endian::write_u64(buf.data() + 24, bat_offset);
        std::memcpy(buf.data() + 32, bat_nonce.data(), 12);
        std::memcpy(buf.data() + 44, bat_mac.data(), 16);
        std::memcpy(buf.data() + 60, hdr_nonce.data(), 12);
        std::memcpy(buf.data() + 72, hdr_mac.data(), 16);        
        return buf;
    }

    static file_header deserialize(const uint8_t* buf)
    {
        file_header sb;
        std::memcpy(sb.magic, buf, 8);
        sb.version              = endian::read_u32(buf + 8);
        sb.logical_block_size   = endian::read_u32(buf + 12);
        sb.total_logical_blocks = endian::read_u64(buf + 16);
        sb.bat_offset           = endian::read_u64(buf + 24);
        std::memcpy(sb.bat_nonce.data(), buf + 32, 12);
        std::memcpy(sb.bat_mac.data(), buf + 44, 16);
        std::memcpy(sb.hdr_nonce.data(), buf + 60, 12);
        std::memcpy(sb.hdr_mac.data(), buf + 72, 16);
        return sb;
    }    
};

// block access table entry
struct bat_entry
{
    uint64_t  physical_offset; // block offset on disk
    uint32_t  physical_size;   // block size on disk

    static constexpr size_t SERIALIZED_SIZE = 12;

    void serialize(uint8_t* buf)
    {
        endian::write_u64(buf + 0, physical_offset);
        endian::write_u32(buf + 8, physical_size);
    }

    static bat_entry deserialize(const uint8_t* buf)
    {
        bat_entry entry;
        entry.physical_offset = endian::read_u64(buf + 0);
        entry.physical_size   = endian::read_u32(buf + 8);
        return entry;
    }
};

// per-block metadata
struct block_header
{
    std::array<uint8_t, 16> mac;    // poly1305 MAC
    std::array<uint8_t, 12> nonce;  // encryption nonce for this block
};

#pragma pack(pop)

struct compressed_block
{
    std::size_t             payload_bytes;
    std::vector<uint8_t>    frequency_table;
    std::vector<uint8_t>    compressed_data;
};

compressed_block     create_compressed_block(const uint8_t* data, std::size_t length);
std::vector<uint8_t> decompress_block(const compressed_block& block);

class block_device
{
public:
    explicit block_device(const std::string& file_path, crypto::chacha20::Key& key);
    ~block_device();

    // prevent copying
    block_device(const block_device&)      = delete;
    block_device& operator=(block_device&) = delete;

    // get volume block size and block count
    uint32_t get_logical_block_size() const;
    uint64_t get_block_count() const;

    // get volume logical size and size on disk
    uint64_t get_logical_size()  const;   // full uncompressed size
    uint64_t get_physical_size() const;   // full compressed size (size on disk)

    // set the logical size of the volume (ie, via truncate)
    void set_logical_size(uint64_t exact_bytes);

    // read / write a block of data
    void read_logical_block(uint64_t block_index, std::vector<uint8_t>& out_buf);
    void write_logical_block(uint64_t block_index, const std::vector<uint8_t>& buf);

protected:
    struct unique_fd {
        int fd;
        unique_fd(int f = -1) : fd(f) {}
        ~unique_fd() { if (fd >= 0) ::close(fd); }
        
        unique_fd(const unique_fd&) = delete;
        unique_fd& operator=(const unique_fd&) = delete;

        unique_fd& operator=(int new_fd) {
            if (fd >= 0) ::close(fd);
            fd = new_fd;
            return *this;
        }

        operator int() const { return fd; }
    };

    static constexpr uint64_t   RELOCATE_BLOCK_SIZE = 1024 * 1024 * 4;

    unique_fd               mFd;          // OS file descriptor
    file_header             mFileHeader;  // file metadata
    std::vector<bat_entry>  mBAT;         // block access table
    std::string             mFilePath;    // path to volume file
    crypto::chacha20::Key   mKey;         // secret key

    // relocate blocks on disk, starting from block_id to end;
    // adjusts offsets in BAT and writes new BAT.
    void relocate_blocks(uint64_t block_index, int64_t byte_offset);
    void write_file_header();
    void write_bat();

    // create an associated data tag for encryption / authentication
    std::array<uint8_t, 12> create_aad(uint64_t block_index) const;

    // compute the total block metadata size, in bytes
    std::size_t compute_block_metadata_size(size_t crc_bytes) const;

    // compress / decompress payloads
    void compress_payload(const std::vector<uint8_t>& in_buf, std::vector<uint8_t>& out_payload);
    void decompress_payload(const std::vector<uint8_t>& decrypted, std::vector<uint8_t>& out_buf);

    // encrypt / decrypt payloads
    void encrypt_payload(const std::vector<uint8_t>& payload, uint64_t block_index, block_header& out_hdr, std::vector<uint8_t>& out_encrypted, std::vector<uint8_t>& out_crc, std::array<uint8_t, ecc::ECC_SHARD_SIZE>& out_parity);
    void decrypt_payload(const std::vector<uint8_t>& buffer, uint64_t block_index, std::vector<uint8_t>& out_decrypted);
    
    // ensure BAT has entries up to block_index
    // (may zero fill on sparse writes)
    void expand_bat(uint64_t block_index);
    
    // perform physical write of block to file
    void write_block_to_disk(uint64_t block_index, const block_header& hdr, const std::vector<uint8_t>& crc_vector, const std::array<uint8_t, ecc::ECC_SHARD_SIZE>& parity_vector, const std::vector<uint8_t>& encrypted);    
};

} // namespace obfusecate
