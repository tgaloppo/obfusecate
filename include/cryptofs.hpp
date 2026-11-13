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

namespace cryptofs
{

#pragma pack(push, 1)

struct file_superblock
{
    char     magic[8];
    uint32_t version;
    uint32_t logical_block_size;
    uint64_t total_logical_bytes;
    uint64_t bat_offset;

    std::array<uint8_t, 32> serialize()
    {
        std::array<uint8_t, 32> buf;
        std::memcpy(buf.data(), magic, 8);
        endian::write_u32(buf.data() + 8,  version);
        endian::write_u32(buf.data() + 12, logical_block_size);
        endian::write_u64(buf.data() + 16, total_logical_bytes);
        endian::write_u64(buf.data() + 24, bat_offset);
        return buf;
    }

    static file_superblock deserialize(const uint8_t* buf)
    {
        file_superblock sb;
        std::memcpy(sb.magic, buf, 8);
        sb.version             = endian::read_u32(buf + 8);
        sb.logical_block_size  = endian::read_u32(buf + 12);
        sb.total_logical_bytes = endian::read_u64(buf + 16);
        sb.bat_offset          = endian::read_u64(buf + 24);
        return sb;
    }    
};

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

struct block_header
{
    std::array<uint8_t, 16> mac;
    std::array<uint8_t, 12> nonce;
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

class cryptofs_file
{
public:
    explicit cryptofs_file(const std::string& file_path, crypto::chacha20::key& key);
    ~cryptofs_file();

    // prevent copying
    cryptofs_file(const cryptofs_file&)      = delete;
    cryptofs_file& operator=(cryptofs_file&) = delete;

    uint32_t get_logical_block_size() const;
    uint64_t get_block_count() const;

    uint64_t get_logical_size()  const;   // full uncompressed size
    uint64_t get_physical_size() const;   // full compressed size (size on disk)

    void set_logical_size(uint64_t exact_bytes);

    void read_logical_block(uint64_t block_index, std::vector<uint8_t>& out_buf);
    void write_logical_block(uint64_t block_index, const std::vector<uint8_t>& buf);

protected:
    struct unique_fd {
        int fd;
        unique_fd(int f = -1) : fd(f) {}
        ~unique_fd() { if (fd >= 0) ::close(fd); }
        
        // 1. Prevent dangerous copies that cause double-closes
        unique_fd(const unique_fd&) = delete;
        unique_fd& operator=(const unique_fd&) = delete;

        // 2. Safely take ownership of a raw integer descriptor
        unique_fd& operator=(int new_fd) {
            if (fd >= 0) ::close(fd);
            fd = new_fd;
            return *this;
        }

        operator int() const { return fd; }
    };

    unique_fd               mFd;          // OS file descriptor
    file_superblock         mSuperblock;  // file metadata
    std::vector<bat_entry>  mBAT;         // block access table
    std::string             mFilePath;
    crypto::chacha20::key   mKey;

    // relocate blocks on disk, starting from block_id to end;
    // adjusts offsets in BAT and writes new BAT.
    void relocate_blocks(uint64_t block_index, int64_t byte_offset);
    void write_superblock();
    void write_bat();

    // wrap POSIX read/write in more useful packages
    void read(uint8_t*, size_t, uint64_t);
    void write(const uint8_t*, size_t, uint64_t);

    // create an associated data tag for encryption / authentication
    std::array<uint8_t, 12> create_aad(uint64_t block_index) const;

    // compute the total block metadata size, in bytes
    std::size_t compute_block_metadata_size(size_t crc_bytes) const;

    // get the logical byte offset of a block index
    uint64_t get_logical_offset(uint64_t block_index) const;

    // get the number of non-pad bytes present in a block
    // (may be less than block size for the final block)
    uint32_t get_active_bytes_in_block(uint64_t block_index) const;

    void decrypt_and_verify(const std::vector<uint8_t>& buffer, uint64_t block_index, std::vector<uint8_t>& out_decrypted);
    void unpack_payload(const std::vector<uint8_t>& decrypted, uint64_t block_index, std::vector<uint8_t>& out_buf);
    void ensure_capacity(uint64_t block_index);
    void pack_payload(const std::vector<uint8_t>& in_buf, std::vector<uint8_t>& out_payload);
    void encrypt_and_armor(const std::vector<uint8_t>& payload, uint64_t block_index, block_header& out_hdr, std::vector<uint8_t>& out_encrypted, std::vector<uint8_t>& out_crc, std::array<uint8_t, ecc::ECC_SHARD_SIZE>& out_parity);
    void flush_to_disk(uint64_t block_index, const block_header& hdr, const std::vector<uint8_t>& crc_vector, const std::array<uint8_t, ecc::ECC_SHARD_SIZE>& parity_vector, const std::vector<uint8_t>& encrypted);    
};

} // namespace cryptofs
