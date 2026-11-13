// ==============================================================================
// ObFUSEcate
// block_device.cpp
// 
// Author: Travis J. Galoppo (tgaloppo@gmail.com)
// 
// SPDX-License-Identifier: MIT
// ==============================================================================
#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <system_error>
#include <fcntl.h>
#include <sys/stat.h>
#include "block_device.hpp"
#include "crypto.hpp"
#include "bitstream.hpp"
#include "arithmetic_encoder.hpp"
#include "arithmetic_decoder.hpp"
#include "poly1305.hpp"
#include "fileio.hpp"

namespace obfusecate
{

// returns true if buffer is all single-value
static bool is_fill(const uint8_t* buf, std::size_t length, uint8_t value)
{
    for (std::size_t j = 0; j < length; j++)
    {
        if (buf[j] != value)
        {
            return false;
        }
    }

    return true;
}

compressed_block create_compressed_block(const uint8_t* data, std::size_t length)
{
    compression::symbol_frequency freq(data, length);
    bitstream::writer             enc_stream(length * 8 + 128);
    compression::arithmetic_encoder encoder(enc_stream, freq);

    encoder.encode(data, length);
    encoder.flush();

    std::vector<uint8_t> compressed(enc_stream.size_in_bytes());
    std::memcpy(compressed.data(), enc_stream.data(), enc_stream.size_in_bytes());

    bitstream::writer freq_stream = freq.serialize();
    std::vector<uint8_t> freq_tbl(freq_stream.size_in_bytes());
    std::memcpy(freq_tbl.data(), freq_stream.data(), freq_stream.size_in_bytes());

    return { length, std::move(freq_tbl), std::move(compressed) };
}

std::vector<uint8_t> decompress_block(const compressed_block& block)
{
    std::vector<uint8_t> data(block.payload_bytes);
    bitstream::reader freq_stream(block.frequency_table.data(), block.frequency_table.size() * 8);
    bitstream::reader data_stream(block.compressed_data.data(), block.compressed_data.size() * 8);
    compression::symbol_frequency freq(freq_stream);
    compression::arithmetic_decoder decoder(data_stream, freq);
    decoder.decode(data.data(), data.size());
    return data;
}

block_device::block_device(const std::string& file_path, crypto::chacha20::Key& key)
        : mFd(-1), mFilePath(file_path)
{
    crypto::armor_memory(mKey.data(), mKey.size());
    mKey = key;

    // open the POSIX descriptor
    mFd = ::open(mFilePath.c_str(), O_RDWR | O_CREAT, 0600);
    if (mFd < 0)
    {
        throw std::system_error(errno, std::generic_category(), "Failed to open volume");
    }

    // check the physical file size
    struct stat st;
    if (::fstat(mFd, &st) < 0)
    {
        throw std::system_error(errno, std::generic_category(), "Failed to stat volume");
    }

    if (st.st_size == 0) // new volume
    {
        std::memset(&mFileHeader, 0, sizeof(file_header));
        std::memcpy(mFileHeader.magic, FILE_HEADER_MAGIC, 8); // 8-byte magic identifier
        mFileHeader.version = FILE_HEADER_VERSION;
        mFileHeader.logical_block_size   = LOGICAL_BLOCK_SIZE;
        mFileHeader.total_logical_blocks = 0;
        mFileHeader.bat_offset = file_header::SERIALIZED_SIZE;

        write_file_header();
    }
    else // existing volume
    {
        std::array<uint8_t, file_header::SERIALIZED_SIZE> raw_fh;
        fileio::read(mFd, raw_fh.data(), raw_fh.size(), 0);
        mFileHeader = file_header::deserialize(raw_fh.data());

        if (std::memcmp(mFileHeader.magic, FILE_HEADER_MAGIC, 8) != 0)
        {
            throw std::runtime_error("mount failed: invalid magic bytes");
        }

        // Verify the Secret Key
        uint8_t dummy = 0;
        bool is_key_valid = crypto::chacha20::poly1305::decrypt(
            &dummy, 0, 
            raw_fh.data(), 60,
            mKey, mFileHeader.hdr_nonce, mFileHeader.hdr_mac,
            &dummy
        );

        if (!is_key_valid)
        {
            throw std::runtime_error("mount failed: incorrect password or corrupt volume");
        }

        if (mFileHeader.bat_offset < file_header::SERIALIZED_SIZE || 
            mFileHeader.bat_offset > static_cast<uint64_t>(st.st_size))
        {
            throw std::runtime_error("mount failed: BAT location invalid");
        }

        // Calculate BAT size and read it into memory
        uint64_t bat_bytes = static_cast<uint64_t>(st.st_size) - mFileHeader.bat_offset;
        if (bat_bytes % bat_entry::SERIALIZED_SIZE != 0)
        {
            throw std::runtime_error("mount failed: corrupt BAT alignment");
        }

        // read the BAT from disk
        std::vector<uint8_t> bat_data(bat_bytes);
        if (bat_bytes > 0)
        {
            fileio::read(mFd, bat_data.data(), bat_bytes, mFileHeader.bat_offset);
        }

        // verify the BAT Integrity
        bool is_bat_valid = crypto::chacha20::poly1305::decrypt(
            &dummy, 0, 
            bat_data.data(), bat_data.size(), 
            mKey, mFileHeader.bat_nonce, mFileHeader.bat_mac,
            &dummy
        );

        if (!is_bat_valid)
        {
            throw std::runtime_error("mount failed: BAT integrity check failed (tampering suspected)");
        }
        
        // fix BAT data to correct endianness
        std::size_t num_entries = bat_bytes / bat_entry::SERIALIZED_SIZE;
        mBAT.resize(num_entries);
        for (std::size_t j = 0; j < num_entries; j++)
        {
            mBAT[j] = bat_entry::deserialize(bat_data.data() + j * bat_entry::SERIALIZED_SIZE);
        }
    }
};

block_device::~block_device()
{
    // note the file descriptor will auto close
    crypto::zero_memory(mKey.data(), mKey.size());
    crypto::dearmor_memory(mKey.data(), mKey.size());
}

void block_device::set_logical_size(uint64_t exact_bytes)
{   
    // Calculate required blocks
    uint64_t required_blocks = (exact_bytes + mFileHeader.logical_block_size - 1) / mFileHeader.logical_block_size;
    
    // record volume logical blocks
    mFileHeader.total_logical_blocks = required_blocks;
    
    // if shrinking, discard trailing blocks
    if (required_blocks < mBAT.size())
    {
        mBAT.resize(required_blocks);
    }
    
    // flush both BAT and Superblock
    write_bat();
}

uint32_t block_device::get_logical_block_size() const
{
    return mFileHeader.logical_block_size;
}

uint64_t block_device::get_block_count() const
{
    return mBAT.size();
}

uint64_t block_device::get_logical_size() const
{
    return mFileHeader.total_logical_blocks * mFileHeader.logical_block_size;
}

uint64_t block_device::get_physical_size() const
{
    if (mBAT.empty())
    {
        return file_header::SERIALIZED_SIZE;
    }
    return mBAT.back().physical_offset + mBAT.back().physical_size;
}

std::array<uint8_t, 12> block_device::create_aad(uint64_t block_index) const
{
    std::array<uint8_t, 12> aad;
    endian::write_u64(&aad[0], block_index);
    endian::write_u32(&aad[8], mFileHeader.logical_block_size);
    return aad;    
}

std::size_t block_device::compute_block_metadata_size(size_t crc_bytes) const
{
    return sizeof(block_header) + 2 + crc_bytes + ecc::ECC_SHARD_SIZE;
}

void block_device::read_logical_block(uint64_t block_index, std::vector<uint8_t>& out_buf)
{
    // make sure read is within volume bounds
    if (block_index >= mFileHeader.total_logical_blocks)
    {
        throw std::out_of_range("block_index out of range");
    }

    // get size and position from the BAT
    uint64_t position  = 0;
    uint64_t size      = 0;
    if (block_index < mBAT.size())
    {
        position = mBAT[block_index].physical_offset;
        size     = mBAT[block_index].physical_size;
    }

    // If the block has size 0, fill buffer with zeros and return
    if (size == 0)
    {
        out_buf.assign(mFileHeader.logical_block_size, 0);
        return;
    }

    // read the whole block
    std::vector<uint8_t> buffer(size);
    fileio::read(mFd, buffer.data(), size, position);

    // decrypt and verify data integrity
    std::vector<uint8_t> decrypted;
    decrypt_payload(buffer, block_index, decrypted);

    // decompress the data and return
    decompress_payload(decrypted, out_buf);
}

void block_device::write_logical_block(uint64_t block_index, const std::vector<uint8_t>& in_buf)
{
    // ensure we are not writing past the end of the file
    if (block_index >= mFileHeader.total_logical_blocks)
    {
        throw std::out_of_range("block_index out of range");
    }

    // enforce block size match
    if (in_buf.size() != mFileHeader.logical_block_size)
    {
        throw std::runtime_error("write_logical_block(): block size mismatch");
    }

    // make sure BAT is complete up to block_index
    // (zero fill if necessary)
    expand_bat(block_index);

    // if this block is all zeros, skip the compression / encryption and
    // simply erase the block
    if (is_fill(in_buf.data(), in_buf.size(), 0))
    {
        int64_t block_shift = -static_cast<int64_t>(mBAT[block_index].physical_size);
        mBAT[block_index].physical_size = 0;
        relocate_blocks(block_index + 1, block_shift);
        write_bat();
        return;
    }

    // compress the payload to be encrypted
    std::vector<uint8_t> payload;
    compress_payload(in_buf, payload);

    // encrypt data, compute crc and parity vectors
    block_header hdr;
    std::vector<uint8_t> encrypted, crc_vector;
    std::array<uint8_t, ecc::ECC_SHARD_SIZE> parity_vector;
    encrypt_payload(payload, block_index, hdr, encrypted, crc_vector, parity_vector);

    // write complete block to disk, and update BAT
    // [hdr][crc][parity][payload]
    write_block_to_disk(block_index, hdr, crc_vector, parity_vector, encrypted);      
}

void block_device::write_file_header()
{
    uint8_t dummy = 0;

    // generate nonce and mac for the BAT
    mFileHeader.bat_nonce = crypto::chacha20::create_nonce();
    std::size_t bat_size_bytes = mBAT.size() * bat_entry::SERIALIZED_SIZE;
    std::vector<uint8_t> serialized_bat(bat_size_bytes);
    for (std::size_t j = 0; j < mBAT.size(); j++)
    {
        mBAT[j].serialize(serialized_bat.data() + j * bat_entry::SERIALIZED_SIZE);
    }
    crypto::chacha20::poly1305::encrypt(
        &dummy, 0, 
        serialized_bat.data(), serialized_bat.size(),
        mKey, mFileHeader.bat_nonce, 
        &dummy, mFileHeader.bat_mac
    );

    // now generate nonce and mac for the first 60 bytes of the header
    mFileHeader.hdr_nonce = crypto::chacha20::create_nonce();
    std::array<uint8_t, file_header::SERIALIZED_SIZE> buf = mFileHeader.serialize();
    crypto::chacha20::poly1305::encrypt(
        &dummy, 0,            // Empty payload
        buf.data(), 60,       // AAD is the first 60 bytes of the header
        mKey, mFileHeader.hdr_nonce, 
        &dummy, mFileHeader.hdr_mac
    );        

    buf = mFileHeader.serialize();
    fileio::write(mFd, buf.data(), buf.size(), 0);
}

void block_device::write_bat()
{
    uint64_t new_bat_offset = mBAT.empty() 
                ? file_header::SERIALIZED_SIZE
                : mBAT.back().physical_offset + mBAT.back().physical_size;

    // we need to put BAT entries into standard endian format
    std::size_t bat_size_bytes = mBAT.size() * bat_entry::SERIALIZED_SIZE; 
    std::vector<uint8_t> serialized_bat(bat_size_bytes);
    for (std::size_t j = 0; j < mBAT.size(); j++)
    {
        mBAT[j].serialize(serialized_bat.data() + j * bat_entry::SERIALIZED_SIZE);
    }
    fileio::write(mFd, serialized_bat.data(), bat_size_bytes, new_bat_offset);

    mFileHeader.bat_offset = new_bat_offset;
    write_file_header();

    __off64_t final_physical_size = static_cast<__off64_t>(new_bat_offset + bat_size_bytes);
    if (::ftruncate(mFd, final_physical_size) != 0)
    {
        throw std::system_error(errno, std::generic_category(), "Failed to truncate volume");
    }    
}

void block_device::relocate_blocks(uint64_t block_index, int64_t byte_offset)
{
    if (byte_offset == 0 || block_index >= mBAT.size())
    {
        return;
    }

    uint64_t begin_offset = mBAT[block_index].physical_offset;
    uint64_t end_offset   = mBAT.back().physical_offset + mBAT.back().physical_size;
    uint64_t total_bytes  = end_offset - begin_offset;
    
    // total bytes could be zero if the spanning BAT entries
    // are all zero size!
    if (total_bytes > 0)
    {
        uint64_t chunk_size    = std::min(total_bytes, RELOCATE_BLOCK_SIZE);
        uint64_t num_chunks    = (total_bytes + chunk_size - 1) / chunk_size;        
        uint64_t byte_offset_u = static_cast<uint64_t>(std::abs(byte_offset));

        std::vector<uint8_t> chunk_buffer;

        if (byte_offset < 0) // moving "up"
        {
            for (std::size_t j = 0; j < num_chunks; j++)
            {
                uint64_t chunk_offset = begin_offset + j * chunk_size;
                uint64_t chunk_bytes  = std::min(chunk_size, total_bytes - j * chunk_size);
                chunk_buffer.resize(chunk_bytes);
                fileio::read(mFd, chunk_buffer.data(), chunk_bytes, chunk_offset);
                fileio::write(mFd, chunk_buffer.data(), chunk_bytes, chunk_offset - byte_offset_u);
            }
        }
        else                 // moving "down"
        {
            for (std::size_t j = 0; j < num_chunks; j++)
            {
                uint64_t chunk_offset = begin_offset + (num_chunks - j - 1) * chunk_size;
                uint64_t chunk_bytes  = std::min(chunk_size, end_offset - chunk_offset);
                chunk_buffer.resize(chunk_bytes);
                fileio::read(mFd, chunk_buffer.data(), chunk_bytes, chunk_offset);
                fileio::write(mFd, chunk_buffer.data(), chunk_bytes, chunk_offset + byte_offset_u);                
            }
        }
    }

    // update the BAT
    for (std::size_t j = block_index; j < mBAT.size(); j++)
    {
        mBAT[j].physical_offset = static_cast<uint64_t>(static_cast<int64_t>(mBAT[j].physical_offset) + byte_offset);
    }    
}

void block_device::encrypt_payload(
    const std::vector<uint8_t>& payload, 
    uint64_t block_index, 
    block_header& out_hdr, 
    std::vector<uint8_t>& out_encrypted, 
    std::vector<uint8_t>& out_crc, 
    std::array<uint8_t, ecc::ECC_SHARD_SIZE>& out_parity)
{
    out_hdr.nonce = crypto::chacha20::create_nonce();
    std::array<uint8_t, 12> aad = create_aad(block_index);
    
    out_encrypted.resize(payload.size());
    crypto::chacha20::poly1305::encrypt(payload.data(), payload.size(), aad.data(), aad.size(), mKey, out_hdr.nonce, out_encrypted.data(), out_hdr.mac);

    ecc::calculate_crc8_vector(out_encrypted.data(), out_encrypted.size(), out_crc);
    ecc::calculate_parity_vector(out_encrypted.data(), out_encrypted.size(), out_parity);
}

void block_device::decrypt_payload(const std::vector<uint8_t>& buffer, uint64_t block_index, std::vector<uint8_t>& out_decrypted)
{
    // ensure incoming buffer is at least large enough 
    // for header and crc size
    if (buffer.size() < sizeof(block_header) + 2)
    {
        throw std::runtime_error("decrypt_payload(): insufficient encrypted_buffer size");
    }

    block_header hdr;
    std::memcpy(&hdr, buffer.data(), sizeof(block_header));

    uint16_t crc_size = endian::read_u16(buffer.data() + sizeof(block_header));
    const uint8_t* expected_crc_vector = buffer.data() + sizeof(block_header) + 2;
    const uint8_t* parity_vector = expected_crc_vector + crc_size;
    
    size_t total_header_size = compute_block_metadata_size(static_cast<size_t>(crc_size));

    if (buffer.size() < total_header_size)
    {
        throw std::runtime_error("decrypt_payload(): encrypted buffer_size error");
    }

    const uint8_t* encrypted_data_ptr = buffer.data() + total_header_size;
    size_t encrypted_data_len = buffer.size() - total_header_size;

    std::vector<uint8_t> data_crc_vector;
    ecc::calculate_crc8_vector(encrypted_data_ptr, encrypted_data_len, data_crc_vector);

    if (data_crc_vector.size() != crc_size) {
        throw std::runtime_error("CRC size mismatch");
    }

    std::size_t n_mismatches = 0;
    std::size_t first_mismatch = 0;
    for (std::size_t j = 0; j < crc_size; j++) {
        if (data_crc_vector[j] != expected_crc_vector[j]) {
            if (n_mismatches == 0) first_mismatch = j;
            n_mismatches += 1;
        }
    }

    if (n_mismatches > 1) {
        throw std::runtime_error("Unrecoverable corruption");
    } else if (n_mismatches == 1) {
        bool ok = ecc::recover_damaged_shard(const_cast<uint8_t*>(encrypted_data_ptr), 
                                             encrypted_data_len, first_mismatch, parity_vector, 
                                             expected_crc_vector[first_mismatch]);
        if (not ok)
        {
            throw std::runtime_error("shard recovery failed; block corrupt");
        }
    }

    std::array<uint8_t, 12> aad = create_aad(block_index);
    out_decrypted.resize(encrypted_data_len);
    
    bool ok = crypto::chacha20::poly1305::decrypt(
        encrypted_data_ptr, encrypted_data_len, 
        aad.data(), aad.size(), mKey, hdr.nonce, hdr.mac, 
        out_decrypted.data());

    if (!ok) {
        throw std::runtime_error("Decryption Failure");
    }
}

void block_device::compress_payload(const std::vector<uint8_t>& in_buf, std::vector<uint8_t>& out_payload)
{
    compressed_block compressed = create_compressed_block(in_buf.data(), in_buf.size());
    std::size_t compressed_size = compressed.compressed_data.size() + compressed.frequency_table.size();

    if (compressed_size < in_buf.size())
    {
        out_payload.resize(2 + compressed_size);
        endian::write_u16(out_payload.data(), static_cast<uint16_t>(compressed.frequency_table.size()));
        std::memcpy(out_payload.data() + 2, compressed.frequency_table.data(), compressed.frequency_table.size());
        std::memcpy(out_payload.data() + 2 + compressed.frequency_table.size(), compressed.compressed_data.data(), compressed.compressed_data.size());        
    }
    else
    {
        out_payload.resize(2 + in_buf.size());
        endian::write_u16(out_payload.data(), 0);
        std::memcpy(out_payload.data() + 2, in_buf.data(), in_buf.size());
    }
}

void block_device::decompress_payload(const std::vector<uint8_t>& decrypted, std::vector<uint8_t>& out_buf)
{
    if (decrypted.size() < 2)
    {
        throw std::runtime_error("decompress_payload(): decrypted payload size error");
    }
    uint16_t freq_table_size = endian::read_u16(decrypted.data());

    // data is uncompressed if frequency table size is
    if (freq_table_size == 0) {
        out_buf.assign(decrypted.begin() + 2, decrypted.end());
    } else {
        std::vector<uint8_t> freq_table(freq_table_size);

        if (decrypted.size() - 2 < static_cast<std::size_t>(freq_table_size))
        {
            throw std::runtime_error("decompress_payload(): size mismatch on freq_table_size");
        }

        std::memcpy(freq_table.data(), decrypted.data() + 2, freq_table_size);

        std::vector<uint8_t> compressed_data(decrypted.begin() + 2 + freq_table_size, decrypted.end());
        out_buf = decompress_block({ mFileHeader.logical_block_size, freq_table, compressed_data });
    }
}

void block_device::expand_bat(uint64_t block_index)
{
    if (block_index >= mFileHeader.total_logical_blocks)
    {
        throw std::out_of_range("block_index out of range");
    }

    if (block_index >= mBAT.size())
    {
        uint64_t end_offset = get_physical_size();
        for (std::size_t j = mBAT.size(); j <= block_index; j++)
        {
            mBAT.push_back({ end_offset, 0 });
        }
    }
}

void block_device::write_block_to_disk(
    uint64_t block_index, 
    const block_header& hdr, 
    const std::vector<uint8_t>& crc_vector, 
    const std::array<uint8_t, ecc::ECC_SHARD_SIZE>& parity_vector, 
    const std::vector<uint8_t>& encrypted)
{
    uint32_t block_size = static_cast<uint32_t>(compute_block_metadata_size(crc_vector.size()) + encrypted.size());
    uint64_t position = mBAT[block_index].physical_offset;

    uint64_t current_size = mBAT[block_index].physical_size;
    if (block_size != current_size)
    {
        int64_t size_delta = static_cast<int64_t>(block_size) - static_cast<int64_t>(current_size);
        mBAT[block_index].physical_size = block_size;
        relocate_blocks(block_index + 1, size_delta);
    }

    std::array<uint8_t, 2> crc_size;
    endian::write_u16(crc_size.data(), static_cast<uint16_t>(crc_vector.size()));

    struct iovec iov[5];
    iov[0].iov_base = const_cast<block_header*>(&hdr);
    iov[0].iov_len  = sizeof(hdr);
    iov[1].iov_base = crc_size.data();
    iov[1].iov_len  = 2;
    iov[2].iov_base = const_cast<uint8_t*>(crc_vector.data());
    iov[2].iov_len  = crc_vector.size();
    iov[3].iov_base = const_cast<uint8_t*>(parity_vector.data());
    iov[3].iov_len  = parity_vector.size();
    iov[4].iov_base = const_cast<uint8_t*>(encrypted.data());
    iov[4].iov_len  = encrypted.size();    
    fileio::writev(mFd, iov, 5, position);

    write_bat();
}

} // namespace obfusecate
