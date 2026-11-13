#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <system_error>
#include <fcntl.h>
#include <sys/stat.h>
#include "cryptofs.hpp"
#include "bitstream.hpp"
#include "arithmetic_encoder.hpp"
#include "arithmetic_decoder.hpp"
#include "poly1305.hpp"

namespace cryptofs
{

compressed_block create_compressed_block(const uint8_t* data, std::size_t length)
{
    std::optional<compressed_block> result = std::nullopt;
    compression::symbol_frequency freq(data, length);
    bitstream::writer             enc_stream(length * 8 + 128);
    compression::arithmetic_coder encoder(enc_stream, freq);

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

cryptofs_file::cryptofs_file(const std::string& file_path, crypto::chacha20::key& key)
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

    if (st.st_size == 0)
    {
        // Format New Volume
        std::memset(&mSuperblock, 0, sizeof(file_superblock));
        std::memcpy(mSuperblock.magic, "ARCANEFS", 8); // 8-byte magic identifier
        mSuperblock.version = 1;
        mSuperblock.logical_block_size = 1024 * 16;
        mSuperblock.total_logical_bytes = 0;
        mSuperblock.bat_offset = sizeof(file_superblock);

        write_superblock();
    }
    else
    {
        // Mount Existing Volume
        std::array<uint8_t, 32> raw_sb;
        read(raw_sb.data(), raw_sb.size(), 0);
        mSuperblock = file_superblock::deserialize(raw_sb.data());

        if (std::memcmp(mSuperblock.magic, "ARCANEFS", 8) != 0)
        {
            throw std::runtime_error("Mount failed: Invalid magic bytes");
        }

        // Calculate BAT size and read it into memory
        uint64_t bat_bytes = static_cast<uint64_t>(st.st_size) - mSuperblock.bat_offset;
        if (bat_bytes % sizeof(bat_entry) != 0)
        {
            throw std::runtime_error("Mount failed: Corrupt BAT alignment");
        }

        std::size_t num_entries = bat_bytes / bat_entry::SERIALIZED_SIZE;
        mBAT.resize(num_entries);

        if (num_entries > 0)
        {
            std::vector<uint8_t> bat_data(bat_bytes);
            read(bat_data.data(), bat_bytes, mSuperblock.bat_offset);
            // fix BAT data to correct endianness
            for (std::size_t j = 0; j < num_entries; j++)
            {
                mBAT[j] = bat_entry::deserialize(bat_data.data() + j * bat_entry::SERIALIZED_SIZE);
            }
        }
    }
};

cryptofs_file::~cryptofs_file()
{
    if (mFd >= 0)
    {
        ::close(mFd);
    }
    crypto::zero_memory(mKey.data(), mKey.size());
    crypto::dearmor_memory(mKey.data(), mKey.size());
}

uint32_t cryptofs_file::get_logical_block_size() const
{
    return mSuperblock.logical_block_size;
}

uint64_t cryptofs_file::get_block_count() const
{
    return mBAT.size();
}

uint64_t cryptofs_file::get_logical_size() const
{
    return mSuperblock.total_logical_bytes;
}

uint64_t cryptofs_file::get_physical_size() const
{
    if (mBAT.empty())
    {
        return sizeof(file_superblock);
    }
    return mBAT.back().physical_offset + mBAT.back().physical_size;
}

void cryptofs_file::set_logical_size(uint64_t exact_bytes)
{
    mSuperblock.total_logical_bytes = exact_bytes;
    
    // Calculate required blocks
    uint64_t required_blocks = (exact_bytes + mSuperblock.logical_block_size - 1) / mSuperblock.logical_block_size;
    
    // if shrinking, discard trailing blocks
    if (required_blocks < mBAT.size())
    {
        mBAT.resize(required_blocks);
    }
    
    // flush both BAT and Superblock
    write_bat();
}

std::array<uint8_t, 12> cryptofs_file::create_aad(uint64_t block_index) const
{
    std::array<uint8_t, 12> aad;
    endian::write_u64(&aad[0], block_index);
    endian::write_u32(&aad[8], mSuperblock.logical_block_size);
    return aad;    
}

std::size_t cryptofs_file::compute_block_metadata_size(size_t crc_bytes) const
{
    return sizeof(block_header) + 2 + crc_bytes + ecc::ECC_SHARD_SIZE;
}

uint64_t cryptofs_file::get_logical_offset(uint64_t block_index) const
{
    return block_index * mSuperblock.logical_block_size;
}

uint32_t cryptofs_file::get_active_bytes_in_block(uint64_t block_index) const
{
    uint64_t offset = get_logical_offset(block_index);
    if (offset >= mSuperblock.total_logical_bytes) 
    {
        return 0;
    }
    
    return static_cast<uint32_t>(std::min(static_cast<uint64_t>(mSuperblock.logical_block_size), 
                                          mSuperblock.total_logical_bytes - offset));
}

void cryptofs_file::read_logical_block(uint64_t block_index, std::vector<uint8_t>& out_buf)
{
    // make sure read is within volume bounds
    if (get_logical_offset(block_index) >= get_logical_size())
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
        std::fill(out_buf.begin(), out_buf.end(), 0);
        return;
    }

    // read the whole block
    std::vector<uint8_t> buffer(size);
    read(buffer.data(), size, position);

    // decrypt and verify data integrity
    std::vector<uint8_t> decrypted;
    decrypt_and_verify(buffer, block_index, decrypted);

    // decompress the data and return
    unpack_payload(decrypted, block_index, out_buf);
}

void cryptofs_file::write_logical_block(uint64_t block_index, const std::vector<uint8_t>& in_buf)
{
    // ensure we are not writing past the end of the file
    if (get_logical_offset(block_index) > get_logical_size())
    {
        throw std::out_of_range("block_index out of range");
    }

    // make sure BAT is complete up to block_index
    // (zero fill if necessary)
    ensure_capacity(block_index);

    // compress the payload to be encrypted
    std::vector<uint8_t> payload;
    pack_payload(in_buf, payload);

    // encrypt data, compute crc and parity vectors
    block_header hdr;
    std::vector<uint8_t> encrypted, crc_vector;
    std::array<uint8_t, ecc::ECC_SHARD_SIZE> parity_vector;
    encrypt_and_armor(payload, block_index, hdr, encrypted, crc_vector, parity_vector);

    // write complete block to disk, and update BAT
    // [hdr][crc][parity][payload]
    flush_to_disk(block_index, hdr, crc_vector, parity_vector, encrypted);      
}

void cryptofs_file::write_superblock()
{
    std::array<uint8_t, 32> buf = mSuperblock.serialize();
    write(buf.data(), buf.size(), 0);
}

void cryptofs_file::write_bat()
{
    uint64_t new_bat_offset = mBAT.empty() 
                ? sizeof(file_superblock)
                : mBAT.back().physical_offset + mBAT.back().physical_size;

    // we need to put BAT entries into standard endian format
    std::size_t bat_size_bytes = mBAT.size() * bat_entry::SERIALIZED_SIZE; 
    std::vector<uint8_t> serialized_bat(bat_size_bytes);
    for (std::size_t j = 0; j < mBAT.size(); j++)
    {
        mBAT[j].serialize(serialized_bat.data() + j * bat_entry::SERIALIZED_SIZE);
    }
    write(serialized_bat.data(), bat_size_bytes, new_bat_offset);

    mSuperblock.bat_offset = new_bat_offset;
    write_superblock();

    __off64_t final_physical_size = static_cast<__off64_t>(new_bat_offset + bat_size_bytes);
    if (::ftruncate(mFd, final_physical_size) != 0)
    {
        throw std::system_error(errno, std::generic_category(), "Failed to truncate volume");
    }    
}

void cryptofs_file::relocate_blocks(uint64_t block_index, int64_t byte_offset)
{
    if (byte_offset == 0 || block_index >= mBAT.size())
    {
        return;
    }
    
    uint64_t begin_offset = mBAT[block_index].physical_offset;
    uint64_t end_offset   = mBAT.back().physical_offset + mBAT.back().physical_size;
    uint64_t total_bytes  = end_offset - begin_offset;

    // if all the blocks to be moved are empty, there is
    // nothing to actually move
    if (total_bytes > 0)
    {
        uint64_t chunk_size   = std::min(total_bytes, static_cast<uint64_t>(1024 * 1024 * 4));
        uint64_t num_chunks   = (total_bytes + chunk_size - 1) / chunk_size;

        // in which direction are we moving the blocks
        // 1 = "down", -1 = "up"
        int64_t direction = byte_offset / std::abs(byte_offset);

        // at which byte do we start; if moving down, start
        // at end, if moving up, start at top
        uint64_t current_pos = direction == 1 
                                  ? end_offset - chunk_size
                                  : begin_offset;
        uint64_t bytes_remaining = total_bytes;

        // relocate the blocks on disk, and update the BAT
        std::vector<uint8_t> buf;
        for (std::size_t j = 0; j < num_chunks; j++)
        {
            uint64_t curr_chunk_size = std::min(chunk_size, bytes_remaining);
            buf.resize(curr_chunk_size);

            // read chunk
            read(buf.data(), curr_chunk_size, current_pos);

            // update position
            uint64_t new_pos = static_cast<uint64_t>(static_cast<int64_t>(current_pos) + byte_offset);        

            // write chunk at new location
            write(buf.data(), curr_chunk_size, new_pos);

            bytes_remaining -= curr_chunk_size;
            current_pos = static_cast<uint64_t>(static_cast<int64_t>(current_pos) - direction * static_cast<int64_t>(std::min(chunk_size, bytes_remaining)));
        }
    }

    // update the BAT
    for (std::size_t j = block_index; j < mBAT.size(); j++)
    {
        mBAT[j].physical_offset = static_cast<uint64_t>(static_cast<int64_t>(mBAT[j].physical_offset) + byte_offset);
    }
}

void cryptofs_file::write(const uint8_t* ptr, size_t nbytes, uint64_t offset)
{
    if (nbytes == 0)
    {
        return;
    }

    size_t total_written = 0;
    do
    {
        ssize_t written = pwrite(mFd, ptr + total_written, nbytes - total_written, static_cast<__off64_t>(offset + total_written));
        if (written > 0)
        {
            total_written += static_cast<size_t>(written);
        }
        else
        {
            throw std::system_error(errno, std::generic_category(), "POSIX I/O failed: pwrite()");
        }
    } while (total_written < nbytes);
}

void cryptofs_file::read(uint8_t* ptr, size_t nbytes, uint64_t offset)
{
    if (nbytes == 0)
    {
        return;
    }

    size_t total_read = 0;
    do
    {
        ssize_t nread = pread(mFd, ptr + total_read, nbytes - total_read, static_cast<__off64_t>(offset + total_read));
        if (nread > 0)
        {
            total_read += static_cast<size_t>(nread);
        }
        else
        {
            throw std::system_error(errno, std::generic_category(), "POSIX I/O failed: pread()");
        }
    } while (total_read < nbytes);
}

void cryptofs_file::decrypt_and_verify(
    const std::vector<uint8_t>& buffer, 
    uint64_t block_index, 
    std::vector<uint8_t>& out_decrypted)
{
    block_header hdr;
    std::memcpy(&hdr, buffer.data(), sizeof(block_header));

    uint16_t crc_size = endian::read_u16(buffer.data() + sizeof(block_header));
    const uint8_t* expected_crc_vector = buffer.data() + sizeof(block_header) + 2;
    const uint8_t* parity_vector = expected_crc_vector + crc_size;
    
    size_t total_header_size = compute_block_metadata_size(static_cast<size_t>(crc_size));
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
        ecc::recover_damaged_shard(const_cast<uint8_t*>(encrypted_data_ptr), 
                                   encrypted_data_len, first_mismatch, parity_vector, 
                                   expected_crc_vector[first_mismatch]);
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

void cryptofs_file::unpack_payload(
    const std::vector<uint8_t>& decrypted, 
    uint64_t block_index, 
    std::vector<uint8_t>& out_buf)
{
    uint16_t freq_table_size = endian::read_u16(decrypted.data());

    // data is uncompressed if frequency table size is
    if (freq_table_size == 0) {
        out_buf.assign(decrypted.begin() + 2, decrypted.end());
    } else {
        std::vector<uint8_t> freq_table(freq_table_size);
        std::memcpy(freq_table.data(), decrypted.data() + 2, freq_table_size);

        std::vector<uint8_t> compressed_data(decrypted.begin() + 2 + freq_table_size, decrypted.end());
        uint64_t block_bytes = get_active_bytes_in_block(block_index); 
        out_buf = decompress_block({ block_bytes, freq_table, compressed_data });
    }
}

void cryptofs_file::ensure_capacity(uint64_t block_index)
{
    if (get_logical_offset(block_index) >= get_logical_size())
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

void cryptofs_file::pack_payload(const std::vector<uint8_t>& in_buf, std::vector<uint8_t>& out_payload)
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

void cryptofs_file::encrypt_and_armor(
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

void cryptofs_file::flush_to_disk(
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

    write(reinterpret_cast<const uint8_t*>(&hdr), sizeof(hdr), position);     position += sizeof(hdr);
    write(crc_size.data(), 2, position);                                      position += 2;
    write(crc_vector.data(), crc_vector.size(), position);                    position += crc_vector.size();
    write(parity_vector.data(), parity_vector.size(), position);              position += parity_vector.size();
    write(encrypted.data(), encrypted.size(), position);
    write_bat();
}

} // namespace cryptofs
