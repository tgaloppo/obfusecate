#include <algorithm>
#include <array>
#include <cstring>
#include <vector>
#include "error_correction.hpp"

namespace ecc
{

namespace crc
{
//
// CRC-8 implementation from:
// https://www.analog.com/media/en/technical-documentation/tech-articles/understanding-and-using-cyclic-redundancy-checks-with-maxim-1wire-and-ibutton-products.pdf
//
static std::array<uint8_t, 256> crc8_table 
{
      0,  94, 188, 226,  97,  63, 221, 131, 194, 156, 126,  32, 163, 253,  31,  65,
    157, 195,  33, 127, 252, 162,  64,  30,  95,   1, 227, 189,  62,  96, 130, 220,
     35, 125, 159, 193,  66,  28, 254, 160, 225, 191,  93,   3, 128, 222,  60,  98,
    190, 224,   2,  92, 223, 129,  99,  61, 124,  34, 192, 158,  29,  67, 161, 255,
     70,  24, 250, 164,  39, 121, 155, 197, 132, 218,  56, 102, 229, 187,  89,   7,
    219, 133, 103,  57, 186, 228,   6,  88,  25,  71, 165, 251, 120,  38, 196, 154,
    101,  59, 217, 135,   4,  90, 184, 230, 167, 249,  27,  69, 198, 152, 122,  36,
    248, 166,  68,  26, 153, 199,  37, 123,  58, 100, 134, 216,  91,   5, 231, 185,
    140, 210,  48, 110, 237, 179,  81,  15,  78,  16, 242, 172,  47, 113, 147, 205,
     17,  79, 173, 243, 112,  46, 204, 146, 211, 141, 111,  49, 178, 236,  14,  80,
    175, 241,  19,  77, 206, 144, 114,  44, 109,  51, 209, 143,  12,  82, 176, 238,
     50, 108, 142, 208,  83,  13, 239, 177, 240, 174,  76,  18, 145, 207,  45, 115,
    202, 148, 118,  40, 171, 245,  23,  73,   8,  86, 180, 234, 105,  55, 213, 139,
     87,   9, 235, 181,  54, 104, 138, 212, 149, 203,  41, 119, 244, 170,  72,  22,
    233, 183,  85,  11, 136, 214,  52, 106,  43, 117, 151, 201,  74,  20, 246, 168,
    116,  42, 200, 150,  21,  75, 169, 247, 182, 232,  10,  84, 215, 137, 107,  53
};

inline uint8_t calc_crc8(uint8_t data, uint8_t crc)
{
    return crc8_table[data ^ crc];
}   

} // namespace crc

void calculate_crc8_vector(const uint8_t* data, std::size_t length, std::vector<uint8_t>& crc_vec)
{
    size_t n_shards = (length + ECC_SHARD_SIZE - 1) / ECC_SHARD_SIZE;
    crc_vec.resize(n_shards);
    for (std::size_t j = 0; j < n_shards; j++)
    {
        uint8_t crc = 0;
        std::size_t n_bytes = std::min(ECC_SHARD_SIZE, length - j * ECC_SHARD_SIZE);
        for (std::size_t k = 0; k < n_bytes; k++)
        {
            crc = crc::calc_crc8(data[j * ECC_SHARD_SIZE + k], crc);
        }
        for (std::size_t k = n_bytes; k < ECC_SHARD_SIZE; k++)
        {
            crc = crc::calc_crc8(0, crc);
        }
        crc_vec[j] = crc;
    }
}

void calculate_parity_vector(const uint8_t* data, std::size_t length, std::array<uint8_t, ECC_SHARD_SIZE>& parity)
{
    parity.fill(0);
    for (std::size_t j = 0; j < length; j++)
    {
        parity[j % ECC_SHARD_SIZE] ^= data[j];
    }
}

bool recover_damaged_shard(uint8_t* data, std::size_t length, std::size_t shard_index, std::array<uint8_t, ECC_SHARD_SIZE>& parity_vector, uint8_t expected_crc)
{
    return recover_damaged_shard(data, length, shard_index, parity_vector.data(), expected_crc);
}

bool recover_damaged_shard(uint8_t* data, std::size_t length, std::size_t shard_index, const uint8_t* parity_vector, uint8_t expected_crc)
{
    std::array<uint8_t, ECC_SHARD_SIZE> recovery;
    std::memcpy(recovery.data(), parity_vector, ECC_SHARD_SIZE);

    // xor all columns excluding the corrupt shard
    for (std::size_t j = 0; j < length; j++)
    {
        if (j / ECC_SHARD_SIZE != shard_index)
        {
            recovery[j % ECC_SHARD_SIZE] ^= data[j];
        }
        else // skip past the whole shard...
        {
            j += ECC_SHARD_SIZE - 1; // loop increment will account for final byte
        }
    }

    // check that the recovered shard has expected CRC-8
    uint8_t recovery_crc = 0;
    for (size_t j = 0; j < ECC_SHARD_SIZE; j++)
    {
        recovery_crc = crc::calc_crc8(recovery[j], recovery_crc);
    }

    if (recovery_crc != expected_crc){
        return false;
    }

    // copy the recovered data back to the data block
    size_t n_bytes = std::min(ECC_SHARD_SIZE, length - shard_index * ECC_SHARD_SIZE);
    std::memcpy(data + ECC_SHARD_SIZE * shard_index, recovery.data(), n_bytes);

    return true;
}

} // namespace ecc
