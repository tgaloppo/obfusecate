// ==============================================================================
// ObFUSEcate
// error_correction.hpp
// 
// Author: Travis J. Galoppo (tgaloppo@gmail.com)
// Description: CRC8 and parity vector error correction module
// 
// SPDX-License-Identifier: MIT
// ==============================================================================
#pragma once

#include <cstdint>

namespace ecc
{

namespace crc
{
inline uint8_t calc_crc8(uint8_t data, uint8_t crc);
} // namespace crc

constexpr size_t ECC_SHARD_SIZE = 128;

// calculates CRC8 value for each shard in data
void calculate_crc8_vector(const uint8_t* data, std::size_t length, std::vector<uint8_t>& crc_vec);

// calculates a parity shard by xor-ing all data shards together
void calculate_parity_vector(const uint8_t* data, std::size_t length, std::array<uint8_t, ECC_SHARD_SIZE>& parity);

// recovers a singular damaged shard by xor-ing all valid shards with the parity shard
bool recover_damaged_shard(uint8_t* data, std::size_t length, std::size_t shard_index, std::array<uint8_t, ECC_SHARD_SIZE>& parity_vector, uint8_t expected_crc);
bool recover_damaged_shard(uint8_t* data, std::size_t length, std::size_t shard_index, const uint8_t* parity_vector, uint8_t expected_crc);

} // namespace ecc
