#pragma once

#include <cstdint>

namespace ecc
{

namespace crc
{
inline uint8_t calc_crc8(uint8_t data, uint8_t crc);
} // namespace crc

constexpr size_t ECC_SHARD_SIZE = 128;

void calculate_crc8_vector(const uint8_t* data, std::size_t length, std::vector<uint8_t>& crc_vec);
void calculate_parity_vector(const uint8_t* data, std::size_t length, std::array<uint8_t, ECC_SHARD_SIZE>& parity);
bool recover_damaged_shard(uint8_t* data, std::size_t length, std::size_t shard_index, std::array<uint8_t, ECC_SHARD_SIZE>& parity_vector, uint8_t expected_crc);
bool recover_damaged_shard(uint8_t* data, std::size_t length, std::size_t shard_index, const uint8_t* parity_vector, uint8_t expected_crc);

} // namespace ecc
