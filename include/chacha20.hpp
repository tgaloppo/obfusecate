#pragma once

#include <array>
#include <cstdint>

namespace crypto
{

void zero_memory(uint8_t* ptr, size_t len);
void armor_memory(void* ptr, size_t size);
void dearmor_memory(void* ptr, size_t size);

namespace chacha20
{

typedef std::array<uint32_t, 16> state;
typedef std::array<uint8_t, 32>  key;
typedef std::array<uint8_t, 12>  nonce;

void initialize(const key&, const nonce&, state&);
void initialize_poly1305(const key&, const nonce&, state&);
nonce create_nonce();
void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d);
void block(state&, std::array<uint8_t, 64>&);
// encrypt and decrypt are identical
void encrypt(uint8_t*, std::size_t, const key&, const nonce&);

} // namespace chacha20
} // namespace crypto
