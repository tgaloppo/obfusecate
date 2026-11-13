#pragma once

#include "chacha20.hpp"

namespace crypto
{
namespace chacha20
{
namespace poly1305
{

typedef std::array<uint8_t, 16> mac;

void compute_mac(const std::array<uint8_t, 64>& one_time_key, 
                 const uint8_t* message, std::size_t length, 
                 mac& out_mac);

void encrypt(
    const uint8_t* plaintext, std::size_t pt_len,
    const uint8_t* aad, std::size_t aad_len,
    const key& key, const nonce& nonce,
    uint8_t* ciphertext, mac& out_mac);

bool decrypt(
    const uint8_t* ciphertext, std::size_t ct_len,
    const uint8_t* aad, std::size_t aad_len,
    const key& key, const nonce& nonce,
    const mac& expected_mac,
    uint8_t* plaintext);

} // namespace poly1305
} // namespace chacha20
} // namespace crypto
