// ==============================================================================
// ObFUSEcate
// poly1305.hpp
// 
// Author: Travis J. Galoppo (tgaloppo@gmail.com)
// Description: ChaCha20-Poly1305 authenticated encryption functions
// 
// SPDX-License-Identifier: MIT
// ==============================================================================
#pragma once

#include "chacha20.hpp"

namespace crypto
{
namespace chacha20
{
namespace poly1305
{

typedef std::array<uint8_t, 16> MAC;

void compute_mac(const std::array<uint8_t, 64>& one_time_key, const uint8_t* message, std::size_t length, MAC& out_mac);

void encrypt(
    const uint8_t* plaintext, std::size_t pt_len,
    const uint8_t* aad, std::size_t aad_len,
    const Key& key, const Nonce& nonce,
    uint8_t* ciphertext, MAC& out_mac);

bool decrypt(
    const uint8_t* ciphertext, std::size_t ct_len,
    const uint8_t* aad, std::size_t aad_len,
    const Key& key, const Nonce& nonce,
    const MAC& expected_mac,
    uint8_t* plaintext);

} // namespace poly1305
} // namespace chacha20
} // namespace crypto
