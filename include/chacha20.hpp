// ==============================================================================
// ObFUSEcate
// chacha20.hpp
// 
// Author: Travis J. Galoppo (tgaloppo@gmail.com)
// Description: ChaCha20 Encryption / Decryption
// 
// SPDX-License-Identifier: MIT
// ==============================================================================
#pragma once

#include <array>
#include <cstdint>

namespace crypto
{
namespace chacha20
{

typedef std::array<uint32_t, 16> State;
typedef std::array<uint8_t, 32>  Key;
typedef std::array<uint8_t, 12>  Nonce;

void initialize(const Key&, const Nonce&, State&);
void initialize_poly1305(const Key&, const Nonce&, State&);
Nonce create_nonce();
void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d);
void block(State&, std::array<uint8_t, 64>&);
// encrypt and decrypt are identical
void encrypt(uint8_t*, std::size_t, const Key&, const Nonce&);

} // namespace chacha20
} // namespace crypto
