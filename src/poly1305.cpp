// ==============================================================================
// ObFUSEcate
// poly1305.cpp
// 
// Author: Travis J. Galoppo (tgaloppo@gmail.com)
// 
// SPDX-License-Identifier: MIT
// ==============================================================================
#include <cstring>
#include <vector>
#include "crypto.hpp"
#include "poly1305.hpp"
#include "endian.hpp"

namespace crypto
{
namespace chacha20
{
namespace poly1305
{

static bool constant_time_mac_compare(const std::array<uint8_t, 16>& a, const std::array<uint8_t, 16>& b)
{
    uint8_t result = 0;
    for (std::size_t i = 0; i < 16; i++)
    {
        result |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return result == 0;
}

void encrypt(
    const uint8_t* plaintext, std::size_t pt_len,
    const uint8_t* aad, std::size_t aad_len,
    const Key& key, const Nonce& nonce,
    uint8_t* ciphertext, MAC& out_mac)
{
    State state;
    std::array<uint8_t, 64> one_time_key;
    initialize_poly1305(key, nonce, state);
    block(state, one_time_key);

    // clear out what we dont need right away
    zero_memory(&one_time_key[32], 32);

    // r = one_time_key[0..15]
    // s = one_time_key[16..31]
    one_time_key[3]  &= 0x0F;
    one_time_key[7]  &= 0x0F;
    one_time_key[11] &= 0x0F;
    one_time_key[15] &= 0x0F;
    one_time_key[4]  &= 0xFC;
    one_time_key[8]  &= 0xFC;
    one_time_key[12] &= 0xFC;

    // copy the plaintext in preparation to encrypt
    std::memcpy(ciphertext, plaintext, pt_len);

    // encrypt copy of plaintext payload
    chacha20::encrypt(ciphertext, pt_len, key, nonce);

    // calculate pad sizes for AAD data and payload
    std::size_t pad_size_aad = (16 - (aad_len % 16)) % 16;
    std::size_t pad_size_pld = (16 - (pt_len % 16)) % 16;

    // calculate the total buffer size
    std::size_t total_bytes = aad_len + pt_len + pad_size_aad + pad_size_pld + 16;

    std::vector<uint8_t> buffer(total_bytes);

    size_t position = 0;
    std::memcpy(buffer.data() + position, aad, aad_len);        position += aad_len;
    std::memset(buffer.data() + position, 0, pad_size_aad);     position += pad_size_aad;
    std::memcpy(buffer.data() + position, ciphertext, pt_len);  position += pt_len;
    std::memset(buffer.data() + position, 0, pad_size_pld);     position += pad_size_pld;
    endian::write_u64(buffer.data() + position, static_cast<uint64_t>(aad_len));
    endian::write_u64(buffer.data() + position + 8, static_cast<uint64_t>(pt_len));

    compute_mac(one_time_key, buffer.data(), buffer.size(), out_mac);

    zero_memory(one_time_key.data(), 32); // already cleared top half...
    zero_memory(reinterpret_cast<uint8_t*>(state.data()), 64);
}

// extract a 130-bit value as 5 26-bit limbs
static std::array<uint64_t, 5> extract_limbs(const uint8_t* buf)
{
    return {
        (endian::read_u32(buf +  0) >> 0) & 0x3FFFFFF,
        (endian::read_u32(buf +  3) >> 2) & 0x3FFFFFF,
        (endian::read_u32(buf +  6) >> 4) & 0x3FFFFFF,
        (endian::read_u32(buf +  9) >> 6) & 0x3FFFFFF,
        (endian::read_u32(buf + 12) >> 8)
    };
}

// compute a = (a * r) mod (2^130 - 5), where r5[i] = 5 * r[i]
static void multiply_mod_p(std::array<uint64_t, 5>& a, const std::array<uint64_t, 5>& r, const std::array<uint64_t, 5>& r5)
{
    uint64_t t[5] = {
        (a[0] * r[0]) + (a[1] * r5[4]) + (a[2] * r5[3]) + (a[3] * r5[2]) + (a[4] * r5[1]),
        (a[0] * r[1]) + (a[1] * r[0])  + (a[2] * r5[4]) + (a[3] * r5[3]) + (a[4] * r5[2]),
        (a[0] * r[2]) + (a[1] * r[1])  + (a[2] * r[0])  + (a[3] * r5[4]) + (a[4] * r5[3]),
        (a[0] * r[3]) + (a[1] * r[2])  + (a[2] * r[1])  + (a[3] * r[0])  + (a[4] * r5[4]),
        (a[0] * r[4]) + (a[1] * r[3])  + (a[2] * r[2])  + (a[3] * r[1])  + (a[4] * r[0])
    };

    // Propagate 26-bit carries across limbs
    for (std::size_t i = 0; i < 4; ++i)
    {
        a[i] = t[i] & 0x3FFFFFF;
        t[i + 1] += t[i] >> 26;
    }
    a[4] = t[4] & 0x3FFFFFF;

    // Fold top overflow back into limb 0 using 2^130 == 5 (mod 2^130 - 5)
    a[0] += (t[4] >> 26) * 5;
    a[1] += a[0] >> 26;
    a[0] &= 0x3FFFFFF;
}

// final reduction: if (a >= 2^130 - 5) a -= (2^130 - 5)
static void freeze_mod_p(std::array<uint64_t, 5>& a)
{
    std::array<uint64_t, 5> g;
    uint64_t carry = 5;
    for (std::size_t i = 0; i < 5; ++i)
    {
        uint64_t sum = a[i] + carry;
        g[i]  = sum & 0x3FFFFFF;
        carry = sum >> 26;
    }

    // carry is 1 if (a + 5 >= 2^130), else 0.
    // mask is 0x0000... if carry == 1 (select g), or 0xFFFF... if carry == 0 (select a).
    uint64_t mask = carry - 1;
    for (std::size_t i = 0; i < 5; ++i)
    {
        a[i] = (a[i] & mask) | (g[i] & ~mask);
    }
}

void compute_mac(const std::array<uint8_t, 64>& key, 
                 const uint8_t* message, std::size_t length, 
                 MAC& out_mac)
{
    std::array<uint64_t, 5> a {};
    std::array<uint64_t, 5> r  = extract_limbs(key.data());
    std::array<uint64_t, 5> r5 = { 0, r[1] * 5, r[2] * 5, r[3] * 5, r[4] * 5 };

    std::size_t n_chunks = length / 16;
    std::array<uint64_t, 5> chunk;
    for (std::size_t j = 0; j < n_chunks; ++j)
    {
        chunk = extract_limbs(&message[j * 16]);
        chunk[4] |= (1ULL << 24); // Append 1-bit at bit 128 per RFC 8439

        for (std::size_t i = 0; i < 5; ++i)
        {
            a[i] += chunk[i];
        }

        multiply_mod_p(a, r, r5);
    }

    freeze_mod_p(a);

    // repack 26-bit limbs into four 32-bit words (mod 2^128)
    uint32_t mac[4] = {
        static_cast<uint32_t>( a[0]        | (a[1] << 26)),
        static_cast<uint32_t>((a[1] >>  6) | (a[2] << 20)),
        static_cast<uint32_t>((a[2] >> 12) | (a[3] << 14)),
        static_cast<uint32_t>((a[3] >> 18) | (a[4] <<  8))
    };

    // add 128-bit one-time pad s (key[16..31]) modulo 2^128
    uint64_t carry = 0;
    for (std::size_t i = 0; i < 4; ++i)
    {
        uint64_t sum = static_cast<uint64_t>(mac[i]) + endian::read_u32(&key[16 + i * 4]) + carry;
        endian::write_u32(&out_mac[i * 4], static_cast<uint32_t>(sum));
        carry = sum >> 32;
    }

    zero_memory(reinterpret_cast<uint8_t*>(r.data()), sizeof(r));
    zero_memory(reinterpret_cast<uint8_t*>(r5.data()), sizeof(r5));
    zero_memory(reinterpret_cast<uint8_t*>(a.data()), sizeof(a));
    zero_memory(reinterpret_cast<uint8_t*>(chunk.data()), sizeof(chunk));
}

bool decrypt(
    const uint8_t* ciphertext, std::size_t ct_len,
    const uint8_t* aad, std::size_t aad_len,
    const Key& key, const Nonce& nonce,
    const MAC& expected_mac,
    uint8_t* plaintext)
{
    State state;
    std::array<uint8_t, 64> one_time_key;
    initialize_poly1305(key, nonce, state);
    block(state, one_time_key);

    zero_memory(&one_time_key[32], 32);

    one_time_key[3]  &= 0x0F;
    one_time_key[7]  &= 0x0F;
    one_time_key[11] &= 0x0F;
    one_time_key[15] &= 0x0F;
    one_time_key[4]  &= 0xFC;
    one_time_key[8]  &= 0xFC;
    one_time_key[12] &= 0xFC;

    std::size_t pad_size_aad = (16 - (aad_len % 16)) % 16;
    std::size_t pad_size_pld = (16 - (ct_len % 16)) % 16;

    std::size_t total_bytes = aad_len + ct_len + pad_size_aad + pad_size_pld + 16;

    std::vector<uint8_t> buffer(total_bytes);

    std::size_t position = 0;
    std::memcpy(buffer.data() + position, aad, aad_len);            position += aad_len;
    std::memset(buffer.data() + position, 0, pad_size_aad);         position += pad_size_aad;
    std::memcpy(buffer.data() + position, ciphertext, ct_len);      position += ct_len;
    std::memset(buffer.data() + position, 0, pad_size_pld);         position += pad_size_pld;
    endian::write_u64(buffer.data() + position, static_cast<uint64_t>(aad_len));
    endian::write_u64(buffer.data() + position + 8, static_cast<uint64_t>(ct_len));

    std::array<uint8_t, 16> calculated_mac;
    compute_mac(one_time_key, buffer.data(), buffer.size(), calculated_mac);

    zero_memory(one_time_key.data(), 64);
    zero_memory(reinterpret_cast<uint8_t*>(state.data()), 64);
    zero_memory(buffer.data(), buffer.size());

    if (!constant_time_mac_compare(calculated_mac, expected_mac))
    {
        return false;
    }

    std::memcpy(plaintext, ciphertext, ct_len);
    chacha20::encrypt(plaintext, ct_len, key, nonce);

    return true;
}

} // namespace poly1305
} // namespace chacha20
} // namespace crypto
