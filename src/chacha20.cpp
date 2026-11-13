// ==============================================================================
// ObFUSEcate
// chacha20.cpp
// 
// Author: Travis J. Galoppo (tgaloppo@gmail.com)
// 
// SPDX-License-Identifier: MIT
// ==============================================================================
#include <algorithm>
#include <cstring>
#include <vector>
#include <cerrno>
#include <system_error>
#include <sys/random.h>
#include "crypto.hpp"
#include "chacha20.hpp"
#include "endian.hpp"

namespace crypto
{
namespace chacha20
{

// bit roll left
static uint32_t rotl(uint32_t x, std::size_t n)
{
    return (x << n) | (x >> (32 - n));
}

// n is number of uint32_t values
static void pack_uint32_little_endian(uint32_t* dst, const uint8_t* src, std::size_t n)
{
    for (std::size_t j = 0; j < n; j++)
    {
        dst[j] = endian::read_u32(&src[j*4]);
    }
}

static void unpack_int32_little_endian(uint8_t* dst, const uint32_t* src, std::size_t n)
{
    for (std::size_t j = 0; j < n; j++)
    {
        endian::write_u32(&dst[j*4], src[j]);
    }
}

void initialize(const Key& key, const Nonce& nonce, State& state)
{
    // 0 - 3 are magic: "expand 32-byte k"
    state[0] = static_cast<uint32_t>('e')          | (static_cast<uint32_t>('x') << 8)  |
                (static_cast<uint32_t>('p') << 16) | (static_cast<uint32_t>('a') << 24);
    state[1] = static_cast<uint32_t>('n')          | (static_cast<uint32_t>('d') << 8)  |
                (static_cast<uint32_t>(' ') << 16) | (static_cast<uint32_t>('3') << 24);
    state[2] = static_cast<uint32_t>('2')          | (static_cast<uint32_t>('-') << 8)  |
                (static_cast<uint32_t>('b') << 16) | (static_cast<uint32_t>('y') << 24);
    state[3] = static_cast<uint32_t>('t')          | (static_cast<uint32_t>('e') << 8)  |
                (static_cast<uint32_t>(' ') << 16) | (static_cast<uint32_t>('k') << 24);               

    // 4 - 11 are key
    pack_uint32_little_endian(&state[4], &key[0], 8);

    // 12 is counter, which starts at 1 except for when creating
    // one-time auth key for poly1305
    state[12] = 1;

    // 13 - 15 are nonce
    pack_uint32_little_endian(&state[13], &nonce[0], 3);
}

// intended for use generating one-time auth key for poly1305
void initialize_poly1305(const Key& key, const Nonce& nonce, State& state)
{
    initialize(key, nonce, state);
    state[12] = 0;
}

Nonce create_nonce()
{
    Nonce nonce;
    ssize_t retval;
    do
    {
        retval = getrandom(nonce.data(), nonce.size(), 0);
        if (retval < 0 && errno != EINTR)
        {
            throw std::system_error(errno, std::generic_category(), "getrandom() failed");
        }
    } while(retval < static_cast<ssize_t>(nonce.size()) && errno == EINTR);
    return nonce;
}

void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d)
{
    a = a + b;
    d = d ^ a;
    d = rotl(d, 16);

    c = c + d;
    b = b ^ c;
    b = rotl(b, 12);

    a = a + b;
    d = d ^ a;
    d = rotl(d, 8);

    c = c + d;
    b = b ^ c;
    b = rotl(b, 7);
}

void block(State& state, std::array<uint8_t, 64>& out_stream)
{
    State work(state);

    for (std::size_t j = 0; j < 10; j++)
    {
        quarter_round(work[0], work[4], work[8], work[12]);
        quarter_round(work[1], work[5], work[9], work[13]);
        quarter_round(work[2], work[6], work[10], work[14]);
        quarter_round(work[3], work[7], work[11], work[15]);

        quarter_round(work[0], work[5], work[10], work[15]);
        quarter_round(work[1], work[6], work[11], work[12]);
        quarter_round(work[2], work[7], work[8], work[13]);
        quarter_round(work[3], work[4], work[9], work[14]);
    }

    for (std::size_t j = 0; j < 16; j++)
    {
        work[j] += state[j];
    }

    // update for next round
    state[12] += 1;

    unpack_int32_little_endian(&out_stream[0], &work[0], 16);
}

void encrypt(uint8_t* data, std::size_t length, const Key& key, const Nonce& nonce)
{
    State state_;
    std::array<uint8_t, 64> cipher_stream;

    initialize(key, nonce, state_);

    std::size_t n_blocks = (length + 63) / 64;
    for (std::size_t j = 0; j < n_blocks; j++)
    {
        block(state_, cipher_stream);

        std::size_t chunk_size = std::min<std::size_t>(64, length - j * 64);
        for (std::size_t k = 0; k < chunk_size; k++)
        {
            data[j * 64 + k] ^= cipher_stream[k];
        }
    }

    // wipe memory!
    zero_memory(cipher_stream.data(), 64);
    zero_memory(reinterpret_cast<uint8_t*>(state_.data()), 64);
}

} // namespace chacha20
} // namespace crypto
