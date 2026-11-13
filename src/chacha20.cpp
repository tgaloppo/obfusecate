#include <algorithm>
#include <cstring>
#include <vector>
#include <random>
#include <unistd.h>
#include <sys/mman.h>
#include "chacha20.hpp"
#include "endian.hpp"

namespace crypto
{

void zero_memory(uint8_t* data, std::size_t length)
{
    volatile uint8_t* ptr = data;
    for (std::size_t j = 0; j < length; j++)
    {
        *(ptr++) = 0;
    }
}

void armor_memory(void* ptr, size_t size)
{
    // Cast to unsigned immediately to ensure safe bitwise arithmetic
    uintptr_t page_size = static_cast<uintptr_t>(::sysconf(_SC_PAGESIZE));
    uintptr_t addr = reinterpret_cast<uintptr_t>(ptr);
    
    uintptr_t aligned_addr = addr & ~(page_size - 1);
    size_t aligned_size = (addr - aligned_addr) + size;
    void* lock_ptr = reinterpret_cast<void*>(aligned_addr);

    ::mlock(lock_ptr, aligned_size);
    ::madvise(lock_ptr, aligned_size, MADV_DONTDUMP);
}

void dearmor_memory(void* ptr, size_t size)
{
    uintptr_t page_size = static_cast<uintptr_t>(::sysconf(_SC_PAGESIZE));
    uintptr_t addr = reinterpret_cast<uintptr_t>(ptr);
    
    uintptr_t aligned_addr = addr & ~(page_size - 1);
    size_t aligned_size = (addr - aligned_addr) + size;
    void* lock_ptr = reinterpret_cast<void*>(aligned_addr);

    // Explicitly cast void* to uint8_t* for zero_memory
    crypto::zero_memory(static_cast<uint8_t*>(ptr), size); 
    ::madvise(lock_ptr, aligned_size, MADV_DODUMP);
    ::munlock(lock_ptr, aligned_size);
}

namespace chacha20
{

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

void initialize(const key& p_key, const nonce& p_nonce, state& p_state)
{
    // 0 - 3 are magic: "expand 32-byte k"
    p_state[0] = static_cast<uint32_t>('e')        | (static_cast<uint32_t>('x') << 8)  |
                (static_cast<uint32_t>('p') << 16) | (static_cast<uint32_t>('a') << 24);
    p_state[1] = static_cast<uint32_t>('n')        | (static_cast<uint32_t>('d') << 8)  |
                (static_cast<uint32_t>(' ') << 16) | (static_cast<uint32_t>('3') << 24);
    p_state[2] = static_cast<uint32_t>('2')        | (static_cast<uint32_t>('-') << 8)  |
                (static_cast<uint32_t>('b') << 16) | (static_cast<uint32_t>('y') << 24);
    p_state[3] = static_cast<uint32_t>('t')        | (static_cast<uint32_t>('e') << 8)  |
                (static_cast<uint32_t>(' ') << 16) | (static_cast<uint32_t>('k') << 24);               

    // 4 - 11 are key
    pack_uint32_little_endian(&p_state[4], &p_key[0], 8);

    // 12 is counter, which starts at 1 except for when creating
    // one-time auth key for poly1305
    p_state[12] = 1;

    // 13 - 15 are nonce
    pack_uint32_little_endian(&p_state[13], &p_nonce[0], 3);
}

// intended for use generating one-time auth key for poly1305
void initialize_poly1305(const key& p_key, const nonce& p_nonce, state& p_state)
{
    initialize(p_key, p_nonce, p_state);
    p_state[12] = 0;
}

nonce create_nonce()
{
    nonce nonce_;
    std::random_device rd; 
    
    // std::random_device generates 32-bit unsigned integers. 
    for (std::size_t i = 0; i < 3; ++i)
    {
        uint32_t val = rd();
        nonce_[i * 4 + 0] = static_cast<uint8_t>(val & 0xFF);
        nonce_[i * 4 + 1] = static_cast<uint8_t>((val >> 8) & 0xFF);
        nonce_[i * 4 + 2] = static_cast<uint8_t>((val >> 16) & 0xFF);
        nonce_[i * 4 + 3] = static_cast<uint8_t>((val >> 24) & 0xFF);
    }

    return nonce_;
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

void block(state& p_state, std::array<uint8_t, 64>& out_stream)
{
    state work(p_state);

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
        work[j] += p_state[j];
    }

    // update for next round
    p_state[12] += 1;

    unpack_int32_little_endian(&out_stream[0], &work[0], 16);
}

void encrypt(uint8_t* data, std::size_t length, const key& p_key, const nonce& p_nonce)
{
    state state_;
    std::array<uint8_t, 64> cipher_stream;

    initialize(p_key, p_nonce, state_);

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
