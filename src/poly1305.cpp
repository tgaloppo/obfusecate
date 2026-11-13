#include <cstring>
#include <vector>
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
    const key& key, const nonce& nonce,
    uint8_t* ciphertext, mac& out_mac)
{
    state state;
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

void compute_mac(const std::array<uint8_t, 64>& key, 
                  const uint8_t* message, std::size_t length, 
                  mac& out_mac)
{
    std::array<uint64_t, 5> r;
    std::array<uint64_t, 5> a {};
    r[0] = ( static_cast<uint64_t>(key[0])         | 
            (static_cast<uint64_t>(key[1]) << 8)   | 
            (static_cast<uint64_t>(key[2]) << 16)  | 
            (static_cast<uint64_t>(key[3]) << 24))   & 0x3FFFFFF;
    r[1] = ((static_cast<uint64_t>(key[3]) >> 2)   | 
            (static_cast<uint64_t>(key[4]) << 6)   | 
            (static_cast<uint64_t>(key[5]) << 14)  | 
            (static_cast<uint64_t>(key[6]) << 22))   & 0x3FFFFFF;
    r[2] = ((static_cast<uint64_t>(key[6]) >> 4)   | 
            (static_cast<uint64_t>(key[7]) << 4)   | 
            (static_cast<uint64_t>(key[8]) << 12)  | 
            (static_cast<uint64_t>(key[9]) << 20))   & 0x3FFFFFF;
    r[3] = ((static_cast<uint64_t>(key[9]) >> 6)   | 
            (static_cast<uint64_t>(key[10]) << 2)  | 
            (static_cast<uint64_t>(key[11]) << 10) | 
            (static_cast<uint64_t>(key[12]) << 18))  & 0x3FFFFFF;
    r[4] = ( static_cast<uint64_t>(key[13])        | 
            (static_cast<uint64_t>(key[14]) << 8)  | 
            (static_cast<uint64_t>(key[15]) << 16))  & 0x3FFFFFF;

    std::array<uint64_t, 5> s {};
    s[1] = r[1] * 5;
    s[2] = r[2] * 5;
    s[3] = r[3] * 5;
    s[4] = r[4] * 5;            

    std::size_t n_chunks = length / 16; // guaranteed to be multiple of 16
    std::array<uint64_t, 5> chunk;
    for (std::size_t j = 0; j < n_chunks; j++)
    {
        chunk[0] = ( static_cast<uint64_t>(message[j*16+0])         | 
                    (static_cast<uint64_t>(message[j*16+1]) << 8)   | 
                    (static_cast<uint64_t>(message[j*16+2]) << 16)  | 
                    (static_cast<uint64_t>(message[j*16+3]) << 24))   & 0x3FFFFFF;
        chunk[1] = ((static_cast<uint64_t>(message[j*16+3]) >> 2)   | 
                    (static_cast<uint64_t>(message[j*16+4]) << 6)   | 
                    (static_cast<uint64_t>(message[j*16+5]) << 14)  | 
                    (static_cast<uint64_t>(message[j*16+6]) << 22))   & 0x3FFFFFF;
        chunk[2] = ((static_cast<uint64_t>(message[j*16+6]) >> 4)   | 
                    (static_cast<uint64_t>(message[j*16+7]) << 4)   | 
                    (static_cast<uint64_t>(message[j*16+8]) << 12)  | 
                    (static_cast<uint64_t>(message[j*16+9]) << 20))   & 0x3FFFFFF;
        chunk[3] = ((static_cast<uint64_t>(message[j*16+9]) >> 6)   | 
                    (static_cast<uint64_t>(message[j*16+10]) << 2)  | 
                    (static_cast<uint64_t>(message[j*16+11]) << 10) | 
                    (static_cast<uint64_t>(message[j*16+12]) << 18))  & 0x3FFFFFF;
        chunk[4] = ( static_cast<uint64_t>(message[j*16+13])        | 
                    (static_cast<uint64_t>(message[j*16+14]) << 8)  | 
                    (static_cast<uint64_t>(message[j*16+15]) << 16))  & 0x3FFFFFF;
        chunk[4] |= (1ULL << 24);
        
        a[0] += chunk[0];
        a[1] += chunk[1];
        a[2] += chunk[2];
        a[3] += chunk[3];
        a[4] += chunk[4];

        uint64_t t0 = (a[0] * r[0]) + (a[1] * s[4]) + (a[2] * s[3]) + (a[3] * s[2]) + (a[4] * s[1]);
        uint64_t t1 = (a[0] * r[1]) + (a[1] * r[0]) + (a[2] * s[4]) + (a[3] * s[3]) + (a[4] * s[2]);
        uint64_t t2 = (a[0] * r[2]) + (a[1] * r[1]) + (a[2] * r[0]) + (a[3] * s[4]) + (a[4] * s[3]);
        uint64_t t3 = (a[0] * r[3]) + (a[1] * r[2]) + (a[2] * r[1]) + (a[3] * r[0]) + (a[4] * s[4]);
        uint64_t t4 = (a[0] * r[4]) + (a[1] * r[3]) + (a[2] * r[2]) + (a[3] * r[1]) + (a[4] * r[0]);   

        a[0] = t0 & 0x3FFFFFF;
        t1 += t0 >> 26;
        a[1] = t1 & 0x3FFFFFF;
        t2 += t1 >> 26;
        a[2] = t2 & 0x3FFFFFF;
        t3 += t2 >> 26;
        a[3] = t3 & 0x3FFFFFF;
        t4 += t3 >> 26;
        a[4] = t4 & 0x3FFFFFF;
        
        a[0] += (t4 >> 26) * 5;
        a[1] += a[0] >> 26;
        a[0] &= 0x3FFFFFF;        
    }

// 1. Final Constant-Time Reduction
    uint64_t g0 = a[0] + 5;
    uint64_t g1 = a[1] + (g0 >> 26); g0 &= 0x3FFFFFF;
    uint64_t g2 = a[2] + (g1 >> 26); g1 &= 0x3FFFFFF;
    uint64_t g3 = a[3] + (g2 >> 26); g2 &= 0x3FFFFFF;
    uint64_t g4 = a[4] + (g3 >> 26); g3 &= 0x3FFFFFF;
    
    uint64_t mask = (g4 >> 26) - 1; 
    g4 &= 0x3FFFFFF;

    a[0] = (a[0] & mask) | (g0 & ~mask);
    a[1] = (a[1] & mask) | (g1 & ~mask);
    a[2] = (a[2] & mask) | (g2 & ~mask);
    a[3] = (a[3] & mask) | (g3 & ~mask);
    a[4] = (a[4] & mask) | (g4 & ~mask);

    // 2. Repack to 32-bit
    uint32_t mac0 = static_cast<uint32_t>((a[0] | (a[1] << 26)) & 0xFFFFFFFF);
    uint32_t mac1 = static_cast<uint32_t>(((a[1] >> 6) | (a[2] << 20)) & 0xFFFFFFFF);
    uint32_t mac2 = static_cast<uint32_t>(((a[2] >> 12) | (a[3] << 14)) & 0xFFFFFFFF);
    uint32_t mac3 = static_cast<uint32_t>(((a[3] >> 18) | (a[4] << 8)) & 0xFFFFFFFF);

    // 3. Add the 's' key (key[16..31])
    uint32_t s0 = static_cast<uint32_t>(key[16]) | (static_cast<uint32_t>(key[17]) << 8) | (static_cast<uint32_t>(key[18]) << 16) | (static_cast<uint32_t>(key[19]) << 24);
    uint32_t s1 = static_cast<uint32_t>(key[20]) | (static_cast<uint32_t>(key[21]) << 8) | (static_cast<uint32_t>(key[22]) << 16) | (static_cast<uint32_t>(key[23]) << 24);
    uint32_t s2 = static_cast<uint32_t>(key[24]) | (static_cast<uint32_t>(key[25]) << 8) | (static_cast<uint32_t>(key[26]) << 16) | (static_cast<uint32_t>(key[27]) << 24);
    uint32_t s3 = static_cast<uint32_t>(key[28]) | (static_cast<uint32_t>(key[29]) << 8) | (static_cast<uint32_t>(key[30]) << 16) | (static_cast<uint32_t>(key[31]) << 24);

    uint64_t f0 = static_cast<uint64_t>(mac0) + s0;
    mac0 = static_cast<uint32_t>(f0);
    uint64_t f1 = static_cast<uint64_t>(mac1) + s1 + (f0 >> 32);
    mac1 = static_cast<uint32_t>(f1);
    uint64_t f2 = static_cast<uint64_t>(mac2) + s2 + (f1 >> 32);
    mac2 = static_cast<uint32_t>(f2);
    uint64_t f3 = static_cast<uint64_t>(mac3) + s3 + (f2 >> 32);
    mac3 = static_cast<uint32_t>(f3);

    // 4. Serialize to out_mac
    endian::write_u32(&out_mac[0],  mac0);
    endian::write_u32(&out_mac[4],  mac1);
    endian::write_u32(&out_mac[8],  mac2);
    endian::write_u32(&out_mac[12], mac3);
}

bool decrypt(
    const uint8_t* ciphertext, std::size_t ct_len,
    const uint8_t* aad, std::size_t aad_len,
    const key& key, const nonce& nonce,
    const mac& expected_mac,
    uint8_t* plaintext)
{
    state state;
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
