// ==============================================================================
// ObFUSEcate
// bitstream.hpp
// 
// Author: Travis J. Galoppo (tgaloppo@gmail.com)
// Description: Bit-packed data stream reader/writer
// 
// SPDX-License-Identifier: MIT
// ==============================================================================
#pragma once

#include <cstdint>
#include <vector>

namespace bitstream
{

struct bit_t
{
    uint8_t bit : 1;
};

static constexpr bit_t ZERO_BIT = bit_t{0};
static constexpr bit_t ONE_BIT  = bit_t{1};

// shifting by >= bit size results in undefined behavior, so
// we use a 2 step shift to allow n = 64...
inline uint64_t safe_shift(uint64_t x, size_t n) { return (x << n / 2) << (n - n / 2); }

class writer
{
public:
    writer() : writer(1024)
    {}

    writer(std::size_t initial_size_bits)
        : mBuffer((initial_size_bits + 7) / 8), mPosition(0)
    {}

    const uint8_t* data() const;

    std::size_t size_in_bits() const;
    std::size_t size_in_bytes() const;

    writer& operator<<(bit_t x);
    writer& operator<<(uint8_t x);
    writer& operator<<(uint16_t x);
    writer& operator<<(uint32_t x);
    writer& operator<<(uint64_t x);
    writer& append(uint64_t x, std::size_t n);

    void    reset();

    inline writer& write_bit(uint64_t bit)
    {
        if (mPosition >= mBuffer.size() * 8)
        {
            std::size_t new_size = std::max(std::size_t{64}, mBuffer.size() * 2);
            mBuffer.resize(new_size);
        }
        std::size_t offset = mPosition / 8;
        std::size_t shift  = mPosition % 8;
        mBuffer[offset] |= static_cast<uint8_t>((bit & 1) << shift);
        mPosition += 1;
        return *this;
    }

private:
    std::vector<uint8_t> mBuffer;
    std::size_t          mPosition;
};

class reader
{
public:
    reader(const uint8_t* data, std::size_t size_in_bits)
        : mData(data), mLength(size_in_bits), mPosition(0)
    {}

    // read from stream operations
    reader& operator>>(bit_t& x);
    reader& operator>>(uint8_t& x);
    reader& operator>>(uint16_t& x);
    reader& operator>>(uint32_t& x);
    reader& operator>>(uint64_t& x);
    reader& extract(uint64_t& x, std::size_t n);

    inline reader& read_bit(uint64_t& x)
    {
        x = 0;
        if (mPosition < mLength)
        {
            std::size_t offset = mPosition / 8;
            std::size_t shift  = mPosition % 8;
            x = (mData[offset] >> shift) & 1;
            mPosition += 1;
        }
        return *this;
    }

private:
    const uint8_t*  mData;
    std::size_t     mLength;
    std::size_t     mPosition;
};

} // namespace bitstream
