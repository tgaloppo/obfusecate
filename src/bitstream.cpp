// ==============================================================================
// ObFUSEcate
// bitstream.cpp
// 
// Author: Travis J. Galoppo (tgaloppo@gmail.com)
// 
// SPDX-License-Identifier: MIT
// ==============================================================================
#include <algorithm>
#include "bitstream.hpp"

namespace bitstream
{

static constexpr uint64_t mask_full = ~static_cast<uint64_t>(0);

const uint8_t* writer::data() const
{
    return mBuffer.data();
}

std::size_t writer::size_in_bits() const
{
    return mPosition;
}

std::size_t writer::size_in_bytes() const
{
    return (mPosition + 7) / 8;
}

void writer::reset()
{
    std::fill(mBuffer.begin(), mBuffer.end(), 0);
    mPosition = 0;
}

writer& writer::append(uint64_t x, std::size_t n)
{
    if ((mPosition + n + 7) / 8 > mBuffer.size())
    {
        std::size_t new_size = std::max(std::size_t{64}, mBuffer.size() * 2);
        mBuffer.resize(new_size);
    }

    // zero out superfluous bits of x
    x &= ~(safe_shift(mask_full, n));
    
    // calculate initial offset and bit shift
    std::size_t offset = mPosition / 8;
    std::size_t shift  = mPosition % 8;

    // append bits fitting in current offset
    uint8_t* buf = &mBuffer[offset];
    *(buf++) |= static_cast<uint8_t>( (x << shift) & 0xFFu );

    // append remaining bits
    x = x >> (8 - shift);
    while (x > 0)
    {
        *(buf++) = static_cast<uint8_t>( x & 0xFFu );
        x = x >> 8;
    }

    mPosition += n;

    return *this;
}

writer& writer::operator<<(const bit_t x)
{
    return append(static_cast<uint64_t>(x.bit), 1);
}

writer& writer::operator<<(uint8_t x)
{
    return append(static_cast<uint64_t>(x), 8);
}

writer& writer::operator<<(uint16_t x)
{
    return append(static_cast<uint64_t>(x), 16);
}

writer& writer::operator<<(uint32_t x)
{
    return append(static_cast<uint64_t>(x), 32);
}

writer& writer::operator<<(uint64_t x)
{
    return append(x, 64);
}

reader& reader::extract(uint64_t& x, std::size_t n)
{
    x = 0;

    if (mPosition + n <= mLength)
    {
        // calculate current offset and shift
        std::size_t offset = mPosition / 8;
        std::size_t shift  = mPosition % 8;

        // mask the number of bits we want
        uint64_t mask = ~(safe_shift(mask_full, n));

        // extract initial bits (may be partial)
        const uint8_t* buf = &mData[offset];
        x = static_cast<uint64_t>( (*(buf++) >> shift) & (mask & 0xFF) );

        // extract remaining bits
        shift = 8 - shift; // shift now has # of bits already extracted
        mask >>= shift;    // account for bits already extracted
        while (mask > 0)
        {
            x |= static_cast<uint64_t>(*(buf++) & (mask & 0xFFu)) << shift;
            mask >>= 8;
            shift += 8;
        }

        mPosition += n;
    }

    return *this;
}


reader& reader::operator>>(bit_t& x)
{
    uint64_t u;
    extract(u, 1);
    x.bit = static_cast<uint8_t>(u & 1u);
    return *this;
}

reader& reader::operator>>(uint8_t& x)
{
    uint64_t u;
    extract(u, 8);
    x = static_cast<uint8_t>(u & 0xFFu);
    return *this;
}

reader& reader::operator>>(uint16_t& x)
{
    uint64_t u;
    extract(u, 16);
    x = static_cast<uint16_t>(u & 0xFFFFu);
    return *this;
}

reader& reader::operator>>(uint32_t& x)
{
    uint64_t u;
    extract(u, 32);
    x = static_cast<uint32_t>(u & 0xFFFFFFFFu);
    return *this;
}

reader& reader::operator>>(uint64_t& x)
{
    return extract(x, 64);
}

} // namespace bitstream