// ==============================================================================
// ObFUSEcate
// arithmetic_encoder.cpp
// 
// Author: Travis J. Galoppo (tgaloppo@gmail.com)
// 
// SPDX-License-Identifier: MIT
// ==============================================================================
#include "arithmetic_encoder.hpp"

namespace compression
{

void arithmetic_encoder::encode(uint8_t symbol)
{
    uint64_t range    = static_cast<uint64_t>(mHigh - mLow) + 1;
    uint64_t sym_low  = static_cast<uint64_t>(mFreqTable.get_lower(symbol));
    uint64_t sym_high = static_cast<uint64_t>(mFreqTable.get_upper(symbol));
    uint64_t scale    = static_cast<uint64_t>(mFreqTable.get_total());
    uint64_t new_low  = static_cast<uint64_t>(mLow) + sym_low * range / scale;
    uint64_t new_high = static_cast<uint64_t>(mLow) + sym_high * range / scale - 1;

    mLow  = static_cast<uint32_t>(new_low);
    mHigh = static_cast<uint32_t>(new_high);
    
    while( true )
    {
        if ( (mLow & HALF_MAX) == (mHigh & HALF_MAX) )
        {
            // what bit do we output
            uint64_t out_bits = static_cast<uint64_t>(mLow >> 31);

            // append bit to bit stream
            mOutStream.write_bit(out_bits);

            // append mUnderflow copies of opposite bit to stream
            out_bits = out_bits - 1; // 1 becomes all zeros; 0 rolls back to all 1's
            while (mUnderflow > 0)
            {
                std::size_t num_bits = std::min<std::size_t>(64, mUnderflow);
                mOutStream.append(out_bits, num_bits);
                mUnderflow -= num_bits;
            }

            // reset underflow
            mUnderflow = 0;

            // update bounds
            mLow = mLow << 1;
            mHigh = (mHigh << 1) | 1u;
        }
        else if (mLow >= 0x40000000 && mHigh < 0xC0000000)
        {
            mLow  = (mLow & 0x3FFFFFFF) << 1;
            mHigh = ((mHigh & 0x3FFFFFFF) << 1) | 0x80000001;
            mUnderflow += 1;
        }
        else
        {
            break;
        }
    }
}

void arithmetic_encoder::encode(const uint8_t* data, std::size_t length)
{
    for (std::size_t j = 0; j < length; j++)
    {
        encode(data[j]);
    }
}

void arithmetic_encoder::flush()
{
    mUnderflow += 1;
    uint64_t out_bits = mLow < 0x40000000 ? 0 : 1;
    mOutStream.write_bit(out_bits);
    out_bits = out_bits - 1; // 1 becomes all zeros; 0 rolls back to all 1's
    while (mUnderflow > 0)
    {
        std::size_t num_bits = std::min<std::size_t>(64, mUnderflow);
        mOutStream.append(out_bits, num_bits);
        mUnderflow -= num_bits;
    }
}

} // namespace compression
