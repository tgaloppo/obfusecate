// ==============================================================================
// ObFUSEcate
// arithmetic_decoder.cpp
// 
// Author: Travis J. Galoppo (tgaloppo@gmail.com)
// 
// SPDX-License-Identifier: MIT
// ==============================================================================
#include "arithmetic_decoder.hpp"

namespace compression
{

arithmetic_decoder::arithmetic_decoder(bitstream::reader& input_stream, const symbol_frequency& frequency_table)
    : mLow(0), mHigh(0xFFFFFFFF), mValue(0), mInStream(input_stream), mFreqTable(frequency_table)
{
    // read first 32 bits (assumes stream is at least 32 bits!)
    uint64_t in_bits;
    for (std::size_t j = 0; j < 32; j++)
    {
        mInStream.read_bit(in_bits);
        mValue = (mValue << 1) | static_cast<uint32_t>(in_bits);
    }        
}

void arithmetic_decoder::decode(uint8_t* out_ptr, std::size_t length)
{
    for (std::size_t j = 0; j < length; j++)
    {
        out_ptr[j] = next_symbol();
    }
}

uint8_t arithmetic_decoder::next_symbol()
{
    uint64_t range    = static_cast<uint64_t>(mHigh - mLow) + 1;
    uint64_t scale    = static_cast<uint64_t>(mFreqTable.get_total());
    uint64_t freq     = ((static_cast<uint64_t>(mValue - mLow) + 1) * scale - 1) / range;
    uint8_t  symbol   = mFreqTable.get_symbol(static_cast<uint32_t>(freq));
    uint64_t sym_low  = static_cast<uint64_t>(mFreqTable.get_lower(symbol));
    uint64_t sym_high = static_cast<uint64_t>(mFreqTable.get_upper(symbol));        
    uint64_t new_low  = static_cast<uint64_t>(mLow) + sym_low * range / scale;
    uint64_t new_high = static_cast<uint64_t>(mLow) + sym_high * range / scale - 1;

    mLow  = static_cast<uint32_t>(new_low);
    mHigh = static_cast<uint32_t>(new_high);

    while( true )
    {
        if ( (mLow & HALF_MAX) == (mHigh & HALF_MAX) )
        {
            mLow = mLow << 1;
            mHigh = (mHigh << 1) | 1u;
            mValue = mValue << 1;

            uint64_t in_bits = 0;
            mInStream.read_bit(in_bits);
            mValue |= static_cast<uint32_t>(in_bits);
        }
        else if (mLow >= 0x40000000 && mHigh < 0xC0000000)
        {
            mLow  = (mLow & 0x3FFFFFFF) << 1;
            mHigh = ((mHigh & 0x3FFFFFFF) << 1) | 0x80000001;
            mValue = (mValue - 0x40000000) << 1;

            uint64_t in_bits = 0;
            mInStream.read_bit(in_bits);
            mValue |= static_cast<uint32_t>(in_bits);
        }
        else
        {
            break;
        }
    }

    return symbol;
}

} // namespace compression
