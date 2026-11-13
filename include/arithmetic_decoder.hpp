// ==============================================================================
// ObFUSEcate
// arithmetic_decoder.hpp
// 
// Author: Travis J. Galoppo (tgaloppo@gmail.com)
// Description: Arithmetic decoder using 32 bit distribution boundaries
// 
// SPDX-License-Identifier: MIT
// ==============================================================================
#pragma once

#include <cstdint>
#include "symbol_frequency.hpp"

namespace compression
{

class arithmetic_decoder
{
public:
    arithmetic_decoder(bitstream::reader& input_stream, const symbol_frequency& frequency_table);

    uint8_t next_symbol();
    void    decode(uint8_t* out_ptr, std::size_t length);

private:
    static constexpr uint32_t HALF_MAX = 0x80000000;

    uint32_t    mLow;
    uint32_t    mHigh;
    uint32_t    mValue;

    bitstream::reader&      mInStream;
    const symbol_frequency& mFreqTable;
};

} // namespace compression
