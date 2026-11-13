#pragma once

#include <cstdint>
#include "symbol_frequency.hpp"

namespace compression
{

class arithmetic_coder
{
public:
    arithmetic_coder(bitstream::writer& output_stream, const symbol_frequency& frequency_table)
        : mLow(0), mHigh(0xFFFFFFFF), mUnderflow(0), mOutStream(output_stream), mFreqTable(frequency_table)
    {}

    void encode(uint8_t symbol);
    void encode(const uint8_t* data, std::size_t length);
    void flush();

private:
    static constexpr uint32_t HALF_MAX = 0x80000000;

    uint32_t    mLow;
    uint32_t    mHigh;
    std::size_t mUnderflow;

    bitstream::writer&      mOutStream;
    const symbol_frequency& mFreqTable;
};

} // namespace compression
