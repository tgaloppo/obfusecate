#include <algorithm>
#include <cmath>
#include "symbol_frequency.hpp"

namespace compression
{

symbol_frequency::symbol_frequency(bitstream::reader& freq_stream)
{
    uint32_t sum = 0;
    uint64_t count;
    bitstream::bit_t in_bit;
    for (std::size_t j = 0; j < 256; j++)
    {
        // lower is current sum
        mCumulative[j] = sum;

        // read "present" bit
        freq_stream >> in_bit;
        if (in_bit.bit) // value is present in data
        {
            freq_stream >> in_bit; // 16 or 32 bit value
            freq_stream.extract(count, static_cast<std::size_t>(16 + in_bit.bit * 16));
            sum += static_cast<uint32_t>(count);
        }
    }
    mCumulative[256] = sum;
}

symbol_frequency::symbol_frequency(const uint8_t* data, std::size_t length)
{
    // count instances of each symbol
    std::array<uint32_t, 256> counts {};
    for (std::size_t j = 0; j < length; j++)
    {
        counts[data[j]] += 1;
    }

    // compute cumulative frequency table
    uint32_t sum = 0;
    for (std::size_t j = 0; j < 256; j++)
    {
        mCumulative[j] = sum;
        sum += counts[j];
    }
    mCumulative[256] = sum;
}

uint32_t symbol_frequency::get_lower(uint8_t symbol) const
{
    return mCumulative[symbol];
}

uint32_t symbol_frequency::get_upper(uint8_t symbol) const
{
    return mCumulative[symbol + 1];
}

uint32_t symbol_frequency::get_total() const
{
    return mCumulative[256];
}

uint8_t symbol_frequency::get_symbol(uint32_t frequency) const
{
    auto it = std::upper_bound(mCumulative.begin(), mCumulative.end(), frequency);
    return static_cast<uint8_t>(std::distance(mCumulative.begin(), it) - 1);
}

bitstream::writer symbol_frequency::serialize()
{
    bitstream::writer out_stream;
    for (std::size_t j = 0; j < 256; j++)
    {
        uint32_t count = get_upper(static_cast<uint8_t>(j)) - get_lower(static_cast<uint8_t>(j));
        if (count > 0)
        {
            out_stream << bitstream::ONE_BIT;
            if (count > 0xFFFF)
            {
                out_stream << bitstream::ONE_BIT; // flag 32 bit value
                out_stream << count;
            }
            else
            {
                out_stream << bitstream::ZERO_BIT; // flag 16 bit value
                out_stream << static_cast<uint16_t>(count);
            }
        }
        else
        {
            out_stream << bitstream::ZERO_BIT;
        }
    }
    return out_stream;
}

} // namespace compression
