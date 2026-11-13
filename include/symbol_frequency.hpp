#pragma once

#include <array>
#include <cstdint>
#include "bitstream.hpp"

namespace compression
{

class symbol_frequency
{
public:
    symbol_frequency(const uint8_t* data, std::size_t length);
    symbol_frequency(bitstream::reader& freq_stream);

    uint8_t  get_symbol(uint32_t frequency) const;

    uint32_t get_lower(uint8_t symbol) const;
    uint32_t get_upper(uint8_t symbol) const;
    uint32_t get_total() const;

    bitstream::writer serialize();

private:
    std::array<uint32_t, 257> mCumulative;
};

} // namespace compression
