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

    writer& operator<<(const bit_t x);
    writer& operator<<(uint8_t x);
    writer& operator<<(uint16_t x);
    writer& operator<<(uint32_t x);
    writer& operator<<(uint64_t x);
    writer& append(uint64_t x, std::size_t n);

    void    reset();

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

private:
    const uint8_t*  mData;
    std::size_t     mLength;
    std::size_t     mPosition;
};

} // namespace bitstream
