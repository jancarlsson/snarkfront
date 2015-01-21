#ifndef _SNARKFRONT_POWERS_OF_2_HPP_
#define _SNARKFRONT_POWERS_OF_2_HPP_

#include <algorithm>
#include <cassert>
#include <climits>
#include <cstdint>
#include <gmp.h>
#include <vector>
#include <BigInt.hpp> // snarklib

namespace snarkfront {

// look up table for powers of 2 for BigInt/field/group
template <typename T>
class PowersOf2
{
public:
    PowersOf2()
        : m_lut(1, T::one())
    {}

    const T& lookUp(const std::size_t index) 
    {
        // protect against huge index from accidental pointer argument
#ifdef USE_ASSERT
        assert(index < 1024);
#endif

        for (std::size_t i = m_lut.size(); i <= index; ++i) {
            // m_lut[i] = 2 * m_lut[i - 1];
            m_lut.emplace_back(m_lut.back() + m_lut.back());
        }

        return m_lut[index];
    }

    T getNumber(const std::size_t number) {
        T accum = T::zero();

        auto b = number;
        std::size_t i = 0;
        while (b) {
            if (b & 0x1)
                accum = accum + lookUp(i);

            b >>= 1;
            ++i;
        }

        return accum;
    }

    T getNumber(const std::vector<int>& bits) {
        T accum = T::zero();

        for (std::size_t i = 0; i < bits.size(); ++i) {
            if (bits[i])
                accum = accum + lookUp(i);
        }

        return accum;
    }

private:
    std::vector<T> m_lut; // index -> T(2^index)
};

// convert Boolean to BigInt/field/group one and zero
template <typename T>
T boolTo(const bool a) {
    return a ? T::one() : T::zero();
}

// size of type in bits
std::size_t sizeBits(const bool& dummy);
std::size_t sizeBits(const std::uint32_t& dummy);
std::size_t sizeBits(const std::uint64_t& dummy);

template <mp_size_t N>
std::size_t sizeBits(const snarklib::BigInt<N>& dummy) {
    return snarklib::BigInt<N>::maxBits();
}

// returns number of matching bits starting from most significant bit
template <typename BIT>
int matchMSB(const std::vector<BIT>& a,
             const std::vector<BIT>& b)
{
    if (a.size() != b.size())
        return -1; // a and b are different sizes, no matching bits

    for (int i = a.size() - 1; i >= 0; --i) {
        if (bool(a[i] != b[i]))
            return a.size() - 1 - i; // some bits match
    }

    return a.size(); // all bits match
}

// convert value to bits
std::vector<int> valueBits(const bool& a);
std::vector<int> valueBits(const std::uint32_t& a);
std::vector<int> valueBits(const std::uint64_t& a);

template <mp_size_t N>
std::vector<int> valueBits(const snarklib::BigInt<N>& a) {
    std::vector<int> v;
    v.reserve(sizeBits(a));

    for (std::size_t i = 0; i < sizeBits(a); ++i) {
        v.push_back(a.testBit(i));
    }

    return v;
}

// convert bits to value
template <typename UINT_N>
std::vector<int> bitsValue(UINT_N& a, const std::vector<int>& b)
{
    UINT_N result = 0;
    const std::size_t N = std::min(sizeBits(a), b.size());
    for (std::size_t i = 0; i < N; ++i) {
        result |= (UINT_N(b[i]) << i);
    }

    a = result;

    std::vector<int> v;
    for (std::size_t i = N; i < b.size(); ++i) {
        v.push_back(b[i]);
    }

    return v;
}

// count number of set bits
std::size_t countBits(const std::vector<int>& v);

// overflow addition (uint32_t and uint64_t)
template <typename UINT_N>
void addover(UINT_N& a1, UINT_N& a0, const UINT_N& b) 
{
    // a0 = 2 * a0_half + a0_bit
    // b = 2 * b_half + b_bit
    const UINT_N
        a0_half = a0 >> 1, a0_bit = a0 & 0x1,
        b_half = b >> 1, b_bit = b & 0x1;

    // a0 + b = 2 * (a0_half + b_half) + (a0_bit + b_bit)
    //        = 2 * halfsum + a0_bit + b_bit
    const UINT_N halfsum = a0_half + b_half;

    // (high, low) = a0 + b
    UINT_N
        high = halfsum >> (sizeBits(high) - 1), // carry bit
        low = (halfsum << 1) + a0_bit;

    const UINT_N lowOriginal = low;
    low += b_bit;
    if ((0 == low) && (-1 == lowOriginal)) ++high; // handle carry

    // accumulate result
    a1 += high;
    a0 = low;
}

} // namespace snarkfront

#endif
