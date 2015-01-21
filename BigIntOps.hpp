#ifndef _SNARKFRONT_BIG_INT_OPS_HPP_
#define _SNARKFRONT_BIG_INT_OPS_HPP_

#include <array>
#include <cassert>
#include <climits>
#include <cstdint>
#include <gmp.h>
#include <BigInt.hpp> // snarklib

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// BigInt arithmetic operations independent of a prime field
//

//
// a + b --> c
//
template <mp_size_t N>
bool addBigInt(const snarklib::BigInt<N>& a,
               const snarklib::BigInt<N>& b,
               snarklib::BigInt<N>& c)
{
    const mp_limb_t carry = mpn_add_n(c.data(), a.data(), b.data(), N);
    return ! carry; // failure if overflow
}

template <mp_size_t N>
snarklib::BigInt<N> operator+ (const snarklib::BigInt<N>& a,
                               const snarklib::BigInt<N>& b)
{
    snarklib::BigInt<N> c;
#ifdef USE_ASSERT
    assert(addBigInt(a, b, c));
#endif
    return c;
}

//
// a - b --> c
//
template <mp_size_t N>
bool subBigInt(const snarklib::BigInt<N>& a,
               const snarklib::BigInt<N>& b,
               snarklib::BigInt<N>& c)
{
    if (mpn_cmp(a.data(), b.data(), N) < 0) return false; // failure
                                                          // if b > a
    const mp_limb_t borrow = mpn_sub(c.data(), a.data(), N, b.data(), N);
#ifdef USE_ASSERT
    assert(0 == borrow);
#endif
    return true;
}

template <mp_size_t N>
snarklib::BigInt<N> operator- (const snarklib::BigInt<N>& a,
                               const snarklib::BigInt<N>& b)
{
    snarklib::BigInt<N> c;
#ifdef USE_ASSERT
    assert(subBigInt(a, b, c));
#endif
    return c;
}

//
// a * b --> c
//
template <mp_size_t N>
bool mulBigInt(const snarklib::BigInt<N>& a,
               const snarklib::BigInt<N>& b,
               snarklib::BigInt<N>& c)
{
    std::array<mp_limb_t, 2*N> scratch;
    mpn_mul_n(scratch.data(), a.data(), b.data(), N);

    for (std::size_t i = N; i < 2*N; ++i) {
        if (scratch[i]) return false; // failure if overflow
    }

    mpn_copyi(c.data(), scratch.data(), N);
    return true;
}

template <mp_size_t N>
snarklib::BigInt<N> operator* (const snarklib::BigInt<N>& a,
                               const snarklib::BigInt<N>& b)
{
    snarklib::BigInt<N> c;
#ifdef USE_ASSERT
    assert(mulBigInt(a, b, c));
#endif
    return c;
}

//
// Russian peasant algorithm
//
template <mp_size_t N>
snarklib::BigInt<N> powerBigInt(const std::size_t exponent)
{
    // set lower bits
    auto mask = exponent;
    for (std::size_t i = 1; i <= (sizeof(std::size_t) * CHAR_BIT) / 2; i *= 2) {
        mask |= (mask >> i);
    }

    mask &= ~(mask >> 1); // most significant bit

    const snarklib::BigInt<N> ONE(1);

    auto accum = snarklib::BigInt<N>::zero();

    while (mask) {
        accum = accum + accum;

        if (exponent & mask) {
            accum = accum + ONE;
        }

        mask >>= 1;
    }

    return accum;
}

} // namespace snarkfront

#endif
