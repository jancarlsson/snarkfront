#ifndef _SNARKFRONT_DSL_BLESS_HPP_
#define _SNARKFRONT_DSL_BLESS_HPP_

#include <array>
#include <cassert>
#include <cstdint>
#include <sstream>
#include <vector>

#include <cryptl/Bless.hpp>

#include <snarkfront/DSL_base.hpp>
#include <snarkfront/DSL_ppzk.hpp>
#include <snarkfront/DSL_utility.hpp>
#include <snarkfront/PowersOf2.hpp>
#include <snarkfront/R1C.hpp>
#include <snarkfront/TLsingleton.hpp>

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// blessing (initialize variables)
//

// variable with value
#define DEFN_BLESS(X, A)                        \
    template <typename FR>                      \
    void bless(X<FR>& x, const A& a) {          \
        x.bless(a);                             \
    }

    DEFN_BLESS(bool_x, bool)
    DEFN_BLESS(uint8_x, std::uint8_t)
    DEFN_BLESS(uint32_x, std::uint32_t)
    DEFN_BLESS(uint64_x, std::uint64_t)
    DEFN_BLESS(bigint_x, std::string)
    DEFN_BLESS(field_x, FR)

#undef DEFN_BLESS

template <typename FR>
void bless(bigint_x<FR>& x,
           const std::uint64_t a,
           const bool assert64bits = true) {
    std::stringstream ss;
    ss << a;
    x.bless(ss.str());

    if (assert64bits) {
        // prevent cheating - high 64-bits must be zero
        std::array<uint64_x<FR>, 2> value64;
        bless(value64, x);
        assert_true(value64[1] == zero(value64[1]));
    }
}

// initialize variable
#define DEFN_BLESS(X, A)                        \
    template <typename FR>                      \
    void bless(X<FR>& x) {                      \
        bless(x, A);                            \
    }

    DEFN_BLESS(bool_x, false)
    DEFN_BLESS(uint8_x, 0)
    DEFN_BLESS(uint32_x, 0)
    DEFN_BLESS(uint64_x, 0)
    DEFN_BLESS(bigint_x, "0")
    DEFN_BLESS(field_x, FR::zero())

#undef DEFN_BLESS

// array of variables with array of values
template <typename T, typename U, std::size_t N>
void bless(std::array<T, N>& a, const std::array<U, N>& b) {
    for (std::size_t i = 0; i < N; ++i)
        bless(a[i], b[i]);
}

// vector of variables with vector of values
template <typename T, typename U>
void bless(std::vector<T>& a, const std::vector<U>& b) {
#ifdef USE_ASSERT
    assert(a.size() == b.size());
#endif
    for (std::size_t i = 0; i < a.size(); ++i)
        bless(a[i], b[i]);
}

// initialize array of variables
template <typename T, std::size_t N>
void bless(std::array<T, N>& a) {
    for (auto& x : a) bless(x);
}

// initialize vector of variables
template <typename T>
void bless(std::vector<T>& a) {
    for (auto& x : a) bless(x);
}

// conversion of:
// - 8-bit octet to 8 bits (Boolean)
// - 32-bit word to 32 bits
// - 32-bit word to four 8-bit octets
// - 64-bit word to 64 bits (Boolean)
// - 64-bit word to eight 8-bit octets
// - 64-bit word to two 32-bit words
// - 128-bit big integer to 128 bits (Boolean)
// - 128-bit big integer to 16 8-bit octets
// - 128-bit big integer to four 32-bit words
// - 128-bit big integer to two 64-bit words
// - 181-bit Edwards scalar field to 181 bits (Boolean)
// - 254-bit Barreto-Naehrig scalar field to 254 bits (Boolean)
template <typename T, std::size_t N, typename U>
void bless_internal(std::array<T, N>& x, const U& a, const bool bigEndian) {
    const std::size_t
        sizeT = sizeBits(x[0]),
        sizeU = sizeBits(a);

#ifdef USE_ASSERT
    assert(sizeT * N == sizeU);
#endif

    typedef typename T::FrType FR;

    const auto term_bits = TL<R1C<FR>>::singleton()->argBits(*a);
    const auto split_bits = a->splitBits();

    for (std::size_t i = 0; i < N; ++i) {
        const std::vector<typename T::R1T> term_vec(
            term_bits.begin() + sizeT * i,
            term_bits.begin() + sizeT * (i + 1));

        const std::vector<int> split_vec(
            split_bits.begin() + sizeT * i,
            split_bits.begin() + sizeT * (i + 1));

        typename T::ValueType value;
        bitsValue(value, split_vec);

        x[bigEndian ? N - 1 - i : i]
            .bless(value,
                   TL<PowersOf2<FR>>::singleton()->getNumber(split_vec),
                   split_vec,
                   term_vec);
    }
}

// conversion
#define DEFN_BLESS(X)                                   \
    template <typename T, std::size_t N, typename FR>   \
    void bless(std::array<T, N>& x,                     \
               const X<FR>& a,                          \
               const bool bigEndian = false) {          \
        bless_internal(x, a, bigEndian);                \
    }

    DEFN_BLESS(uint8_x)
    DEFN_BLESS(uint32_x)
    DEFN_BLESS(uint64_x)
    DEFN_BLESS(bigint_x)
    DEFN_BLESS(field_x)

#undef DEFN_BLESS

template <typename T, std::size_t N, typename U, std::size_t M>
void bless(std::array<T, N>& x,
           const std::array<U, M>& a,
           const bool bigEndian = true) { // SHA message buffer is big-endian
#ifdef USE_ASSERT
    assert(0 == N % M);
#endif

    for (std::size_t i = 0; i < M; ++i) {
        std::array<T, N / M> xtmp;

        for (std::size_t j = 0; j < N / M; ++j)
            xtmp[j] = x[i * (N / M) + j];

        bless(xtmp, a[i], bigEndian);

        for (std::size_t j = 0; j < N / M; ++j)
            x[i * (N / M) + j] = xtmp[j];
    }
}

// variable from proof inputs
template <typename T, typename FR>
void bless(T& x, const R1Cowitness<FR>& input) {
    x.bless(input);
}

// array of variables from proof input
template <typename T, std::size_t N, typename FR>
void bless(std::array<T, N>& a, const R1Cowitness<FR>& input) {
    for (auto& x : a) bless(x, input);
}

// 8-bit octet variable from input stream
template <typename FR>
bool bless(snarkfront::uint8_x<FR>& x, std::istream& is) {
    std::uint8_t a;
    if (cryptl::bless(a, is)) {
        bless(x, a);
        return true;
    } else {
        return false;
    }
}

// 8-bit octet variable array from input stream
template <typename FR, std::size_t N>
bool bless(std::array<snarkfront::uint8_x<FR>, N>& a, std::istream& is) {
    for (auto& x : a) {
        if (! bless(x, is)) return false;
    }

    return true;
}

// 32-bit word variable from input stream
template <typename FR>
bool bless(snarkfront::uint32_x<FR>& x, std::istream& is) {
    std::uint32_t a;
    if (cryptl::bless(a, is)) {
        bless(x, a);
        return true;
    } else {
        return false;
    }
}

// 32-bit octet variable array from input stream
template <typename FR, std::size_t N>
bool bless(std::array<snarkfront::uint32_x<FR>, N>& a, std::istream& is) {
    for (auto& x : a) {
        if (! bless(x, is)) return false;
    }

    return true;
}

// 64-bit word variable from input stream
template <typename FR>
bool bless(snarkfront::uint64_x<FR>& x, std::istream& is) {
    std::uint64_t a;
    if (cryptl::bless(a, is)) {
        bless(x, a);
        return true;
    } else {
        return false;
    }
}

// 64-bit octet variable array from input stream
template <typename FR, std::size_t N>
bool bless(std::array<snarkfront::uint64_x<FR>, N>& a, std::istream& is) {
    for (auto& x : a) {
        if (! bless(x, is)) return false;
    }

    return true;
}

} // namespace snarkfront

#endif
