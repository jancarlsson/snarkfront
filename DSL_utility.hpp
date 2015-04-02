#ifndef _SNARKFRONT_DSL_UTILITY_HPP_
#define _SNARKFRONT_DSL_UTILITY_HPP_

#include <array>
#include <cstdint>
#include <iostream>
#include <istream>
#include <ostream>
#include <vector>
#include "Alg.hpp"
#include "AST.hpp"
#include "BitwiseAST.hpp"

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// elliptic curve pairing
//

// check if string name is: BN128, Edwards
bool validPairingName(const std::string& name);

// returns true if "BN128"
bool pairingBN128(const std::string& name);

// returns true if "Edwards"
bool pairingEdwards(const std::string& name);

////////////////////////////////////////////////////////////////////////////////
// SHA-2
//

// check if: "1", "224", "256", "384", "512", "512_224", "512_256"
bool validSHA2Name(const std::string& shaBits);

// check if: 1, 224, 256, 384, 512
bool validSHA2Name(const std::size_t shaBits);

// returns true if "SHA256"
bool nameSHA256(const std::string& shaBits);

// returns true if "SHA512"
bool nameSHA512(const std::string& shaBits);

////////////////////////////////////////////////////////////////////////////////
// AES
//

// check if: 128, 192, 256
bool validAESName(const std::size_t aesBits);

////////////////////////////////////////////////////////////////////////////////
// powers of 2
//

template <typename ALG>
std::size_t sizeBits(const AST_Const<ALG>&) {
    typename AST_Const<ALG>::ValueType dummy;
    return sizeBits(dummy);
}

template <typename ALG>
std::size_t sizeBits(const AST_Var<ALG>&) {
    typename AST_Var<ALG>::ValueType dummy;
    return sizeBits(dummy);
}

////////////////////////////////////////////////////////////////////////////////
// serialize hash digests and preimages
//

#define DEFN_ARRAY_OUT(UINT)                            \
template <std::size_t N>                                \
std::ostream& operator<< (std::ostream& os,             \
                          const std::array<UINT, N>& a) \
{                                                       \
    for (const auto& r : a)                             \
        os << r << std::endl;                           \
    return os;                                          \
}

DEFN_ARRAY_OUT(std::uint8_t)
DEFN_ARRAY_OUT(std::uint32_t)
DEFN_ARRAY_OUT(std::uint64_t)

#undef DEFN_ARRAY_OUT

#define DEFN_VECTOR_ARRAY_OUT(UINT)                                     \
template <std::size_t N>                                                \
std::ostream& operator<< (std::ostream& os,                             \
                          const std::vector<std::array<UINT, N>>& a)    \
{                                                                       \
    os << a.size() << std::endl;                                        \
    for (const auto& r : a)                                             \
        os << r;                                                        \
    return os;                                                          \
}

DEFN_VECTOR_ARRAY_OUT(std::uint8_t)
DEFN_VECTOR_ARRAY_OUT(std::uint32_t)
DEFN_VECTOR_ARRAY_OUT(std::uint64_t)

#undef DEFN_VECTOR_ARRAY_OUT

#define DEFN_ARRAY_IN(UINT)                             \
template <std::size_t N>                                \
std::istream& operator>> (std::istream& is,             \
                          std::array<UINT, N>& a)       \
{                                                       \
    for (auto& r : a)                                   \
        if (!(is >> r)) break;                          \
    return is;                                          \
}

DEFN_ARRAY_IN(std::uint8_t)
DEFN_ARRAY_IN(std::uint32_t)
DEFN_ARRAY_IN(std::uint64_t)

#undef DEFN_ARRAY_IN

#define DEFN_VECTOR_ARRAY_IN(UINT)                              \
template <std::size_t N>                                        \
std::istream& operator>> (std::istream& is,                     \
                          std::vector<std::array<UINT, N>>& a)  \
{                                                               \
    std::size_t len = -1;                                       \
    if (!(is >> len) || (-1 == len)) return is;                 \
    a.resize(len);                                              \
    for (auto& r : a)                                           \
        if (!(is >> r)) break;                                  \
    return is;                                                  \
}

DEFN_VECTOR_ARRAY_IN(std::uint8_t)
DEFN_VECTOR_ARRAY_IN(std::uint32_t)
DEFN_VECTOR_ARRAY_IN(std::uint64_t)

#undef DEFN_VECTOR_ARRAY_IN

////////////////////////////////////////////////////////////////////////////////
// lookup table for unsigned integer types
//

template <typename T, typename U, typename VAL, typename BITWISE>
class BitwiseLUT
{
public:
    template <std::size_t N>
    BitwiseLUT(const std::array<VAL, N>& table_elements)
        : m_value(table_elements.begin(),
                  table_elements.end())
    {}

    std::size_t size() const { return m_value.size(); }

    U operator[] (const T& x) const
    {
        const auto N = m_value.size();

        auto sum = BITWISE::_AND(BITWISE::_constant(m_value[0]),
                                 BITWISE::_CMPLMNT(BITWISE::_bitmask(0 != x)));

        for (std::size_t i = 1; i < N - 1; ++i) {
            sum = BITWISE::_ADDMOD(sum,
                                   BITWISE::_AND(
                                       BITWISE::_constant(m_value[i]),
                                       BITWISE::_CMPLMNT(BITWISE::_bitmask(i != x))));
        }

        return BITWISE::ADDMOD(sum,
                               BITWISE::_AND(
                                   BITWISE::_constant(m_value[N - 1]),
                                   BITWISE::_CMPLMNT(BITWISE::_bitmask((N-1) != x))));
    }

private:
    const std::vector<VAL> m_value;
};

template <typename FR> using
array_uint8 = BitwiseLUT<AST_Node<Alg_uint8<FR>>,
                         AST_Op<Alg_uint8<FR>>,
                         std::uint8_t,
                         BitwiseAST<Alg_uint8<FR>>>;

template <typename FR> using
array_uint32 = BitwiseLUT<AST_Node<Alg_uint32<FR>>,
                          AST_Op<Alg_uint32<FR>>,
                          std::uint32_t,
                          BitwiseAST<Alg_uint32<FR>>>;

template <typename FR> using
array_uint64 = BitwiseLUT<AST_Node<Alg_uint64<FR>>,
                          AST_Op<Alg_uint64<FR>>,
                          std::uint64_t,
                          BitwiseAST<Alg_uint64<FR>>>;

} // namespace snarkfront

#endif
