#ifndef _SNARKFRONT_DSL_UTILITY_HPP_
#define _SNARKFRONT_DSL_UTILITY_HPP_

#include <array>
#include <cstdint>
#include <iostream>
#include <istream>
#include <ostream>
#include <vector>
#include "AST.hpp"

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

} // namespace snarkfront

#endif
