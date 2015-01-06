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
// serialize hash digests
//

template <std::size_t N>
std::ostream& operator<< (std::ostream& os,
                          const std::array<std::uint32_t, N>& a) {
    for (const auto& r : a)
        os << r << std::endl;
    return os;
}

template <std::size_t N>
std::ostream& operator<< (std::ostream& os,
                          const std::array<std::uint64_t, N>& a) {
    for (const auto& r : a)
        os << r << std::endl;
    return os;
}

template <std::size_t N>
std::ostream& operator<< (std::ostream& os,
                          const std::vector<std::array<std::uint32_t, N>>& a) {
    os << a.size() << std::endl;

    for (const auto& r : a)
        os << r;

    return os;
}

template <std::size_t N>
std::ostream& operator<< (std::ostream& os,
                          const std::vector<std::array<std::uint64_t, N>>& a) {
    os << a.size() << std::endl;

    for (const auto& r : a)
        os << r;

    return os;
}

template <std::size_t N>
std::istream& operator>> (std::istream& is,
                          std::array<std::uint32_t, N>& a) {
    for (auto& r : a)
        if (!(is >> r)) break;
    return is;
}

template <std::size_t N>
std::istream& operator>> (std::istream& is,
                          std::array<std::uint64_t, N>& a) {
    for (auto& r : a)
        if (!(is >> r)) break;
    return is;
}

template <std::size_t N>
std::istream& operator>> (std::istream& is,
                          std::vector<std::array<std::uint32_t, N>>& a) {
    std::size_t len = -1;
    if (!(is >> len) || (-1 == len)) return is;

    a.resize(len);
    for (auto& r : a)
        if (!(is >> r)) break;

    return is;
}

template <std::size_t N>
std::istream& operator>> (std::istream& is,
                          std::vector<std::array<std::uint64_t, N>>& a) {
    std::size_t len = -1;
    if (!(is >> len) || (-1 == len)) return is;

    a.resize(len);
    for (auto& r : a)
        if (!(is >> r)) break;

    return is;
}

} // namespace snarkfront

#endif
