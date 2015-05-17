#ifndef _SNARKFRONT_DSL_IDENTITY_HPP_
#define _SNARKFRONT_DSL_IDENTITY_HPP_

#include <array>
#include <cstdint>

#include <snarklib/BigInt.hpp>

#include <snarkfront/DSL_base.hpp>

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// identity elements
//

// Boolean
bool zero(const bool& dummy);
bool one(const bool& dummy);

template <std::size_t N>
std::array<bool, N> zero(const std::array<bool, N>& dummy) {
    std::array<bool, N> a;
    for (std::size_t i = 0; i < N; ++i) a[i] = zero(dummy[i]);
    return a;
}

template <typename FR>
c_bool<FR> zero(const bool_x<FR>& dummy) {
    return c_bool<FR>(false);
}

template <typename FR>
c_bool<FR> one(const bool_x<FR>& dummy) {
    return c_bool<FR>(true);
}

template <typename FR, std::size_t N>
std::array<c_bool<FR>, N> zero(const std::array<bool_x<FR>, N>& dummy) {
    std::array<c_bool<FR>, N> a;
    for (std::size_t i = 0; i < N; ++i) a[i] = zero(dummy[i]);
    return a;
}

// 8-bit octet
std::uint8_t zero(const std::uint8_t& dummy);
std::uint8_t one(const std::uint8_t& dummy);

template <std::size_t N>
std::array<std::uint8_t, N> zero(const std::array<std::uint8_t, N>& dummy) {
    std::array<std::uint8_t, N> a;
    for (std::size_t i = 0; i < N; ++i) a[i] = zero(dummy[i]);
    return a;
}

template <typename FR>
c_uint8<FR> zero(const uint8_x<FR>& dummy) {
    return c_uint8<FR>(0);
}

template <typename FR>
c_uint8<FR> one(const uint8_x<FR>& dummy) {
    return c_uint8<FR>(1);
}

template <typename FR, std::size_t N>
std::array<c_uint8<FR>, N> zero(const std::array<uint8_x<FR>, N>& dummy) {
    std::array<c_uint8<FR>, N> a;
    for (std::size_t i = 0; i < N; ++i) a[i] = zero(dummy[i]);
    return a;
}

// 32-bit word
std::uint32_t zero(const std::uint32_t& dummy);
std::uint32_t one(const std::uint32_t& dummy);

template <std::size_t N>
std::array<std::uint32_t, N> zero(const std::array<std::uint32_t, N>& dummy) {
    std::array<std::uint32_t, N> a;
    for (std::size_t i = 0; i < N; ++i) a[i] = zero(dummy[i]);
    return a;
}

template <typename FR>
c_uint32<FR> zero(const uint32_x<FR>& dummy) {
    return c_uint32<FR>(0);
}

template <typename FR>
c_uint32<FR> one(const uint32_x<FR>& dummy) {
    return c_uint32<FR>(1);
}

template <typename FR, std::size_t N>
std::array<c_uint32<FR>, N> zero(const std::array<uint32_x<FR>, N>& dummy) {
    std::array<c_uint32<FR>, N> a;
    for (std::size_t i = 0; i < N; ++i) a[i] = zero(dummy[i]);
    return a;
}

// 64-bit word
std::uint64_t zero(const std::uint64_t& dummy);
std::uint64_t one(const std::uint64_t& dummy);

template <std::size_t N>
std::array<std::uint64_t, N> zero(const std::array<std::uint64_t, N>& dummy) {
    std::array<std::uint64_t, N> a;
    for (std::size_t i = 0; i < N; ++i) a[i] = zero(dummy[i]);
    return a;
}

template <typename FR>
c_uint64<FR> zero(const uint64_x<FR>& dummy) {
    return c_uint64<FR>(0);
}

template <typename FR>
c_uint64<FR> one(const uint64_x<FR>& dummy) {
    return c_uint64<FR>(1);
}

template <typename FR, std::size_t N>
std::array<c_uint64<FR>, N> zero(const std::array<uint64_x<FR>, N>& dummy) {
    std::array<c_uint64<FR>, N> a;
    for (std::size_t i = 0; i < N; ++i) a[i] = zero(dummy[i]);
    return a;
}

// big integer
template <mp_size_t N>
snarklib::BigInt<N> zero(const snarklib::BigInt<N>& dummy) {
    return snarklib::BigInt<N>::zero();
}

template <mp_size_t N>
snarklib::BigInt<N> one(const snarklib::BigInt<N>& dummy) {
    return snarklib::BigInt<N>::one();
}

// 128-bit big integer
template <typename FR>
c_bigint<FR> zero(const bigint_x<FR>& dummy) {
    return c_bigint<FR>(bigint_x<FR>::ValueType::zero());
}

template <typename FR>
c_bigint<FR> one(const bigint_x<FR>& dummy) {
    return c_bigint<FR>(bigint_x<FR>::ValueType::one());
}

template <typename FR, std::size_t N>
std::array<c_bigint<FR>, N> zero(const std::array<bigint_x<FR>, N>& dummy) {
    std::array<c_bigint<FR>, N> a;
    for (std::size_t i = 0; i < N; ++i) a[i] = zero(dummy[i]);
    return a;
}

// field
template <typename T, std::size_t N>
snarklib::Field<T, N> zero(const snarklib::Field<T, N>& dummy) {
    return snarklib::Field<T, N>::zero();
}

template <typename T, std::size_t N>
snarklib::Field<T, N> one(const snarklib::Field<T, N>& dummy) {
    return snarklib::Field<T, N>::one();
}

// finite scalar field
template <typename FR>
c_field<FR> zero(const field_x<FR>& dummy) {
    return c_field<FR>(field_x<FR>::ValueType::zero());
}

template <typename FR>
c_field<FR> one(const field_x<FR>& dummy) {
    return c_field<FR>(field_x<FR>::ValueType::one());
}

template <typename FR, std::size_t N>
std::array<c_field<FR>, N> zero(const std::array<field_x<FR>, N>& dummy) {
    std::array<c_field<FR>, N> a;
    for (std::size_t i = 0; i < N; ++i) a[i] = zero(dummy[i]);
    return a;
}

} // namespace snarkfront

#endif
