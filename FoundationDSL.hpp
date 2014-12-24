#ifndef _SNARKFRONT_FOUNDATION_DSL_HPP_
#define _SNARKFRONT_FOUNDATION_DSL_HPP_

#include <array>
#include <cassert>
#include <cstdint>
#include <memory>
#include <vector>
#include "Alg.hpp"
#include "Alg_BigInt.hpp"
#include "Alg_bool.hpp"
#include "Alg_uint.hpp"
#include <BigInt.hpp> // snarklib
#include "DataBuffer.hpp"
#include <PPZK.hpp> // snarklib
#include "PowersOf2.hpp"
#include <ProgressCallback.hpp> // snarklib
#include "R1C.hpp"
#include <sstream>
#include "TLsingleton.hpp"

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// algebraic types
//

// constants
template <typename FR> using c_bool = AST_Const<Alg_bool<FR>>;
template <typename FR> using c_bigint = AST_Const<Alg_BigInt<FR>>;
template <typename FR> using c_uint32 = AST_Const<Alg_uint32<FR>>;
template <typename FR> using c_uint64 = AST_Const<Alg_uint64<FR>>;

// variables
template <typename FR> using bool_x = AST_Var<Alg_bool<FR>>;
template <typename FR> using bigint_x = AST_Var<Alg_BigInt<FR>>;
template <typename FR> using uint32_x = AST_Var<Alg_uint32<FR>>;
template <typename FR> using uint64_x = AST_Var<Alg_uint64<FR>>;

////////////////////////////////////////////////////////////////////////////////
// identity elements
//

// Boolean
bool zero(const bool& dummy);
bool one(const bool& dummy);

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

    for (std::size_t i = 0; i < N; ++i)
        a[i] = zero(dummy[i]);

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

    for (std::size_t i = 0; i < N; ++i)
        a[i] = zero(dummy[i]);

    return a;
}

// 32-bit word
std::uint32_t zero(const std::uint32_t& dummy);
std::uint32_t one(const std::uint32_t& dummy);

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

    for (std::size_t i = 0; i < N; ++i)
        a[i] = zero(dummy[i]);

    return a;
}

// 64-bit word
std::uint64_t zero(const std::uint64_t& dummy);
std::uint64_t one(const std::uint64_t& dummy);

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

    for (std::size_t i = 0; i < N; ++i)
        a[i] = zero(dummy[i]);

    return a;
}

////////////////////////////////////////////////////////////////////////////////
// zero knowledge proof management
//

template <typename PAIRING> using Keypair = snarklib::PPZK_Keypair<PAIRING>;
template <typename PAIRING> using Input = R1Cowitness<typename PAIRING::Fr>;
template <typename PAIRING> using Proof = snarklib::PPZK_Proof<PAIRING>;
typedef snarklib::ProgressCallback ProgressCallback;

template <typename PAIRING>
void reset()
{
    TL<R1C<typename PAIRING::Fr>>::singleton()
        ->reset();
}

template <typename PAIRING>
void end_input()
{
    TL<R1C<typename PAIRING::Fr>>::singleton()
        ->checkpointInput();
}

template <typename PAIRING>
std::size_t variable_count()
{
    return TL<R1C<typename PAIRING::Fr>>::singleton()
        ->counterID();
}

template <typename PAIRING>
snarklib::PPZK_Keypair<PAIRING> keypair()
{
    return TL<R1C<typename PAIRING::Fr>>::singleton()
        ->keypair<PAIRING>();
}

template <typename PAIRING>
snarklib::PPZK_Keypair<PAIRING> keypair(
    snarklib::ProgressCallback& callback)
{
    return TL<R1C<typename PAIRING::Fr>>::singleton()
        ->keypair<PAIRING>(std::addressof(callback));
}

template <typename PAIRING>
const R1Cowitness<typename PAIRING::Fr>& input()
{
    return TL<R1C<typename PAIRING::Fr>>::singleton()
        ->input();
}

template <typename PAIRING>
snarklib::PPZK_Proof<PAIRING> proof(
    const snarklib::PPZK_Keypair<PAIRING>& keypair)
{
    return TL<R1C<typename PAIRING::Fr>>::singleton()
        ->proof(keypair);
}

template <typename PAIRING>
snarklib::PPZK_Proof<PAIRING> proof(
    const snarklib::PPZK_Keypair<PAIRING>& keypair,
    snarklib::ProgressCallback& callback)
{
    return TL<R1C<typename PAIRING::Fr>>::singleton()
        ->proof(keypair, std::addressof(callback));
}

template <typename PAIRING>
bool verify(
    const snarklib::PPZK_Keypair<PAIRING>& keypair,
    const R1Cowitness<typename PAIRING::Fr>& input,
    const snarklib::PPZK_Proof<PAIRING>& proof)
{
    return TL<R1C<typename PAIRING::Fr>>::singleton()
        ->verify(keypair, input, proof);
}

template <typename PAIRING>
bool verify(
    const snarklib::PPZK_Keypair<PAIRING>& keypair,
    const R1Cowitness<typename PAIRING::Fr>& input,
    const snarklib::PPZK_Proof<PAIRING>& proof,
    snarklib::ProgressCallback& callback)
{
    return TL<R1C<typename PAIRING::Fr>>::singleton()
        ->verify(keypair, input, proof, std::addressof(callback));
}

////////////////////////////////////////////////////////////////////////////////
// blessing (initialize variables)
//

// variable with value
template <typename FR> void bless(bool_x<FR>& x, const bool a) { x.bless(a); }
template <typename FR> void bless(bigint_x<FR>& x, const std::string& a) { x.bless(a); }
template <typename FR> void bless(uint32_x<FR>& x, const std::uint32_t a) { x.bless(a); }
template <typename FR> void bless(uint64_x<FR>& x, const std::uint64_t a) { x.bless(a); }

template <typename FR> void bless(bigint_x<FR>& x, const std::uint64_t a) {
    std::stringstream ss;
    ss << a;
    x.bless(ss.str());
}

// initialize variable
template <typename FR> void bless(bool_x<FR>& x) { bless(x, false); }
template <typename FR> void bless(bigint_x<FR>& x) { bless(x, "0"); }
template <typename FR> void bless(uint32_x<FR>& x) { bless(x, 0); }
template <typename FR> void bless(uint64_x<FR>& x) { bless(x, 0); }

// array of variables with array of values
template <typename T, typename U, std::size_t N>
void bless(std::array<T, N>& a, const std::array<U, N>& b) {
    for (std::size_t i = 0; i < N; ++i)
        bless(a[i], b[i]);
}

// initialize array of variables
template <typename T, std::size_t N>
void bless(std::array<T, N>& a) {
    for (auto& x : a)
        bless(x);
}

// conversion of:
// - 64-bit word to two 32-bit words
// - 128-bit big integer to four 32-bit words
// - 128 bit big integer to two 64-bit words
template <typename T, std::size_t N, typename U>
void bless(std::array<T, N>& x, const U& a)
{
    const std::size_t
        sizeT = sizeBits(x[0]),
        sizeU = sizeBits(a);

    assert(sizeT * N == sizeU);

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

        x[i].bless(value,
                   TL<PowersOf2<FR>>::singleton()->getNumber(split_vec),
                   split_vec,
                   term_vec);
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
    for (auto& x : a)
        bless(x, input);
}

// 32-bit word variable from data buffer stream
template <typename FR>
void bless(uint32_x<FR>& x, DataBufferStream& ss) {
    bless(x, ss.getWord<std::uint32_t>());
}

// 64-bit word variable from data buffer stream
template <typename FR>
void bless(uint64_x<FR>& x, DataBufferStream& ss) {
    bless(x, ss.getWord<std::uint64_t>());
}

// 32-bit value from data buffer stream (useful for templates)
void bless(std::uint32_t& a, DataBufferStream& ss);

// 64-bit value from data buffer stream (useful for templates)
void bless(std::uint64_t& a, DataBufferStream& ss);

// array of variables/values from data buffer stream
template <typename T, std::size_t N>
void bless(std::array<T, N>& a, DataBufferStream& ss) {
    for (auto& x : a)
        bless(x, ss);
}

////////////////////////////////////////////////////////////////////////////////
// convenient message digest for data
// (new variables for entire message block)
//

template <typename T>
typename T::DigType digest(T hashAlgo, const DataBufferStream& buf)
{
    auto bufCopy = buf; // need copy as blessing from stream consumes it

    while (! bufCopy.empty()) {
        typename T::MsgType msg;
        bless(msg, bufCopy);
        hashAlgo.msgInput(msg);
    }

    hashAlgo.computeHash();

    return hashAlgo.digest();
}

template <typename T>
typename T::DigType digest(T hashAlgo, const std::string& a)
{
    DataBufferStream buf(a);
    T::padMessage(buf);
    return digest(hashAlgo, buf);
}

template <typename T>
typename T::DigType digest(T hashAlgo, const char* a)
{
    return digest(hashAlgo, std::string(a));
}

template <typename T>
typename T::DigType digest(T hashAlgo, const std::vector<std::uint8_t>& a)
{
    DataBufferStream buf(a);
    T::padMessage(buf);
    return digest(hashAlgo, buf);
}

template <typename T, typename... Args>
typename T::DigType digest(T hashAlgo, const Args... parameterPack)
{
    DataBufferStream buf;
    buf.push(parameterPack...);
    T::padMessage(buf);
    return digest(hashAlgo, buf);
}

////////////////////////////////////////////////////////////////////////////////
// logical and bitwise complement
//

#define DEFN_CMPLMNT(ALG, OP)                                           \
    template <typename FR>                                              \
    AST_Op<Alg_ ## ALG<FR>>                                             \
    operator OP(                                                        \
        const AST_Node<Alg_ ## ALG<FR>>& x)                             \
    {                                                                   \
        return AST_Op<Alg_ ## ALG<FR>>(Alg_ ## ALG<FR>::OpType::CMPLMNT, \
                                       x);                              \
    }

    DEFN_CMPLMNT(bool, !)
    DEFN_CMPLMNT(uint32, ~)
    DEFN_CMPLMNT(uint64, ~)

#undef DEFN_CMPLMNT

////////////////////////////////////////////////////////////////////////////////
// AND, OR, XOR, ADD, SUB, MUL, ADDMOD
//

#define DEFN_OP(ALG, OP, ENUM)                                          \
    template <typename FR>                                              \
    AST_Op<Alg_ ## ALG<FR>>                                             \
    operator OP(                                                        \
        const AST_Node<Alg_ ## ALG<FR>>& x,                             \
        const AST_Node<Alg_ ## ALG<FR>>& y)                             \
    {                                                                   \
        return AST_Op<Alg_ ## ALG<FR>>(Alg_ ## ALG<FR>::OpType:: ENUM,  \
                                       x,                               \
                                       y);                              \
    }                                                                   \
    template <typename FR>                                              \
    AST_Op<Alg_ ## ALG<FR>>                                             \
    operator OP(                                                        \
        const AST_Node<Alg_ ## ALG<FR>>& x,                             \
        const typename Alg_ ## ALG<FR>::ValueType& y)                   \
    {                                                                   \
        return AST_Op<Alg_ ## ALG<FR>>(Alg_ ## ALG<FR>::OpType:: ENUM,  \
                                       x,                               \
                                       new AST_Const<Alg_ ## ALG<FR>>(y)); \
    }                                                                   \
    template <typename FR>                                              \
    AST_Op<Alg_ ## ALG<FR>>                                             \
    operator OP(                                                        \
        const typename Alg_ ## ALG<FR>::ValueType& x,                   \
        const AST_Node<Alg_ ## ALG<FR>>& y)                             \
    {                                                                   \
        return AST_Op<Alg_ ## ALG<FR>>(Alg_ ## ALG<FR>::OpType:: ENUM,  \
                                       new AST_Const<Alg_ ## ALG<FR>>(x), \
                                       y);                              \
    }

    DEFN_OP(bool, &&, AND)
    DEFN_OP(uint32, &, AND)
    DEFN_OP(uint64, &, AND)

    DEFN_OP(bool, ||, OR)
    DEFN_OP(uint32, |, OR)
    DEFN_OP(uint64, |, OR)

    DEFN_OP(uint32, ^, XOR)
    DEFN_OP(uint64, ^, XOR)

    DEFN_OP(BigInt, +, ADD)
    DEFN_OP(BigInt, -, SUB)
    DEFN_OP(BigInt, *, MUL)

    DEFN_OP(uint32, +, ADDMOD)
    DEFN_OP(uint64, +, ADDMOD)

#undef DEFN_OP

////////////////////////////////////////////////////////////////////////////////
// bitwise shift and rotate
//

#define DEFN_PERMUTE(ALG, OP, ENUM)                                     \
    template <typename FR>                                              \
    AST_Op<Alg_ ## ALG<FR>>                                             \
    OP(                                                                 \
        const AST_Node<Alg_ ## ALG<FR>>& x,                             \
        const unsigned int n)                                           \
    {                                                                   \
        return AST_Op<Alg_ ## ALG<FR>>(Alg_ ## ALG<FR>::OpType:: ENUM,  \
                                       x,                               \
                                       new AST_Const<Alg_ ## ALG<FR>>(n)); \
    }

    DEFN_PERMUTE(uint32, operator<<, SHL)
    DEFN_PERMUTE(uint64, operator<<, SHL)

    DEFN_PERMUTE(uint32, operator>>, SHR)
    DEFN_PERMUTE(uint64, operator>>, SHR)

    DEFN_PERMUTE(uint32, ROTL, ROTL)
    DEFN_PERMUTE(uint64, ROTL, ROTL)

    DEFN_PERMUTE(uint32, ROTR, ROTR)
    DEFN_PERMUTE(uint64, ROTR, ROTR)

#undef DEFN_PERMUTE

////////////////////////////////////////////////////////////////////////////////
// comparison
//

#define DEFN_CMP(ALG, OP, ENUM)                                         \
    template <typename FR>                                              \
    AST_X<Alg_bool<FR>>                                                 \
    operator OP(                                                        \
        const AST_Node<Alg_ ## ALG<FR>>& x,                             \
        const AST_Node<Alg_ ## ALG<FR>>& y)                             \
    {                                                                   \
        return AST_X<Alg_bool<FR>>(Alg_ ## ALG<FR>::CmpType:: ENUM,     \
                                   x,                                   \
                                   y);                                  \
    }                                                                   \
    template <typename FR>                                              \
    AST_X<Alg_bool<FR>>                                                 \
    operator OP(                                                        \
        const AST_Node<Alg_ ## ALG<FR>>& x,                             \
        const typename Alg_ ## ALG<FR>::ValueType& y)                   \
    {                                                                   \
        return AST_X<Alg_bool<FR>>(Alg_ ## ALG<FR>::CmpType:: ENUM,     \
                                   x,                                   \
                                   y);                                  \
    }                                                                   \
    template <typename FR>                                              \
    AST_X<Alg_bool<FR>>                                                 \
    operator OP(                                                        \
        const typename Alg_ ## ALG<FR>::ValueType& x,                   \
        const AST_Node<Alg_ ## ALG<FR>>& y)                             \
    {                                                                   \
        return AST_X<Alg_bool<FR>>(Alg_ ## ALG<FR>::CmpType:: ENUM,     \
                                   x,                                   \
                                   y);                                  \
    }

    DEFN_CMP(bool, ==, EQ)
    DEFN_CMP(bool, !=, NEQ)

    DEFN_CMP(BigInt, ==, EQ)
    DEFN_CMP(BigInt, !=, EQ)
    DEFN_CMP(BigInt, <, LT)
    DEFN_CMP(BigInt, <=, LE)
    DEFN_CMP(BigInt, >, GT)
    DEFN_CMP(BigInt, >=, GE)

    DEFN_CMP(uint32, ==, EQ)
    DEFN_CMP(uint32, !=, EQ)

    DEFN_CMP(uint64, ==, EQ)
    DEFN_CMP(uint64, !=, EQ)

#undef DEFN_CMP

template <typename FR, typename T, typename U, std::size_t N>
class ArrayCmp;

template <typename FR, typename T, typename U>
class ArrayCmp<FR, T, U, 1>
{
public:
    static
    AST_X<Alg_bool<FR>>
    equal(const std::array<T, 1>& x, const std::array<U, 1>& y) {
        return x[0] == y[0];
    }

    static
    AST_X<Alg_bool<FR>>
    notEqual(const std::array<T, 1>& x, const std::array<U, 1>& y) {
        return x[0] != y[0];
    }
};

template <typename FR, typename T, typename U, std::size_t N>
class ArrayCmp
{
public:
    static
    AST_X<Alg_bool<FR>>
    equal(const std::array<T, N>& x, const std::array<U, N>& y) {
        std::array<T, N-1> xslice;
        std::array<U, N-1> yslice;
        for (std::size_t i = 0; i < N - 1; ++i) {
            xslice[i] = x[i];
            yslice[i] = y[i];
        }

        return
            ArrayCmp<FR, T, U, N-1>::equal(xslice, yslice) &&
            x[N-1] == y[N-1];
    }

    static
    AST_X<Alg_bool<FR>>
    notEqual(const std::array<T, N>& x, const std::array<U, N>& y) {
        std::array<T, N-1> xslice;
        std::array<U, N-1> yslice;
        for (std::size_t i = 0; i < N - 1; ++i) {
            xslice[i] = x[i];
            yslice[i] = y[i];
        }

        return
            ArrayCmp<FR, T, U, N-1>::notEqual(xslice, yslice) &&
            x[N-1] != y[N-1];
    }
};

#define DEFN_CMP_ARRAY(T, U)                                    \
template <typename FR, std::size_t N>                           \
AST_X<Alg_bool<FR>> operator== (const std::array< T , N>& x,    \
                                const std::array< U , N>& y) {  \
    return ArrayCmp<FR, T , U , N>::equal(x, y);                \
}                                                               \
template <typename FR, std::size_t N>                           \
AST_X<Alg_bool<FR>> operator!= (const std::array< T , N>& x,    \
                                const std::array< U , N>& y) {  \
    return ArrayCmp<FR, T , U , N>::notEqual(x, y);             \
}

DEFN_CMP_ARRAY(uint32_x<FR>, uint32_x<FR>)
DEFN_CMP_ARRAY(uint32_x<FR>, std::uint32_t)
DEFN_CMP_ARRAY(std::uint32_t, uint32_x<FR>)

DEFN_CMP_ARRAY(uint64_x<FR>, uint64_x<FR>)
DEFN_CMP_ARRAY(uint64_x<FR>, std::uint64_t)
DEFN_CMP_ARRAY(std::uint64_t, uint64_x<FR>)

#undef DEFN_CMP_ARRAY

////////////////////////////////////////////////////////////////////////////////
// convert to and between 32-bit and 64-bit words
//

template <typename FR>
AST_X<Alg_uint32<FR>> xword(const AST_Node<Alg_uint64<FR>>& x) {
    return AST_X<Alg_uint32<FR>>(x);
}

template <typename FR>
AST_X<Alg_uint64<FR>> xword(const AST_Node<Alg_uint32<FR>>& x) {
    return AST_X<Alg_uint64<FR>>(x);
}

template <typename FR>
AST_X<Alg_uint32<FR>> xword(const AST_Node<Alg_bool<FR>>& x,
                            const AST_Node<Alg_uint32<FR>>& dummy) {
    return AST_X<Alg_uint32<FR>>(x);
}

template <typename FR>
AST_X<Alg_uint64<FR>> xword(const AST_Node<Alg_bool<FR>>& x,
                            const AST_Node<Alg_uint64<FR>>& dummy) {
    return AST_X<Alg_uint64<FR>>(x);
}

////////////////////////////////////////////////////////////////////////////////
// conditional operator (ternary)
//

template <typename FR>
AST_Op<Alg_uint32<FR>> ternary(const AST_Node<Alg_bool<FR>>& b,
                               const AST_Node<Alg_uint32<FR>>& x,
                               const AST_Node<Alg_uint32<FR>>& y)
{
    return
        // (x & xword(b)) | (y & ~xword(b))
        AST_Op<Alg_uint32<FR>>(
            Alg_uint32<FR>::OpType::OR,

            // x & xword(b)
            new AST_Op<Alg_uint32<FR>>(
                Alg_uint32<FR>::OpType::AND,
                x,
                new AST_X<Alg_uint32<FR>>(b)),

            // y & ~xword(b)
            new AST_Op<Alg_uint32<FR>>(
                Alg_uint32<FR>::OpType::AND,
                y,
                new AST_Op<Alg_uint32<FR>>(
                    Alg_uint32<FR>::OpType::CMPLMNT,
                    new AST_X<Alg_uint32<FR>>(b))));
}

template <typename FR>
AST_Op<Alg_uint64<FR>> ternary(const AST_Node<Alg_bool<FR>>& b,
                               const AST_Node<Alg_uint64<FR>>& x,
                               const AST_Node<Alg_uint64<FR>>& y)
{
    return
        // (x & xword(b)) | (y & ~xword(b))
        AST_Op<Alg_uint64<FR>>(
            Alg_uint64<FR>::OpType::OR,

            // x & xword(b)
            new AST_Op<Alg_uint64<FR>>(
                Alg_uint64<FR>::OpType::AND,
                x,
                new AST_X<Alg_uint64<FR>>(b)),

            // y & ~xword(b)
            new AST_Op<Alg_uint64<FR>>(
                Alg_uint64<FR>::OpType::AND,
                y,
                new AST_Op<Alg_uint64<FR>>(
                    Alg_uint64<FR>::OpType::CMPLMNT,
                    new AST_X<Alg_uint64<FR>>(b))));
}

template <typename FR, std::size_t N>
std::array<AST_Var<Alg_uint32<FR>>, N>
ternary(const AST_Node<Alg_bool<FR>>& b,
        const std::array<AST_Var<Alg_uint32<FR>>, N>& x,
        const std::array<AST_Var<Alg_uint32<FR>>, N>& y)
{
    std::array<AST_Var<Alg_uint32<FR>>, N> result;

    for (std::size_t i = 0; i < N; ++i) {
        result[i] = ternary(b, x[i], y[i]);
    }

    return result;
}

template <typename FR, std::size_t N>
std::array<AST_Var<Alg_uint64<FR>>, N>
ternary(const AST_Node<Alg_bool<FR>>& b,
        const std::array<AST_Var<Alg_uint64<FR>>, N>& x,
        const std::array<AST_Var<Alg_uint64<FR>>, N>& y)
{
    std::array<AST_Var<Alg_uint64<FR>>, N> result;

    for (std::size_t i = 0; i < N; ++i) {
        result[i] = ternary(b, x[i], y[i]);
    }

    return result;
}

std::uint32_t ternary(const bool b,
                      const std::uint32_t x,
                      const std::uint32_t y);

std::uint64_t ternary(const bool b,
                      const std::uint64_t x,
                      const std::uint64_t y);

template <std::size_t N>
std::array<std::uint32_t, N> ternary(const bool b,
                                     const std::array<std::uint32_t, N>& x,
                                     const std::array<std::uint32_t, N>& y)
{
    std::array<std::uint32_t, N> result;

    for (std::size_t i = 0; i < N; ++i) {
        result[i] = ternary(b, x[i], y[i]);
    }

    return result;
}

template <std::size_t N>
std::array<std::uint64_t, N> ternary(const bool b,
                                     const std::array<std::uint64_t, N>& x,
                                     const std::array<std::uint64_t, N>& y)
{
    std::array<std::uint64_t, N> result;

    for (std::size_t i = 0; i < N; ++i) {
        result[i] = ternary(b, x[i], y[i]);
    }

    return result;
}

////////////////////////////////////////////////////////////////////////////////
// terminate circuits, constrain final proof output
//

template <typename FR>
void assert_true(const AST_Var<Alg_bool<FR>>& x) {
    TL<R1C<FR>>::singleton()->setTrue(x->r1Terms()[0]);
}

template <typename FR>
void assert_false(const AST_Var<Alg_bool<FR>>& x) {
    TL<R1C<FR>>::singleton()->setFalse(x->r1Terms()[0]);
}

template <typename FR>
void assert_true(const AST_X<Alg_bool<FR>>& a) {
    assert_true(bool_x<FR>(a));
}

template <typename FR>
void assert_false(const AST_X<Alg_bool<FR>>& a) {
    assert_false(bool_x<FR>(a));
}

} // namespace snarkfront

#endif
