#ifndef _SNARKFRONT_DSL_BASE_HPP_
#define _SNARKFRONT_DSL_BASE_HPP_

#include <array>
#include <cstdint>
#include <vector>
#include "Alg.hpp"
#include "Alg_BigInt.hpp"
#include "Alg_bool.hpp"
#include "Alg_uint.hpp"
#include "DataBuffer.hpp"
#include "PowersOf2.hpp"

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

} // namespace snarkfront

#endif
