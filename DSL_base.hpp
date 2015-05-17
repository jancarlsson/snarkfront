#ifndef _SNARKFRONT_DSL_BASE_HPP_
#define _SNARKFRONT_DSL_BASE_HPP_

#include <array>
#include <cstdint>
#include <vector>

#include <snarkfront/Alg.hpp>
#include <snarkfront/Alg_BigInt.hpp>
#include <snarkfront/Alg_bool.hpp>
#include <snarkfront/Alg_Field.hpp>
#include <snarkfront/Alg_uint.hpp>
#include <snarkfront/BitwiseAST.hpp>
#include <snarkfront/DataBuffer.hpp>

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// algebraic types
//

// constants
template <typename FR> using c_bool = AST_Const<Alg_bool<FR>>;
template <typename FR> using c_uint8 = AST_Const<Alg_uint8<FR>>;
template <typename FR> using c_uint32 = AST_Const<Alg_uint32<FR>>;
template <typename FR> using c_uint64 = AST_Const<Alg_uint64<FR>>;
template <typename FR> using c_bigint = AST_Const<Alg_BigInt<FR>>;
template <typename FR> using c_field = AST_Const<Alg_Field<FR>>;

// variables
template <typename FR> using bool_x = AST_Var<Alg_bool<FR>>;
template <typename FR> using uint8_x = AST_Var<Alg_uint8<FR>>;
template <typename FR> using uint32_x = AST_Var<Alg_uint32<FR>>;
template <typename FR> using uint64_x = AST_Var<Alg_uint64<FR>>;
template <typename FR> using bigint_x = AST_Var<Alg_BigInt<FR>>;
template <typename FR> using field_x = AST_Var<Alg_Field<FR>>;

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

#define DEFN_CMPLMNT(ALG, OP)                   \
    template <typename FR>                      \
    AST_Op<Alg_ ## ALG<FR>>                     \
    operator OP(                                \
        const AST_Node<Alg_ ## ALG<FR>>& x)     \
    {                                           \
        return AST_Op<Alg_ ## ALG<FR>>(         \
            Alg_ ## ALG<FR>::OpType::CMPLMNT,   \
            x);                                 \
    }

    DEFN_CMPLMNT(bool, !)
    DEFN_CMPLMNT(uint8, ~)
    DEFN_CMPLMNT(uint32, ~)
    DEFN_CMPLMNT(uint64, ~)

#undef DEFN_CMPLMNT

////////////////////////////////////////////////////////////////////////////////
// AND, OR, XOR, ADD, SUB, MUL, ADDMOD
//

#define DEFN_OP(ALG, OP, ENUM)                          \
    template <typename FR>                              \
    AST_Op<Alg_ ## ALG<FR>>                             \
    operator OP(                                        \
        const AST_Node<Alg_ ## ALG<FR>>& x,             \
        const AST_Node<Alg_ ## ALG<FR>>& y)             \
    {                                                   \
        return AST_Op<Alg_ ## ALG<FR>>(                 \
            Alg_ ## ALG<FR>::OpType:: ENUM,             \
            x,                                          \
            y);                                         \
    }                                                   \
    template <typename FR>                              \
    AST_Op<Alg_ ## ALG<FR>>                             \
    operator OP(                                        \
        const AST_Node<Alg_ ## ALG<FR>>& x,             \
        const typename Alg_ ## ALG<FR>::ValueType& y)   \
    {                                                   \
        return AST_Op<Alg_ ## ALG<FR>>(                 \
            Alg_ ## ALG<FR>::OpType:: ENUM,             \
            x,                                          \
            new AST_Const<Alg_ ## ALG<FR>>(y));         \
    }                                                   \
    template <typename FR>                              \
    AST_Op<Alg_ ## ALG<FR>>                             \
    operator OP(                                        \
        const typename Alg_ ## ALG<FR>::ValueType& x,   \
        const AST_Node<Alg_ ## ALG<FR>>& y)             \
    {                                                   \
        return AST_Op<Alg_ ## ALG<FR>>(                 \
            Alg_ ## ALG<FR>::OpType:: ENUM,             \
            new AST_Const<Alg_ ## ALG<FR>>(x),          \
            y);                                         \
    }

    DEFN_OP(bool, &&, AND)
    DEFN_OP(uint8, &, AND)
    DEFN_OP(uint32, &, AND)
    DEFN_OP(uint64, &, AND)

    DEFN_OP(bool, ||, OR)
    DEFN_OP(uint8, |, OR)
    DEFN_OP(uint32, |, OR)
    DEFN_OP(uint64, |, OR)

    DEFN_OP(uint8, ^, XOR)
    DEFN_OP(uint32, ^, XOR)
    DEFN_OP(uint64, ^, XOR)

    DEFN_OP(BigInt, +, ADD)
    DEFN_OP(BigInt, -, SUB)
    DEFN_OP(BigInt, *, MUL)

    DEFN_OP(Field, +, ADD)
    DEFN_OP(Field, -, SUB)
    DEFN_OP(Field, *, MUL)

    DEFN_OP(uint8, +, ADDMOD)
    DEFN_OP(uint32, +, ADDMOD)
    DEFN_OP(uint64, +, ADDMOD)

#undef DEFN_OP

////////////////////////////////////////////////////////////////////////////////
// inverse for finite scalar field
//

template <typename FR>
AST_Op<Alg_Field<FR>> inverse(const AST_Node<Alg_Field<FR>>& x) {
    return AST_Op<Alg_Field<FR>>(
        Alg_Field<FR>::OpType::INV,
        x);
}

////////////////////////////////////////////////////////////////////////////////
// bitwise shift and rotate
//

#define DEFN_PERMUTE(ALG, OP, ENUM)                             \
    template <typename FR>                                      \
    AST_Op<Alg_ ## ALG<FR>>                                     \
    OP(                                                         \
        const AST_Node<Alg_ ## ALG<FR>>& x,                     \
        const unsigned int n)                                   \
    {                                                           \
        return BitwiseAST<Alg_ ## ALG<FR>>:: ENUM(x, n);        \
    }

    DEFN_PERMUTE(uint8, operator<<, SHL)
    DEFN_PERMUTE(uint32, operator<<, SHL)
    DEFN_PERMUTE(uint64, operator<<, SHL)

    DEFN_PERMUTE(uint8, operator>>, SHR)
    DEFN_PERMUTE(uint32, operator>>, SHR)
    DEFN_PERMUTE(uint64, operator>>, SHR)

    DEFN_PERMUTE(uint8, ROTL, ROTL)
    DEFN_PERMUTE(uint32, ROTL, ROTL)
    DEFN_PERMUTE(uint64, ROTL, ROTL)

    DEFN_PERMUTE(uint8, ROTR, ROTR)
    DEFN_PERMUTE(uint32, ROTR, ROTR)
    DEFN_PERMUTE(uint64, ROTR, ROTR)

#undef DEFN_PERMUTE

////////////////////////////////////////////////////////////////////////////////
// comparison
//

#define DEFN_CMP(ALG, OP, ENUM)                         \
    template <typename FR>                              \
    AST_X<Alg_bool<FR>>                                 \
    operator OP(                                        \
        const AST_Node<Alg_ ## ALG<FR>>& x,             \
        const AST_Node<Alg_ ## ALG<FR>>& y)             \
    {                                                   \
        return AST_X<Alg_bool<FR>>(                     \
            Alg_ ## ALG<FR>::CmpType:: ENUM,            \
            x,                                          \
            y);                                         \
    }                                                   \
    template <typename FR>                              \
    AST_X<Alg_bool<FR>>                                 \
    operator OP(                                        \
        const AST_Node<Alg_ ## ALG<FR>>& x,             \
        const typename Alg_ ## ALG<FR>::ValueType& y)   \
    {                                                   \
        return AST_X<Alg_bool<FR>>(                     \
            Alg_ ## ALG<FR>::CmpType:: ENUM,            \
            x,                                          \
            y);                                         \
    }                                                   \
    template <typename FR>                              \
    AST_X<Alg_bool<FR>>                                 \
    operator OP(                                        \
        const typename Alg_ ## ALG<FR>::ValueType& x,   \
        const AST_Node<Alg_ ## ALG<FR>>& y)             \
    {                                                   \
        return AST_X<Alg_bool<FR>>(                     \
            Alg_ ## ALG<FR>::CmpType:: ENUM,            \
            x,                                          \
            y);                                         \
    }

    // imperative tests
    DEFN_CMP(bool, ==, EQ)
    DEFN_CMP(bool, !=, NEQ)

    // declarative equality test, imperative inequality and ordering tests
    DEFN_CMP(BigInt, ==, EQ)
    DEFN_CMP(BigInt, !=, NEQ)
    DEFN_CMP(BigInt, <, LT)
    DEFN_CMP(BigInt, <=, LE)
    DEFN_CMP(BigInt, >, GT)
    DEFN_CMP(BigInt, >=, GE)

    // declarative equality test, imperative inequality test
    DEFN_CMP(Field, ==, EQ)
    DEFN_CMP(Field, !=, NEQ)

    // declarative equality test, imperative inequality test
    DEFN_CMP(uint8, ==, EQ)
    DEFN_CMP(uint8, !=, NEQ)

    // declarative equality test, imperative inequality test
    DEFN_CMP(uint32, ==, EQ)
    DEFN_CMP(uint32, !=, NEQ)

    // declarative equality test, imperative inequality test
    DEFN_CMP(uint64, ==, EQ)
    DEFN_CMP(uint64, !=, NEQ)

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

    DEFN_CMP_ARRAY(uint8_x<FR>, uint8_x<FR>)
    DEFN_CMP_ARRAY(uint8_x<FR>, std::uint8_t)
    DEFN_CMP_ARRAY(std::uint8_t, uint8_x<FR>)

    DEFN_CMP_ARRAY(uint32_x<FR>, uint32_x<FR>)
    DEFN_CMP_ARRAY(uint32_x<FR>, std::uint32_t)
    DEFN_CMP_ARRAY(std::uint32_t, uint32_x<FR>)

    DEFN_CMP_ARRAY(uint64_x<FR>, uint64_x<FR>)
    DEFN_CMP_ARRAY(uint64_x<FR>, std::uint64_t)
    DEFN_CMP_ARRAY(std::uint64_t, uint64_x<FR>)

#undef DEFN_CMP_ARRAY

////////////////////////////////////////////////////////////////////////////////
// type conversions
//

#define DEFN_XWORD(IN, OUT)                             \
template <typename FR>                                  \
AST_X< OUT > xword(const AST_Node< IN >& x,             \
                   const AST_Node< OUT >& dummy) {      \
    return AST_X< OUT >(x);                             \
}                                                       \
template <typename FR>                                  \
AST_X< OUT >* _xword(const AST_Node< IN >& x,           \
                     const AST_Node< OUT >& dummy) {    \
    return new AST_X< OUT >(x);                         \
}

    DEFN_XWORD(Alg_uint32<FR>, Alg_uint64<FR>)
    DEFN_XWORD(Alg_uint64<FR>, Alg_uint32<FR>)
    DEFN_XWORD(Alg_bool<FR>, Alg_uint8<FR>)
    DEFN_XWORD(Alg_bool<FR>, Alg_uint32<FR>)
    DEFN_XWORD(Alg_bool<FR>, Alg_uint64<FR>)
    DEFN_XWORD(Alg_bool<FR>, Alg_BigInt<FR>)
    DEFN_XWORD(Alg_bool<FR>, Alg_Field<FR>)

#undef DEFN_XWORD

////////////////////////////////////////////////////////////////////////////////
// conditional operator (ternary)
//

#define DEFN_TERNARY_UINT(N)                                            \
template <typename FR>                                                  \
AST_Op<Alg_uint ## N <FR>> ternary(                                     \
    const AST_Node<Alg_bool<FR>>& b,                                    \
    const AST_Node<Alg_uint ## N <FR>>& x,                              \
    const AST_Node<Alg_uint ## N<FR>>& y)                               \
{                                                                       \
    return BitwiseAST<Alg_uint ## N <FR>>::ternary(b, x, y);            \
}                                                                       \
template <typename FR>                                                  \
AST_Op<Alg_uint ## N <FR>>* _ternary(                                   \
    const AST_Node<Alg_bool<FR>>& b,                                    \
    const AST_Node<Alg_uint ## N <FR>>& x,                              \
    const AST_Node<Alg_uint ## N<FR>>& y)                               \
{                                                                       \
    return BitwiseAST<Alg_uint ## N <FR>>::_ternary(b, x, y);           \
}

    DEFN_TERNARY_UINT(8)
    DEFN_TERNARY_UINT(32)
    DEFN_TERNARY_UINT(64)

#undef DEFN_TERNARY_UINT

#define DEFN_TERNARY_SCALAR(T, AS)                              \
template <typename FR>                                          \
AST_Op<Alg_ ## T <FR>> ternary(                                 \
    const AST_Node<Alg_bool<FR>>& b,                            \
    const AST_Node<Alg_ ## T <FR>>& x,                          \
    const AST_Node<Alg_ ## T <FR>>& y)                          \
{                                                               \
    return AST_Op<Alg_ ## T <FR>>(                              \
        Alg_ ## T <FR>::OpType::ADD,                            \
        new AST_Op<Alg_ ## T <FR>>(Alg_ ## T <FR>::OpType::MUL, \
                                   x,                           \
                                   _as_ ## AS (b)),             \
        new AST_Op<Alg_ ## T <FR>>(Alg_ ## T <FR>::OpType::MUL, \
                                   y,                           \
                                   _as_ ## AS (~b)));           \
}                                                               \
template <typename FR>                                          \
AST_Op<Alg_ ## T <FR>>* _ternary(                               \
    const AST_Node<Alg_bool<FR>>& b,                            \
    const AST_Node<Alg_ ## T <FR>>& x,                          \
    const AST_Node<Alg_ ## T <FR>>& y)                          \
{                                                               \
    return new AST_Op<Alg_ ## T <FR>>(                          \
        Alg_ ## T <FR>::OpType::ADD,                            \
        new AST_Op<Alg_ ## T <FR>>(Alg_ ## T <FR>::OpType::MUL, \
                                   x,                           \
                                   _as_ ## AS (b)),             \
        new AST_Op<Alg_ ## T <FR>>(Alg_ ## T <FR>::OpType::MUL, \
                                   y,                           \
                                   _as_ ## AS (~b)));           \
}

    DEFN_TERNARY_SCALAR(BigInt, bigint)
    DEFN_TERNARY_SCALAR(Field, field)

#undef DEFN_TERNARY_SCALAR

std::uint8_t ternary(const bool b, const std::uint8_t x, const std::uint8_t y);
std::uint32_t ternary(const bool b, const std::uint32_t x, const std::uint32_t y);
std::uint64_t ternary(const bool b, const std::uint64_t x, const std::uint64_t y);

template <mp_size_t N>
snarklib::BigInt<N> ternary(
    const bool b,
    const snarklib::BigInt<N>& x,
    const snarklib::BigInt<N>& y)
{
    return b ? x : y;
}

template <typename T, std::size_t N>
snarklib::Field<T, N> ternary(
    const bool b,
    const snarklib::Field<T, N>& x,
    const snarklib::Field<T, N>& y)
{
    return b ? x : y;
}

template <typename B, typename T, std::size_t N>
std::array<T, N> ternary_array(const B& b,
                               const std::array<T, N>& x,
                               const std::array<T, N>& y)
{
    std::array<T, N> result;

    for (std::size_t i = 0; i < N; ++i) {
        result[i] = ternary(b, x[i], y[i]);
    }

    return result;
}

#define DEFN_TERNARY_ARRAY(T, B, V)             \
template <T std::size_t N>                      \
std::array<V, N> ternary(                       \
    const B& b,                                 \
    const std::array<V, N>& x,                  \
    const std::array<V, N>& y)                  \
{                                               \
    return ternary_array(b, x, y);              \
}

#define COMMA ,

    DEFN_TERNARY_ARRAY(typename FR COMMA, AST_Node<Alg_bool<FR>>, AST_Var<Alg_uint8<FR>>)
    DEFN_TERNARY_ARRAY(typename FR COMMA, AST_Node<Alg_bool<FR>>, AST_Var<Alg_uint32<FR>>)
    DEFN_TERNARY_ARRAY(typename FR COMMA, AST_Node<Alg_bool<FR>>, AST_Var<Alg_uint64<FR>>)
    DEFN_TERNARY_ARRAY(typename FR COMMA, AST_Node<Alg_bool<FR>>, AST_Var<Alg_BigInt<FR>>)
    DEFN_TERNARY_ARRAY(typename FR COMMA, AST_Node<Alg_bool<FR>>, AST_Var<Alg_Field<FR>>)
    DEFN_TERNARY_ARRAY(, bool, std::uint8_t)
    DEFN_TERNARY_ARRAY(, bool, std::uint32_t)
    DEFN_TERNARY_ARRAY(, bool, std::uint64_t)
    DEFN_TERNARY_ARRAY(mp_size_t M COMMA, bool, snarklib::BigInt<M>)
    DEFN_TERNARY_ARRAY(typename T COMMA std::size_t M COMMA, bool, snarklib::Field<T COMMA M>)

#undef COMMA

#undef DEFN_TERNARY_ARRAY

} // namespace snarkfront

#endif
