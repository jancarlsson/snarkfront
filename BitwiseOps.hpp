#ifndef _SNARKFRONT_BITWISE_OPS_HPP_
#define _SNARKFRONT_BITWISE_OPS_HPP_

#include <climits>
#include "AST.hpp"

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// operations on built-in integer types
// (templated hash algorithm parameter)
//
// (T, U) is (uint32_t, uint64_t)
//        or (uint64_t, uint32_t)
//

template <typename T, typename U>
class BitwiseINT
{
public:
    // bitwise logical operations
    static T AND(const T x, const T y) { return x & y; }
    static T _AND(const T x, const T y) { return AND(x, y); }
    static T OR(const T x, const T y) { return x | y; }
    static T _OR(const T x, const T y) { return OR(x, y); }
    static T XOR(const T x, const T y) { return x ^ y; }
    static T _XOR(const T x, const T y) { return XOR(x, y); }
    static T CMPLMNT(const T x) { return ~x; }
    static T _CMPLMNT(const T x) { return CMPLMNT(x); }

    // modulo addition
    static T ADDMOD(const T x, const T y) { return x + y; }
    static T _ADDMOD(const T x, const T y) { return ADDMOD(x, y); }
        
    // bitwise shift
    static T SHL(const T x, const unsigned int n) { return x << n; }
    static T _SHL(const T x, const unsigned int n) { return SHL(x, n); }
    static T SHR(const T x, const unsigned int n) { return x >> n; }
    static T _SHR(const T x, const unsigned int n) { return SHR(x, n); }

    // bitwise rotate
    static T ROTL(const T x, const unsigned int n) {
        return OR(SHL(x, n), SHR(x, sizeof(T) * CHAR_BIT - n));
    }
    static T _ROTL(const T x, const unsigned int n) {
        return ROTL(x, n);
    }
    static T ROTR(const T x, const unsigned int n) {
        return OR(SHR(x, n), SHL(x, sizeof(T) * CHAR_BIT - n));
    }
    static T _ROTR(const T x, const unsigned int n) {
        return ROTR(x, n);
    }

    // literal value
    static T constant(const T x) { return x; }
    static T _constant(const T x) { return constant(x); }

    // converting between 32-bit and 64-bit
    static U xword(const T x) { return x; }
    static U _xword(const T x) { return xword(x); }
};

////////////////////////////////////////////////////////////////////////////////
// operations on AST nodes
// (templated hash algorithm parameter)
//
// (T, U) is (Alg_uint32, Alg_uint64)
//        or (Alg_uint64, Alg_uint32)
//

template <typename T, typename U>
class BitwiseAST
{
    // Note: Every member function is templated to accept both
    // reference and pointer arguments.

public:
    // bitwise complement
    template <typename X>
    static AST_Op<T> CMPLMNT(const X& x) {
        return AST_Op<T>(T::OpType::CMPLMNT, x);
    }
    template <typename X>
    static AST_Op<T>* _CMPLMNT(const X& x) {
        return new AST_Op<T>(T::OpType::CMPLMNT, x);
    }

#define DEFN_OPXY(NAME)                                         \
    template <typename X, typename Y>                           \
    static AST_Op<T> NAME (const X& x, const Y& y) {            \
        return objOp(T::OpType:: NAME , x, y);                  \
    }                                                           \
    template <typename X, typename Y>                           \
    static AST_Op<T>* _ ## NAME (const X& x, const Y& y) {      \
        return ptrOp(T::OpType:: NAME , x, y);                  \
    }

    // AND, OR, XOR, ADDMOD
    DEFN_OPXY(AND)
    DEFN_OPXY(OR)
    DEFN_OPXY(XOR)
    DEFN_OPXY(ADDMOD)

#undef DEFN_OPXY

#define DEFN_OPXN(NAME)                                                 \
    template <typename X>                                               \
    static AST_Op<T> NAME (const X& x, const unsigned int n) {          \
        return objOp(T::OpType:: NAME , x, _constant(n));               \
    }                                                                   \
    template <typename X>                                               \
    static AST_Op<T>* _ ## NAME (const X& x, const unsigned int n) {    \
        return ptrOp(T::OpType:: NAME , x, _constant(n));               \
    }

    // SHL, SHR, ROTL, ROTR
    DEFN_OPXN(SHL)
    DEFN_OPXN(SHR)
    DEFN_OPXN(ROTL)
    DEFN_OPXN(ROTR)

#undef DEFN_OPXN

    // literal value
    template <typename X>
    static AST_Const<T> constant(const X& x) { return AST_Const<T>(x); }

    template <typename X>
    static AST_Const<T>* _constant(const X& x) { return new AST_Const<T>(x); }

    // converting between 32-bit and 64-bit
    template <typename X>
    static AST_X<U> xword(const X& x) { return AST_X<U>(x); }

    template <typename X>
    static AST_X<U> _xword(const X& x) { return new AST_X<U>(x); }

private:
    // AST nodes at statement scope are on stack
    template <typename X, typename Y>
    static AST_Op<T> objOp(const typename T::OpType op, const X& x, const Y& y) {
        return AST_Op<T>(op, x, y);
    }

    // AST nodes nested below statement scope are on the heap
    template <typename X, typename Y>
    static AST_Op<T>* ptrOp(const typename T::OpType op, const X& x, const Y& y) {
        return new AST_Op<T>(op, x, y);
    }
};

} // namespace snarkfront

#endif
