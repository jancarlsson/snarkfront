#ifndef _SNARKFRONT_BITWISE_AST_HPP_
#define _SNARKFRONT_BITWISE_AST_HPP_

#include <array>
#include <cassert>
#include <climits>
#include <cstdint>

#include <snarkfront/Alg.hpp>
#include <snarkfront/AST.hpp>

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// operations on AST nodes
// (templated algorithm parameter)
//
// T is: Alg_uint8, Alg_uint32, Alg_uint64
//

template <typename T>
class BitwiseAST
{
    // Note: Every member function is templated to accept both
    // reference and pointer arguments.

    typedef typename T::ValueType VAL;
    typedef typename T::FrType FR;

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

    // AND, OR, XOR, ADDMOD, MULMOD
    DEFN_OPXY(AND)
    DEFN_OPXY(OR)
    DEFN_OPXY(XOR)
    DEFN_OPXY(ADDMOD)
    DEFN_OPXY(MULMOD)

#undef DEFN_OPXY

#define DEFN_SHIFT(NAME)                                                \
    template <typename X>                                               \
    static AST_Op<T> NAME (const X& x, const unsigned int n) {          \
        return objOp(T::OpType:: NAME , x, _constant(n));               \
    }                                                                   \
    template <typename X>                                               \
    static AST_Op<T>* _ ## NAME (const X& x, const unsigned int n) {    \
        return ptrOp(T::OpType:: NAME , x, _constant(n));               \
    }

    // SHL, SHR
    DEFN_SHIFT(SHL)
    DEFN_SHIFT(SHR)

#undef DEFN_SHIFT

    // ROTL
    template <typename X>
    static AST_Op<T> ROTL(const X& x, const unsigned int n) {
#ifdef USE_ASSERT
    assert(n <= sizeof(VAL) * CHAR_BIT);
#endif
        return objOp(T::OpType::ROTL, x, _constant(n));
    }

    template <typename X>
    static AST_Op<T>* _ROTL(const X& x, const unsigned int n) {
#ifdef USE_ASSERT
    assert(n <= sizeof(VAL) * CHAR_BIT);
#endif
        return ptrOp(T::OpType::ROTL, x, _constant(n));
    }

    // ROTR
    template <typename X>
    static AST_Op<T> ROTR(const X& x, const unsigned int n) {
#ifdef USE_ASSERT
    assert(n <= sizeof(VAL) * CHAR_BIT);
#endif
        return objOp(T::OpType::ROTR, x, _constant(n));
    }

    template <typename X>
    static AST_Op<T>* _ROTR(const X& x, const unsigned int n) {
#ifdef USE_ASSERT
    assert(n <= sizeof(VAL) * CHAR_BIT);
#endif
        return ptrOp(T::OpType::ROTR, x, _constant(n));
    }

    // literal value
    template <typename X>
    static AST_Const<T> constant(const X& x) { return AST_Const<T>(x); }

    template <typename X>
    static AST_Const<T>* _constant(const X& x) { return new AST_Const<T>(x); }

    // zero array
    template <typename X, std::size_t N>
    static std::array<AST_Const<T>, N> zero(const std::array<X, N>& dummy) {
        std::array<AST_Const<T>, N> a;
        for (auto& b : a) b = constant(0);
        return a;
    }

    // conversion between unsigned integer types
    template <typename X, typename U>
    static AST_X<U> xword(const X& x, const U& dummy) {
        return AST_X<U>(x);
    }

    template <typename X, typename U>
    static AST_X<U>* _xword(const X& x, const U& dummy) {
        return new AST_X<U>(x);
    }

    // conversion from bool
    template <typename B>
    static AST_X<T> xword(const B& x) {
        return AST_X<T>(x);
    }

    template <typename B>
    static AST_X<T>* _xword(const B& x) {
        return new AST_X<T>(x);
    }

    // negation
    template <typename X>
    static AST_Op<T> negate(const X& x) {
        return ADDMOD(
            _CMPLMNT(x),
            _constant(static_cast<VAL>(1)));
    }

    template <typename X>
    static AST_Op<T>* _negate(const X& x) {
        return _ADDMOD(
            _CMPLMNT(x),
            _constant(static_cast<VAL>(1)));
    }

    // logical NOT
    template <typename B>
    static AST_Op<Alg_bool<FR>> logicalNOT(const B& b) {
        return AST_Op<Alg_bool<FR>>(
            Alg_bool<FR>::OpType::CMPLMNT,
            b);
    }

    template <typename B>
    static AST_Op<Alg_bool<FR>>* _logicalNOT(const B& b) {
        return new AST_Op<Alg_bool<FR>>(
            Alg_bool<FR>::OpType::CMPLMNT,
            b);
    }

    // logical AND
    template <typename A, typename B>
    static AST_Op<Alg_bool<FR>> logicalAND(const A& a, const B& b) {
        return AST_Op<Alg_bool<FR>>(
            Alg_bool<FR>::OpType::AND,
            a,
            b);
    }

    template <typename A, typename B>
    static AST_Op<Alg_bool<FR>>* _logicalAND(const A& a, const B& b) {
        return new AST_Op<Alg_bool<FR>>(
            Alg_bool<FR>::OpType::AND,
            a,
            b);
    }

    // logical OR
    template <typename A, typename B>
    static AST_Op<Alg_bool<FR>> logicalOR(const A& a, const B& b) {
        return AST_Op<Alg_bool<FR>>(
            Alg_bool<FR>::OpType::OR,
            a,
            b);
    }

    template <typename A, typename B>
    static AST_Op<Alg_bool<FR>>* _logicalOR(const A& a, const B& b) {
        return new AST_Op<Alg_bool<FR>>(
            Alg_bool<FR>::OpType::OR,
            a,
            b);
    }

    // all mask bits take value of same bool
    template <typename B>
    static AST_X<T> bitmask(const B& b) {
        return AST_X<T>(b);
    }

    template <typename B>
    static AST_X<T>* _bitmask(const B& b) {
        return new AST_X<T>(b);
    }

    // ternary
    template <typename B, typename X, typename Y>
    static AST_Op<T> ternary(const B& b, const X& x, const Y& y) {
        // (x & xword(b)) | (y & ~xword(b))
        return OR(
            _AND(x, _bitmask(b)),
            _AND(y, _CMPLMNT(_bitmask(b))));
    }

    template <typename B, typename X, typename Y>
    static AST_Op<T>* _ternary(const B& b, const X& x, const Y& y) {
        // (x & xword(b)) | (y & ~xword(b))
        return _OR(
            _AND(x, _bitmask(b)),
            _AND(y, _CMPLMNT(_bitmask(b))));
    }

    // test bit
    template <typename X>
    static AST_X<Alg_bool<FR>> testbit(const X& x, const unsigned int n) {
#ifdef USE_ASSERT
        assert(n < sizeof(VAL) * CHAR_BIT);
#endif
        return AST_X<Alg_bool<FR>>(SHR(x, n));
    }

    template <typename X>
    static AST_X<Alg_bool<FR>>* _testbit(const X& x, const unsigned int n) {
#ifdef USE_ASSERT
        assert(n < sizeof(VAL) * CHAR_BIT);
#endif
        return new AST_X<Alg_bool<FR>>(SHR(x, n));
    }

    // look-up table
    template <typename X, std::size_t N>
    static AST_Op<T> lookuptable(const std::array<VAL, N>& a, const X& idx) {
        if (1 == N) {
            // returns value if index is 0, else all clear bits
            return AND(
                _constant(a[0]),
                _CMPLMNT(_bitmask(0 != idx)));

        } else {
            auto sum = _AND(
                _constant(a[0]),
                _CMPLMNT(_bitmask(0 != idx)));

            for (std::size_t i = 1; i < N - 1; ++i) {
                sum = _ADDMOD(
                    sum,
                    _AND(_constant(a[i]),
                         _CMPLMNT(_bitmask(i != idx))));
            }

            return ADDMOD(
                sum,
                _AND(_constant(a[N-1]),
                     _CMPLMNT(_bitmask((N-1) != idx))));
        }
    }

    template <typename X, std::size_t N>
    static AST_Op<T>* _lookuptable(const std::array<VAL, N>& a, const X& idx) {
        if (1 == N) {
            // returns value if index is 0, else all clear bits
            return _AND(
                _constant(a[0]),
                _CMPLMNT(_bitmask(0 != idx)));

        } else {
            auto sum = _AND(
                _constant(a[0]),
                _CMPLMNT(_bitmask(0 != idx)));

            for (std::size_t i = 1; i < N - 1; ++i) {
                sum = _ADDMOD(
                    sum,
                    _AND(_constant(a[i]),
                         _CMPLMNT(_bitmask(i != idx))));
            }

            return _ADDMOD(
                sum,
                _AND(_constant(a[N-1]),
                     _CMPLMNT(_bitmask((N-1) != idx))));
        }
    }

    // array subscript
    template <typename X, typename Y, std::size_t N>
    static AST_Op<T> arraysubscript(const std::array<Y, N>& a, const X& idx) {
        if (1 == N) {
            // returns value if index is 0, else all clear bits
            return AND(a[0], _CMPLMNT(_bitmask(0 != idx)));

        } else {
            auto sum = _AND(a[0], _CMPLMNT(_bitmask(0 != idx)));

            for (std::size_t i = 1; i < N - 1; ++i) {
                sum = _ADDMOD(sum, _AND(a[i], _CMPLMNT(_bitmask(i != idx))));
            }

            return ADDMOD(sum, _AND(a[N-1], _CMPLMNT(_bitmask((N-1) != idx))));
        }
    }

    template <typename X, typename Y, std::size_t N>
    static AST_Op<T>* _arraysubscript(const std::array<Y, N>& a, const X& idx) {
        if (1 == N) {
            // returns value if index is 0, else all clear bits
            return _AND(a[0], _CMPLMNT(_bitmask(0 != idx)));

        } else {
            auto sum = _AND(a[0], _CMPLMNT(_bitmask(0 != idx)));

            for (std::size_t i = 1; i < N - 1; ++i) {
                sum = _ADDMOD(sum, _AND(a[i], _CMPLMNT(_bitmask(i != idx))));
            }

            return _ADDMOD(sum, _AND(a[N-1], _CMPLMNT(_bitmask((N-1) != idx))));
        }
    }

    // multiplication by x in GF(2^n)
    template <typename X, typename M>
    static AST_Op<T> xtime(const X& a, const M& modpoly) {
        return XOR(
            _SHL(a, 1),
            _AND(modpoly, _bitmask(testbit(a, sizeof(VAL) * CHAR_BIT - 1))));
    }

    template <typename X, typename M>
    static AST_Op<T>* _xtime(const X& a, const M& modpoly) {
        return _XOR(
            _SHL(a, 1),
            _AND(modpoly, _bitmask(testbit(a, sizeof(VAL) * CHAR_BIT - 1))));
    }

    // multiplication by GF(2^n)
    template <typename X, typename Y, typename M>
    static AST_Op<T> multiply(const X& a, const Y& b, const M& modpoly) {
        return XOR(multiply_internal(a, b, modpoly),
                   _AND(a, bitmask(testbit(b, 0))));
    }

    template <typename X, typename Y, typename M>
    static AST_Op<T>* _multiply(const X& a, const Y& b, const M& modpoly) {
        return _XOR(multiply_internal(a, b, modpoly),
                    _AND(a, bitmask(testbit(b, 0))));
    }

private:
    template <typename X, typename Y, typename M>
    static AST_Op<T>* multiply_internal(const X& a, const Y& b, const M& modpoly) {
        constexpr std::size_t N = sizeof(VAL) * CHAR_BIT;

        // multiplication by x in GF(2^n) for each bit position in b
        std::array<AST_Op<T>*, N> xtmp;
        xtmp[1] = _xtime(a, modpoly);
        for (std::size_t i = 2; i < N; ++i) {
            xtmp[i] = _xtime(xtmp[i - 1], modpoly);
        }

        // apply bits of b
        std::array<AST_Op<T>*, N> btmp;
        for (std::size_t i = 1; i < N; ++i) {
            btmp[i] = _AND(xtmp[i], _bitmask(testbit(b, i)));
        }

        // sum components up to last one
        auto* xorsum = btmp[N - 1];
        for (std::size_t i = N - 2; i > 0; --i) {
            xorsum = _XOR(xorsum, btmp[i]);
        }

        return xorsum;
    }

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
