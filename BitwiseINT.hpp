#ifndef _SNARKFRONT_BITWISE_INT_HPP_
#define _SNARKFRONT_BITWISE_INT_HPP_

#include <cassert>
#include <climits>

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// operations on built-in integer types
// (templated algorithm parameter)
//
// T is: uint8_t, uint32_t, uint64_t
//

template <typename T>
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
#ifdef USE_ASSERT
        assert(n <= sizeof(T) * CHAR_BIT);
#endif
        return OR(SHL(x, n),
                  SHR(x, sizeof(T) * CHAR_BIT - n));
    }

    static T _ROTL(const T x, const unsigned int n) {
        return ROTL(x, n);
    }

    static T ROTR(const T x, const unsigned int n) {
#ifdef USE_ASSERT
        assert(n <= sizeof(T) * CHAR_BIT);
#endif
        return OR(SHR(x, n),
                  SHL(x, sizeof(T) * CHAR_BIT - n));
    }

    static T _ROTR(const T x, const unsigned int n) {
        return ROTR(x, n);
    }

    // literal value
    static T constant(const T x) { return x; }
    static T _constant(const T x) { return constant(x); }

    // conversion between unsigned integer types
    template <typename U>
    static U xword(const T x, const U& dummy) { return x; }

    template <typename U>
    static U _xword(const T x, const U& dummy) { return xword(x, dummy); }

    // all mask bits take value of same bool
    static T bitmask(const bool b) { return b ? -1 : 0; }
    static T _bitmask(const bool b) { return bitmask(b); }

    // ternary
    static T ternary(const bool b, const T x, const T y) { return b ? x : y; }
    static T _ternary(const bool b, const T x, const T y) { return ternary(b, x, y); }

    // test bit
    static bool testbit(const T x, const unsigned int n) {
#ifdef USE_ASSERT
        assert(n < sizeof(T) * CHAR_BIT);
#endif
        return AND(x, SHL(1, n));
    }

    static bool _testbit(const T x, const unsigned int n) {
        return testbit(x, n);
    }

    // multiplication by x in GF(2^n)
    static T xtime(const T a, const T modpoly) {
        return testbit(a, sizeof(T) * CHAR_BIT - 1)
            ? XOR(SHL(a, 1), modpoly)
            : SHL(a, 1);
    }

    static T _xtime(const T a, const T modpoly) {
        return _xtime(a, modpoly);
    }

    // multiplication in GF(2^n)
    static T multiply(const T x, const T y, const T modpoly) {
        T xtmp = x, ytmp = y, xorsum = 0;
        while (ytmp) {
            if (testbit(ytmp, 0)) xorsum = XOR(xorsum, xtmp);
            ytmp = SHR(ytmp, 1);
            xtmp = xtime(xtmp, modpoly);
        }
        return xorsum;
    }

    static T _multiply(const T x, const T y, const T modpoly) {
        return multiply(x, y, modpoly);
    }
};

} // namespace snarkfront

#endif
