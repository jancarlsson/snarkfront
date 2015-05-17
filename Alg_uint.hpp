#ifndef _SNARKFRONT_ALG_UINT_HPP_
#define _SNARKFRONT_ALG_UINT_HPP_

#include <algorithm>
#include <cassert>

#include <snarkfront/Alg.hpp>
#include <snarkfront/Alg_internal.hpp>

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// Alg_uint8
// Alg_uint32
// Alg_uint64
//

template <typename ALG>
void evalStackOp_Bitwise(std::stack<ALG>& S, const BitwiseOps op)
{
    typedef typename ALG::ValueType Value;
    typedef typename ALG::FrType Fr;
    typedef typename ALG::R1T R1T;
    auto& RS = TL<R1C<Fr>>::singleton();

    typedef BitwiseINT<Value> BitOps;

    // y is right argument
    const auto R = S.top();
    S.pop();
    const Value yvalue = R.value();
    const Fr ywitness = R.witness();

    // modulo addition
    if (BitwiseOps::ADDMOD == op) {
        // x is left argument
        const auto L = S.top();
        S.pop();
        const Value xvalue = L.value();
        const Fr xwitness = L.witness();

        // left argument
        R1T x;
        Fr x_witness;
        Value xhigh, xlow;
        std::size_t xhighCnt;
        if (L.splitBits().size() < 2 * sizeBits(xvalue)) {
            x_witness = xwitness;
            x = RS->argScalar(L);

            const std::vector<int> xrem = bitsValue(xlow, L.splitBits());
            bitsValue(xhigh, xrem);
            xhighCnt = xrem.size();

#ifdef USE_ASSERT
            assert(xlow == xvalue);
            assert(xhighCnt < sizeBits(xvalue));
#endif

        } else {
            x_witness = ALG::valueToString(xvalue);
            const std::vector<R1T> xbits = RS->argBits(L);
            const std::vector<R1T> xfit = rank1_xword(xbits, sizeBits(xvalue));
            x = RS->bitsToWitness(xfit, x_witness);

            xlow = xvalue;
            xhigh = 0;
            xhighCnt = 0;
        }

        // right argument
        R1T y;
        Fr y_witness;
        Value yhigh, ylow;
        std::size_t yhighCnt;
        if (R.splitBits().size() < 2 * sizeBits(yvalue)) {
            y_witness = ywitness;
            y = RS->argScalar(R);

            const std::vector<int> yrem = bitsValue(ylow, R.splitBits());
            bitsValue(yhigh, yrem);
            yhighCnt = yrem.size();

#ifdef USE_ASSERT
            assert(ylow == yvalue);
            assert(yhighCnt < sizeBits(yvalue));
#endif

        } else {
            y_witness = ALG::valueToString(yvalue);
            const std::vector<R1T> ybits = RS->argBits(R);
            const std::vector<R1T> yfit = rank1_xword(ybits, sizeBits(yvalue));
            y = RS->bitsToWitness(yfit, y_witness);

            ylow = yvalue;
            yhigh = 0;
            yhighCnt = 0;
        }

        // overflow addition
        Value high = xhigh + yhigh, low = xlow;
        addover(high, low, ylow);

        const Value zvalue = BitOps::ADDMOD(xvalue, yvalue);
#ifdef USE_ASSERT
        assert(zvalue == low);
#endif

        std::vector<int> zbits = valueBits(low);
        for (std::size_t i = 0; i < xhighCnt + yhighCnt + 1; ++i) {
            zbits.push_back(high & 0x1);
            high >>= 1;
        }
#ifdef USE_ASSERT
        assert(0 == high);
#endif

        const Fr zwitness = x_witness + y_witness;
        const R1T z = RS->createResult(op, x, y, zwitness);

        S.push(
            ALG(zvalue, zwitness, zbits, {z}));

    } else if (BitwiseOps::CMPLMNT == op) {
        // y is only argument
        const std::vector<R1T> y = RS->argBits(R);
#ifdef USE_ASSERT
        assert(y.size() >= sizeBits(yvalue));
        assert(y.size() == R.splitBits().size());
#endif

        // z is result
        const Value zvalue = BitOps::CMPLMNT(yvalue);

        std::vector<int> zbits;
        std::vector<R1T> z;
        zbits.reserve(sizeBits(zvalue));
        z.reserve(sizeBits(zvalue));
        for (std::size_t i = 0; i < sizeBits(zvalue); ++i) {
            const bool b = ! R.splitBits()[i];
            zbits.push_back(b);
            z.emplace_back(
                RS->createResult(op, y[i], y[i], boolTo<Fr>(b)));
        }
#ifdef USE_ASSERT
        assert(zbits == valueBits(zvalue));
#endif

        S.push(
            ALG(zvalue, ALG::valueToString(zvalue), zbits, z));

    } else {
        // x is left argument
        const auto L = S.top();
        S.pop();
        const Value xvalue = L.value();
        const Fr xwitness = L.witness();

        const std::vector<R1T> x = RS->argBits(L);
#ifdef USE_ASSERT
        assert(x.size() >= sizeBits(xvalue));
#endif

        // z is result
        const Value zvalue = evalOp(op, xvalue, yvalue);

        std::vector<R1T> z;
        z.reserve(sizeBits(zvalue));

        if (isPermute(op)) {
            const std::vector<R1T> xfit = rank1_xword(x, sizeBits(xvalue));
            z = RS->permuteBits(op, xfit, yvalue);

        } else {
            const std::vector<R1T> y = RS->argBits(R);
#ifdef USE_ASSERT
            assert(y.size() >= sizeBits(yvalue));
#endif

            Value mask = 0x1;
            for (std::size_t i = 0; i < sizeBits(zvalue); ++i) {
                z.emplace_back(
                    RS->createResult(op, x[i], y[i], boolTo<Fr>(zvalue & mask)));

                mask <<= 1;
            }
        }

        S.push(
            ALG(zvalue, ALG::valueToString(zvalue), valueBits(zvalue), z));
    }
}

template <typename FR>
void evalStackOp(std::stack<Alg_uint8<FR>>& S, const BitwiseOps op) {
    evalStackOp_Bitwise<Alg_uint8<FR>>(S, op);
}

template <typename FR>
void evalStackOp(std::stack<Alg_uint32<FR>>& S, const BitwiseOps op) {
    evalStackOp_Bitwise<Alg_uint32<FR>>(S, op);
}

template <typename FR>
void evalStackOp(std::stack<Alg_uint64<FR>>& S, const BitwiseOps op) {
    evalStackOp_Bitwise<Alg_uint64<FR>>(S, op);
}

template <typename FR>
void evalStackCmp(std::stack<Alg_uint8<FR>>& S, const EqualityCmp op) {
    evalStackCmp_Equality(S, op);
}

template <typename FR>
void evalStackCmp(std::stack<Alg_uint32<FR>>& S, const EqualityCmp op) {
    evalStackCmp_Equality(S, op);
}

template <typename FR>
void evalStackCmp(std::stack<Alg_uint64<FR>>& S, const EqualityCmp op) {
    evalStackCmp_Equality(S, op);
}

} // namespace snarkfront

#endif
