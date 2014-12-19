#ifndef _SNARKFRONT_ALG_UINT_HPP_
#define _SNARKFRONT_ALG_UINT_HPP_

#include <algorithm>
#include <cassert>
#include "Alg.hpp"

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// Alg_uint32
// Alg_uint64
//

template <typename ALG, typename U>
void evalStackOp_internal(std::stack<ALG>& S, const BitwiseOps op)
{
    typedef typename ALG::ValueType Value;
    typedef typename ALG::FrType Fr;
    typedef typename ALG::R1T R1T;
    auto& RS = TL<R1C<Fr>>::singleton();

    typedef BitwiseINT<Value, U> BitOps;

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

            assert(xlow == xvalue);
            assert(xhighCnt < sizeBits(xvalue));

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

            assert(ylow == yvalue);
            assert(yhighCnt < sizeBits(yvalue));

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
        assert(zvalue == low);

        std::vector<int> zbits = valueBits(low);
        for (std::size_t i = 0; i < xhighCnt + yhighCnt + 1; ++i) {
            zbits.push_back(high & 0x1);
            high >>= 1;
        }
        assert(0 == high);

        const Fr zwitness = x_witness + y_witness;
        const R1T z = RS->createResult(op, x, y, zwitness);

        S.push(
            ALG(zvalue, zwitness, zbits, {z}));

    } else if (BitwiseOps::CMPLMNT == op) {
        // y is only argument
        const std::vector<R1T> y = RS->argBits(R);
        assert(y.size() >= sizeBits(yvalue));
        assert(y.size() == R.splitBits().size());

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
        assert(zbits == valueBits(zvalue));

        S.push(
            ALG(zvalue, ALG::valueToString(zvalue), zbits, z));

    } else {
        // x is left argument
        const auto L = S.top();
        S.pop();
        const Value xvalue = L.value();
        const Fr xwitness = L.witness();

        const std::vector<R1T> x = RS->argBits(L);
        assert(x.size() >= sizeBits(xvalue));

        // z is result
        const Value zvalue = evalOp(op, xvalue, yvalue);

        std::vector<R1T> z;
        z.reserve(sizeBits(zvalue));

        if (isPermute(op)) {
            const std::vector<R1T> xfit = rank1_xword(x, sizeBits(xvalue));
            z = RS->permuteBits(op, xfit, yvalue);

        } else {
            const std::vector<R1T> y = RS->argBits(R);
            assert(y.size() >= sizeBits(yvalue));

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
void evalStackOp(std::stack<Alg_uint32<FR>>& S, const BitwiseOps op)
{
    evalStackOp_internal<Alg_uint32<FR>, std::uint64_t>(S, op);
}

template <typename FR>
void evalStackOp(std::stack<Alg_uint64<FR>>& S, const BitwiseOps op)
{
    evalStackOp_internal<Alg_uint64<FR>, std::uint32_t>(S, op);
}

template <typename ALG>
void evalStackCmp_internal(std::stack<ALG>& S, const EqualityCmp op)
{
    typedef typename ALG::ValueType Value;
    typedef typename ALG::FrType Fr;
    typedef typename ALG::R1T R1T;
    auto& RS = TL<R1C<Fr>>::singleton();
    auto& POW2 = TL<PowersOf2<Fr>>::singleton();

    // y is right argument
    const auto R = S.top();
    S.pop();
    const Value yvalue = R.value();
    const std::vector<int> ybits = R.splitBits();
    const std::vector<R1T> y = RS->argBits(R);

    assert(y.size() >= sizeBits(yvalue));

    // x is left argument
    const auto L = S.top();
    S.pop();
    const Value xvalue = L.value();
    const std::vector<int> xbits = L.splitBits();
    const std::vector<R1T> x = RS->argBits(L);

    assert(x.size() >= sizeBits(xvalue));

    // intermediate constraint variables for each bit
    std::vector<R1T> zvec;
    std::vector<int> zwitness;
    zvec.reserve(sizeBits(yvalue));
    zwitness.reserve(sizeBits(yvalue));
    for (std::size_t i = 0; i < sizeBits(yvalue); ++i) {
        const bool b = evalOp(op, xbits[i], ybits[i]);
        zwitness.push_back(b);
        zvec.emplace_back(
            RS->createResult(eqToLogical(op), x[i], y[i], boolTo<Fr>(b)));
    }

    // z is result
    const Value zvalue = evalOp(op, xvalue, yvalue);
    const R1T z = EqualityCmp::EQ == op
        ? RS->safeAND(zvec) // all must be same
        : RS->safeOR(zvec, zwitness); // one must be different

    S.push(
        ALG(zvalue, boolTo<Fr>(zvalue), valueBits(zvalue), {z}));
}

template <typename FR>
void evalStackCmp(std::stack<Alg_uint32<FR>>& S, const EqualityCmp op)
{
    evalStackCmp_internal(S, op);
}

template <typename FR>
void evalStackCmp(std::stack<Alg_uint64<FR>>& S, const EqualityCmp op)
{
    evalStackCmp_internal(S, op);
}

} // namespace snarkfront

#endif
