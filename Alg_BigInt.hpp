#ifndef _SNARKFRONT_ALG_BIGINT_HPP_
#define _SNARKFRONT_ALG_BIGINT_HPP_

#include <gmp.h>
#include "Alg.hpp"
#include "BigIntOps.hpp"

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// Alg_BigInt
//

template <typename FR>
void evalStackOp(std::stack<Alg_BigInt<FR>>& S, const ScalarOps op)
{
    typedef typename Alg_BigInt<FR>::ValueType Value;
    typedef typename Alg_BigInt<FR>::R1T R1T;
    auto& RS = TL<R1C<FR>>::singleton();

    // y is right argument
    const auto R = S.top();
    S.pop();
    const Value yvalue = R.value();
    const FR ywitness = R.witness();
    const R1T y = RS->argScalar(R);

    // x is left argument
    const auto L = S.top();
    S.pop();
    const Value xvalue = L.value();
    const FR xwitness = L.witness();
    const R1T x = RS->argScalar(L);

    // z is result
    const Value zvalue = evalOp(op, xvalue, yvalue);
    const FR zwitness = evalOp(op, xwitness, ywitness);
    const R1T z = RS->createResult(op, x, y, zwitness);

    S.push(
        Alg_BigInt<FR>(zvalue, zwitness, valueBits(zvalue), {z}));
}

template <typename FR>
void evalStackCmp(std::stack<Alg_BigInt<FR>>& S, const ScalarCmp op)
{
    typedef typename Alg_BigInt<FR>::ValueType Value;
    typedef typename Alg_BigInt<FR>::R1T R1T;
    auto& RS = TL<R1C<FR>>::singleton();
    auto& POW2 = TL<PowersOf2<FR>>::singleton();

    // y is right argument
    const auto R = S.top();
    S.pop();
    const Value yvalue = R.value();
    const FR ywitness = R.witness();
    const R1T y = RS->argScalar(R);

    // x is left argument
    const auto L = S.top();
    S.pop();
    const Value xvalue = L.value();
    const FR xwitness = L.witness();
    const R1T x = RS->argScalar(L);

    // for BigInt
    const mp_size_t N = Value::numberLimbs();
    const std::size_t N127 = sizeBits(yvalue) - 1;
    static const Value ovalue = powerBigInt<N>(N127); // half of max value

    // offset is half of maximum value (127 bits)
    const FR owitness = POW2->getNumber(N127);
    const R1T o = RS->createConstant(owitness);

    // simpler to handle LT(x, y) as GT(y, x)
    //               and LE(x, y) as GE(y, x)
    // which means offset + y - x
    //  instead of offset + x - y
    const bool interchangeXY = (ScalarCmp::LT == op || ScalarCmp::LE == op);

    // offset + x (or offset + y)
    const Value oxvalue = ovalue + (interchangeXY ? yvalue : xvalue);
    const FR oxwitness = owitness + (interchangeXY ? ywitness : xwitness);
    const R1T ox = RS->createResult(ScalarOps::ADD,
                                    o,
                                    interchangeXY ? y : x,
                                    oxwitness);

    // offset + x - y (or offset + y - x)
    const Value oxyvalue = oxvalue - (interchangeXY ? xvalue : yvalue);
    const FR oxywitness = oxwitness - (interchangeXY ? xwitness : ywitness);
    const R1T oxy = RS->createResult(ScalarOps::SUB,
                                     ox,
                                     interchangeXY ? x : y,
                                     oxywitness);

    // constraint variable bit representation of offset + x - y (or offset + y - x)
    const std::vector<int> oxy_splitBits = valueBits(oxyvalue);
    const std::vector<R1T> oxybits = RS->witnessToBits(oxy, oxy_splitBits);
    const bool high_witness = oxy_splitBits[N127];
    const R1T& high_bit = oxybits[N127];

    // z is result
    const bool result = evalOp(op, xvalue, yvalue);
    const Value zvalue = powerBigInt<N>(result);
    const FR zwitness = boolTo<FR>(result);
    R1T z;

    switch (op) {
    case (ScalarCmp::EQ) :
        // if x == y, then offset + x - y == offset == high_bit
        // so all low bits should be clear and high bit set
        {
            std::vector<R1T> bits;
            bits.reserve(sizeBits(yvalue));

            // all low bits should be clear
            for (std::size_t i = 0; i < N127; ++i) {
                bits.emplace_back(oxybits[i]);
            }

            // complement of high bit should be clear
            const bool b = evalOp(LogicalOps::CMPLMNT, high_witness, high_witness);
            bits.emplace_back(
                RS->createResult(LogicalOps::CMPLMNT,
                                 high_bit,
                                 high_bit,
                                 boolTo<FR>(b)));

            // all bits must be clear
            z = RS->safeNOR(bits);
        }
        break;

    case (ScalarCmp::NEQ) :
        // if x != y, then offset + x - y != offset == high_bit
        // so some low bit should be set or the high bit clear
        {
            std::vector<int> witness;
            std::vector<R1T> bits;
            witness.reserve(sizeBits(yvalue));
            bits.reserve(sizeBits(yvalue));

            // low bits
            for (std::size_t i = 0; i < N127; ++i) {
                witness.push_back(oxy_splitBits[i]);
                bits.emplace_back(oxybits[i]);
            }

            // complement of high bit
            const bool b = evalOp(LogicalOps::CMPLMNT, high_witness, high_witness);
            witness.push_back(b);
            bits.emplace_back(
                RS->createResult(LogicalOps::CMPLMNT,
                                 high_bit,
                                 high_bit,
                                 boolTo<FR>(b)));

            z = RS->safeOR(bits, witness);
        }
        break;

    case (ScalarCmp::LT) : // interchanged X and Y so same as GT
        // if x < y, then offset + x - y < offset == high_bit
        // so high bit should be clear and some low bit set
    case (ScalarCmp::GT) :
        // if x > y, then offset + x - y > offset == high_bit
        // so high bit should be set and some low bit should also be set
        {
            std::vector<int> low_witness;
            std::vector<R1T> low_bits;
            low_witness.reserve(sizeBits(yvalue));
            low_bits.reserve(sizeBits(yvalue));

            // low bits
            for (std::size_t i = 0; i < N127; ++i) {
                low_witness.push_back(oxy_splitBits[i]);
                low_bits.emplace_back(oxybits[i]);
            }

            // last bit is duplicate to make vector even power of 2
            low_witness.push_back(low_witness[0]);
            low_bits.emplace_back(low_bits[0]);

            const R1T low_bit_set = RS->safeOR(low_bits, low_witness);
            z = RS->createResult(LogicalOps::AND, high_bit, low_bit_set, zwitness);
        }
        break;

    case (ScalarCmp::LE) : // interchanged X and Y so same as GE
        // if x <= y, then offset + x - y <= offset == high_bit
        // so there are two cases:
        // some low bit is set and high bit clear (less than)
        // low bits are clear and high bit is set (equal)
    case (ScalarCmp::GE) :
        // if x >= y, then offset + x - y >= offset == high_bit
        // so high bit should be set (ignore low bits)
        z = high_bit;
        break;
    }

    S.push(
        Alg_BigInt<FR>(zvalue, zwitness, valueBits(zvalue), {z}));
}

} // namespace snarkfront

#endif
