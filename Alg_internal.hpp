#ifndef _SNARKFRONT_ALG_INTERNAL_HPP_
#define _SNARKFRONT_ALG_INTERNAL_HPP_

#include <cassert>
#include <cstdint>
#include <stack>
#include <vector>

#include <snarkfront/Alg.hpp>
#include <snarkfront/EnumOps.hpp>

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// used by:
// - Alg_BigInt
// - Alg_Field
//

template <typename ALG, typename OPS>
void evalStackOp_internal(std::stack<ALG>& S, const OPS op)
{
    typedef typename ALG::ValueType Value;
    typedef typename ALG::FrType Fr;
    typedef typename ALG::R1T R1T;
    auto& RS = TL<R1C<Fr>>::singleton();

    // y is right argument
    const auto R = S.top();
    S.pop();
    const Value yvalue = R.value();
    const Fr ywitness = R.witness();
    const R1T y = RS->argScalar(R);

    // x is left argument
    const auto L = S.top();
    S.pop();
    const Value xvalue = L.value();
    const Fr xwitness = L.witness();
    const R1T x = RS->argScalar(L);

    // z is result
    const Value zvalue = evalOp(op, xvalue, yvalue);
    const Fr zwitness = evalOp(op, xwitness, ywitness);
    const R1T z = RS->createResult(op, x, y, zwitness);

    S.push(
        ALG(zvalue, zwitness, valueBits(zvalue), {z}));
}

template <typename ALG>
void evalStackOp_Scalar(std::stack<ALG>& S, const ScalarOps op) {
    evalStackOp_internal(S, op);
}

template <typename ALG>
void evalStackOp_Field(std::stack<ALG>& S, const FieldOps op) {
    evalStackOp_internal2(S, op);
}

////////////////////////////////////////////////////////////////////////////////
// used by:
// - Alg_Field
// - Alg_uint8
// - Alg_uint32
// - Alg_uint64
//

template <typename ALG>
void evalStackCmp_Equality(std::stack<ALG>& S, const EqualityCmp op)
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

#ifdef USE_ASSERT
    assert(y.size() >= sizeBits(yvalue));
#endif

    // x is left argument
    const auto L = S.top();
    S.pop();
    const Value xvalue = L.value();
    const std::vector<int> xbits = L.splitBits();
    const std::vector<R1T> x = RS->argBits(L);

#ifdef USE_ASSERT
    assert(x.size() >= sizeBits(xvalue));
#endif

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
    const bool result = evalOp(op, xvalue, yvalue);
    const Value zvalue = boolTo<Value>(result);
    const R1T z = EqualityCmp::EQ == op
        ? RS->declarative_AND(zvec) // all must be same
        : RS->imperative_OR(zvec, zwitness); // one must be different

    S.push(
        ALG(zvalue, boolTo<Fr>(result), valueBits(zvalue), {z}));
}

} // namespace snarkfront

#endif
