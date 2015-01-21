#ifndef _SNARKFRONT_ALG_BOOL_HPP_
#define _SNARKFRONT_ALG_BOOL_HPP_

#include <cassert>
#include "Alg.hpp"

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// Alg_bool
//

template <typename FR>
void evalStackOp(std::stack<Alg_bool<FR>>& S, const LogicalOps op)
{
    typedef typename Alg_bool<FR>::R1T R1T;
    auto& RS = TL<R1C<FR>>::singleton();

    // y is right argument
    const auto R = S.top();
    S.pop();
    const bool yvalue = R.value();
#ifdef USE_ASSERT
    assert(1 == R.r1Terms().size());
#endif
    const R1T y = RS->argScalar(R);

    // z is result
    bool zvalue;
    FR zwitness;
    R1T z;

    // complement takes one argument
    if (LogicalOps::CMPLMNT == op) {
        zvalue = ! yvalue;
        zwitness = boolTo<FR>(zvalue);
        z = RS->createResult(op, y, y, zwitness);

    } else {
        // x is left argument
        const auto L = S.top();
        S.pop();
        const bool xvalue = L.value();
#ifdef USE_ASSERT
        assert(1 == L.r1Terms().size());
#endif
        const R1T x = RS->argScalar(L);

        zvalue = evalOp(op, xvalue, yvalue);
        zwitness = boolTo<FR>(zvalue);

        const bool
            xIsVar = x.isVariable(),
            yIsVar = y.isVariable();

        const LogicalOps NOT = LogicalOps::CMPLMNT;

        if (xIsVar == yIsVar) {
            z = RS->createResult(op, x, y, zwitness);

        } else if (xIsVar) { // && ! yIsVar
            if (yvalue) {
                switch (op) {
                case (LogicalOps::AND) : z = x; break;
                case (LogicalOps::OR) : z = y; break;
                case (LogicalOps::XOR) : z = RS->createResult(NOT, x, x, zwitness); break;
                case (LogicalOps::SAME) : z = x; break;
                }
            } else {
                switch (op) {
                case (LogicalOps::AND) : z = y; break;
                case (LogicalOps::OR) : z = x; break;
                case (LogicalOps::XOR) : z = x; break;
                case (LogicalOps::SAME) : z = RS->createResult(NOT, x, x, zwitness); break;
                }
            }

        } else if (yIsVar) { // && ! xIsVar
            if (xvalue) {
                switch (op) {
                case (LogicalOps::AND) : z = y; break;
                case (LogicalOps::OR) : z = x; break;
                case (LogicalOps::XOR) : z = RS->createResult(NOT, y, y, zwitness); break;
                case (LogicalOps::SAME) : z = y; break;
                }
            } else {
                switch (op) {
                case (LogicalOps::AND) : z = x; break;
                case (LogicalOps::OR) : z = y; break;
                case (LogicalOps::XOR) : z = y; break;
                case (LogicalOps::SAME) : z = RS->createResult(NOT, y, y, zwitness); break;
                }
            }
        }
    }

    S.push(
        Alg_bool<FR>(zvalue, zwitness, valueBits(zvalue), {z}));
}

template <typename FR>
void evalStackCmp(std::stack<Alg_bool<FR>>& S, const EqualityCmp op)
{
    typedef typename Alg_bool<FR>::R1T R1T;
    auto& RS = TL<R1C<FR>>::singleton();

    // y is right argument
    const auto R = S.top();
    S.pop();
    const bool yvalue = R.value();
    const R1T y = RS->argScalar(R);

    // x is left argument
    const auto L = S.top();
    S.pop();
    const bool xvalue = L.value();
    const R1T x = RS->argScalar(L);

    // z is result
    const bool zvalue = evalOp(op, xvalue, yvalue);
    const FR zwitness = boolTo<FR>(zvalue);
    const R1T z = RS->createResult(eqToLogical(op), x, y, zwitness);

    S.push(
        Alg_bool<FR>(zvalue, zwitness, valueBits(zvalue), {z}));
}

} // namespace snarkfront

#endif
