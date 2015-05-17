#ifndef _SNARKFRONT_ALG_FIELD_HPP_
#define _SNARKFRONT_ALG_FIELD_HPP_

#include <gmp.h>

#include <snarkfront/Alg.hpp>
#include <snarkfront/Alg_internal.hpp>

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// Alg_Field
//

template <typename FR>
void evalStackOp(std::stack<Alg_Field<FR>>& S, const FieldOps op) {
    evalStackOp_Field<Alg_Field<FR>>(S, op);
}

template <typename FR>
void evalStackCmp(std::stack<Alg_Field<FR>>& S, const EqualityCmp op) {
    evalStackCmp_Equality(S, op);
}

} // namespace snarkfront

#endif
