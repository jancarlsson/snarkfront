#include "EnumOps.hpp"

using namespace std;

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// number of operator input arguments
//

#define DEFN_OPARGC(E, R) template <> size_t opArgc<E>(const E op) { return R; }

DEFN_OPARGC(LogicalOps, LogicalOps::CMPLMNT == op ? 1 : 2)
DEFN_OPARGC(ScalarOps, 2)
DEFN_OPARGC(BitwiseOps, BitwiseOps::CMPLMNT == op ? 1 : 2)
DEFN_OPARGC(EqualityCmp, 2)
DEFN_OPARGC(ScalarCmp, 2)

#undef DEFN_OPARGC

////////////////////////////////////////////////////////////////////////////////
// returns true for shift and rotate
//

bool isPermute(const BitwiseOps op) {
    switch (op) {
    case (BitwiseOps::SHL) :
    case (BitwiseOps::SHR) :
    case (BitwiseOps::ROTL) :
    case (BitwiseOps::ROTR) :
        return true;

    default:
        return false;
    }
}

////////////////////////////////////////////////////////////////////////////////
// EQ --> SAME
// NEQ --> XOR
//

LogicalOps eqToLogical(const EqualityCmp op) {
    switch (op) {
    case (EqualityCmp::EQ) : return LogicalOps::SAME;
    case (EqualityCmp::NEQ) : return LogicalOps::XOR;
    }
}

} // namespace snarkfront
