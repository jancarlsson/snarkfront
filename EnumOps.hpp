#ifndef _SNARKFRONT_ENUM_OPS_HPP_
#define _SNARKFRONT_ENUM_OPS_HPP_

#include <cstdint>
#include "BitwiseINT.hpp"
#include "PowersOf2.hpp"

namespace snarkfront {

// logical and arithmetic
enum class LogicalOps { AND, OR, XOR, SAME, CMPLMNT };
enum class ScalarOps { ADD, SUB, MUL };
enum class BitwiseOps { AND, OR, XOR, SAME, CMPLMNT, ADDMOD, SHL, SHR, ROTL, ROTR };

// comparison
enum class EqualityCmp { EQ, NEQ };
enum class ScalarCmp { EQ, NEQ, LT, LE, GT, GE };

// number of operator input arguments
template <typename ENUM_OPS> std::size_t opArgc(const ENUM_OPS op);

// returns true for shift and rotate
bool isPermute(const BitwiseOps op);

// EQ --> SAME
// NEQ --> XOR
LogicalOps eqToLogical(const EqualityCmp op);

// evaluate logical operations
template <typename T>
T evalOp(const LogicalOps op, const T& x, const T& y)
{
    switch (op) {
    case (LogicalOps::AND) : return x && y;
    case (LogicalOps::OR) : return x || y;
    case (LogicalOps::XOR) : return x != y;
    case (LogicalOps::SAME) : return x == y;
    case (LogicalOps::CMPLMNT) : return ! x;
    }
}

// evaluate scalar arithmetic operations
template <typename T>
T evalOp(const ScalarOps op, const T& x, const T& y)
{
    switch (op) {
    case (ScalarOps::ADD) : return x + y;
    case (ScalarOps::SUB) : return x - y;
    case (ScalarOps::MUL) : return x * y;
    }
}

// evaluate bitwise word operations
template <typename T>
T evalOp(const BitwiseOps op, const T& x, const T& y)
{
    typedef BitwiseINT<T> B;

    switch (op) {
    case (BitwiseOps::AND) : return B::AND(x, y);
    case (BitwiseOps::OR) : return B::OR(x, y);
    case (BitwiseOps::XOR) : return B::XOR(x, y);
    case (BitwiseOps::SAME) : return B::CMPLMNT(B::XOR(x, y));
    case (BitwiseOps::CMPLMNT) : return B::CMPLMNT(x);
    case (BitwiseOps::ADDMOD) : return B::ADDMOD(x, y);
    case (BitwiseOps::SHL) : return B::SHL(x, y);
    case (BitwiseOps::SHR) : return B::SHR(x, y);
    case (BitwiseOps::ROTL) : return B::ROTL(x, y);
    case (BitwiseOps::ROTR) : return B::ROTR(x, y);
    }
}

// evaluate equality comparison operations
template <typename T>
bool evalOp(const EqualityCmp op, const T& x, const T& y)
{
    switch (op) {
    case (EqualityCmp::EQ) : return x == y;
    case (EqualityCmp::NEQ) : return x != y;
    }
}

// evaluate scalar comparsion operations
template <typename T>
bool evalOp(const ScalarCmp op, const T& x, const T& y)
{
    switch (op) {
    case (ScalarCmp::EQ) : return x == y;
    case (ScalarCmp::NEQ) : return x != y;
    case (ScalarCmp::LT) : return x < y;
    case (ScalarCmp::LE) : return (x < y) || (x == y);
    case (ScalarCmp::GT) : return y < x;
    case (ScalarCmp::GE) : return (y < x) || (x == y);
    }
}

} // namespace snarkfront

#endif
