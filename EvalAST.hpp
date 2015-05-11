#ifndef _SNARKFRONT_EVAL_AST_HPP_
#define _SNARKFRONT_EVAL_AST_HPP_

#include <stack>

#include <snarkfront/AST.hpp>
#include <snarkfront/EnumOps.hpp>

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// evaluate abstract syntax trees
//

template <typename ALG>
class EvalAST : public VisitAST<ALG>
{
public:
    // circuit inputs and constants
    void visit(const AST_Const<ALG>& a) {
        m_valueStack.push(*a);
    }

    // variables
    void visit(const AST_Var<ALG>& a) {
        m_valueStack.push(*a);
    }

    // operators
    void visit(const AST_Op<ALG>& a) {
        a.descendLeft(*this); // first argument

        if (1 != opArgc(a.opType())) {
            a.descendRight(*this); // second argument
        }

        evalStackOp(m_valueStack, a.opType());
    }

    // foreign tree - comparison and type conversion
    void visit(const AST_X<ALG>& a) {
        m_valueStack.push(*a);
    }

    // return result after evaluation
    const ALG& result() const {
        return m_valueStack.top();
    }

    // for comparison operators
    void push(const ALG& a) {
        m_valueStack.push(a);
    }

    template <typename ENUM_CMP>
    void compareOp(const ENUM_CMP op) {
        evalStackCmp(m_valueStack, op);
    }

private:
    // evaluation stack
    std::stack<ALG> m_valueStack;
};

} // namespace snarkfront

#endif
