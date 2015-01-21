#ifndef _SNARKFRONT_AST_HPP_
#define _SNARKFRONT_AST_HPP_

#include <memory>
#include <string>
#include <vector>
#include "Lazy.hpp"

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// base interfaces
//

template <typename ALG> class AST_Const;
template <typename ALG> class AST_Var;
template <typename ALG> class AST_Op;
template <typename ALG> class AST_X;

// visitor pattern
template <typename ALG>
class VisitAST
{
public:
    virtual ~VisitAST() = default;

    virtual void visit(const AST_Const<ALG>&) = 0;
    virtual void visit(const AST_Var<ALG>&) = 0;
    virtual void visit(const AST_Op<ALG>&) = 0;
    virtual void visit(const AST_X<ALG>&) = 0;
};

// abstract syntax tree nodes
template <typename ALG>
class AST_Node
{
public:
    virtual ~AST_Node() = default;

    virtual void accept(VisitAST<ALG>&) const = 0;
};

////////////////////////////////////////////////////////////////////////////////
// circuit inputs and constants
//

template <typename ALG>
class AST_Const : public AST_Node<ALG>
{
public:
    typedef typename ALG::ValueType ValueType;

    AST_Const() = default;

    template <typename VAL>
    AST_Const(const VAL& a)
        : m_alg(a, false)
    {}

    void accept(VisitAST<ALG>& a) const {
        a.visit(*this);
    }

    const ALG& operator* () const {
        return m_alg;
    }

    const ALG* operator-> () const {
        return std::addressof(m_alg);
    }

private:
    const ALG m_alg;
};

////////////////////////////////////////////////////////////////////////////////
// operators
//

template <typename ALG>
class AST_Op : public AST_Node<ALG>
{
    typedef typename ALG::OpType OP;

public:
    AST_Op() = default;

    AST_Op(const OP op, const AST_Node<ALG>& a)
        : m_opType(op)
    {
        m_links.push_back(std::addressof(a));
    }

    AST_Op(const OP op, const AST_Node<ALG>* a)
        : AST_Op{op, *a}
    {
        m_delete.push_back(a);
    }

    AST_Op(const OP op, const AST_Node<ALG>& a, const AST_Node<ALG>& b)
        : AST_Op{op, a}
    {
        m_links.push_back(std::addressof(b));
    }

    AST_Op(const OP op, const AST_Node<ALG>& a, const AST_Node<ALG>* b)
        : AST_Op{op, a, *b}
    {
        m_delete.push_back(b);
    }

    AST_Op(const OP op, const AST_Node<ALG>* a, const AST_Node<ALG>& b)
        : AST_Op{op, *a, b}
    {
        m_delete.push_back(a);
    }

    AST_Op(const OP op, const AST_Node<ALG>* a, const AST_Node<ALG>* b)
        : AST_Op{op, a, *b}
    {
        m_delete.push_back(b);
    }

    virtual ~AST_Op() {
        for (const auto& p : m_delete)
            delete p;
    }

    void accept(VisitAST<ALG>& a) const {
        a.visit(*this);
    }

    void descendLeft(VisitAST<ALG>& a) const {
        leftLink()->accept(a);
    }

    void descendRight(VisitAST<ALG>& a) const {
        rightLink()->accept(a);
    }

    OP opType() const {
        return m_opType;
    }

private:
    const AST_Node<ALG>* leftLink() const {
        return m_links.front();
    }

    const AST_Node<ALG>* rightLink() const {
        return m_links.back();
    }

    OP m_opType;
    std::vector<const AST_Node<ALG>*> m_links, m_delete;
};

////////////////////////////////////////////////////////////////////////////////
// foreign tree - comparison and type conversion
//

template <typename ALG>
class AST_X : public AST_Node<ALG>
{
public:
    // comparison
    template <typename ALG_OTHER>
    AST_X(const typename ALG_OTHER::CmpType op,
          const AST_Node<ALG_OTHER>& a,
          const AST_Node<ALG_OTHER>& b)
        : m_alg(ALG_OTHER::compareOp(op, a, b))
    {}

    // comparison
    template <typename ALG_OTHER>
    AST_X(const typename ALG_OTHER::CmpType op,
          const AST_Node<ALG_OTHER>& a,
          const typename ALG_OTHER::ValueType b)
        : AST_X{op, a, AST_Const<ALG_OTHER>(b)}
    {}

    // comparison
    template <typename ALG_OTHER>
    AST_X(const typename ALG_OTHER::CmpType op,
          const typename ALG_OTHER::ValueType a,
          const AST_Node<ALG_OTHER>& b)
        : AST_X{op, AST_Const<ALG_OTHER>(a), b}
    {}

    // conversion
    template <typename ALG_OTHER>
    AST_X(const AST_Node<ALG_OTHER>& a)
        : m_alg(ALG_OTHER::xwordOp(a, m_alg))
    {}

    explicit operator bool() const {
        return bool(m_alg);
    }

    void accept(VisitAST<ALG>& a) const {
        a.visit(*this);
    }

    const ALG& operator* () const {
        return m_alg;
    }

    const ALG* operator-> () const {
        return std::addressof(m_alg);
    }

private:
    ALG m_alg;
};

////////////////////////////////////////////////////////////////////////////////
// variables
//

template <typename FR> class R1Cowitness;

template <typename ALG>
class AST_Var : public AST_Node<ALG>
{
public:
    typedef typename ALG::ValueType ValueType;
    typedef typename ALG::FrType FrType;
    typedef typename ALG::R1T R1T;

    AST_Var() = default;

    // circuit input
    template <typename VAL>
    AST_Var(const VAL& a)
        : m_alg(a, true)
    {}

    // circuit input from demarshalled witness
    AST_Var(const R1Cowitness<typename ALG::FrType>& input)
        : m_alg(input)
    {}

    // assignment case at point of declaration
    AST_Var(const AST_Const<ALG>& rhs)
        : m_alg(ALG::assignEval(*this, rhs))
    {}

    // assignment case at point of declaration
    AST_Var(const AST_Op<ALG>& rhs)
        : m_alg(ALG::assignEval(*this, rhs))
    {}

    // assignment case at point of declaration
    AST_Var(const AST_X<ALG>& rhs)
        : m_alg(ALG::assignEval(*this, rhs))
    {}

    // circuit input
    template <typename VAL>
    void bless(const VAL& a) {
        m_alg.bless(a);
    }

    // conversion blessing
    void bless(const typename ALG::ValueType& a,
               const typename ALG::FrType& b,
               const std::vector<int>& c,
               const std::vector<typename ALG::R1T>& d) {
        m_alg = ALG(a, b, c, d);
    }

    // circuit input from demarshalled witness
    void bless(const R1Cowitness<typename ALG::FrType>& input) {
        m_alg.bless(input);
    }

    void accept(VisitAST<ALG>& a) const {
        a.visit(*this);
    }

    const ALG& operator* () const {
        return m_alg;
    }

    const ALG* operator-> () const {
        return std::addressof(m_alg);
    }

    // copy assignment
    AST_Var& operator= (const AST_Var& other) {
        m_alg = *other;
        return *this;
    }

    // copy assignment from lazy variable
    AST_Var& operator= (Lazy<AST_Var, typename ALG::ValueType>& other) {
        return *this = *other; // unboxing here
    }

    // assignment
    template <typename RHS>
    AST_Var& operator= (const RHS& a) {
        m_alg = ALG::assignEval(*this, a);
        return *this;
    }

private:
    ALG m_alg;
};

} // namespace snarkfront

#endif
