#ifndef _SNARKFRONT_ALG_HPP_
#define _SNARKFRONT_ALG_HPP_

#include <cassert>
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

#include <snarklib/BigInt.hpp>
#include <snarklib/Rank1DSL.hpp>

#include <snarkfront/AST.hpp>
#include <snarkfront/EnumOps.hpp>
#include <snarkfront/EvalAST.hpp>
#include <snarkfront/PowersOf2.hpp>
#include <snarkfront/R1C.hpp>
#include <snarkfront/TLsingleton.hpp>

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// Parameters for specializing the AST templates to primitive types
//
// - Alg_bool for predicate
// - Alg_uint8 for 8-bit octets (char)
// - Alg_uint32 for 32-bit words
// - Alg_uint64 for 64-bit words
// - Alg_BigInt for 128-bit GMP big numbers
// - Alg_Field for finite scalar field used by elliptic curve
//

template <typename VAL,
          typename FR,
          typename OP,
          typename CMP> class Alg;

template <typename FR> using
Alg_bool = Alg<bool,
               FR,
               LogicalOps,
               EqualityCmp>;

template <typename FR> using
Alg_uint8 = Alg<std::uint8_t,
                FR,
                BitwiseOps,
                EqualityCmp>;

template <typename FR> using
Alg_uint32 = Alg<std::uint32_t,
                 FR,
                 BitwiseOps,
                 EqualityCmp>;

template <typename FR> using
Alg_uint64 = Alg<std::uint64_t,
                 FR,
                 BitwiseOps,
                 EqualityCmp>;

template <typename FR> using
Alg_BigInt = Alg<snarklib::BigInt<2>, // N = 2 is 128 bits on x86-64
                 FR,
                 ScalarOps,
                 ScalarCmp>;

template <typename FR> using
Alg_Field = Alg<FR,
                FR,
                FieldOps,
                EqualityCmp>;

////////////////////////////////////////////////////////////////////////////////
// algebra parameter
//

std::string valueToString(const bool& a);
std::string valueToString(const std::uint8_t& a);
std::string valueToString(const std::uint32_t& a);
std::string valueToString(const std::uint64_t& a);

template <mp_size_t N>
std::string valueToString(const snarklib::BigInt<N>& a) {
    std::stringstream ss;
    ss << a;
    return ss.str();
}

template <typename FR>
std::string valueToString(const FR& a) {
#ifdef USE_ASSERT
    assert(1 == a.dimension()); // always true for elliptic curve
                                // scalar field
#endif
    return valueToString(a[0].asBigInt());
}

template <typename VAL, // value for application code
          typename FR,  // finite field witness (elliptic curve Fr)
          typename OP,  // logical and arithmetic operators
          typename CMP> // comparison operators
class Alg
{
public:
    typedef VAL ValueType;
    typedef FR FrType;
    typedef OP OpType;
    typedef CMP CmpType;

    typedef snarklib::R1Term<FR> R1T;
    typedef snarklib::R1Variable<FR> R1V;

    Alg() = default;

    // circuit input
    template <typename T>
    void bless(const T& a) {
        // object is not already initialized
#ifdef USE_ASSERT
        assert(m_splitBits.empty());
        assert(m_r1Terms.empty());
#endif

        m_value = VAL(a);
        m_witness = FR(valueToString(VAL(a)));
        m_splitBits = valueBits(VAL(a));

        initTerms(true);
    }

    // circuit input from demarshalled witness
    void bless(const R1Cowitness<FR>& input) {
        bless(valueFromWitness(input));
    }

    // used by AST_Const and AST_Var constructors (bit representation)
    template <typename T>
    Alg(const T& a, const bool blessed)
        : m_value(a),
          m_witness(valueToString(VAL(a))),
          m_splitBits(valueBits(VAL(a)))
    {
        initTerms(blessed);
    }

    // used by AST_Const and AST_Var constructors from demarshalled witness
    Alg(const R1Cowitness<FR>& input)
        : Alg{valueFromWitness(input), true}
    {}

    // used by operator evaluation and conversion blessing
    Alg(const VAL& a,
        const FR& b,
        const std::vector<int>& c,
        const std::vector<R1T>& d)
        : m_value(a),
          m_witness(b),
          m_splitBits(c),
          m_r1Terms(d)
    {}

    explicit operator bool() const {
        return bool(m_value);
    }

    // application value
    const VAL& value() const {
        return m_value;
    }

    // finite field witness
    const FR& witness() const {
        return m_witness;
    }

    // bits for witness split
    const std::vector<int>& splitBits() const {
        return m_splitBits;
    }

    // return constraint terms for bit representation
    const std::vector<R1T>& r1Terms() const {
        return m_r1Terms;
    }

    // field constructors accept strings
    static std::string valueToString(const VAL& a) {
        return snarkfront::valueToString(a);
    }

    // called from AST Variable overloaded assignment operator
    static Alg
    assignEval(const AST_Var<Alg>& lhs, const AST_Node<Alg>& rhs) {
        EvalAST<Alg> E;
        rhs.accept(E);
        return E.result();
    }

    static Alg
    assignEval(const AST_Var<Alg>& lhs, const VAL& rhs) {
        return assignEval(lhs, AST_Const<Alg>(rhs));
    }

    // called from AST Foreign node constructor
    static Alg_bool<FR>
    compareOp(const CMP op, const AST_Node<Alg>& a, const AST_Node<Alg>& b)
    {
        // evaluate left and right hand side nodes
        EvalAST<Alg> A, B;
        a.accept(A);
        b.accept(B);

        // push left and right hand side results on stack
        EvalAST<Alg> C;
        C.push(A.result());
        C.push(B.result());

        // evaluate comparison operation
        C.compareOp(op);

        // convert comparison result of foreign algebraic type to predicate
        const bool result = bool(C.result());
        return Alg_bool<FR>(result,
                            boolTo<FR>(result),
                            valueBits(result),
                            C.result().r1Terms());
    }

    // conversion from bool to 8-bit, 32-bit, 64-bit unsigned word bitmasks
    // conversion from bool to 128-bit and finite field one and zero
    // bitwise type conversion between unsigned integer words
    // conversion from 128-bit big integer and finite field are undefined
    template <typename U>
    static U xwordOp(const AST_Node<Alg>& src, const U& dummy)
    {
        // evaluate source node
        EvalAST<Alg> E;
        src.accept(E);

        const auto x = TL<R1C<FR>>::singleton()->argBits(E.result());
        typename U::ValueType uvalue;
        const auto returnSize = sizeBits(uvalue);

#ifdef USE_ASSERT
        // source must be: bool, 8-bit, 32-bit, 64-bit
        assert(x.size() <= 64);
#endif

        if (1 == x.size()) {
            // source is bool

            if (returnSize <= 64) {
                // replicate bit to unsigned integer word
                uvalue = E.result().value()
                    ? -1 // all bits set
                    : 0; // all bits clear

            } else {
                // convert bit to zero and one
                uvalue = typename U::ValueType(E.result().value()
                                               ? 1ul
                                               : 0ul);
            }

        } else {
            // source is 8-bit octet, 32-bit or 64-bit word
            uvalue = E.result().value();
        }

        // convert result of foreign algebraic source type to target type
        return U(uvalue,
                 valueToString(uvalue),
                 valueBits(uvalue),
                 rank1_xword(x, returnSize));
    }

private:
    VAL valueFromWitness(const R1Cowitness<FR>& input) const {
        const std::size_t peekID = TL<R1C<FR>>::singleton()->counterID();
#ifdef USE_ASSERT
        assert(peekID <= input.sizeSTR());
#endif

        std::stringstream ss(input[peekID]);

        VAL value;
        ss >> value;
#ifdef USE_ASSERT
        assert(!!ss);
#endif

        return value;
    }

    void initTerms(const bool blessed) {
        auto& RS = TL<R1C<FR>>::singleton();

        // create terms for bits, may be constant or variable
        m_r1Terms.reserve(sizeBits(m_value));
        for (const auto& b : m_splitBits) {
            m_r1Terms.emplace_back(
                RS->createTerm(boolTo<FR>(b), blessed));
        }

#ifdef USE_ASSERT
        assert(m_splitBits.size() == m_r1Terms.size());
#endif

        if (blessed) {
            // associate bits with variable value
            RS->witnessTerms(m_r1Terms, m_value);

            // input consistency on bits
            for (const auto& b : m_r1Terms)
                RS->addBooleanity(b);
        }
    }

    VAL m_value;
    FR m_witness;
    std::vector<int> m_splitBits;
    std::vector<R1T> m_r1Terms;
};

} // namespace snarkfront

#endif
