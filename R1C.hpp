#ifndef _SNARKFRONT_R1C_HPP_
#define _SNARKFRONT_R1C_HPP_

#include <cassert>
#include <cstdint>
#include <istream>
#include <ostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <snarklib/HugeSystem.hpp>
#include <snarklib/PPZK_keypair.hpp>
#include <snarklib/PPZK_proof.hpp>
#include <snarklib/PPZK_verify.hpp>
#include <snarklib/ProgressCallback.hpp>
#include <snarklib/Rank1DSL.hpp>

#include <snarkfront/Counter.hpp>
#include <snarkfront/EnumOps.hpp>
#include <snarkfront/PowersOf2.hpp>
#include <snarkfront/Rank1Ops.hpp>
#include <snarkfront/TLsingleton.hpp>

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// variable assignment cowitness for public inputs
//

template <typename FR>
class R1Cowitness
{
public:
    const snarklib::R1Witness<FR>& operator* () const {
        return m_FR;
    }

    const std::string& operator[] (const std::size_t varIndex) const {
        return m_str[varIndex - 1]; // subtract one to make absolute index
    }

    void clear() {
        m_FR.clear();
        m_str.clear();
    }

    bool empty() const {
        return
            m_FR.empty() ||
            m_str.empty();
    }

    void checkpoint(const snarklib::R1Witness<FR>& a,
                    const std::vector<std::pair<std::size_t, std::string>>& b) {
        m_FR = a;

        for (const auto& p : b) {
            // subtract one to make absolute index
            const std::size_t idx = p.first - 1;

            for (std::size_t i = m_str.size(); i <= idx; ++i) {
                m_str.emplace_back("*"); // dummy value
            }

            m_str[idx] = p.second;
        }
    }

    std::size_t sizeFR() const {
        return m_FR.size();
    }

    std::size_t sizeSTR() const {
        return m_str.size();
    }

    void marshal_out(std::ostream& os) const {
        m_FR.marshal_out(os);

        os << m_str.size() << std::endl;

        for (const auto& a : m_str)
            os << a << ' ';
    }

    bool marshal_in(std::istream& is) {
        if (! m_FR.marshal_in(is)) return false;

        std::size_t numberElems;
        if (! (is >> numberElems)) return false;

        m_str.clear();
        m_str.reserve(numberElems);
        for (std::size_t i = 0; i < numberElems; ++i) {
            std::string value;
            if (! (is >> value)) return false;
            m_str.emplace_back(value);
        }

        // consume trailing space
        char c;
        if (!is.get(c) || (' ' != c)) return false;

        return true;
    }

private:
    snarklib::R1Witness<FR> m_FR;
    std::vector<std::string> m_str;
};

template <typename FR>
std::ostream& operator<< (std::ostream& os, const R1Cowitness<FR>& a) {
    a.marshal_out(os);
    return os;
}

template <typename FR>
std::istream& operator>> (std::istream& is, R1Cowitness<FR>& a) {
    if (! a.marshal_in(is)) a.clear();
    return is;
}

////////////////////////////////////////////////////////////////////////////////
// Rank-1 Collector
//

template <typename FR>
class R1C
{
public:
    typedef snarklib::R1Variable<FR> R1V;
    typedef snarklib::R1Term<FR> R1T;

    R1C()
        : m_swap_AB_if_beneficial(false)
    {}

    // constraint system written out to files as it is built
    void writeFiles(const std::string& filePrefix, const std::size_t maxSize) {
        m_constraintSystem.clearAppend(filePrefix, maxSize);
    }

    // constraint system is finished, write final part to disk
    // returns true if ok, false if there was an error
    bool finalizeFiles() {
        m_constraintSystem.finalize(input().sizeFR());
        return !!m_constraintSystem;
    }

    void reset() {
        // variable indices
        m_counter.reset();

        // quadratic constraint system
        m_swap_AB_if_beneficial = false;
        m_constraintSystem.clear();

        // variable assignment witness
        m_witness_FR.clear();
        m_witness_str.clear();

        // input witness for (de)marshalling
        m_input.clear();
    }

    std::size_t counterID() const {
        return m_counter.peekID();
    }

    // mark end of public circuit inputs known to prover and verifier
    void checkpointInput() {
        // assumes all inputs are first
        m_input.checkpoint(
            m_witness_FR,
            m_witness_str);
    }

    const R1Cowitness<FR>& input() const {
        return m_input;
    }

    // generate proving/verification key pair from constraint system
    template <typename PAIRING>
    snarklib::PPZK_Keypair<PAIRING> keypair(
        snarklib::ProgressCallback* callback = nullptr)
    {
        swap_AB_if_beneficial();

        return snarklib::PPZK_Keypair<PAIRING>(
            m_constraintSystem,
            m_input.sizeFR(),
            snarklib::PPZK_LagrangePoint<typename PAIRING::Fr>(0),
            snarklib::PPZK_BlindGreeks<typename PAIRING::Fr, typename PAIRING::Fr>(0),
            callback);
    }

    const snarklib::R1Witness<FR>& witness() const {
        return m_witness_FR;
    }

    // generate proof with private witness
    template <typename PAIRING>
    snarklib::PPZK_Proof<PAIRING> proof(
        const snarklib::PPZK_ProvingKey<PAIRING>& pk,
        const std::size_t reserveTune,
        snarklib::ProgressCallback* callback = nullptr)
    {
        swap_AB_if_beneficial();

        return snarklib::PPZK_Proof<PAIRING>(
            m_constraintSystem,
            m_input.sizeFR(),
            pk,
            m_witness_FR,
            snarklib::PPZK_ProofRandomness<typename PAIRING::Fr>(0),
            reserveTune,
            callback);
    }

    // generate proof with private witness
    template <typename PAIRING>
    snarklib::PPZK_Proof<PAIRING> proof(
        const snarklib::PPZK_Keypair<PAIRING>& key,
        const std::size_t reserveTune,
        snarklib::ProgressCallback* callback = nullptr)
    {
        return proof(key.pk(), reserveTune, callback);
    }

    // verify proof with public circuit inputs
    template <typename PAIRING>
    bool verify(const snarklib::PPZK_VerificationKey<PAIRING>& vk,
                const R1Cowitness<FR>& in,
                const snarklib::PPZK_Proof<PAIRING>& p,
                snarklib::ProgressCallback* callback = nullptr)
    {
        return snarklib::strongVerify(
            vk,
            *in,
            p,
            callback);
    }

    // verify proof with public circuit inputs
    template <typename PAIRING>
    bool verify(const snarklib::PPZK_Keypair<PAIRING>& key,
                const R1Cowitness<FR>& in,
                const snarklib::PPZK_Proof<PAIRING>& p,
                snarklib::ProgressCallback* callback = nullptr)
    {
        return verify(key.vk(), in, p, callback);
    }

    R1T createTerm(const FR& a, const bool nonzeroIndex) {
        if (nonzeroIndex) {
            R1V x(m_counter.uniqueID());
            addWitness(x, a);
            return x; // x_i

        } else {
            return a; // a * x_0
        }
    }

    R1T createConstant(const FR& a) {
        return createTerm(a, false);
    }

    template <typename VAL>
    void witnessTerms(const std::vector<R1T>& r1Terms, const VAL& value) {
        std::stringstream ss;
        ss << value;
        addWitness(r1Terms, ss.str());
    }

    void addBooleanity(const R1T& x) {
        rank1_booleanity(m_constraintSystem, x);
    }

    void setTrue(const R1T& x) {
        setVariable(x, FR::one());
    }

    void setFalse(const R1T& x) {
        setVariable(x, FR::zero());
    }

    std::vector<R1T>
    witnessToBits(const R1T& x,
                  const std::vector<int>& splitBits)
    {
        std::vector<R1T> v;
        v.reserve(splitBits.size());

        const bool isVar = x.isVariable();

        for (const auto& b : splitBits) {
            v.emplace_back(
                createTerm(boolTo<FR>(b), isVar));
        }

        if (isVar) {
            addSplit(x, v);

            for (const auto& b : v)
                addBooleanity(b);
        }

        return v;
    }

    R1T bitsToWitness(const std::vector<R1T>& splitTerms,
                      const FR& value)
    {
        bool isVar = false;
        for (const auto& a : splitTerms) {
            if (a.isVariable())
                isVar = true;
        }

        const auto x = createTerm(value, isVar);

        if (isVar) {
            addSplit(x, splitTerms);
        }

        return x;
    }

    // argument as scalar, converts bit representation as necessary
    template <typename ALG>
    R1T argScalar(const ALG& arg) {
        const std::size_t termCnt = arg.r1Terms().size();

        typename ALG::ValueType dummy;
#ifdef USE_ASSERT
        assert(sizeBits(dummy) == termCnt || 1 == termCnt);
#endif

        // For bool and BigInt, sizeBits(dummy) is 1 so the
        // conditional always fails. It can only be true for uint32/64.
        return ((sizeBits(dummy) == termCnt) && (1 != termCnt))
            ? bitsToWitness(arg.r1Terms(), arg.witness())
            : arg.r1Terms()[0];
    }

    // argument as bit representation, converts scalar as necessary
    template <typename ALG>
    std::vector<R1T> argBits(const ALG& arg) {
        const std::size_t termCnt = arg.r1Terms().size();

        typename ALG::ValueType dummy;
#ifdef USE_ASSERT
        assert(sizeBits(dummy) == termCnt || 1 == termCnt);
#endif

        // For uint32/64, sizeBits(dummy) is greater than 1 so the
        // conditional is equivalent to: 1 == termCnt. This will be
        // true only for ADDMOD.
        return ((1 == termCnt) && (sizeBits(dummy) != termCnt))
            ? witnessToBits(arg.r1Terms()[0], arg.splitBits())
            : arg.r1Terms();
    }

    // create constant or variable for operation result
    R1T createResult(const LogicalOps op, const R1T& x, const R1T& y, const FR& witness) {
        if (! x.isVariable() && ! y.isVariable()) {
            // x and y are constant
            return createConstant(witness);

        } else {
            // at least one of x and y is a variable
            const R1T z = createVariable(witness);
            addConstraint(op, x, y, z);
            return z;
        }
    }

    // create constant or variable for operation result
    R1T createResult(const ScalarOps op, const R1T& x, const R1T& y, const FR& witness) {
        if (! x.isVariable() && ! y.isVariable()) {
            // x and y are constant
            return createConstant(witness);

        } else {
            // at least one of x and y is a variable
            const R1T z = createVariable(witness);
            addConstraint(op, x, y, z);
            return z;
        }
    }

    // create constant or variable for operation result
    R1T createResult(const BitwiseOps op, const R1T& x, const R1T& y, const FR& witness) {
        if (! x.isVariable() && ! y.isVariable()) {
            // x and y are constant
            return createConstant(witness);

        } else if (x.zeroTerm()) {
            // shifts leave null bits
            return otherTermZero(op, y);

        } else if (y.zeroTerm()) {
            // shifts leave null bits
            return otherTermZero(op, x);

        } else {
            // at least one of x and y is a variable
            const R1T z = createVariable(witness);
            addConstraint(op, x, y, z);
            return z;
        }
    }

    // shift and rotate
    std::vector<R1T> permuteBits(const BitwiseOps op,
                                 const std::vector<R1T>& x,
                                 const std::size_t n)
    {
        auto z = x;

        switch (op) {
        case (BitwiseOps::SHL) : rank1_shiftleft(z, n); break;
        case (BitwiseOps::SHR) : rank1_shiftright(z, n); break;
        case (BitwiseOps::ROTL) : rank1_rotateleft(z, n); break;
        case (BitwiseOps::ROTR) : rank1_rotateright(z, n); break;
        }

        return z;
    }

    // z = AND(x[0], x[1],... , x[N-1])
    // general AND gate with arbitrary number of inputs
    //
    // A few notes:
    //
    // Proving a bit is true generates a different circuit from
    // proving a bit is false. For that reason, the value of zbit
    // must be known to both prover and verifier. All parties must
    // agree on the same arithmetic circuit.
    //
    // The declarative snarkfront EDSL makes this possible. Prover
    // and verifier agree on the same language which defines the
    // problem (constraint system) and what passes as a valid
    // solution (witness).
    //
    // This function is called from declarative_AND() with zbit = true.
    //
    R1T declarative_multiAND(const std::vector<R1T>& x,
                             const FR& xsum_witness,
                             const bool zbit)
    {
        // sum of input wires
        snarklib::R1Combination<FR> inputs;
        for (const auto& t : x) inputs.addTerm(t);

        // number of inputs as field type
        const auto N = TL<PowersOf2<FR>>::singleton()->getNumber(x.size());

        // z is result
        const auto z = createVariable(boolTo<FR>(zbit));

        // (N - x[0] + x[1] +...+ x[N-1]) * z == 0
        m_constraintSystem.addConstraint(
            (N - inputs) * z == FR::zero());

        // (N - x[0] + x[1] +...+ x[N-1]) * INV == 1 - z
        // If z == 1, then INV = 0
        // If z == 0, then INV = inverse(N - x[0] + x[1] +...+ x[N-1])
        m_constraintSystem.addConstraint(
            inputs * (zbit ? FR::zero() : inverse(N - xsum_witness)) == FR::one() - z);

        return z;
    }

    R1T declarative_AND(const std::vector<R1T>& x) {
        return declarative_multiAND(
            x,
            FR::zero(), // dummy value is not used
            true);      // validity requires all bits to be 1
    }

    // z = OR(x[0], x[1],... , x[N-1])
    // general OR gate with arbitrary number of inputs
    //
    // A few notes:
    //
    // Proving a bit is true generates a different circuit from
    // proving a bit is false. For that reason, the value of zbit
    // must be known to both prover and verifier. All parties must
    // agree on the same arithmetic circuit.
    //
    // The declarative snarkfront EDSL makes this possible. Prover
    // and verifier agree on the same language which defines the
    // problem (constraint system) and what passes as a valid
    // solution (witness).
    //
    // This function is called from declarative_NOR() with zbit = false.
    //
    R1T declarative_multiOR(const std::vector<R1T>& x,
                            const FR& xsum_witness,
                            const bool zbit)
    {
        // sum of input wires
        snarklib::R1Combination<FR> inputs;
        for (const auto& t : x) inputs.addTerm(t);

        // z is result
        const auto z = createVariable(boolTo<FR>(zbit));

        // (x[0] + x[1] +...+ x[N-1]) * (1 - z) == 0
        m_constraintSystem.addConstraint(
            inputs * (FR::one() - z) == FR::zero());

        // (x[0] + x[1] +...+ x[N-1]) * INV == z
        // If z == 1, then INV = inverse(x[0] + x[1] +...+ x[N-1])
        // If z == 0, then INV = 0
        m_constraintSystem.addConstraint(
            inputs * (zbit ? inverse(xsum_witness) : FR::zero()) == z);

        return z;
    }

    R1T declarative_NOR(const std::vector<R1T>& x) {
        return declarative_multiOR(
            x,
            FR::zero(), // dummy value is not used
            false);     // validity requires all bits to be 0
    }

    // z = AND(x[0],... , x[x^N - 1])
    // zero knowledge AND gate with power of 2 number of inputs
    R1T imperative_AND(const std::vector<R1T>& x,
                       const std::vector<int>& witness)
    {
        return imperative_GATE(LogicalOps::AND, x, witness);
    }

    // z = OR(x[0],... , x[2^N - 1])
    // zero knowledge OR gate with power of 2 number of inputs
    R1T imperative_OR(const std::vector<R1T>& x,
                      const std::vector<int>& witness) 
    {
        return imperative_GATE(LogicalOps::OR, x, witness);
    }

    // z = XOR(x[0],... , x[x^N - 1])
    // zero knowledge XOR gate with power of 2 number of inputs
    R1T imperative_XOR(const std::vector<R1T>& x,
                       const std::vector<int>& witness)
    {
        return imperative_GATE(LogicalOps::XOR, x, witness);
    }

private:
    template <typename ENUM>
    R1T imperative_GATE(const ENUM op,
                        const std::vector<R1T>& x,
                        const std::vector<int>& witness) 
    {
        const std::size_t N = x.size();
        const std::size_t halfN = N / 2;
#ifdef USE_ASSERT
        assert(N == 2 * halfN);
        assert(N == witness.size());
#endif

        if (2 == N) {
            return createResult(op,
                                x[0],
                                x[1],
                                boolTo<FR>(evalOp(op, witness[0], witness[1])));

        } else {
            std::vector<R1T> x2;
            x2.reserve(halfN);

            std::vector<int> witness2;
            witness2.reserve(halfN);

            for (std::size_t i = 0; i < halfN; ++i) {
                const bool b = evalOp(op,
                                      witness[i],
                                      witness[i + halfN]);

                witness2.push_back(b);

                x2.emplace_back(
                    createResult(op,
                                 x[i],
                                 x[i + halfN],
                                 boolTo<FR>(b)));
            }

            return imperative_GATE(op, x2, witness2);
        }
    }

    R1T createVariable(const FR& a) {
        return createTerm(a, true);
    }

    void setVariable(const R1T& x, const FR& value) {
        m_constraintSystem.addConstraint(x == value);
    }

    void addWitness(const R1V& x, const FR& value) {
        m_witness_FR.assignVar(x, value);
    }

    void addWitness(const R1T& x, const FR& value) {
        addWitness(x.var(), value);
    }

    void addWitness(const std::vector<R1T>& r1Terms, const std::string& value) {
        m_witness_str.emplace_back(
            std::pair<std::size_t, std::string>(
                r1Terms.front().index(),
                value));
    }

    void addSplit(const R1T& x, const std::vector<R1T>& b) {
        rank1_split(m_constraintSystem, x, b);
    }

    // z = OP(x, y)
    void addConstraint(const LogicalOps op, const R1T& x, const R1T& y, const R1T& z) {
#ifdef USE_ASSERT
        assert(z.isVariable() && (x.isVariable() || y.isVariable()));
#endif

        switch (op) {
        case (LogicalOps::AND) :
            rank1_op<snarklib::HugeSystem, R1_AND<FR>>(m_constraintSystem, x, y, z);
            break;

        case (LogicalOps::OR) :
            rank1_op<snarklib::HugeSystem, R1_OR<FR>>(m_constraintSystem, x, y, z);
            break;

        case (LogicalOps::XOR) :
            rank1_op<snarklib::HugeSystem, R1_XOR<FR>>(m_constraintSystem, x, y, z);
            break;

        case (LogicalOps::SAME) :
            rank1_op<snarklib::HugeSystem, R1_SAME<FR>>(m_constraintSystem, x, y, z);
            break;

        case (LogicalOps::CMPLMNT) :
            rank1_op<snarklib::HugeSystem, R1_CMPLMNT<FR>>(m_constraintSystem, x, y, z);
            break;
        }
    }

    // z = OP(x, y)
    void addConstraint(const ScalarOps op, const R1T& x, const R1T& y, const R1T& z) {
#ifdef USE_ASSERT
        assert(z.isVariable() && (x.isVariable() || y.isVariable()));
#endif

        switch (op) {
        case (ScalarOps::ADD) :
            rank1_op<snarklib::HugeSystem, R1_ADD<FR>>(m_constraintSystem, x, y, z);
            break;

        case (ScalarOps::SUB) :
            rank1_op<snarklib::HugeSystem, R1_SUB<FR>>(m_constraintSystem, x, y, z);
            break;

        case (ScalarOps::MUL) :
            rank1_op<snarklib::HugeSystem, R1_MUL<FR>>(m_constraintSystem, x, y, z);
            break;
        }
    }

    // z = OP(x, y)
    void addConstraint(const BitwiseOps op, const R1T& x, const R1T& y, const R1T& z) {
#ifdef USE_ASSERT
        assert(z.isVariable() && (x.isVariable() || y.isVariable()));
#endif

        switch (op) {
        case (BitwiseOps::AND) :
            rank1_op<snarklib::HugeSystem, R1_AND<FR>>(m_constraintSystem, x, y, z);
            break;

        case (BitwiseOps::OR) :
            rank1_op<snarklib::HugeSystem, R1_OR<FR>>(m_constraintSystem, x, y, z);
            break;

        case (BitwiseOps::XOR) :
            rank1_op<snarklib::HugeSystem, R1_XOR<FR>>(m_constraintSystem, x, y, z);
            break;

        case (BitwiseOps::SAME) :
            rank1_op<snarklib::HugeSystem, R1_SAME<FR>>(m_constraintSystem, x, y, z);
            break;

        case (BitwiseOps::CMPLMNT) :
            rank1_op<snarklib::HugeSystem, R1_CMPLMNT<FR>>(m_constraintSystem, x, y, z);
            break;

        case (BitwiseOps::ADDMOD) :
            rank1_op<snarklib::HugeSystem, R1_ADD<FR>>(m_constraintSystem, x, y, z);
            break;
        }
    }

    R1T otherTermZero(const BitwiseOps op, const R1T& x) {
#ifdef USE_ASSERT
        assert(x.isVariable());
#endif

        switch (op) {
        case (BitwiseOps::AND) :
            // x & 0 == 0
            return R1T();

        case (BitwiseOps::OR) :
            // x | 0 == x
            return x;

        case (BitwiseOps::XOR) :
            // x ^ 0 == x
            return x;

        case (BitwiseOps::SAME) :
            // (x == 0) == !x
            return createResult(BitwiseOps::CMPLMNT, x, x, boolTo<FR>(true));

        case (BitwiseOps::CMPLMNT) :
            // !0 == 1
            return boolTo<FR>(true); // note: this case should never happen

        case (BitwiseOps::ADDMOD) :
            // x + 0 == x
            return x;
        }
    }

    // not optional, must do this before everything
    void swap_AB_if_beneficial() {
        if (! m_swap_AB_if_beneficial) {
            m_swap_AB_if_beneficial = true;

            m_constraintSystem.swap_AB_if_beneficial();
        }
    }

    // variable indices
    Counter<std::size_t> m_counter;

    // quadratic constraint system
    bool m_swap_AB_if_beneficial;
    snarklib::HugeSystem<FR> m_constraintSystem;

    // variable assignment witness
    snarklib::R1Witness<FR> m_witness_FR;
    std::vector<std::pair<std::size_t, std::string>> m_witness_str;

    // input witness for (de)marshalling
    R1Cowitness<FR> m_input;
};

} // namespace snarkfront

#endif
