#ifndef _SNARKFRONT_COMPILE_PPZK_WITNESS_HPP_
#define _SNARKFRONT_COMPILE_PPZK_WITNESS_HPP_

#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>

// snarklib
#include <AuxSTL.hpp>
#include <HugeSystem.hpp>
#include <PPZK_witness.hpp>
#include <PPZK_randomness.hpp>
#include <ProgressCallback.hpp>
#include <Rank1DSL.hpp>
#include <Util.hpp>

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// witnesses A, B, C
//

template <typename WITNESS, typename PAIRING>
class PPZK_witness_ABC
{
    typedef typename PAIRING::Fr FR;

public:
    PPZK_witness_ABC(const std::string& sysfile,
                     const std::string& randfile,
                     const std::string& witfile)
        : m_error(false),
          m_numVariables(0),
          m_reserveTune(0),
          m_hugeSystem(sysfile)
    {
        std::ifstream ifsR(randfile), ifsW(witfile);
        if (!ifsR || !m_randomness.marshal_in(ifsR) ||
            !ifsW || !m_witness.marshal_in(ifsW) ||
            !m_hugeSystem.loadIndex())
        {
            m_error = true;
        }
        else
        {
            const snarklib::QAP_SystemPoint<snarklib::HugeSystem, FR>
                qap(m_hugeSystem,
                    m_hugeSystem.numCircuitInputs());

            m_numVariables = qap.numVariables();
        }
    }

    PPZK_witness_ABC(const std::string& sysfile,
                     const snarklib::PPZK_ProofRandomness<FR>& proofRand,
                     const std::string& witfile)
        : m_error(false),
          m_numVariables(0),
          m_reserveTune(0),
          m_hugeSystem(sysfile),
          m_randomness(proofRand)
    {
        std::ifstream ifs(witfile);
        if (!ifs || !m_witness.marshal_in(ifs) || !m_hugeSystem.loadIndex())
        {
            m_error = true;
        }
        else
        {
            const snarklib::QAP_SystemPoint<snarklib::HugeSystem, FR>
                qap(m_hugeSystem,
                    m_hugeSystem.numCircuitInputs());

            m_numVariables = qap.numVariables();
        }
    }

    bool operator! () const { return m_error; }

    void initA() {
        m_sum = WITNESS(m_numVariables, m_witness, m_randomness.d1());
    }

    void initB() {
        m_sum = WITNESS(m_numVariables, m_witness, m_randomness.d2());
    }

    void initC() {
        m_sum = WITNESS(m_numVariables, m_witness, m_randomness.d3());
    }

    void reserveTune(const std::size_t n = 0) {
        m_reserveTune = n;
    }

    void accumQuery(const std::string& queryfile,
                    const std::size_t blocknum,
                    snarklib::ProgressCallback* callback = nullptr)
    {

        typename WITNESS::SparseVec query;

        std::stringstream ss;
        ss << queryfile << blocknum;

        std::ifstream ifs(ss.str());
#ifdef USE_ADD_SPECIAL
        if (!ifs ||
            !query.marshal_in(
                ifs,
                [] (std::istream& i, typename WITNESS::Val& a) {
                    return a.marshal_in_rawspecial(i);
                }))
        {
#else
        if (!ifs ||
            !query.marshal_in(
                ifs,
                [] (std::istream& i, typename WITNESS:Val& a) {
                    return a.marshal_in_raw(i);
                }))
        {
#endif
            m_error = true;

        } else {
            if (callback) callback->major(true);
            m_sum.accumQuery(query,
                             m_reserveTune,
                             callback);
        }
    }

    typename WITNESS::Val val() const {
        return m_sum.val();
    }

private:
    bool m_error;
    std::size_t m_numVariables, m_reserveTune;
    snarklib::HugeSystem<FR> m_hugeSystem;
    snarklib::PPZK_ProofRandomness<FR> m_randomness;
    snarklib::R1Witness<FR> m_witness;
    WITNESS m_sum;
};

////////////////////////////////////////////////////////////////////////////////
// witness H
//

template <typename PAIRING>
class PPZK_witness_H
{
    typedef typename PAIRING::Fr FR;
    typedef typename PAIRING::G1 G1;

public:
    PPZK_witness_H(const std::string& qapABCH)
        : m_error(false),
          m_qapABCH(qapABCH)
    {}

    bool operator! () const { return m_error; }

    void accumQuery(const std::string& queryfile,
                    const std::size_t blocknum,
                    snarklib::ProgressCallback* callback = nullptr)
    {
        snarklib::BlockVector<G1> query;
        snarklib::BlockVector<FR> scalar;
#ifdef USE_ADD_SPECIAL
        if (!snarklib::read_blockvector_rawspecial(queryfile, blocknum, query) ||
            !snarklib::read_blockvector_raw(m_qapABCH, blocknum, scalar)) {
#else
        if (!snarklib::read_blockvector_raw(queryfile, blocknum, query) ||
            !snarklib::read_blockvector_raw(m_qapABCH, blocknum, scalar)) {
#endif
            m_error = true;

        } else {
            if (callback) callback->major(true);
            m_sum.accumQuery(query,
                             scalar,
                             callback);
        }
    }

    const G1& val() const {
        return m_sum.val();
    }

private:
    bool m_error;
    const std::string m_qapABCH;
    snarklib::PPZK_WitnessH<PAIRING> m_sum;
};

////////////////////////////////////////////////////////////////////////////////
// witness K
//

template <typename PAIRING>
class PPZK_witness_K
{
    typedef typename PAIRING::Fr FR;
    typedef typename PAIRING::G1 G1;

public:
    PPZK_witness_K(const std::string& randfile,
                   const std::string& witfile)
        : m_error(false),
          m_reserveTune(0)
    {
        std::ifstream ifsR(randfile), ifsW(witfile);
        if (!ifsR || !m_randomness.marshal_in(ifsR) ||
            !ifsW || !m_witness.marshal_in(ifsW)) {
            m_error = true;

        } else {
            m_sum = snarklib::PPZK_WitnessK<PAIRING>(m_witness,
                                                     m_randomness.d1(),
                                                     m_randomness.d2(),
                                                     m_randomness.d3());
        }
    }

    PPZK_witness_K(const snarklib::PPZK_ProofRandomness<FR>& proofRand,
                   const std::string& witfile)
        : m_error(false),
          m_reserveTune(0),
          m_randomness(proofRand)
    {
        std::ifstream ifs(witfile);
        if (!ifs || !m_witness.marshal_in(ifs)) {
            m_error = true;

        } else {
            m_sum = snarklib::PPZK_WitnessK<PAIRING>(m_witness,
                                                     m_randomness.d1(),
                                                     m_randomness.d2(),
                                                     m_randomness.d3());
        }
    }

    bool operator! () const { return m_error; }

    void reserveTune(const std::size_t n = 0) {
        m_reserveTune = n;
    }

    void accumQuery(const std::string& queryfile,
                    const std::size_t blocknum,
                    snarklib::ProgressCallback* callback = nullptr)
    {
        snarklib::BlockVector<G1> query;
        if (!snarklib::read_blockvector_rawspecial(queryfile, blocknum, query)) {
            m_error = true;

        } else {
            if (callback) callback->major(true);
            m_sum.accumQuery(query,
                             m_reserveTune,
                             callback);
        }
    }

    const G1& val() const {
        return m_sum.val();
    }

private:
    bool m_error;
    std::size_t m_reserveTune;
    snarklib::PPZK_ProofRandomness<FR> m_randomness;
    snarklib::R1Witness<FR> m_witness;
    snarklib::PPZK_WitnessK<PAIRING> m_sum;
};

} // namespace snarkfront

#endif
