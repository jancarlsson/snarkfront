#ifndef _SNARKFRONT_COMPILE_PPZK_HPP_
#define _SNARKFRONT_COMPILE_PPZK_HPP_

#include <array>
#include <cassert>
#include <cstdint>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include "snarkfront.hpp"

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// query AC
//

template <typename PAIRING>
class PPZK_query_AC
{
    typedef typename PAIRING::Fr FR;
    typedef typename PAIRING::G1 G1;

public:
    PPZK_query_AC(const std::size_t g1_exp_count,
                  const std::size_t numWindowBlocks,
                  const std::string& qapfile,
                  const std::string& randfile)
        : m_qapfile(qapfile),
          m_space(snarklib::WindowExp<G1>::space(g1_exp_count))
    {
#ifdef USE_ASSERT
        assert(numWindowBlocks <= m_space.globalID()[0]);
#endif
        m_space.blockPartition(std::array<std::size_t, 1>{ numWindowBlocks });

        std::ifstream ifs(randfile);
        m_error = !ifs || !m_randomness.marshal_in(ifs);
    }

    bool operator! () const { return m_error; }

    void A(const std::string& outfile,
           const std::size_t blocknum,
           snarklib::ProgressCallback* callback = nullptr) {
        writeFiles<snarklib::PPZK_QueryA<PAIRING>>(outfile,
                                                   blocknum,
                                                   callback,
                                                   m_randomness.rA(),
                                                   m_randomness.alphaA());
    }

    void C(const std::string& outfile,
           const std::size_t blocknum,
           snarklib::ProgressCallback* callback = nullptr) {
        writeFiles<snarklib::PPZK_QueryC<PAIRING>>(outfile,
                                                   blocknum,
                                                   callback,
                                                   m_randomness.rC(),
                                                   m_randomness.alphaC());
    }

private:
    template <typename QUERY>
    void writeFiles(const std::string& outfile,
                    const std::size_t blocknum,
                    snarklib::ProgressCallback* callback,
                    const FR& random_AC,
                    const FR& random_alphaAC)
    {
        const auto N = m_space.blockID()[0];

        snarklib::ProgressCallback_NOP<PAIRING> dummyNOP;
        snarklib::ProgressCallback* dummy = callback ? callback : std::addressof(dummyNOP);
        dummy->majorSteps(N);

        snarklib::BlockVector<FR> v;
        if (!snarklib::read_blockvector(m_qapfile, blocknum, v)) { m_error = true; return; }

        QUERY Q(v, random_AC, random_alphaAC);

        for (std::size_t i = 0; i < N; ++i) {
            const snarklib::WindowExp<G1> g1table(m_space, i);
            dummy->major(true);
            Q.accumTable(g1table,
                         g1table,
                         callback);
        }

#ifdef USE_ADD_SPECIAL
        Q.batchSpecial();
#endif

        std::stringstream ss;
        ss << outfile << blocknum;
        std::ofstream ofs(ss.str());
        if (!ofs)
            m_error = true;
        else
            Q.vec().marshal_out(ofs);
    }

    bool m_error;
    const std::string m_qapfile;
    snarklib::IndexSpace<1> m_space;
    snarklib::PPZK_KeypairRandomness<FR> m_randomness;
};

////////////////////////////////////////////////////////////////////////////////
// query B
//

template <typename PAIRING>
class PPZK_query_B
{
    typedef typename PAIRING::Fr FR;
    typedef typename PAIRING::G1 G1;
    typedef typename PAIRING::G2 G2;

public:
    PPZK_query_B(const std::size_t g1_exp_count,
                 const std::size_t numWindowBlocks,
                 const std::size_t g2_exp_count,
                 const std::string& qapfile,
                 const std::string& randfile)
        : m_qapfile(qapfile),
          m_space(snarklib::WindowExp<G1>::space(g1_exp_count)),
          m_g2table(g2_exp_count),
          m_g2null()
    {
#ifdef USE_ASSERT
        assert(numWindowBlocks <= m_space.globalID()[0]);
#endif
        m_space.blockPartition(std::array<std::size_t, 1>{ numWindowBlocks });

        std::ifstream ifs(randfile);
        m_error = !ifs || !m_randomness.marshal_in(ifs);
    }

    bool operator! () const { return m_error; }

    void B(const std::string& outfile,
           const std::size_t blocknum,
           snarklib::ProgressCallback* callback = nullptr) {
        writeFiles<snarklib::PPZK_QueryB<PAIRING>>(outfile,
                                                   blocknum,
                                                   callback);
    }

private:
    template <typename QUERY>
    void writeFiles(const std::string& outfile,
                    const std::size_t blocknum,
                    snarklib::ProgressCallback* callback)
    {
        const auto N = m_space.blockID()[0];

        snarklib::ProgressCallback_NOP<PAIRING> dummyNOP;
        snarklib::ProgressCallback* dummy = callback ? callback : std::addressof(dummyNOP);
        dummy->majorSteps(N);

        snarklib::BlockVector<FR> v;
        if (!snarklib::read_blockvector(m_qapfile, blocknum, v)) { m_error = true; return; }

        QUERY Q(v, m_randomness.rB(), m_randomness.alphaB());

        for (std::size_t i = 0; i < N; ++i) {
            const snarklib::WindowExp<G1> g1table(m_space, i);
            dummy->major(true);
            Q.accumTable(0 == i ? m_g2table : m_g2null,
                         g1table,
                         callback);
        }

#ifdef USE_ADD_SPECIAL
        Q.batchSpecial();
#endif

        std::stringstream ss;
        ss << outfile << blocknum;
        std::ofstream ofs(ss.str());
        if (!ofs)
            m_error = true;
        else
            Q.vec().marshal_out(ofs);
    }

    bool m_error;
    const std::string m_qapfile;
    snarklib::IndexSpace<1> m_space;
    const snarklib::WindowExp<G2> m_g2table, m_g2null;
    snarklib::PPZK_KeypairRandomness<FR> m_randomness;
};

////////////////////////////////////////////////////////////////////////////////
// query HK
//

template <typename PAIRING>
class PPZK_query_HK
{
    typedef typename PAIRING::Fr FR;
    typedef typename PAIRING::G1 G1;

public:
    PPZK_query_HK(const std::size_t g1_exp_count,
                  const std::size_t numWindowBlocks,
                  const std::string& qapfile)
        : m_error(false),
          m_qapfile(qapfile),
          m_space(snarklib::WindowExp<G1>::space(g1_exp_count))
    {
#ifdef USE_ASSERT
        assert(numWindowBlocks <= m_space.globalID()[0]);
#endif
        m_space.blockPartition(std::array<std::size_t, 1>{ numWindowBlocks });
    }

    bool operator! () const { return m_error; }

    void H(const std::string& outfile,
           const std::size_t blocknum,
           snarklib::ProgressCallback* callback = nullptr) {
        writeFiles<snarklib::PPZK_QueryH<PAIRING>>(outfile,
                                                   blocknum,
                                                   callback,
                                                   false);
    }

    void K(const std::string& outfile,
           const std::size_t blocknum,
           snarklib::ProgressCallback* callback = nullptr) {
        writeFiles<snarklib::PPZK_QueryK<PAIRING>>(outfile,
                                                   blocknum,
                                                   callback,
                                                   true);
    }

private:
    template <typename QUERY>
    void writeFiles(const std::string& outfile,
                    const std::size_t blocknum,
                    snarklib::ProgressCallback* callback,
                    const bool special) // only true for K
    {
        const auto N = m_space.blockID()[0];

        snarklib::ProgressCallback_NOP<PAIRING> dummyNOP;
        snarklib::ProgressCallback* dummy = callback ? callback : std::addressof(dummyNOP);
        dummy->majorSteps(N);

        snarklib::BlockVector<FR> v;
        if (!snarklib::read_blockvector(m_qapfile, blocknum, v)) { m_error = true; return; }

        QUERY Q(v);

        for (std::size_t i = 0; i < N; ++i) {
            const snarklib::WindowExp<G1> g1table(m_space, i);
            dummy->major(true);
            Q.accumTable(g1table,
                         callback);
        }

#ifdef USE_ADD_SPECIAL
        if (special) Q.batchSpecial();
#endif

        std::stringstream ss;
        ss << outfile << blocknum;
        std::ofstream ofs(ss.str());
        if (!ofs)
            m_error = true;
        else
            Q.vec().marshal_out(ofs);
    }

    bool m_error;
    const std::string m_qapfile;
    snarklib::IndexSpace<1> m_space;
};

////////////////////////////////////////////////////////////////////////////////
// verification key
//

template <typename PAIRING>
class PPZK_verification_key
{
    typedef typename PAIRING::Fr FR;
    typedef typename PAIRING::G1 G1;
    typedef typename PAIRING::G2 G2;

public:
    PPZK_verification_key(const std::size_t g1_exp_count,
                          const std::size_t numWindowBlocks,
                          const std::string& qapICfile,
                          const std::string& sysfile,
                          const std::string& randfile)
        : m_hugeSystem(sysfile),
          m_space(snarklib::WindowExp<G1>::space(g1_exp_count))
    {
#ifdef USE_ASSERT
        assert(numWindowBlocks <= m_space.globalID()[0]);
#endif
        m_space.blockPartition(std::array<std::size_t, 1>{ numWindowBlocks });

        std::ifstream ifs(randfile);
        m_error =
            !ifs || !m_randomness.marshal_in(ifs) ||
            !m_hugeSystem.loadIndex() ||
            !read_blockvector(qapICfile, 0, m_qapIC);
    }

    bool operator! () const { return m_error; }

    void writeFiles(const std::string& outfile,
                    snarklib::ProgressCallback* callback = nullptr)
    {
        const auto N = m_space.blockID()[0];

        snarklib::ProgressCallback_NOP<PAIRING> dummyNOP;
        snarklib::ProgressCallback* dummy = callback ? callback : std::addressof(dummyNOP);
        dummy->majorSteps(N);

        const snarklib::QAP_SystemPoint<snarklib::HugeSystem, FR>
            qap(m_hugeSystem,
                m_hugeSystem.numCircuitInputs(),
                m_randomness.point());

        snarklib::PPZK_QueryIC<PAIRING> Q(m_qapIC.vec());

        for (std::size_t i = 0; i < N; ++i) {
            const snarklib::WindowExp<G1> g1table(m_space, i);
            dummy->major(true);
            Q.accumTable(g1table,
                         callback);
        }

        const snarklib::PPZK_VerificationKey<PAIRING> vk(
            m_randomness.alphaA() * G2::one(),
            m_randomness.alphaB() * G1::one(),
            m_randomness.alphaC() * G2::one(),
            m_randomness.gamma() * G2::one(),
            (m_randomness.gamma() * m_randomness.beta()) * G1::one(),
            (m_randomness.gamma() * m_randomness.beta()) * G2::one(),
            (m_randomness.rC() * qap.compute_Z()) * G2::one(),
            Q);

        std::ofstream ofs(outfile);
        if (!ofs)
            m_error = true;
        else
            vk.marshal_out(ofs);
    }

private:
    bool m_error;
    snarklib::BlockVector<FR> m_qapIC;
    snarklib::PPZK_KeypairRandomness<FR> m_randomness;
    snarklib::HugeSystem<FR> m_hugeSystem;
    snarklib::IndexSpace<1> m_space;
};

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
                    ProgressCallback* callback = nullptr)
    {

        typename WITNESS::SparseVec query;

        std::stringstream ss;
        ss << queryfile << blocknum;

        std::ifstream ifs(ss.str());
        if (!ifs || !query.marshal_in(ifs)) {
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
                    ProgressCallback* callback = nullptr)
    {
        snarklib::BlockVector<G1> query;
        snarklib::BlockVector<FR> scalar;
        if (!snarklib::read_blockvector(queryfile, blocknum, query) ||
            !snarklib::read_blockvector(m_qapABCH, blocknum, scalar)) {
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

    bool operator! () const { return m_error; }

    void reserveTune(const std::size_t n = 0) {
        m_reserveTune = n;
    }

    void accumQuery(const std::string& queryfile,
                    const std::size_t blocknum,
                    ProgressCallback* callback = nullptr)
    {
        snarklib::BlockVector<G1> query;
        if (!snarklib::read_blockvector(queryfile, blocknum, query)) {
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
