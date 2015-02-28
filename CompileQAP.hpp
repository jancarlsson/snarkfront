#ifndef _SNARKFRONT_COMPILE_QAP_HPP_
#define _SNARKFRONT_COMPILE_QAP_HPP_

#include <array>
#include <cstdint>
#include <fstream>
#include <string>
#include "snarkfront.hpp"

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// query ABCH
//

template <typename PAIRING>
class QAP_query_ABCH
{
    typedef typename PAIRING::Fr FR;
    typedef typename snarklib::QAP_QueryABC<snarklib::HugeSystem, FR> ABC;

public:
    QAP_query_ABCH(const std::size_t numBlocks,
                   const std::string& sysfile,
                   const std::string& randfile)
        : m_numBlocks(numBlocks),
          m_hugeSystem(sysfile)
    {
        std::ifstream ifs(randfile);
        m_error = !ifs || !m_randomness.marshal_in(ifs) || !m_hugeSystem.loadIndex();
    }

    // for g1_exp_count() and g2_exp_count() only
    QAP_query_ABCH(const std::string& sysfile)
        : m_numBlocks(0),
          m_hugeSystem(sysfile)
    {
        m_error = !m_hugeSystem.loadIndex();
    }

    bool operator! () const { return m_error; }

    void A(const std::string& outfile) {
        writeFilesABC(outfile, ABC::VecSelect::A);
    }

    void B(const std::string& outfile) {
        writeFilesABC(outfile, ABC::VecSelect::B);
    }

    void C(const std::string& outfile) {
        writeFilesABC(outfile, ABC::VecSelect::C);
    }

    void H(const std::string& outfile) {
        writeFilesH(outfile);
    }

    std::size_t g1_exp_count(const std::string& afile,
                             const std::string& bfile,
                             const std::string& cfile,
                             const std::string& hfile) {
        return snarklib::g1_exp_count(
            m_hugeSystem.maxIndex(),         // same as QAP numVariables()
            m_hugeSystem.numCircuitInputs(), // same as QAP numCircuitInputs()
            nonzeroCount(afile),
            nonzeroCount(bfile),
            nonzeroCount(cfile),
            nonzeroCount(hfile));
    }

    std::size_t g2_exp_count(const std::string& bfile) {
        return snarklib::g2_exp_count(
            nonzeroCount(bfile));
    }

private:
    template <typename QUERY>
    void writeFiles(const std::string& outfile,
                    const QUERY& Q)
    {
        auto space = snarklib::BlockVector<FR>::space(Q.vec());
        space.blockPartition(std::array<size_t, 1>{m_numBlocks});
        space.param(Q.nonzeroCount());

        std::ofstream ofs(outfile);
        if (!ofs || !write_blockvector(outfile, space, Q.vec()))
            m_error = true;
        else
            space.marshal_out(ofs);
    }

    void writeFilesABC(const std::string& outfile,
                       const unsigned int mask)
    {
        const snarklib::QAP_SystemPoint<snarklib::HugeSystem, FR>
            qap(m_hugeSystem,
                m_hugeSystem.numCircuitInputs(),
                m_randomness.point());

        writeFiles(outfile,
                   snarklib::QAP_QueryABC<snarklib::HugeSystem, FR>(qap, mask));
    }

    void writeFilesH(const std::string& outfile)
    {
        const snarklib::QAP_SystemPoint<snarklib::HugeSystem, FR>
            qap(m_hugeSystem,
                m_hugeSystem.numCircuitInputs(),
                m_randomness.point());

        writeFiles(outfile,
                   snarklib::QAP_QueryH<snarklib::HugeSystem, FR>(qap));
    }

    std::size_t nonzeroCount(const std::string& abchfile) {
        snarklib::IndexSpace<1> space;
        std::ifstream ifs(abchfile);
        return (!ifs || !space.marshal_in(ifs))
            ? m_error = false
            : space.param()[0];
    }

    const std::size_t m_numBlocks;

    snarklib::PPZK_KeypairRandomness<FR, FR> m_randomness;
    snarklib::HugeSystem<FR> m_hugeSystem;
    bool m_error;
};

////////////////////////////////////////////////////////////////////////////////
// query K
//

template <typename PAIRING>
class QAP_query_K
{
    typedef typename PAIRING::Fr FR;

public:
    QAP_query_K(const std::string& afile,
                const std::string& bfile,
                const std::string& cfile,
                const std::string& sysfile,
                const std::string& randfile)
        : m_afile(afile),
          m_bfile(bfile),
          m_cfile(cfile),
          m_hugeSystem(sysfile)
    {
        std::ifstream ifs(randfile);
        m_error = !ifs || !m_randomness.marshal_in(ifs) || !m_hugeSystem.loadIndex();
    }

    bool operator! () const { return m_error; }

    void K(const std::string& outfile,
           const std::size_t blocknum) {
        writeFiles(outfile, blocknum);
    }

private:
    void writeFiles(const std::string& outfile,
                    const std::size_t blocknum)
    {
        const snarklib::QAP_SystemPoint<snarklib::HugeSystem, FR>
            qap(m_hugeSystem,
                m_hugeSystem.numCircuitInputs(),
                m_randomness.point());

        snarklib::QAP_QueryK<snarklib::HugeSystem, FR> Q(qap,
                                                         m_randomness.rA(),
                                                         m_randomness.rB(),
                                                         m_randomness.beta());

        std::size_t block = (-1 == blocknum) ? 0 : blocknum;
        bool b = true;
        while (b) {
            snarklib::BlockVector<FR> A, B, C;

            if (!snarklib::read_blockvector(m_afile, block, A)) { m_error = true; return; }
            if (!snarklib::read_blockvector(m_bfile, block, B)) { m_error = true; return; }
            if (!snarklib::read_blockvector(m_cfile, block, C)) { m_error = true; return; }

            Q.accumVector(A, B, C);

            if (!snarklib::write_blockvector(outfile, block, A.space(), Q.vec())) {
                m_error = true;
                return;
            }

            b = (-1 == blocknum)
                ? ++block < A.space().blockID()[0]
                : false;

            if (!b) {
                std::ofstream ofs(outfile);
                if (!ofs)
                    m_error = true;
                else
                    A.space().marshal_out(ofs);
            }
        }
    }

    const std::string m_afile, m_bfile, m_cfile;

    snarklib::PPZK_KeypairRandomness<FR, FR> m_randomness;
    snarklib::HugeSystem<FR> m_hugeSystem;
    bool m_error;
};

////////////////////////////////////////////////////////////////////////////////
// query IC
//

template <typename PAIRING>
class QAP_query_IC
{
    typedef typename PAIRING::Fr FR;

public:
    QAP_query_IC(const std::string& afile,
                 const std::string& sysfile,
                 const std::string& randfile)
        : m_afile(afile),
          m_hugeSystem(sysfile)
    {
        std::ifstream ifs(randfile);
        m_error = !ifs || !m_randomness.marshal_in(ifs) || !m_hugeSystem.loadIndex();
    }

    bool operator! () const { return m_error; }

    void IC(const std::string& outfile) {
        writeFiles(outfile);
    }

private:
    void writeFiles(const std::string& outfile) {
        const snarklib::QAP_SystemPoint<snarklib::HugeSystem, FR>
            qap(m_hugeSystem,
                m_hugeSystem.numCircuitInputs(),
                m_randomness.point());

        snarklib::QAP_QueryIC<snarklib::HugeSystem, FR> Q(qap,
                                                          m_randomness.rA());

        std::size_t block = 0;
        bool b = true;
        while (b) {
            snarklib::BlockVector<FR> A;

            if (!snarklib::read_blockvector(m_afile, block, A)) {
                m_error = true;
                return;
            }

            if (!Q.accumVector(A)) break;

            std::stringstream ss;
            ss << m_afile << block;

            std::ofstream ofs(ss.str());
            if (!ofs)
                m_error = true;
            else
                A.marshal_out(ofs);

            b = ++block < A.space().blockID()[0];
        }

        std::ofstream ofs(outfile);
        const auto space = snarklib::BlockVector<FR>::space(Q.vec());
        if (!ofs || !snarklib::write_blockvector(outfile, space, Q.vec()))
            m_error = true;
        else
            space.marshal_out(ofs);
    }

    const std::string m_afile;

    snarklib::PPZK_KeypairRandomness<FR, FR> m_randomness;
    snarklib::HugeSystem<FR> m_hugeSystem;
    bool m_error;
};

////////////////////////////////////////////////////////////////////////////////
// witness ABCH
//

template <typename PAIRING>
class QAP_witness_ABCH
{
    typedef typename PAIRING::Fr FR;

public:
    QAP_witness_ABCH(const std::size_t numBlocks,
                     const std::string& sysfile,
                     const std::string& randfile,
                     const std::string& witfile)
        : m_numBlocks(numBlocks),
          m_hugeSystem(sysfile)
    {
        std::ifstream ifsR(randfile), ifsW(witfile);
        m_error =
            !ifsR || !m_randomness.marshal_in(ifsR) ||
            !ifsW || !m_witness.marshal_in(ifsW) ||
            !m_hugeSystem.loadIndex();
    }

    bool operator! () const { return m_error; }

    void writeFiles(const std::string& outfile)
    {
        const snarklib::QAP_SystemPoint<snarklib::HugeSystem, FR>
            qap(m_hugeSystem,
                m_hugeSystem.numCircuitInputs());

        const snarklib::QAP_WitnessABCH<snarklib::HugeSystem, FR>
            ABCH(qap,
                 m_witness,
                 m_randomness.d1(),
                 m_randomness.d2(),
                 m_randomness.d3());

        auto space = snarklib::BlockVector<FR>::space(ABCH.vec());
        space.blockPartition(std::array<size_t, 1>{m_numBlocks});

        if (! write_blockvector(outfile, space, ABCH.vec()))
            m_error = true;
    }

private:
    const std::size_t m_numBlocks;

    snarklib::R1Witness<FR> m_witness;
    snarklib::PPZK_ProofRandomness<FR> m_randomness;
    snarklib::HugeSystem<FR> m_hugeSystem;
    bool m_error;
};

} // namespace snarkfront

#endif
