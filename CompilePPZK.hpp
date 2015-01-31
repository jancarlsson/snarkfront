#ifndef _SNARKFRONT_COMPILE_PPZK_HPP_
#define _SNARKFRONT_COMPILE_PPZK_HPP_

#include <cstdint>
#include <fstream>
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
                  const std::string& qapfile,
                  const std::string& randfile)
        : m_error(false),
          m_qapfile(qapfile),
          m_g1table(g1_exp_count)
    {
        std::ifstream ifs(randfile);
        if (!ifs || !m_randomness.marshal_in(ifs))
            m_error = true;
    }

    bool operator! () const { return m_error; }

    void A(const std::string& outfile,
           const std::size_t blocknum) {
        writeFiles<snarklib::PPZK_QueryA<PAIRING>>(outfile,
                                                   blocknum,
                                                   m_randomness.rA(),
                                                   m_randomness.alphaA());
    }

    void C(const std::string& outfile,
           const std::size_t blocknum) {
        writeFiles<snarklib::PPZK_QueryC<PAIRING>>(outfile,
                                                   blocknum,
                                                   m_randomness.rC(),
                                                   m_randomness.alphaC());
    }

private:
    template <typename QUERY>
    void writeFiles(const std::string& outfile,
                    const std::size_t blocknum,
                    const FR& random_AC,
                    const FR& random_alphaAC)
    {
        snarklib::BlockVector<FR> v;
        if (!snarklib::read_blockvector(m_qapfile, blocknum, v)) { m_error = true; return; }

        QUERY Q(v, random_AC, random_alphaAC);
        Q.accumTable(m_g1table, m_g1table);

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
    const snarklib::WindowExp<G1> m_g1table;
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
                 const std::size_t g2_exp_count,
                 const std::string& qapfile,
                 const std::string& randfile)
        : m_error(false),
          m_qapfile(qapfile),
          m_g1table(g1_exp_count),
          m_g2table(g2_exp_count)
    {
        std::ifstream ifs(randfile);
        if (!ifs || !m_randomness.marshal_in(ifs))
            m_error = true;
    }

    bool operator! () const { return m_error; }

    void B(const std::string& outfile,
           const std::size_t blocknum) {
        writeFiles<snarklib::PPZK_QueryB<PAIRING>>(outfile, blocknum);
    }

private:
    template <typename QUERY>
    void writeFiles(const std::string& outfile,
                    const std::size_t blocknum)
    {
        snarklib::BlockVector<FR> v;
        if (!snarklib::read_blockvector(m_qapfile, blocknum, v)) { m_error = true; return; }

        QUERY Q(v, m_randomness.rB(), m_randomness.alphaB());
        Q.accumTable(m_g2table, m_g1table);

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
    const snarklib::WindowExp<G1> m_g1table;
    const snarklib::WindowExp<G2> m_g2table;
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
                  const std::string& qapfile)
        : m_error(false),
          m_qapfile(qapfile),
          m_g1table(g1_exp_count)
    {}

    bool operator! () const { return m_error; }

    void H(const std::string& outfile,
           const std::size_t blocknum) {
        writeFiles<snarklib::PPZK_QueryH<PAIRING>>(outfile, blocknum, false);
    }

    void K(const std::string& outfile,
           const std::size_t blocknum) {
        writeFiles<snarklib::PPZK_QueryH<PAIRING>>(outfile, blocknum,
#ifdef USE_ADD_SPECIAL
                                                   true);
#else
                                                   false);
#endif
    }

private:
    template <typename QUERY>
    void writeFiles(const std::string& outfile,
                    const std::size_t blocknum,
                    const bool special) // only true for K #ifdef USE_ADD_SPECIAL
    {
        snarklib::BlockVector<FR> v;
        if (!snarklib::read_blockvector(m_qapfile, blocknum, v)) { m_error = true; return; }

        QUERY Q(v);
        Q.accumTable(m_g1table);
        if (special) batchSpecial(Q.llvec());

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
    const snarklib::WindowExp<G1> m_g1table;
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
                          const std::string& qapICfile,
                          const std::string& sysfile,
                          const std::string& randfile)
        : m_error(false),
          m_hugeSystem(sysfile),
          m_g1table(g1_exp_count)
    {
        std::ifstream ifs(randfile);
        if (!ifs || !m_randomness.marshal_in(ifs) ||
            !m_hugeSystem.loadIndex() ||
            !read_blockvector(qapICfile, 0, m_qapIC))
        {
            m_error = true;
        }
    }

    bool operator! () const { return m_error; }

    void writeFiles(const std::string& outfile)
    {
        const snarklib::QAP_SystemPoint<snarklib::HugeSystem, FR>
            qap(m_hugeSystem,
                m_hugeSystem.numCircuitInputs(),
                m_randomness.point());

        snarklib::PPZK_QueryIC<PAIRING> ppzkIC(m_qapIC.vec());
        ppzkIC.accumTable(m_g1table);

        const snarklib::PPZK_VerificationKey<PAIRING> vk(
            m_randomness.alphaA() * G2::one(),
            m_randomness.alphaB() * G1::one(),
            m_randomness.alphaC() * G2::one(),
            m_randomness.gamma() * G2::one(),
            (m_randomness.gamma() * m_randomness.beta()) * G1::one(),
            (m_randomness.gamma() * m_randomness.beta()) * G2::one(),
            (m_randomness.rC() * qap.compute_Z()) * G2::one(),
            ppzkIC);

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
    const snarklib::WindowExp<G1> m_g1table;
};

} // namespace snarkfront

#endif
