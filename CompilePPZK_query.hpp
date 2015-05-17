#ifndef _SNARKFRONT_COMPILE_PPZK_QUERY_HPP_
#define _SNARKFRONT_COMPILE_PPZK_QUERY_HPP_

#include <array>
#include <cassert>
#include <cstdint>
#include <fstream>
#include <functional>
#include <memory>
#include <sstream>
#include <string>

#include <snarklib/AuxSTL.hpp>
#include <snarklib/HugeSystem.hpp>
#include <snarklib/IndexSpace.hpp>
#include <snarklib/PPZK_keystruct.hpp>
#include <snarklib/PPZK_query.hpp>
#include <snarklib/PPZK_randomness.hpp>
#include <snarklib/ProgressCallback.hpp>
#include <snarklib/QAP_system.hpp>
#include <snarklib/Util.hpp>
#include <snarklib/WindowExp.hpp>

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// query AC
//

template <typename PAIRING>
class PPZK_query_AC
{
    typedef typename PAIRING::Fr FR;
    typedef typename PAIRING::G1 G1;
    typedef typename PAIRING::G2 G2;

public:
    PPZK_query_AC(const std::size_t g1_exp_count,
                  const std::size_t numWindowBlocks,
                  const std::string& qapfile,
                  const std::string& randfile,
                  const bool is_blind_entropy = false)
        : m_qapfile(qapfile),
          m_space(snarklib::WindowExp<G1>::space(g1_exp_count))
    {
#ifdef USE_ASSERT
        assert(numWindowBlocks <= m_space.globalID()[0]);
#endif
        m_space.blockPartition(std::array<std::size_t, 1>{ numWindowBlocks });

        std::ifstream ifs(randfile);
        m_error = !ifs ||
            !m_lagrangePoint.marshal_in(ifs) ||
            (is_blind_entropy
             ? !m_blindGreeks.marshal_in(ifs)
             : !m_clearGreeks.marshal_in(ifs));
    }

    PPZK_query_AC(const std::size_t g1_exp_count,
                  const std::size_t numWindowBlocks,
                  const std::string& qapfile,
                  const snarklib::PPZK_LagrangePoint<FR>& lagrangeRand,
                  const snarklib::PPZK_BlindGreeks<FR, FR>& greeksRand)
        : m_qapfile(qapfile),
          m_space(snarklib::WindowExp<G1>::space(g1_exp_count)),
          m_lagrangePoint(lagrangeRand),
          m_clearGreeks(greeksRand),
          m_error(false)
    {
#ifdef USE_ASSERT
        assert(numWindowBlocks <= m_space.globalID()[0]);
#endif
        m_space.blockPartition(std::array<std::size_t, 1>{ numWindowBlocks });
    }

    bool operator! () const { return m_error; }

    void A(const std::string& outfile,
           const std::size_t blocknum,
           snarklib::ProgressCallback* callback = nullptr)
    {
        if (m_blindGreeks.empty())
            writeFiles<snarklib::PPZK_QueryA<PAIRING>>(
                outfile,
                blocknum,
                callback,
                m_clearGreeks.rA(), // FR
                m_clearGreeks.alphaA_rA()); // FR
        else 
            writeFiles<snarklib::PPZK_QueryA<PAIRING>>(
                outfile,
                blocknum,
                callback,
                m_blindGreeks.rA().G(), // G1
                m_blindGreeks.alphaA_rA().G()); // G1
    }

    void C(const std::string& outfile,
           const std::size_t blocknum,
           snarklib::ProgressCallback* callback = nullptr)
    {
        if (m_blindGreeks.empty())
            writeFiles<snarklib::PPZK_QueryC<PAIRING>>(
                outfile,
                blocknum,
                callback,
                m_clearGreeks.rC(), // FR
                m_clearGreeks.alphaC_rC()); // FR
        else
            writeFiles<snarklib::PPZK_QueryC<PAIRING>>(
                outfile,
                blocknum,
                callback,
                m_blindGreeks.rC().G(), // G1
                m_blindGreeks.alphaC_rC().G()); // G1
    }

private:
    template <typename QUERY>
    void writeFiles(
        const std::string& outfile,
        const std::size_t blocknum,
        snarklib::ProgressCallback* callback,
        const FR& random_rX,
        const FR& random_alphaX_rX,
        std::function<void (QUERY& Q, snarklib::ProgressCallback*)> func)
    {
        snarklib::ProgressCallback_NOP<PAIRING> dummyNOP;
        snarklib::ProgressCallback* dummy = callback
            ? callback
            : std::addressof(dummyNOP);

        const auto N = m_space.blockID()[0];
        dummy->majorSteps(N);

        snarklib::BlockVector<FR> v;
        if (!snarklib::read_blockvector_raw(m_qapfile, blocknum, v)) {
            m_error = true;
            return;
        }

        QUERY Q(v, random_rX, random_alphaX_rX);

        func(Q, dummy);

#ifdef USE_ADD_SPECIAL
        Q.batchSpecial();
#endif

        std::stringstream ss;
        ss << outfile << blocknum;

        std::ofstream ofs(ss.str());
        if (!ofs)
            m_error = true;
        else
#ifdef USE_ADD_SPECIAL
            Q.vec().marshal_out(
                ofs,
                [] (std::ostream& o, const typename QUERY::Val& a) {
                    a.marshal_out_rawspecial(o);
                });
#else
            Q.vec().marshal_out(
                ofs,
                [] (std::ostream& o, const typename QUERY::Val& a) {
                    a.marshal_out_raw(o);
                });
#endif
    }

    // entropy in clear
    template <typename QUERY>
    void writeFiles(const std::string& outfile,
                    const std::size_t blocknum,
                    snarklib::ProgressCallback* callback,
                    const FR& random_rX,
                    const FR& random_alphaX_rX)
    {
        const auto& space = m_space;

        writeFiles<QUERY>(
            outfile, blocknum, callback,
            random_rX, random_alphaX_rX,

            [&space] (QUERY& Q, snarklib::ProgressCallback* dummy)
            {
                for (std::size_t i = 0; i < space.blockID()[0]; ++i) {
                    const snarklib::WindowExp<G1> g1_table(space, i);
                    dummy->major(true);
                    Q.accumTable(g1_table, g1_table, dummy);
                }
            });
    }

    // blinded entropy
    template <typename QUERY>
    void writeFiles(const std::string& outfile,
                    const std::size_t blocknum,
                    snarklib::ProgressCallback* callback,
                    const G1& random_rX,
                    const G1& random_alphaX_rX)
    {
        const auto& space = m_space;

        writeFiles<QUERY>(
            outfile, blocknum, callback,
            FR::one(), FR::one(),

            [&space,
             &random_rX,
             &random_alphaX_rX] (QUERY& Q, snarklib::ProgressCallback* dummy)
            {
                for (std::size_t i = 0; i < space.blockID()[0]; ++i) {
                    const snarklib::WindowExp<G1>
                        gA_table(space, i, random_rX),
                        gB_table(space, i, random_alphaX_rX);
                    dummy->major(true);
                    Q.accumTable(gA_table, gB_table, dummy);
                }
            });
    }

    bool m_error;
    const std::string m_qapfile;
    snarklib::IndexSpace<1> m_space;
    snarklib::PPZK_LagrangePoint<FR> m_lagrangePoint;
    snarklib::PPZK_BlindGreeks<FR, FR> m_clearGreeks;
    snarklib::PPZK_BlindGreeks<FR, snarklib::Pairing<G1, G2>> m_blindGreeks;
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
                 const std::string& randfile,
                 const bool is_blind_entropy = false)
        : m_qapfile(qapfile),
          m_g2_exp_count(g2_exp_count),
          m_space(snarklib::WindowExp<G1>::space(g1_exp_count))
    {
#ifdef USE_ASSERT
        assert(numWindowBlocks <= m_space.globalID()[0]);
#endif
        m_space.blockPartition(std::array<std::size_t, 1>{ numWindowBlocks });

        std::ifstream ifs(randfile);
        m_error = !ifs ||
            !m_lagrangePoint.marshal_in(ifs) ||
            (is_blind_entropy
             ? !m_blindGreeks.marshal_in(ifs)
             : !m_clearGreeks.marshal_in(ifs));
    }

    PPZK_query_B(const std::size_t g1_exp_count,
                 const std::size_t numWindowBlocks,
                 const std::size_t g2_exp_count,
                 const std::string& qapfile,
                 const snarklib::PPZK_LagrangePoint<FR>& lagrangeRand,
                 const snarklib::PPZK_BlindGreeks<FR, FR>& greeksRand)
        : m_qapfile(qapfile),
          m_g2_exp_count(g2_exp_count),
          m_space(snarklib::WindowExp<G1>::space(g1_exp_count)),
          m_lagrangePoint(lagrangeRand),
          m_clearGreeks(greeksRand),
          m_error(false)
    {
#ifdef USE_ASSERT
        assert(numWindowBlocks <= m_space.globalID()[0]);
#endif
        m_space.blockPartition(std::array<std::size_t, 1>{ numWindowBlocks });
    }

    bool operator! () const { return m_error; }

    void B(const std::string& outfile,
           const std::size_t blocknum,
           snarklib::ProgressCallback* callback = nullptr)
    {
        if (m_blindGreeks.empty())
            writeFiles<snarklib::PPZK_QueryB<PAIRING>>(
                outfile,
                blocknum,
                callback,
                m_clearGreeks.rB(), // FR
                m_clearGreeks.alphaB_rB()); // FR
        else
            writeFiles<snarklib::PPZK_QueryB<PAIRING>>(
                outfile,
                blocknum,
                callback,
                m_blindGreeks.rB().H(), // G2
                m_blindGreeks.alphaB_rB().G()); // G1
    }

private:
    template <typename QUERY>
    void writeFiles(
        const std::string& outfile,
        const std::size_t blocknum,
        snarklib::ProgressCallback* callback,
        const FR& random_rX,
        const FR& random_alphaX_rX,
        std::function<void (QUERY& Q, snarklib::ProgressCallback*)> func)
    {
        snarklib::ProgressCallback_NOP<PAIRING> dummyNOP;
        snarklib::ProgressCallback* dummy = callback
            ? callback
            : std::addressof(dummyNOP);

        const auto N = m_space.blockID()[0];
        dummy->majorSteps(N);

        snarklib::BlockVector<FR> v;
        if (!snarklib::read_blockvector_raw(m_qapfile, blocknum, v)) {
            m_error = true;
            return;
        }

        QUERY Q(v, random_rX, random_alphaX_rX);

        func(Q, dummy);

#ifdef USE_ADD_SPECIAL
        Q.batchSpecial();
#endif

        std::stringstream ss;
        ss << outfile << blocknum;

        std::ofstream ofs(ss.str());
        if (!ofs)
            m_error = true;
        else
#ifdef USE_ADD_SPECIAL
            Q.vec().marshal_out(
                ofs,
                [] (std::ostream& o, const typename QUERY::Val& a) {
                    a.marshal_out_rawspecial(o);
                });
#else
            Q.vec().marshal_out(
                ofs,
                [] (std::ostream& o, const typename QUERY::Val& a) {
                    a.marshal_out_raw(o);
                });
#endif
    }

    // entropy in clear
    template <typename QUERY>
    void writeFiles(const std::string& outfile,
                    const std::size_t blocknum,
                    snarklib::ProgressCallback* callback,
                    const FR& random_rB,
                    const FR& random_alphaB_rB)
    {
        const auto& space = m_space;
        const auto g2_exp_count = m_g2_exp_count;

        writeFiles<QUERY>(
            outfile, blocknum, callback,
            random_rB, random_alphaB_rB,

            [&space,
             &g2_exp_count] (QUERY& Q, snarklib::ProgressCallback* dummy)
            {
                const snarklib::WindowExp<G2>
                    g2_table(g2_exp_count),
                    g2_null;

                for (std::size_t i = 0; i < space.blockID()[0]; ++i) {
                    const snarklib::WindowExp<G1> g1_table(space, i);
                    dummy->major(true);
                    Q.accumTable(0 == i ? g2_table : g2_null,
                                 g1_table,
                                 dummy);
                }
            });
    }

    // blinded entropy
    template <typename QUERY>
    void writeFiles(const std::string& outfile,
                    const std::size_t blocknum,
                    snarklib::ProgressCallback* callback,
                    const G2& random_rB,
                    const G1& random_alphaB_rB)
    {
        const auto& space = m_space;
        const auto g2_exp_count = m_g2_exp_count;

        writeFiles<QUERY>(
            outfile, blocknum, callback,
            FR::one(), FR::one(),

            [&space,
             &g2_exp_count,
             &random_rB,
             &random_alphaB_rB] (QUERY& Q, snarklib::ProgressCallback* dummy)
            {
                const snarklib::WindowExp<G2>
                    g2_table(g2_exp_count, nullptr, random_rB),
                    g2_null;

                for (std::size_t i = 0; i < space.blockID()[0]; ++i) {
                    const snarklib::WindowExp<G1> g1_table(space, i, random_alphaB_rB);
                    dummy->major(true);
                    Q.accumTable(0 == i ? g2_table : g2_null,
                                 g1_table,
                                 dummy);
                }
            });
    }

    bool m_error;
    const std::string m_qapfile;
    const std::size_t m_g2_exp_count;
    snarklib::IndexSpace<1> m_space;
    snarklib::PPZK_LagrangePoint<FR> m_lagrangePoint;
    snarklib::PPZK_BlindGreeks<FR, FR> m_clearGreeks;
    snarklib::PPZK_BlindGreeks<FR, snarklib::Pairing<G1, G2>> m_blindGreeks;
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
        writeFiles(outfile, blocknum, callback);
    }

    void K(const std::string& outfile,
           const std::size_t blocknum,
           snarklib::ProgressCallback* callback = nullptr) {
        writeFiles(outfile, blocknum, callback);
    }

private:
    void writeFiles(const std::string& outfile,
                    const std::size_t blocknum,
                    snarklib::ProgressCallback* callback)
    {
        snarklib::ProgressCallback_NOP<PAIRING> dummyNOP;
        snarklib::ProgressCallback* dummy = callback
            ? callback
            : std::addressof(dummyNOP);

        const auto N = m_space.blockID()[0];
        dummy->majorSteps(N);

        snarklib::BlockVector<FR> v;
        if (!snarklib::read_blockvector_raw(m_qapfile, blocknum, v)) {
            m_error = true;
            return;
        }

        snarklib::PPZK_QueryHK<PAIRING> Q(v);

        for (std::size_t i = 0; i < N; ++i) {
            const snarklib::WindowExp<G1> g1table(m_space, i);
            dummy->major(true);
            Q.accumTable(g1table, v, dummy);
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
#ifdef USE_ADD_SPECIAL
            Q.vec().marshal_out(
                ofs,
                [] (std::ostream& o, const G1& a) {
                    a.marshal_out_rawspecial(o);
                });
#else
            Q.vec().marshal_out(
                ofs,
                [] (std::ostream& o, const G1& a) {
                    a.marshal_out_raw(o);
                });
#endif
    }

    bool m_error;
    const std::string m_qapfile;
    snarklib::IndexSpace<1> m_space;
};

////////////////////////////////////////////////////////////////////////////////
// query K
//

template <typename PAIRING>
class PPZK_query_K
{
    typedef typename PAIRING::Fr FR;
    typedef typename PAIRING::G1 G1;
    typedef typename PAIRING::G2 G2;

public:
    PPZK_query_K(const std::size_t g1_exp_count,
                 const std::size_t numWindowBlocks,
                 const std::string& afile,
                 const std::string& bfile,
                 const std::string& cfile,
                 const std::string& randfile)
        : m_error(false),
          m_afile(afile),
          m_bfile(bfile),
          m_cfile(cfile),
          m_space(snarklib::WindowExp<G1>::space(g1_exp_count))
    {
#ifdef USE_ASSERT
        assert(numWindowBlocks <= m_space.globalID()[0]);
#endif
        m_space.blockPartition(std::array<std::size_t, 1>{ numWindowBlocks });

        std::ifstream ifs(randfile);
        m_error = !ifs ||
            !m_lagrangePoint.marshal_in(ifs) ||
            !m_blindGreeks.marshal_in(ifs);
    }

    bool operator! () const { return m_error; }

    void K(const std::string& outfile,
           const std::size_t blocknum,
           snarklib::ProgressCallback* callback = nullptr)
    {
        snarklib::ProgressCallback_NOP<PAIRING> dummyNOP;
        snarklib::ProgressCallback* dummy = callback
            ? callback
            : std::addressof(dummyNOP);

        const auto N = m_space.blockID()[0];

        const auto
            &random_beta_rA = m_blindGreeks.beta_rA().G(), // G1
            &random_beta_rB = m_blindGreeks.beta_rB().G(), // G1
            &random_beta_rC = m_blindGreeks.beta_rC().G(); // G1

        std::size_t block = (-1 == blocknum) ? 0 : blocknum;
        bool b = true;
        while (b) {
            snarklib::BlockVector<FR> A, B, C;

            if (!snarklib::read_blockvector_raw(m_afile, block, A) ||
                !snarklib::read_blockvector_raw(m_bfile, block, B) ||
                !snarklib::read_blockvector_raw(m_cfile, block, C)) {
                m_error = true;
                return;
            }

            const auto& space = A.space();

            snarklib::PPZK_QueryHK<PAIRING> Q(space, block);

            dummy->majorSteps(3 * N);

            for (std::size_t i = 0; i < N; ++i) {
                const snarklib::WindowExp<G1> g1_table(m_space, i, random_beta_rA);
                dummy->major(true);
                Q.accumTable(g1_table, A, dummy);
            }

            for (std::size_t i = 0; i < N; ++i) {
                const snarklib::WindowExp<G1> g1_table(m_space, i, random_beta_rB);
                dummy->major(true);
                Q.accumTable(g1_table, B, dummy);
            }

            for (std::size_t i = 0; i < N; ++i) {
                const snarklib::WindowExp<G1> g1_table(m_space, i, random_beta_rC);
                dummy->major(true);
                Q.accumTable(g1_table, C, dummy);
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
#ifdef USE_ADD_SPECIAL
            Q.vec().marshal_out(
                ofs,
                [] (std::ostream& o, const G1& a) {
                    a.marshal_out_rawspecial(o);
                });
#else
            Q.vec().marshal_out(
                ofs,
                [] (std::ostream& o, const G1& a) {
                    a.marshal_out_raw(o);
                });
#endif

            b = (-1 == blocknum)
                ? ++block < space.blockID()[0]
                : false;
        }
    }

private:
    bool m_error;
    const std::string m_afile, m_bfile, m_cfile;
    snarklib::IndexSpace<1> m_space;
    snarklib::PPZK_LagrangePoint<FR> m_lagrangePoint;
    snarklib::PPZK_BlindGreeks<FR, snarklib::Pairing<G1, G2>> m_blindGreeks;
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
    typedef typename snarklib::QAP_SystemPoint<snarklib::HugeSystem, FR> SYSPT;

public:
    PPZK_verification_key(const std::size_t g1_exp_count,
                          const std::size_t numWindowBlocks,
                          const std::string& qapICfile,
                          const std::string& sysfile,
                          const std::string& randfile,
                          const bool is_blind_entropy = false)
        : m_hugeSystem(sysfile),
          m_space(snarklib::WindowExp<G1>::space(g1_exp_count))
    {
#ifdef USE_ASSERT
        assert(numWindowBlocks <= m_space.globalID()[0]);
#endif
        m_space.blockPartition(std::array<std::size_t, 1>{ numWindowBlocks });

        std::ifstream ifs(randfile);
        m_error = !ifs ||
            !m_lagrangePoint.marshal_in(ifs) ||
            (is_blind_entropy
             ? !m_blindGreeks.marshal_in(ifs)
             : !m_clearGreeks.marshal_in(ifs)) ||
            !m_hugeSystem.loadIndex() ||
            !read_blockvector_raw(qapICfile, 0, m_qapIC);
    }

    PPZK_verification_key(const std::size_t g1_exp_count,
                          const std::size_t numWindowBlocks,
                          const std::string& qapICfile,
                          const std::string& sysfile,
                          const snarklib::PPZK_LagrangePoint<FR>& lagrangeRand,
                          const snarklib::PPZK_BlindGreeks<FR, FR>& greeksRand)
        : m_hugeSystem(sysfile),
          m_space(snarklib::WindowExp<G1>::space(g1_exp_count)),
          m_lagrangePoint(lagrangeRand),
          m_clearGreeks(greeksRand)
    {
#ifdef USE_ASSERT
        assert(numWindowBlocks <= m_space.globalID()[0]);
#endif
        m_space.blockPartition(std::array<std::size_t, 1>{ numWindowBlocks });

        m_error =
            !m_hugeSystem.loadIndex() ||
            !read_blockvector_raw(qapICfile, 0, m_qapIC);
    }

    bool operator! () const { return m_error; }

    void writeFiles(const std::string& outfile,
                    snarklib::ProgressCallback* callback = nullptr)
    {
        snarklib::ProgressCallback_NOP<PAIRING> dummyNOP;
        snarklib::ProgressCallback* dummy = callback
            ? callback
            : std::addressof(dummyNOP);

        const auto N = m_space.blockID()[0];
        dummy->majorSteps(N);

        const SYSPT qap(m_hugeSystem,
                        m_hugeSystem.numCircuitInputs(),
                        m_lagrangePoint.point());

        if (qap.weakPoint()) {
            // Lagrange evaluation point is root of unity
            m_error = true;
            return;
        }

        const auto& Z = qap.compute_Z();

        const bool blind = !m_blindGreeks.empty();

        snarklib::PPZK_QueryIC<PAIRING> Q(
            m_qapIC.vec(),
            blind ? m_blindGreeks.rA().G() : m_clearGreeks.rA() * G1::one());

        for (std::size_t i = 0; i < N; ++i) {
            const snarklib::WindowExp<G1> g1_table(m_space, i,
                                                   blind
                                                   ? m_blindGreeks.rA().G()
                                                   : m_clearGreeks.rA() * G1::one());
            dummy->major(true);
            Q.accumTable(g1_table, dummy);
        }

        const snarklib::PPZK_VerificationKey<PAIRING> vk(
            blind ? m_blindGreeks.alphaA().H() : m_clearGreeks.alphaA() * G2::one(),
            blind ? m_blindGreeks.alphaB().G() : m_clearGreeks.alphaB() * G1::one(),
            blind ? m_blindGreeks.alphaC().H() : m_clearGreeks.alphaC() * G2::one(),
            blind ? m_blindGreeks.gamma().H() : m_clearGreeks.gamma() * G2::one(),
            blind ? m_blindGreeks.beta_gamma().G() : m_clearGreeks.beta_gamma() * G1::one(),
            blind ? m_blindGreeks.beta_gamma().H() : m_clearGreeks.beta_gamma() * G2::one(),
            blind ? Z * m_blindGreeks.rC().H() : Z * (m_clearGreeks.rC() * G2::one()),
            Q);

        std::ofstream ofs(outfile);
        if (!ofs)
            m_error = true;
        else
            vk.marshal_out_raw(ofs);
    }

private:
    bool m_error;
    snarklib::BlockVector<FR> m_qapIC;
    snarklib::PPZK_LagrangePoint<FR> m_lagrangePoint;
    snarklib::PPZK_BlindGreeks<FR, FR> m_clearGreeks;
    snarklib::PPZK_BlindGreeks<FR, snarklib::Pairing<G1, G2>> m_blindGreeks;
    snarklib::HugeSystem<FR> m_hugeSystem;
    snarklib::IndexSpace<1> m_space;
};

} // namespace snarkfront

#endif
