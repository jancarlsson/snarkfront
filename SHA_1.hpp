#ifndef _SNARKFRONT_SHA_1_HPP_
#define _SNARKFRONT_SHA_1_HPP_

#include <array>
#include <cstdint>
#include "Alg.hpp"
#include "Alg_uint.hpp"
#include "AST.hpp"
#include "BitwiseOps.hpp"
#include "Lazy.hpp"
#include "SecureHashStd.hpp"

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// SHA-1
//

template <typename T, typename MSG, typename U, typename F>
class SHA_1 : public SHA_Base<SHA_1<T, MSG, U, F>,
                              SHA_BlockSize::BLOCK_512,
                              MSG>
{
public:
    typedef T WordType;
    typedef U ByteType;

    typedef std::array<T, 16> MsgType;
    typedef std::array<T, 5> DigType;
    typedef std::array<U, 16 * 4> PreType;

    SHA_1() {
        initConstants();
    }

    const std::array<T, 5>& digest() const {
        return m_H;
    }

    void initHashValue() {
        // set initial hash value (NIST FIPS 180-4 section 5.3.1)
        const std::array<std::uint32_t, 5> a {
            0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };

        for (std::size_t i = 0; i < 5; ++i) {
            m_H[i] = F::constant(a[i]);
        }
    }

    void prepMsgSchedule(std::size_t& msgIndex) {
        // prepare message schedule (NIST FIPS 180-4 section 6.1.2)
        for (std::size_t i = 0; i < 16; ++i) {
            m_W[i] = this->msgWord(msgIndex);
        }

        for (std::size_t i = 16; i < 80; ++i) {
            //m_W[i] = F::ROTL(m_W[i-3] ^ m_W[i-8] ^ m_W[i-14] ^ m_W[i-16], 1);
            m_W[i] = F::ROTL(F::XOR(
                                 F::XOR(
                                     F::XOR(m_W[i-3],
                                            m_W[i-8]),
                                     m_W[i-14]),
                                 m_W[i-16]),
                             1);
        }
    }

    void initWorkingVars() {
        // initialize five working variables (NIST FIPS 180-4 section 6.1.2)
        m_a = m_H[0];
        m_b = m_H[1];
        m_c = m_H[2];
        m_d = m_H[3];
        m_e = m_H[4];
    }

    void workingLoop() {
        // inner loop (NIST FIPS 180-4 section 6.1.2)
        for (std::size_t i = 0; i < 80; ++i) {
            //m_T = F::ROTL(m_a, 5) + F::f(m_b, m_c, m_d, i) + m_e + m_K[i] + m_W[i];
            m_T = F::ADDMOD(F::ADDMOD(
                                F::ADDMOD(
                                    F::ADDMOD(
                                        F::ROTL(m_a, 5),
                                        F::f(m_b, m_c, m_d, i)),
                                    m_e),
                                m_K[i]),
                            m_W[i]);
            m_e = m_d;
            m_d = m_c;
            m_c = F::ROTL(m_b, 30);
            m_b = m_a;
            m_a = m_T;
        }
    }

    void updateHash() {
        // compute intermediate hash value (NIST FIPS 180-4 section 6.1.2)
        //m_H[0] = m_H[0] + m_a;
        //m_H[1] = m_H[1] + m_b;
        //m_H[2] = m_H[2] + m_c;
        //m_H[3] = m_H[3] + m_d;
        //m_H[4] = m_H[4] + m_e;
        m_H[0] = F::ADDMOD(m_H[0], m_a);
        m_H[1] = F::ADDMOD(m_H[1], m_b);
        m_H[2] = F::ADDMOD(m_H[2], m_c);
        m_H[3] = F::ADDMOD(m_H[3], m_d);
        m_H[4] = F::ADDMOD(m_H[4], m_e);
    }

    void afterHash() {
    }

private:
    void initConstants() {
        // set constants (NIST FIPS 180-4 section 4.2.1)
        for (std::size_t i = 0; i < 80; ++i) {
            if (i < 20)
                m_K[i] = F::constant(0x5a827999);
            else if (i < 40)
                m_K[i] = F::constant(0x6ed9eba1);
            else if (i < 60)
                m_K[i] = F::constant(0x8f1bbcdc);
            else
                m_K[i] = F::constant(0xca62c1d6);
        }
    }

    // five 32-bit working variables
    T m_a, m_b, m_c, m_d, m_e;

    // 80 constant 32-bit words
    std::array<T, 80> m_K;

    // message schedule of 80 32-bit words
    std::array<T, 80> m_W;

    // 160-bit hash value
    std::array<T, 5> m_H;

    // temporary word
    T m_T;
};

////////////////////////////////////////////////////////////////////////////////
// typedefs
//

namespace zk {
    template <typename FR> using
    SHA1 = SHA_1<AST_Var<Alg_uint32<FR>>,
                 Lazy<AST_Var<Alg_uint32<FR>>, std::uint32_t>,
                 AST_Var<Alg_uint8<FR>>,
                 SHA_Functions<AST_Node<Alg_uint32<FR>>,
                               AST_Op<Alg_uint32<FR>>,
                               BitwiseAST<Alg_uint32<FR>, Alg_uint32<FR>>>>;
} // namespace zk

namespace eval {
    typedef SHA_1<std::uint32_t,
                  std::uint32_t,
                  std::uint8_t,
                  SHA_Functions<std::uint32_t,
                                std::uint32_t,
                                BitwiseINT<std::uint32_t, std::uint32_t>>>
        SHA1;
} // namespace eval

} // namespace snarkfront

#endif
