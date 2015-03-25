#ifndef _SNARKFRONT_SHA_256_HPP_
#define _SNARKFRONT_SHA_256_HPP_

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
// SHA-256
//

template <typename T, typename MSG, typename U, typename F>
class SHA_256 : public SHA_Base<SHA_256<T, MSG, U, F>,
                                SHA_BlockSize::BLOCK_512,
                                MSG>
{
public:
    typedef T WordType;
    typedef U ByteType;

    typedef std::array<T, 16> MsgType;
    typedef std::array<T, 8> DigType;
    typedef std::array<U, 16 * 4> PreType;

    SHA_256() {
        initConstants();
    }

    const std::array<T, 8>& digest() const {
        return m_H;
    }

    virtual void initHashValue() {
        // set initial hash value (NIST FIPS 180-4 section 5.3.3)
        const std::array<std::uint32_t, 8> a {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

        for (std::size_t i = 0; i < 8; ++i) {
            m_H[i] = F::constant(a[i]);
        }
    }

    void prepMsgSchedule(std::size_t& msgIndex) {
        // prepare message schedule (NIST FIPS 180-4 section 6.2.2)
        for (std::size_t i = 0; i < 16; ++i) {
            m_W[i] = this->msgWord(msgIndex);
        }

        for (std::size_t i = 16; i < 64; ++i) {
            //m_W[i] = F::sigma_256_1(m_W[i-2]) + m_W[i-7] + F::sigma_256_0(m_W[i-15]) + m_W[i-16];
            m_W[i] = F::ADDMOD(F::ADDMOD(
                                   F::ADDMOD(
                                       F::sigma_256_1(m_W[i-2]),
                                       m_W[i-7]),
                                   F::sigma_256_0(m_W[i-15])),
                               m_W[i-16]);
        }
    }

    void initWorkingVars() {
        // initialize eight working variables (NIST FIPS 180-4 section 6.2.2)
        m_a = m_H[0];
        m_b = m_H[1];
        m_c = m_H[2];
        m_d = m_H[3];
        m_e = m_H[4];
        m_f = m_H[5];
        m_g = m_H[6];
        m_h = m_H[7];
    }

    void workingLoop() {
        // inner loop (NIST FIPS 180-4 section 6.2.2)
        for (std::size_t i = 0; i < 64; ++i) {
            //m_T[0] = m_h + F::SIGMA_256_1(m_e) + F::Ch(m_e, m_f, m_g) + m_K[i] + m_W[i];
            m_T[0] = F::ADDMOD(F::ADDMOD(
                                   F::ADDMOD(
                                       F::ADDMOD(m_h,
                                                 F::SIGMA_256_1(m_e)),
                                       F::Ch(m_e, m_f, m_g)),
                                   m_K[i]),
                               m_W[i]);
            //m_T[1] = F::SIGMA_256_0(m_a) + F::Maj(m_a, m_b, m_c);
            m_T[1] = F::ADDMOD(F::SIGMA_256_0(m_a),
                               F::Maj(m_a, m_b, m_c));
            m_h = m_g;
            m_g = m_f;
            m_f = m_e;
            //m_e = m_d + m_T[0];
            m_e = F::ADDMOD(m_d, m_T[0]);
            m_d = m_c;
            m_c = m_b;
            m_b = m_a;
            //m_a = m_T[0] + m_T[1];
            m_a = F::ADDMOD(m_T[0], m_T[1]);
        }
    }

    void updateHash() {
        // compute intermediate hash value (NIST FIPS 180-4 section 6.2.2)
        //m_H[0] = m_H[0] + m_a;
        //m_H[1] = m_H[1] + m_b;
        //m_H[2] = m_H[2] + m_c;
        //m_H[3] = m_H[3] + m_d;
        //m_H[4] = m_H[4] + m_e;
        //m_H[5] = m_H[5] + m_f;
        //m_H[6] = m_H[6] + m_g;
        //m_H[7] = m_H[7] + m_h;
        m_H[0] = F::ADDMOD(m_H[0], m_a);
        m_H[1] = F::ADDMOD(m_H[1], m_b);
        m_H[2] = F::ADDMOD(m_H[2], m_c);
        m_H[3] = F::ADDMOD(m_H[3], m_d);
        m_H[4] = F::ADDMOD(m_H[4], m_e);
        m_H[5] = F::ADDMOD(m_H[5], m_f);
        m_H[6] = F::ADDMOD(m_H[6], m_g);
        m_H[7] = F::ADDMOD(m_H[7], m_h);
    }

    virtual void afterHash() {
    }

protected:
    void initConstants() {
        // set constants (NIST FIPS 180-4 section 4.2.2)
        const std::array<std::uint32_t, 64> a {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,

            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,

            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,

            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,

            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,

            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,

            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,

            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

        for (std::size_t i = 0; i < 64; ++i) {
            m_K[i] = F::constant(a[i]);
        }
    }

    // eight 32-bit working variables
    T m_a, m_b, m_c, m_d, m_e, m_f, m_g, m_h;

    // 64 constant 32-bit words
    std::array<T, 64> m_K;

    // message schedule of 64 32-bit words
    std::array<T, 64> m_W;

    // 256-bit hash value
    std::array<T, 8> m_H;

    // two temporary words
    std::array<T, 2> m_T;
};

////////////////////////////////////////////////////////////////////////////////
// typedefs
//

namespace zk {
    template <typename FR> using
    SHA256 = SHA_256<AST_Var<Alg_uint32<FR>>,
                     Lazy<AST_Var<Alg_uint32<FR>>, std::uint32_t>,
                     AST_Var<Alg_uint8<FR>>,
                     SHA_Functions<AST_Node<Alg_uint32<FR>>,
                                   AST_Op<Alg_uint32<FR>>,
                                   BitwiseAST<Alg_uint32<FR>>>>;
} // namespace zk

namespace eval {
typedef SHA_256<std::uint32_t,
                std::uint32_t,
                std::uint8_t,
                SHA_Functions<std::uint32_t,
                              std::uint32_t,
                              BitwiseINT<std::uint32_t>>>
    SHA256;
} // namespace eval

} // namespace snarkfront

#endif
