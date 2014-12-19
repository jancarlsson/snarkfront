#ifndef _SNARKFRONT_SHA_512_HPP_
#define _SNARKFRONT_SHA_512_HPP_

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
// SHA-512
//

template <typename T, typename MSG, typename F>
class SHA_512 : public SHA_Base<SHA_512<T, MSG, F>,
                                SHA_BlockSize::BLOCK_1024,
                                MSG>
{
public:
    typedef T WordType;
    typedef std::array<T, 16> MsgType;
    typedef std::array<T, 8> DigType;

    SHA_512() {
        initConstants();
    }

    const std::array<T, 8>& digest() const {
        return m_H;
    }

    virtual void initHashValue() {
        // set initial hash value (NIST FIPS 180-4 section 5.3.5)
        const std::array<std::uint64_t, 8> a {
            0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,

            0x510e527fade682d1, 0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 };

        for (std::size_t i = 0; i < 8; ++i) {
            m_H[i] = F::constant(a[i]);
        }
    }

    void prepMsgSchedule(std::size_t& msgIndex) {
        // prepare message schedule (NIST FIPS 180-4 section 6.4.2)
        for (std::size_t i = 0; i < 16; ++i) {
            m_W[i] = this->msgWord(msgIndex);
        }

        for (std::size_t i = 16; i < 80; ++i) {
            //m_W[i] = F::sigma_512_1(m_W[i-2]) + m_W[i-7] + F::sigma_512_0(m_W[i-15]) + m_W[i-16];
            m_W[i] = F::ADDMOD(F::ADDMOD(
                                   F::ADDMOD(
                                       F::sigma_512_1(m_W[i-2]),
                                       m_W[i-7]),
                                   F::sigma_512_0(m_W[i-15])),
                               m_W[i-16]);
        }
    }

    void initWorkingVars() {
        // initialize eight working variables (NIST FIPS 180-4 section 6.4.2)
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
        // inner loop (NIST FIPS 180-4 section 6.4.2)
        for (std::size_t i = 0; i < 80; ++i) {
            //m_T[0] = m_h + F::SIGMA_512_1(m_e) + F::Ch(m_e, m_f, m_g) + m_K[i] + m_W[i];
            m_T[0] = F::ADDMOD(F::ADDMOD(
                                   F::ADDMOD(
                                       F::ADDMOD(m_h,
                                                 F::SIGMA_512_1(m_e)),
                                       F::Ch(m_e, m_f, m_g)),
                                   m_K[i]),
                               m_W[i]);
            //m_T[1] = F::SIGMA_512_0(m_a) + F::Maj(m_a, m_b, m_c);
            m_T[1] = F::ADDMOD(F::SIGMA_512_0(m_a),
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
        // compute intermediate hash value (NIST FIPS 180-4 section 6.4.2)
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
        // set constants (NIST FIPS 180-4 section 4.2.3)
        const std::array<std::uint64_t, 80> a {
            0x428a2f98d728ae22, 0x7137449123ef65cd,
            0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,

            0x3956c25bf348b538, 0x59f111f1b605d019,
            0x923f82a4af194f9b, 0xab1c5ed5da6d8118,

            0xd807aa98a3030242, 0x12835b0145706fbe,
            0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,

            0x72be5d74f27b896f, 0x80deb1fe3b1696b1,
            0x9bdc06a725c71235, 0xc19bf174cf692694,

            0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
            0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,

            0x2de92c6f592b0275, 0x4a7484aa6ea6e483,
            0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,

            0x983e5152ee66dfab, 0xa831c66d2db43210,
            0xb00327c898fb213f, 0xbf597fc7beef0ee4,

            0xc6e00bf33da88fc2, 0xd5a79147930aa725,
            0x06ca6351e003826f, 0x142929670a0e6e70,

            0x27b70a8546d22ffc, 0x2e1b21385c26c926,
            0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,

            0x650a73548baf63de, 0x766a0abb3c77b2a8,
            0x81c2c92e47edaee6, 0x92722c851482353b,

            0xa2bfe8a14cf10364, 0xa81a664bbc423001,
            0xc24b8b70d0f89791, 0xc76c51a30654be30,

            0xd192e819d6ef5218, 0xd69906245565a910,
            0xf40e35855771202a, 0x106aa07032bbd1b8,

            0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
            0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,

            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
            0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,

            0x748f82ee5defb2fc, 0x78a5636f43172f60,
            0x84c87814a1f0ab72, 0x8cc702081a6439ec,

            0x90befffa23631e28, 0xa4506cebde82bde9,
            0xbef9a3f7b2c67915, 0xc67178f2e372532b,

            0xca273eceea26619c, 0xd186b8c721c0c207,
            0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,

            0x06f067aa72176fba, 0x0a637dc5a2c898a6,
            0x113f9804bef90dae, 0x1b710b35131c471b,

            0x28db77f523047d84, 0x32caab7b40c72493,
            0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,

            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
            0x5fcb6fab3ad6faec, 0x6c44198c4a475817 };

        for (std::size_t i = 0; i < 80; ++i) {
            m_K[i] = F::constant(a[i]);
        }
    }

    // eight 64-bit working variables
    T m_a, m_b, m_c, m_d, m_e, m_f, m_g, m_h;

    // 80 constant 64-bit words
    std::array<T, 80> m_K;

    // message schedule of 80 64-bit words
    std::array<T, 80> m_W;

    // 512-bit hash value
    std::array<T, 8> m_H;

    // two temporary words
    std::array<T, 2> m_T;
};

////////////////////////////////////////////////////////////////////////////////
// typedefs
//

namespace zk {
    template <typename FR> using
    SHA512 = SHA_512<AST_Var<Alg_uint64<FR>>,
                     Lazy<AST_Var<Alg_uint64<FR>>, std::uint64_t>,
                     SHA_Functions<AST_Node<Alg_uint64<FR>>,
                                   AST_Op<Alg_uint64<FR>>,
                                   BitwiseAST<Alg_uint64<FR>, Alg_uint64<FR>>>>;
} // namespace zk

namespace eval {
    typedef SHA_512<std::uint64_t,
                    std::uint64_t,
                    SHA_Functions<std::uint64_t,
                                  std::uint64_t,
                                  BitwiseINT<std::uint64_t, std::uint64_t>>>
        SHA512;
} // namespace eval

} // namespace snarkfront

#endif
