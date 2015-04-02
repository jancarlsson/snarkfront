#ifndef _SNARKFRONT_SHA_512_224_HPP_
#define _SNARKFRONT_SHA_512_224_HPP_

#include <array>
#include <cstdint>
#include "Alg.hpp"
#include "Alg_uint.hpp"
#include "AST.hpp"
#include "BitwiseAST.hpp"
#include "BitwiseINT.hpp"
#include "Lazy.hpp"
#include "SHA_512.hpp"

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// SHA-512/224
//

template <typename H, typename T, typename MSG, typename U, typename F, typename X>
class SHA_512_224 : public SHA_512<T, MSG, U, F>
{
public:
    typedef T WordType;
    typedef U ByteType;

    typedef std::array<T, 16> MsgType;
    typedef std::array<H, 7> DigType;
    typedef std::array<U, 16 * 8> PreType;

    SHA_512_224()
        : m_setDigest(false)
    {}

    // overrides base class SHA-512
    const std::array<H, 7>& digest() {
        if (m_setDigest) {
            for (std::size_t i = 0; i < 3; ++i) {
                // high 32 bits
                m_Hleft224[2*i] = F::xword(F::SHR(
                                               this->m_H[i],
                                               32),
                                           X());

                // low 32 bits
                m_Hleft224[2*i + 1] = F::xword(F::SHR(
                                                   F::SHL(
                                                       this->m_H[i],
                                                       32),
                                                   32),
                                               X());
            }

            // high 32 bits
            m_Hleft224[6] = F::xword(F::SHR(
                                         this->m_H[3],
                                         32),
                                     X());

            m_setDigest = false;
        }

        return m_Hleft224;
    }

    // overrides base class SHA-512
    virtual void initHashValue() {
        // set initial hash value (NIST FIPS 180-4 section 5.3.6.1)
        const std::array<std::uint64_t, 8> a {
            0x8C3D37C819544DA2, 0x73E1996689DCD4D6,
            0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF,

            0x0F6D2B697BD44DA8, 0x77E36F7304C48942,
            0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1 };

        for (std::size_t i = 0; i < 8; ++i) {
            this->m_H[i] = F::constant(a[i]);
        }
    }

    virtual void afterHash() {
        m_setDigest = true;
    }

private:
    // truncated 224-bit message digest
    std::array<H, 7> m_Hleft224;

    bool m_setDigest;
};

////////////////////////////////////////////////////////////////////////////////
// typedefs
//

namespace zk {
    template <typename FR> using
    SHA512_224 = SHA_512_224<AST_Var<Alg_uint32<FR>>,
                             AST_Var<Alg_uint64<FR>>,
                             Lazy<AST_Var<Alg_uint64<FR>>, std::uint64_t>,
                             AST_Var<Alg_uint8<FR>>,
                             SHA_Functions<AST_Node<Alg_uint64<FR>>,
                                           AST_Op<Alg_uint64<FR>>,
                                           BitwiseAST<Alg_uint64<FR>>>,
                             Alg_uint32<FR>>;
} // namespace zk

namespace eval {
    typedef SHA_512_224<std::uint32_t,
                        std::uint64_t,
                        std::uint64_t,
                        std::uint8_t,
                        SHA_Functions<std::uint64_t,
                                      std::uint64_t,
                                      BitwiseINT<std::uint64_t>>,
                        std::uint32_t>
        SHA512_224;
} // namespace eval

} // namespace snarkfront

#endif
