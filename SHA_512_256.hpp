#ifndef _SNARKFRONT_SHA_512_256_HPP_
#define _SNARKFRONT_SHA_512_256_HPP_

#include <array>
#include <cstdint>
#include "Alg.hpp"
#include "Alg_uint.hpp"
#include "AST.hpp"
#include "BitwiseOps.hpp"
#include "Lazy.hpp"
#include "SHA_512.hpp"

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// SHA-512/256
//

template <typename H, typename T, typename MSG, typename U, typename F>
class SHA_512_256 : public SHA_512<T, MSG, U, F>
{
public:
    typedef T WordType;
    typedef U ByteType;

    typedef std::array<T, 16> MsgType;
    typedef std::array<H, 8> DigType;
    typedef std::array<U, 16 * 8> PreType;

    SHA_512_256()
        : m_setDigest(false)
    {}

    // overrides base class SHA-512
    const std::array<H, 8>& digest() {
        if (m_setDigest) {
            for (std::size_t i = 0; i < 4; ++i) {
                // high 32 bits
                m_Hleft256[2*i] = F::xword(F::SHR(
                                               this->m_H[i],
                                               32));

                // low 32 bits
                m_Hleft256[2*i + 1] = F::xword(F::SHR(
                                                   F::SHL(
                                                       this->m_H[i],
                                                       32),
                                                   32));
            }

            m_setDigest = false;
        }

        return m_Hleft256;
    }

    virtual void afterHash() {
        m_setDigest = true;
    }

protected:
    // overrides base class SHA-512
    void initHashValue() {
        // set initial hash value (NIST FIPS 180-4 section 5.3.6.2)
        const std::array<std::uint64_t, 8> a {
            0x22312194FC2BF72C, 0x9F555FA3C84C64C2,
            0x2393B86B6F53B151, 0x963877195940EABD,

            0x96283EE2A88EFFE3, 0xBE5E1E2553863992,
            0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2 };

        for (std::size_t i = 0; i < 8; ++i) {
            this->m_H[i] = F::constant(a[i]);
        }
    }

    // truncated 256-bit message digest
    std::array<H, 8> m_Hleft256;

    bool m_setDigest;
};

////////////////////////////////////////////////////////////////////////////////
// typedefs
//

namespace zk {
    template <typename FR> using
    SHA512_256 = SHA_512_256<AST_Var<Alg_uint32<FR>>,
                             AST_Var<Alg_uint64<FR>>,
                             Lazy<AST_Var<Alg_uint64<FR>>, std::uint64_t>,
                             AST_Var<Alg_uint8<FR>>,
                             SHA_Functions<AST_Node<Alg_uint64<FR>>,
                                           AST_Op<Alg_uint64<FR>>,
                                           BitwiseAST<Alg_uint64<FR>, Alg_uint32<FR>>>>;
} // namespace zk

namespace eval {
    typedef SHA_512_256<std::uint32_t,
                        std::uint64_t,
                        std::uint64_t,
                        std::uint8_t,
                        SHA_Functions<std::uint64_t,
                                      std::uint64_t,
                                      BitwiseINT<std::uint64_t, std::uint32_t>>>
        SHA512_256;
} // namespace eval

} // namespace snarkfront

#endif
