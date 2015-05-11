#ifndef _SNARKFRONT_AES_CIPHER_HPP_
#define _SNARKFRONT_AES_CIPHER_HPP_

#include <array>
#include <cstdint>

#include <snarkfront/AES_KeyExpansion.hpp>
#include <snarkfront/AES_SBox.hpp>

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// FIPS PUB 197, NIST November 2001
//
// Algorithm     Key Length    Block Size   Number of Rounds
//               (Nk words)    (Nb words)   (Nr)
//
// AES-128       4             4            10
// AES-192       6             4            12
// AES-256       8             4            14
//

////////////////////////////////////////////////////////////////////////////////
// 5.1 Cipher
//

template <typename VAR, typename T, typename U, typename BITWISE>
class AES_Cipher
{
public:
    typedef VAR VarType;
    typedef std::array<VAR, 16> BlockType;
    typedef AES_KeyExpansion<VAR, T, U, BITWISE> KeyExpansion;

    AES_Cipher() = default;

    // AES-128
    void operator() (const std::array<VAR, 16>& in,
                     std::array<VAR, 16>& out,
                     const std::array<VAR, 176>& w) const {
        encrypt(in, out, w);
    }

    // AES-192
    void operator() (const std::array<VAR, 16>& in,
                     std::array<VAR, 16>& out,
                     const std::array<VAR, 208>& w) const {
        encrypt(in, out, w);
    }

    // AES-256
    void operator() (const std::array<VAR, 16>& in,
                     std::array<VAR, 16>& out,
                     const std::array<VAR, 240>& w) const {
        encrypt(in, out, w);
    }

private:
    // AES-128 key schedule size 176 (Nr = 10)
    // AES-192 key schedule size 208 (Nr = 12)
    // AES-256 key schedule size 240 (Nr = 14)
    template <std::size_t WSZ>
    void encrypt(const std::array<VAR, 16>& in,
                 std::array<VAR, 16>& out,
                 const std::array<VAR, WSZ>& w) const // 16 * (Nr + 1) octets
    {
        const auto Nr = w.size() / 16 - 1;

        auto state = in;

        AddRoundKey(state, w, 0);

        for (std::size_t round = 1; round < Nr; ++round) {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, w, 16*round);
        }

        SubBytes(state);
        ShiftRows(state);
        AddRoundKey(state, w, 16*Nr);

        out = state;
    }

    // 5.1.1 SubBytes() Transformation
    void SubBytes(std::array<VAR, 16>& state) const {
        for (auto& a : state)
            a = m_sbox(a);
    }

    // 5.1.2 ShiftRows() Transformation
    void ShiftRows(std::array<VAR, 16>& state) const {
        VAR tmp;

        // second row rotate left by one element
        tmp = state[1];
        state[1] = state[5];
        state[5] = state[9];
        state[9] = state[13];
        state[13] = tmp;

        // third row rotate left by two elements
        tmp = state[2];
        state[2] = state[10];
        state[10] = tmp;
        tmp = state[6];
        state[6] = state[14];
        state[14] = tmp;

        // fourth row rotate left by three elements
        tmp = state[3];
        state[3] = state[15];
        state[15] = state[11];
        state[11] = state[7];
        state[7] = tmp;
    }

    // 5.1.3 MixColumns() Transformation
    void MixColumns(std::array<VAR, 16>& state) const {
        // irreducible polynomial for AES
        const auto modpoly = BITWISE::constant(0x1b);

        for (std::size_t i = 0; i < 16; i += 4) {
            const VAR xs0 = BITWISE::xtime(state[i], modpoly); // {02} * s0
            const VAR xs1 = BITWISE::xtime(state[i+1], modpoly); // {02} * s1
            const VAR xs2 = BITWISE::xtime(state[i+2], modpoly); // {02} * s2
            const VAR xs3 = BITWISE::xtime(state[i+3], modpoly); // {02} * s3

            // sp0 = ({02} * s0) XOR ({03} * s1) XOR s2 XOR s3
            const VAR sp0 =
                BITWISE::XOR(
                    BITWISE::XOR(xs0, BITWISE::XOR(xs1, state[i+1])),
                    BITWISE::XOR(state[i+2], state[i+3]));

            // sp1 = s0 XOR ({02} * s1) XOR ({03} * s2) XOR s3
            const VAR sp1 =
                BITWISE::XOR(
                    BITWISE::XOR(xs1, BITWISE::XOR(xs2, state[i+2])),
                    BITWISE::XOR(state[i], state[i+3]));

            // sp2 = s0 XOR s1 XOR ({02} * s2) XOR ({03} * s3)
            const VAR sp2 =
                BITWISE::XOR(
                    BITWISE::XOR(xs2, BITWISE::XOR(xs3, state[i+3])),
                    BITWISE::XOR(state[i], state[i+1]));

            // sp3 = ({03} * s0) XOR s1 XOR s2 XOR ({02} * s3)
            const VAR sp3 =
                BITWISE::XOR(
                    BITWISE::XOR(xs3, BITWISE::XOR(xs0, state[i])),
                    BITWISE::XOR(state[i+1], state[i+2]));

            state[i] = sp0;
            state[i+1] = sp1;
            state[i+2] = sp2;
            state[i+3] = sp3;
        }
    }

    // 5.1.4 AddRoundKey() Transformation
    template <std::size_t N>
    void AddRoundKey(std::array<VAR, 16>& state,
                     const std::array<VAR, N>& w,
                     const std::size_t offset) const {
        for (std::size_t i = 0; i < 16; ++i)
            state[i] = BITWISE::XOR(state[i], w[i + offset]);
    }

    const AES_SBox<T, U, BITWISE> m_sbox;
};

////////////////////////////////////////////////////////////////////////////////
// typedefs
//

namespace zk {
    template <typename FR> using
    AES_Encrypt = AES_Cipher<AST_Var<Alg_uint8<FR>>,
                             AST_Node<Alg_uint8<FR>>,
                             AST_Op<Alg_uint8<FR>>,
                             BitwiseAST<Alg_uint8<FR>>>;
} // namespace zk

namespace eval {
    typedef AES_Cipher<std::uint8_t,
                       std::uint8_t,
                       std::uint8_t,
                       BitwiseINT<std::uint8_t>>
        AES_Encrypt;
} // namespace eval

} // namespace snarkfront

#endif
