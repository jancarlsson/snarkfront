#ifndef _SNARKFRONT_AES_INV_CIPHER_HPP_
#define _SNARKFRONT_AES_INV_CIPHER_HPP_

#include <array>
#include <cstdint>
#include "AES_InvSBox.hpp"
#include "AES_KeyExpansion.hpp"

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
// 5.3 Inverse Cipher
//

template <typename VAR, typename T, typename U, typename BITWISE>
class AES_InvCipher
{
public:
    typedef VAR VarType;
    typedef std::array<VAR, 16> BlockType;
    typedef AES_KeyExpansion<VAR, T, U, BITWISE> KeyExpansion;

    AES_InvCipher() = default;

    // AES-128
    void operator() (const std::array<VAR, 16>& in,
                     std::array<VAR, 16>& out,
                     const std::array<VAR, 176>& w) const {
        decrypt(in, out, w);
    }

    // AES-192
    void operator() (const std::array<VAR, 16>& in,
                     std::array<VAR, 16>& out,
                     const std::array<VAR, 208>& w) const {
        decrypt(in, out, w);
    }

    // AES-256
    void operator() (const std::array<VAR, 16>& in,
                     std::array<VAR, 16>& out,
                     const std::array<VAR, 240>& w) const {
        decrypt(in, out, w);
    }

private:
    // AES-128 key schedule size 176 (Nr = 10)
    // AES-192 key schedule size 208 (Nr = 12)
    // AES-256 key schedule size 240 (Nr = 14)
    template <std::size_t WSZ>
    void decrypt(const std::array<VAR, 16>& in,
                 std::array<VAR, 16>& out,
                 const std::array<VAR, WSZ>& w) const // 16 * (Nr + 1) octets
    {
        const auto Nr = w.size() / 16 - 1;

        auto state = in;

        AddRoundKey(state, w, 16*Nr);

        for (std::size_t round = Nr - 1; round > 0; --round) {
            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, w, 16*round);
            InvMixColumns(state);
        }

        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, w, 0);

        out = state;
    }

    // 5.3.1 InvShiftRows() Transformation
    void InvShiftRows(std::array<VAR, 16>& state) const {
        VAR tmp;

        // second row rotate right by one element
        tmp = state[13];
        state[13] = state[9];
        state[9] = state[5];
        state[5] = state[1];
        state[1] = tmp;

        // third row rotate right by two elements
        tmp = state[14];
        state[14] = state[6];
        state[6] = tmp;
        tmp = state[10];
        state[10] = state[2];
        state[2] = tmp;

        // fourth row rotate right by three elements
        tmp = state[15];
        state[15] = state[3];
        state[3] = state[7];
        state[7] = state[11];
        state[11] = tmp;
    }

    // 5.3.2 InvSubBytes() Transformation
    void InvSubBytes(std::array<VAR, 16>& state) const {
        for (auto& a : state)
            a = m_inv_sbox(a);
    }

    // 5.3.3 InvMixColumns() Transformation
    void InvMixColumns(std::array<VAR, 16>& state) const {
        // irreducible polynomial for AES
        const auto modpoly = BITWISE::constant(0x1b);

        for (std::size_t i = 0; i < 16; i += 4) {
            const VAR
                xs0 = BITWISE::xtime(state[i], modpoly), // {02} * s0
                xxs0 = BITWISE::xtime(xs0, modpoly),     // {04} * s0
                xxxs0 = BITWISE::xtime(xxs0, modpoly);   // {08} * s0

            const VAR
                xs1 = BITWISE::xtime(state[i + 1], modpoly), // {02} * s1
                xxs1 = BITWISE::xtime(xs1, modpoly),         // {04} * s1
                xxxs1 = BITWISE::xtime(xxs1, modpoly);       // {08} * s1

            const VAR
                xs2 = BITWISE::xtime(state[i + 2], modpoly), // {02} * s2
                xxs2 = BITWISE::xtime(xs2, modpoly),         // {04} * s2
                xxxs2 = BITWISE::xtime(xxs2, modpoly);       // {08} * s2

            const VAR
                xs3 = BITWISE::xtime(state[i + 3], modpoly), // {02} * s3
                xxs3 = BITWISE::xtime(xs3, modpoly),         // {04} * s3
                xxxs3 = BITWISE::xtime(xxs3, modpoly);       // {08} * s3

            // sp0 = ({0e} * s0) XOR ({0b} * s1) XOR ({0d} * s2) XOR ({09} * s3)
            const VAR sp0 =
                BITWISE::XOR(
                    BITWISE::XOR(xs0, BITWISE::XOR(xxs0, xxxs0)),
                    BITWISE::XOR(
                        BITWISE::XOR(state[i + 1], BITWISE::XOR(xs1, xxxs1)),
                        BITWISE::XOR(
                            BITWISE::XOR(state[i + 2], BITWISE::XOR(xxs2, xxxs2)),
                            BITWISE::XOR(state[i + 3], xxxs3))));

            // sp1 = ({09} * s0) XOR ({0e} * s1) XOR ({0b} * s2) XOR ({0d} * s3)
            const VAR sp1 =
                BITWISE::XOR(
                    BITWISE::XOR(state[i], xxxs0),
                    BITWISE::XOR(
                        BITWISE::XOR(xs1, BITWISE::XOR(xxs1, xxxs1)),
                        BITWISE::XOR(
                            BITWISE::XOR(state[i + 2], BITWISE::XOR(xs2, xxxs2)),
                            BITWISE::XOR(state[i + 3], BITWISE::XOR(xxs3, xxxs3)))));

            // sp2 = ({0d} * s0) XOR ({09} * s1) XOR ({0e} * s2) XOR ({0b} * s3)
            const VAR sp2 =
                BITWISE::XOR(
                    BITWISE::XOR(state[i], BITWISE::XOR(xxs0, xxxs0)),
                    BITWISE::XOR(
                        BITWISE::XOR(state[i + 1], xxxs1),
                        BITWISE::XOR(
                            BITWISE::XOR(xs2, BITWISE::XOR(xxs2, xxxs2)),
                            BITWISE::XOR(state[i + 3], BITWISE::XOR(xs3, xxxs3)))));

            // sp3 = ({0b} * s0) XOR ({0d} * s1) XOR ({09} * s2) XOR ({0e} * s3)
            const VAR sp3 =
                BITWISE::XOR(
                    BITWISE::XOR(state[i], BITWISE::XOR(xs0, xxxs0)),
                    BITWISE::XOR(
                        BITWISE::XOR(state[i + 1], BITWISE::XOR(xxs1, xxxs1)),
                        BITWISE::XOR(
                            BITWISE::XOR(state[i + 2], xxxs2),
                            BITWISE::XOR(xs3, BITWISE::XOR(xxs3, xxxs3)))));

            state[i] = sp0;
            state[i + 1] = sp1;
            state[i + 2] = sp2;
            state[i + 3] = sp3;
        }
    }

    // 5.3.4 AddRoundKey() Transformation
    template <std::size_t N>
    void AddRoundKey(std::array<VAR, 16>& state,
                     const std::array<VAR, N>& w,
                     const std::size_t offset) const {
        for (std::size_t i = 0; i < 16; ++i)
            state[i] = BITWISE::XOR(state[i], w[i + offset]);
    }

    const AES_InvSBox<T, U, BITWISE> m_inv_sbox;
};

////////////////////////////////////////////////////////////////////////////////
// typedefs
//

namespace zk {
    template <typename FR> using
    AES_Decrypt = AES_InvCipher<AST_Var<Alg_uint8<FR>>,
                                AST_Node<Alg_uint8<FR>>,
                                AST_Op<Alg_uint8<FR>>,
                                BitwiseAST<Alg_uint8<FR>>>;
} // namespace zk

namespace eval {
    typedef AES_InvCipher<std::uint8_t,
                          std::uint8_t,
                          std::uint8_t,
                          BitwiseINT<std::uint8_t>>
        AES_Decrypt;
} // namespace eval

} // namespace snarkfront

#endif
