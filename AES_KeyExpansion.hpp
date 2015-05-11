#ifndef _SNARKFRONT_AES_KEY_EXPANSION_HPP_
#define _SNARKFRONT_AES_KEY_EXPANSION_HPP_

#include <array>
#include <cstdint>

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
// 5.2 Key Expansion
//

template <typename VAR, typename T, typename U, typename BITWISE>
class AES_KeyExpansion
{
public:
    typedef VAR VarType;

    typedef std::array<VAR, 16> Key128Type;
    typedef std::array<VAR, 24> Key192Type;
    typedef std::array<VAR, 32> Key256Type;

    typedef std::array<VAR, 176> Schedule128Type;
    typedef std::array<VAR, 208> Schedule192Type;
    typedef std::array<VAR, 240> Schedule256Type;

    AES_KeyExpansion() = default;

    // AES-128
    void operator() (const std::array<VAR, 16>& key,
                     std::array<VAR, 176>& w) const {
        expand(key, w);
    }

    // AES-192
    void operator() (const std::array<VAR, 24>& key,
                     std::array<VAR, 208>& w) const {
        expand(key, w);
    }

    // AES-256
    void operator() (const std::array<VAR, 32>& key,
                     std::array<VAR, 240>& w) const {
        expand(key, w);
    }

private:
    // AES-128 max (4(Nr + 1) - 1)/Nk - 1 is 10 - 1 = 9
    // AES-192 max (4(Nr + 1) - 1)/Nk - 1 is 8 - 1 = 7
    // AES-256 max (4(Nr + 1) - 1)/Nk - 1 is 7 - 1 = 6
    std::uint8_t rcon(const std::size_t i) const {
        if (i < 8) {
            // i = 0 is x^0 = 0x01 = 1 << 0
            // i = 1 is x^1 = 0x02 = 1 << 1
            // i = 2 is x^2 = 0x04 = 1 << 2
            // i = 3 is x^3 = 0x08 = 1 << 3
            // i = 4 is x^4 = 0x10 = 1 << 4
            // i = 5 is x^5 = 0x20 = 1 << 5
            // i = 6 is x^6 = 0x40 = 1 << 6
            // i = 7 is x^7 = 0x80 = 1 << 7
            return 1 << i;
        } else if (8 == i) {
            // i = 8 is x^4 + x^3 + x + 1 = 0x1b
            return 0x1b;
        } else if (9 == i) {
            // i = 9 is x^5 + x^4 + x^2 + x = 0x36
            return 0x36;
        } else {
            return 0; // should never happen
        }
    }

    // AES-128 key size 16 (Nk = 4) with key schedule size 176 (Nr = 10)
    // AES-192 key size 24 (Nk = 6) with key schedule size 208 (Nr = 12)
    // AES-256 key size 32 (Nk = 8) with key schedule size 240 (Nr = 14)
    template <std::size_t KSZ, std::size_t WSZ>
    void expand(const std::array<VAR, KSZ>& key, // 4 * Nk octets
                std::array<VAR, WSZ>& w) const   // 16 * (Nr + 1) octets
    {
        const std::size_t
            Nk = key.size() / 4,
            Nr = w.size() / 16 - 1;

        for (std::size_t i = 0; i < Nk; ++i) {
            w[4*i] = key[4*i];
            w[4*i + 1] = key[4*i + 1];
            w[4*i + 2] = key[4*i + 2];
            w[4*i + 3] = key[4*i + 3];
        }

        for (std::size_t i = Nk; i < 4 * (Nr + 1); ++i) {
            std::array<VAR, 4> temp = { w[4*(i - 1)],
                                        w[4*(i - 1) + 1],
                                        w[4*(i - 1) + 2],
                                        w[4*(i - 1) + 3] };

            if (0 == i % Nk) {
                const VAR tmp = temp[0];
                temp[0] = BITWISE::XOR(m_sbox(temp[1]), BITWISE::constant(rcon(i/Nk - 1)));
                temp[1] = m_sbox(temp[2]);
                temp[2] = m_sbox(temp[3]);
                temp[3] = m_sbox(tmp);

            } else if (Nk > 6 && 4 == i % Nk) {
                temp[0] = m_sbox(temp[0]);
                temp[1] = m_sbox(temp[1]);
                temp[2] = m_sbox(temp[2]);
                temp[3] = m_sbox(temp[3]);
            }

            w[4*i] = BITWISE::XOR(w[4*(i - Nk)], temp[0]);
            w[4*i + 1] = BITWISE::XOR(w[4*(i - Nk) + 1], temp[1]);
            w[4*i + 2] = BITWISE::XOR(w[4*(i - Nk) + 2], temp[2]);
            w[4*i + 3] = BITWISE::XOR(w[4*(i - Nk) + 3], temp[3]);
        }
    }

    const AES_SBox<T, U, BITWISE> m_sbox;
};

} // namespace snarkfront

#endif
