#ifndef _SNARKFRONT_HEX_UTIL_HPP_
#define _SNARKFRONT_HEX_UTIL_HPP_

#include <array>
#include <cstdint>
#include <ostream>
#include <sstream>
#include <string>
#include <vector>

#include <snarkfront/DataBuffer.hpp>

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// print as hex digits
//

class PrintHex
{
public:
    PrintHex(std::ostream&, const bool trailingSpace);

    void pushOctet(const std::uint8_t);

private:
    const bool m_trailingSpace;
    const std::array<char, 16> m_nibbles;
    std::ostream& m_out;
};

////////////////////////////////////////////////////////////////////////////////
// print as text characters
//

class PrintText
{
public:
    PrintText(std::ostream&);

    void pushOctet(const std::uint8_t);

private:
    std::ostream& m_out;
};

////////////////////////////////////////////////////////////////////////////////
// print messages in hexdump format
//

class HexDumper
{
public:
    HexDumper(std::ostream&);

    void print(const std::vector<std::uint8_t>&);
    void print(const DataBufferStream&);

private:
    DataBuffer<PrintHex> m_hex;
    DataBuffer<PrintText> m_text;
    std::ostream& m_out;
};

////////////////////////////////////////////////////////////////////////////////
// convert between hexadecimal ASCII and binary
//

std::uint8_t asciiHexToNibble(const char c);
std::uint8_t asciiHexToOctet(const char high, const char low, bool& status);

template <typename T>
bool asciiHexToVector(const std::string& hexDigits, std::vector<T>& v)
{
    const std::size_t
        N = hexDigits.size(),
        numDigits = 2 * sizeof(T),
        numBits = 8 * sizeof(T);

    // insist on even number of fully specified elements
    if (0 != N % numDigits) return false;

    bool status = true;

    for (std::size_t i = 0; i < N; i += numDigits) {
        T e = 0;

        for (std::size_t j = 0; j < numDigits; j += 2) {
            // assume big-endian format of hex digits in text string
            // most significant digit is first on the left
            // least significant digit is last on the right
            const T b = asciiHexToOctet(hexDigits[i + j],
                                        hexDigits[i + j + 1],
                                        status);

            e |= (b << (numBits - 8 - 4*j));
        }

        v.push_back(e);
    }

    return status;
}

template <typename T, std::size_t N>
bool asciiHexToArray(const std::string& hexDigits, std::array<T, N>& dig)
{
    std::vector<T> v;

    if (!asciiHexToVector(hexDigits, v) || N != v.size()) {
        return false;
    } else {
        for (std::size_t i = 0; i < N; ++i) dig[i] = v[i];
        return true;
    }
}

#define DEFN_ASCII_HEX_ARRAY(BITS)                      \
template <std::size_t N>                                \
std::string asciiHex(                                   \
    const std::array<std::uint ## BITS ## _t, N>& a,    \
    const bool space = false)                           \
{                                                       \
    std::stringstream ss;                               \
    DataBuffer<PrintHex> hexpr(ss, false);              \
    hexpr.push(a[0]);                                   \
    for (std::size_t i = 1; i < N; ++i) {               \
        if (space) ss << " ";                           \
        hexpr.push(a[i]);                               \
    }                                                   \
    return ss.str();                                    \
}

DEFN_ASCII_HEX_ARRAY(8)
DEFN_ASCII_HEX_ARRAY(32)
DEFN_ASCII_HEX_ARRAY(64)

#undef DEFN_ASCII_HEX_ARRAY

std::string asciiHex(const std::vector<std::uint8_t>& a,
                     const bool space = false);

std::string asciiHex(const std::vector<std::uint32_t>& a,
                     const bool space = false);

std::string asciiHex(const std::vector<std::uint64_t>& a,
                     const bool space = false);

} // namespace snarkfront

#endif
