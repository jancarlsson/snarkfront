#include "snarkfront/HexUtil.hpp"

using namespace std;

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// convert from hexadecimal ASCII to binary
//

uint8_t asciiHexToNibble(const char c) {
    switch (c) {
    case ('0') : return 0;
    case ('1') : return 1;
    case ('2') : return 2;
    case ('3') : return 3;
    case ('4') : return 4;
    case ('5') : return 5;
    case ('6') : return 6;
    case ('7') : return 7;
    case ('8') : return 8;
    case ('9') : return 9;

    case ('a') :
    case ('A') :
        return 10;

    case ('b') :
    case ('B') :
        return 11;

    case ('c') :
    case ('C') :
        return 12;

    case ('d') :
    case ('D') :
        return 13;

    case ('e') :
    case ('E') :
        return 14;

    case ('f') :
    case ('F') :
        return 15;
    }

    return 0xff;
}

uint8_t asciiHexToOctet(const char high, const char low, bool& status) {
    const uint8_t
        highNibble = asciiHexToNibble(high),
        lowNibble = asciiHexToNibble(low);

    if (0xff == highNibble || 0xff == lowNibble)
        status = false;

    return (highNibble << 4) | lowNibble;
}

////////////////////////////////////////////////////////////////////////////////
// print as hex digits
//

PrintHex::PrintHex(ostream& out, const bool trailingSpace)
    : m_trailingSpace(trailingSpace),
      m_nibbles{'0', '1', '2', '3', '4', '5', '6', '7',
                '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'},
      m_out(out)
{}

void PrintHex::pushOctet(const uint8_t a) {
    m_out << m_nibbles[a >> CHAR_BIT / 2]
          << m_nibbles[a & 0xf];

    if (m_trailingSpace) m_out << ' ';
}

////////////////////////////////////////////////////////////////////////////////
// print as text characters
//

PrintText::PrintText(ostream& out)
    : m_out(out)
{}

void PrintText::pushOctet(const uint8_t a) {
    if (isprint(a) && !isspace(a))
        m_out << a;
    else
        m_out << '.';
}

////////////////////////////////////////////////////////////////////////////////
// print messages in hexdump format
//

HexDumper::HexDumper(ostream& out)
    : m_hex(out, true),
      m_text(out),
      m_out(out)
{}

void HexDumper::print(const vector<uint8_t>& msg) {
    const size_t octetsPerLine = 16;

    size_t lineIdx = 0;
    while (lineIdx < msg.size()) {

        // index to beginning of line
        m_out << lineIdx << "\t";

        // hex numbers
        size_t i = lineIdx;
        while (i < msg.size() && (i - lineIdx) < octetsPerLine) {
            m_hex.push8(msg[i]);
            if (7 == i - lineIdx) {
                m_out << ' ';
            }
            ++i;
        }

        // final line may need more whitespace to make columns line up
        if (i >= msg.size()) {
            while (i - lineIdx < octetsPerLine) {
                m_out << "   "; // three spaces for uint8_t in hex format
                if (7 == i - lineIdx) {
                    m_out << ' ';
                }
                ++i;
            }
        }

        // start of ASCII
        m_out << " |";

        // ASCII text
        i = lineIdx;
        while (i < msg.size() && (i - lineIdx) < octetsPerLine) {
            m_text.push8(msg[i]);
            ++i;
        }

        // final line may need more whitespace to make columns line up
        if (i >= msg.size()) {
            while (i - lineIdx < octetsPerLine) {
                m_out << ' ';
                ++i;
            }
        }

        // end of ASCII
        m_out << "|" << endl;

        // next line
        lineIdx += octetsPerLine;
    }
}

void HexDumper::print(const DataBufferStream& a) {
    print(a.data());
}

////////////////////////////////////////////////////////////////////////////////
// convert between hexadecimal ASCII and binary
//

#define DEFN_ASCII_HEX_VECTOR(BITS)             \
    string asciiHex(                            \
    const vector<uint ## BITS ## _t>& a,        \
    const bool space)                           \
{                                               \
    stringstream ss;                            \
    DataBuffer<PrintHex> hexpr(ss, false);      \
    hexpr.push(a[0]);                           \
    for (size_t i = 1; i < a.size(); ++i) {     \
        if (space) ss << " ";                   \
        hexpr.push(a[i]);                       \
    }                                           \
    return ss.str();                            \
}

DEFN_ASCII_HEX_VECTOR(8)
DEFN_ASCII_HEX_VECTOR(32)
DEFN_ASCII_HEX_VECTOR(64)

#undef DEFN_ASCII_HEX_VECTOR

} // namespace snarkfront
