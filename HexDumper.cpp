#include <cctype>
#include <sstream>

#include "snarkfront/HexDumper.hpp"

using namespace std;

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// print messages in hexdump format
//

HexDumper::HexDumper(ostream& os)
    : m_hex(os),
      m_text(os),
      m_os(os)
{}

void HexDumper::print(const vector<uint8_t>& msg) {
    const size_t octetsPerLine = 16;

    size_t lineIdx = 0;
    while (lineIdx < msg.size()) {

        // index to beginning of line
        m_os << lineIdx << "\t";

        // hex numbers
        size_t i = lineIdx;
        while (i < msg.size() && (i - lineIdx) < octetsPerLine) {
            m_hex.push8(msg[i]);
            if (7 == i - lineIdx) {
                m_os << ' ';
            }
            ++i;
        }

        // final line may need more whitespace to make columns line up
        if (i >= msg.size()) {
            while (i - lineIdx < octetsPerLine) {
                m_os << "   "; // three spaces for uint8_t in hex format
                if (7 == i - lineIdx) {
                    m_os << ' ';
                }
                ++i;
            }
        }

        // start of ASCII
        m_os << " |";

        // ASCII text
        i = lineIdx;
        while (i < msg.size() && (i - lineIdx) < octetsPerLine) {
            m_text.push8(msg[i]);
            ++i;
        }

        // final line may need more whitespace to make columns line up
        if (i >= msg.size()) {
            while (i - lineIdx < octetsPerLine) {
                m_os << ' ';
                ++i;
            }
        }

        // end of ASCII
        m_os << "|" << endl;

        // next line
        lineIdx += octetsPerLine;
    }
}

void HexDumper::print(std::istream& is) {
    vector<uint8_t> v;
    char c;
    while (!is.eof() && is.get(c)) v.push_back(c);
    print(v);
}

////////////////////////////////////////////////////////////////////////////////
// print as text characters
//

HexDumper::PrintText::PrintText(ostream& os)
    : m_os(os)
{}

void HexDumper::PrintText::pushOctet(const uint8_t a) {
    if (isprint(a) && !isspace(a))
        m_os << a;
    else
        m_os << '.';
}

} // namespace snarkfront
