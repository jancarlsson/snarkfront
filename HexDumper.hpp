#ifndef _SNARKFRONT_HEX_DUMPER_HPP_
#define _SNARKFRONT_HEX_DUMPER_HPP_

#include <cstdint>
#include <istream>
#include <ostream>
#include <vector>

#include <cryptl/ASCII_Hex.hpp>
#include <cryptl/DataPusher.hpp>

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// print messages in hexdump format
//

class HexDumper
{
public:
    HexDumper(std::ostream&);

    void print(const std::vector<std::uint8_t>&);
    void print(std::istream&);

private:
    // print as text characters
    class PrintText
    {
    public:
        PrintText(std::ostream&);
        void pushOctet(const std::uint8_t);
    private:
        std::ostream& m_os;
    };

    cryptl::DataPusher<cryptl::PrintHex<true>> m_hex;
    cryptl::DataPusher<PrintText> m_text;
    std::ostream& m_os;
};

} // namespace snarkfront

#endif
