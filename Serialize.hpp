#ifndef _SNARKFRONT_SERIALIZE_HPP_
#define _SNARKFRONT_SERIALIZE_HPP_

#include <array>
#include <cstdint>
#include <istream>
#include <ostream>
#include <string>
#include <vector>

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// read and write types: uint64_t
//

void writeStream(std::ostream& os, const std::uint64_t& a);
bool readStream(std::istream& is, std::uint64_t& a);

////////////////////////////////////////////////////////////////////////////////
// read and write types: string
//

void writeStream(std::ostream& os, const std::string& a);
bool readStream(std::istream& is, std::string& a);

////////////////////////////////////////////////////////////////////////////////
// read and write types: vector<uint8_t>      (byte vector)
//

void writeStream(std::ostream& os, const std::vector<std::uint8_t>& a);
bool readStream(std::istream& is, std::vector<std::uint8_t>& a);

////////////////////////////////////////////////////////////////////////////////
// read and write types: array<uint8_t, N>    (byte array)
//

template <std::size_t N>
void writeStream(std::ostream& os, const std::array<std::uint8_t, N>& a) {
    os.write(reinterpret_cast<const char*>(a.data()), N);
}

template <std::size_t N>
bool readStream(std::istream& is, std::array<std::uint8_t, N>& a) {
    return is.read(reinterpret_cast<char*>(a.data()), N);
}

////////////////////////////////////////////////////////////////////////////////
// read and write types: array<uint32_t, N>   (hash digest/trapdoor)
//

template <std::size_t N>
void writeStream(std::ostream& os, const std::array<std::uint32_t, N>& a) {
    os << a;
}

template <std::size_t N>
bool readStream(std::istream& is, std::array<std::uint32_t, N>& a) {
    return !!(is >> a);
}

} // namespace snarkfront

#endif
