#include "snarkfront/Alg.hpp"

using namespace std;

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// valueToString
//

string valueToString(const bool& a) {
    stringstream ss;
    ss << a;
    return ss.str();
}

string valueToString(const uint32_t& a) {
    stringstream ss;
    ss << a;
    return ss.str();
}

string valueToString(const uint64_t& a) {
    stringstream ss;
    ss << a;
    return ss.str();
}

string valueToString(const uint8_t& a) {
    // must handle uint8_t as a special case
    // stream insertion regards it as text instead of numeric
    return valueToString(static_cast<uint32_t>(a));
}

} // namespace snarkfront
