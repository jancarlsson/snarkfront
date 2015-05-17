#include "snarkfront/PowersOf2.hpp"

using namespace std;

namespace snarkfront {

bool zero_internal(const bool& dummy) { return false; }
bool one_internal(const bool& dummy) { return true; }

size_t sizeBits(const bool& dummy) { return 1; }
size_t sizeBits(const uint8_t& dummy) { return 8; }
size_t sizeBits(const uint32_t& dummy) { return 32; }
size_t sizeBits(const uint64_t& dummy) { return 64; }

vector<int> valueBits(const bool& a) { return vector<int>(1, a); }

template <typename UINT_N>
vector<int> valueBits_internal(const UINT_N& a) {
    vector<int> v;
    v.reserve(sizeBits(a));

    UINT_N b = a;
    for (size_t i = 0; i < sizeBits(b); ++i) {
        v.push_back(b & 0x1);
        b >>= 1;
    }

    return v;
}

vector<int> valueBits(const uint8_t& a) { return valueBits_internal(a); }
vector<int> valueBits(const uint32_t& a) { return valueBits_internal(a); }
vector<int> valueBits(const uint64_t& a) { return valueBits_internal(a); }

size_t countBits(const vector<int>& v) {
    size_t count = 0;

    for (const auto& b : v)
        count += b;

    return count;
}

} // namespace snarkfront
