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

void mulover(uint8_t& c1, uint8_t& c0, const uint8_t& a, const uint8_t& b)
{
    const uint32_t c = static_cast<uint32_t>(a) * static_cast<uint32_t>(b);
    c0 = c & 0xff;
    c1 = (c >> 8) & 0xff;
}

void mulover(uint32_t& c1, uint32_t& c0, const uint32_t& a, const uint32_t& b)
{
    const uint64_t c = static_cast<uint64_t>(a) * static_cast<uint64_t>(b);
    c0 = c & 0xffffffff;
    c1 = (c >> 32) & 0xffffffff;
}

void mulover(uint64_t& c1, uint64_t& c0, const uint64_t& a, const uint64_t& b)
{
    // a = (a >> 32) * (1 << 32) + (a & 0xffffffff)
    //   = a_high * (1 << 32) + a_low
    const uint64_t a_high = a >> 32, a_low = a & 0xffffffff;

    // b = (b >> 32) * (1 << 32) + (b & 0xffffffff)
    //   = b_high * (1 << 32) + b_low
    const uint64_t b_high = b >> 32, b_low = b & 0xffffffff;

    // a * b = a_high * b_high * (1 << 64)
    //         + a_high * b_low * (1 << 32)
    //         + b_high * a_low * (1 << 32)
    //         + a_low * b_low
    const uint64_t ab = a_high * b_low, ba = b_high * a_low;
    c0 = a_low * b_low;
    c1 = a_high * b_high + (ab >> 32) + (ba >> 32);
    addover(c1, c0, ab << 32);
    addover(c1, c0, ba << 32);
}

} // namespace snarkfront
