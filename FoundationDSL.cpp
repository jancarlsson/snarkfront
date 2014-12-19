#include "FoundationDSL.hpp"

using namespace std;

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// identity elements
//

// Boolean
bool zero(const bool& dummy) {
    return false;
}

bool one(const bool& dummy) {
    return true;
}

// 32-bit word
uint32_t zero(const uint32_t& dummy) {
    return 0;
}

uint32_t one(const uint32_t& dummy) {
    return 1;
}

// 64-bit word
uint64_t zero(const uint64_t& dummy) {
    return 0;
}

uint64_t one(const uint64_t& dummy) {
    return 1;
}

////////////////////////////////////////////////////////////////////////////////
// blessing (initialize variables)
//

// 32-bit value from data buffer stream (useful for templates)
void bless(uint32_t& a, DataBufferStream& ss) {
    a = ss.getWord<uint32_t>();
}

// 64-bit value from data buffer stream (useful for templates)
void bless(uint64_t& a, DataBufferStream& ss) {
    a = ss.getWord<uint64_t>();
}

////////////////////////////////////////////////////////////////////////////////
// conditional operator (ternary)
//

uint32_t ternary(const bool b, const uint32_t x, const uint32_t y) {
    return b ? x : y;
}

uint64_t ternary(const bool b, const uint64_t x, const uint64_t y) {
    return b ? x : y;
}

} // namespace snarkfront
