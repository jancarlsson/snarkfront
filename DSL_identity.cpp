#include "DSL_identity.hpp"

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

} // namespace snarkfront
