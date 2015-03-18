#include "DSL_base.hpp"

using namespace std;

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// conditional operator (ternary)
//

uint8_t ternary(const bool b, const uint8_t x, const uint8_t y) {
    return b ? x : y;
}

uint32_t ternary(const bool b, const uint32_t x, const uint32_t y) {
    return b ? x : y;
}

uint64_t ternary(const bool b, const uint64_t x, const uint64_t y) {
    return b ? x : y;
}

} // namespace snarkfront
