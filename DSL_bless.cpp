#include "DSL_bless.hpp"

using namespace std;

namespace snarkfront {

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

} // namespace snarkfront
