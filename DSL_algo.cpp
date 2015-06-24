#include "snarkfront/DSL_algo.hpp"

using namespace std;

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// SHA-256 hash algorithm specializations
// (arises frequently in applications)
//

cryptl::SHA256 H(const uint32_t& dummy) {
    return cryptl::SHA256();
}

cryptl::SHA256 H(const vector<uint32_t>& dummy) {
    return cryptl::SHA256();
}

}; // namespace snarkfront
