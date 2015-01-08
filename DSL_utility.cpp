#include "DSL_utility.hpp"

using namespace std;

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// elliptic curve pairing
//

bool validPairingName(const string& name) {
    return pairingBN128(name) || pairingEdwards(name);
}

bool pairingBN128(const string& name) {
    return "BN128" == name;
}

bool pairingEdwards(const string& name) {
    return "Edwards" == name;
}

} // namespace snarkfront
