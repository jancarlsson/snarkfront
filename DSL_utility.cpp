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

////////////////////////////////////////////////////////////////////////////////
// SHA-2
//

bool validSHA2Name(const string& shaBits) {
    return
        ("1" == shaBits) ||
        ("224" == shaBits) ||
        ("256" == shaBits) ||
        ("384" == shaBits) ||
        ("512" == shaBits) ||
        ("512_224" == shaBits) ||
        ("512_256" == shaBits);
}

bool validSHA2Name(const size_t shaBits) {
    return
        (1 == shaBits) ||
        (224 == shaBits) ||
        (256 == shaBits) ||
        (384 == shaBits) ||
        (512 == shaBits);
}

bool nameSHA256(const string& shaBits) {
    return "256" == shaBits;
}

bool nameSHA512(const string& shaBits) {
    return "512" == shaBits;
}

////////////////////////////////////////////////////////////////////////////////
// AES
//

bool validAESName(const size_t aesBits) {
    return 128 == aesBits || 192 == aesBits || 256 == aesBits;
}

} // namespace snarkfront
