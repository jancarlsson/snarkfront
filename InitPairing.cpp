#include <cassert>
#include "InitPairing.hpp"

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// Barreto-Naehrig 128 bits
//

const snarklib::BigInt<snarklib::BN128_Modulus::r_limbs>
BN128_MODULUS_R = snarklib::BN128::modulus_r();

const snarklib::BigInt<snarklib::BN128_Modulus::q_limbs>
BN128_MODULUS_Q = snarklib::BN128::modulus_q();

// initialize elliptic curve parameters
void init_BN128() {
    typedef snarklib::BN128 CURVE;

    // the R and Q modulus should be about the same size for GMP
    assert(CURVE::r_limbs == CURVE::q_limbs);

    // critically important to initialize finite field and group parameters
    CURVE::Fields<BN128_NRQ, BN128_MODULUS_R>::initParams();
    CURVE::Fields<BN128_NRQ, BN128_MODULUS_Q>::initParams();
    CURVE::Groups<BN128_NRQ, BN128_MODULUS_R, BN128_MODULUS_Q>::initParams();
}

////////////////////////////////////////////////////////////////////////////////
// Edwards 80 bits
//

const snarklib::BigInt<snarklib::Edwards_Modulus::r_limbs>
EDWARDS_MODULUS_R = snarklib::Edwards::modulus_r();

const snarklib::BigInt<snarklib::Edwards_Modulus::q_limbs>
EDWARDS_MODULUS_Q = snarklib::Edwards::modulus_q();

// initialize elliptic curve parameters
void init_Edwards() {
    typedef snarklib::Edwards CURVE;

    // the R and Q modulus should be about the same size for GMP
    assert(CURVE::r_limbs == CURVE::q_limbs);

    // critically important to initialize finite field and group parameters
    CURVE::Fields<EDWARDS_NRQ, EDWARDS_MODULUS_R>::initParams();
    CURVE::Fields<EDWARDS_NRQ, EDWARDS_MODULUS_Q>::initParams();
    CURVE::Groups<EDWARDS_NRQ, EDWARDS_MODULUS_R, EDWARDS_MODULUS_Q>::initParams();
}

} // namespace snarkfront
