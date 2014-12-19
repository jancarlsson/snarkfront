////////////////////////////////////////////////////////////////////////////////
// to be included by translation unit with main()
//

#include <cassert>
#include <EC.hpp> // snarklib

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// Barreto-Naehrig 128 bits
//

const mp_size_t BN128_NRQ = snarklib::BN128::q_limbs;
extern const auto BN128_MODULUS_R = snarklib::BN128::modulus_r();
extern const auto BN128_MODULUS_Q = snarklib::BN128::modulus_q();

typedef typename
snarklib::BN128::Groups<BN128_NRQ, BN128_MODULUS_R, BN128_MODULUS_Q>::Fr
BN128_FR;

typedef typename
snarklib::BN128::Pairing<BN128_NRQ, BN128_MODULUS_R, BN128_MODULUS_Q>
BN128_PAIRING;

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

const mp_size_t EDWARDS_NRQ = snarklib::Edwards::q_limbs;
extern const auto EDWARDS_MODULUS_R = snarklib::Edwards::modulus_r();
extern const auto EDWARDS_MODULUS_Q = snarklib::Edwards::modulus_q();

typedef typename
snarklib::Edwards::Groups<EDWARDS_NRQ, EDWARDS_MODULUS_R, EDWARDS_MODULUS_Q>::Fr
EDWARDS_FR;

typedef typename
snarklib::Edwards::Pairing<EDWARDS_NRQ, EDWARDS_MODULUS_R, EDWARDS_MODULUS_Q>
EDWARDS_PAIRING;

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
