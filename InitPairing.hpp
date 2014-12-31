#ifndef _SNARKFRONT_INIT_PAIRING_HPP_
#define _SNARKFRONT_INIT_PAIRING_HPP_

#include <EC.hpp> // snarklib

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// Barreto-Naehrig 128 bits
//

const mp_size_t BN128_NRQ = snarklib::BN128::q_limbs;

extern const snarklib::BigInt<snarklib::BN128_Modulus::r_limbs> BN128_MODULUS_R;
extern const snarklib::BigInt<snarklib::BN128_Modulus::q_limbs> BN128_MODULUS_Q;

typedef typename
snarklib::BN128::Groups<BN128_NRQ, BN128_MODULUS_R, BN128_MODULUS_Q>::Fr
BN128_FR;

typedef typename
snarklib::BN128::Pairing<BN128_NRQ, BN128_MODULUS_R, BN128_MODULUS_Q>
BN128_PAIRING;

// initialize elliptic curve parameters
void init_BN128();

////////////////////////////////////////////////////////////////////////////////
// Edwards 80 bits
//

const mp_size_t EDWARDS_NRQ = snarklib::Edwards::q_limbs;

extern const snarklib::BigInt<snarklib::Edwards_Modulus::r_limbs> EDWARDS_MODULUS_R;
extern const snarklib::BigInt<snarklib::Edwards_Modulus::q_limbs> EDWARDS_MODULUS_Q;

typedef typename
snarklib::Edwards::Groups<EDWARDS_NRQ, EDWARDS_MODULUS_R, EDWARDS_MODULUS_Q>::Fr
EDWARDS_FR;

typedef typename
snarklib::Edwards::Pairing<EDWARDS_NRQ, EDWARDS_MODULUS_R, EDWARDS_MODULUS_Q>
EDWARDS_PAIRING;

// initialize elliptic curve parameters
void init_Edwards();

} // namespace snarkfront

#endif
