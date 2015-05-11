#ifndef _SNARKFRONT_DSL_PPZK_HPP_
#define _SNARKFRONT_DSL_PPZK_HPP_

#include <cstdint>
#include <memory>
#include <string>

#include <snarklib/PPZK_keypair.hpp>
#include <snarklib/PPZK_proof.hpp>
#include <snarklib/ProgressCallback.hpp>

#include <snarkfront/Alg.hpp>
#include <snarkfront/Alg_bool.hpp>
#include <snarkfront/DSL_base.hpp>
#include <snarkfront/R1C.hpp>
#include <snarkfront/TLsingleton.hpp>

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// zero knowledge proof management
//

template <typename PAIRING> using Keypair = snarklib::PPZK_Keypair<PAIRING>;
template <typename PAIRING> using ProvingKey = snarklib::PPZK_ProvingKey<PAIRING>;
template <typename PAIRING> using VerificationKey = snarklib::PPZK_VerificationKey<PAIRING>;
template <typename PAIRING> using Input = R1Cowitness<typename PAIRING::Fr>;
template <typename PAIRING> using Proof = snarklib::PPZK_Proof<PAIRING>;
typedef snarklib::ProgressCallback ProgressCallback;

template <typename PAIRING>
void write_files(const std::string& filePrefix, const std::size_t maxSize)
{
    TL<R1C<typename PAIRING::Fr>>::singleton()
        ->writeFiles(filePrefix, maxSize);
}

template <typename PAIRING>
void finalize_files()
{
    TL<R1C<typename PAIRING::Fr>>::singleton()
        ->finalizeFiles();
}

template <typename PAIRING>
void reset()
{
    TL<R1C<typename PAIRING::Fr>>::singleton()
        ->reset();
}

template <typename PAIRING>
void end_input()
{
    TL<R1C<typename PAIRING::Fr>>::singleton()
        ->checkpointInput();
}

template <typename PAIRING>
std::size_t variable_count()
{
    return TL<R1C<typename PAIRING::Fr>>::singleton()
        ->counterID();
}

template <typename PAIRING>
snarklib::PPZK_Keypair<PAIRING> keypair()
{
    return TL<R1C<typename PAIRING::Fr>>::singleton()
        ->keypair<PAIRING>();
}

template <typename PAIRING>
snarklib::PPZK_Keypair<PAIRING> keypair(
    snarklib::ProgressCallback& callback)
{
    return TL<R1C<typename PAIRING::Fr>>::singleton()
        ->keypair<PAIRING>(std::addressof(callback));
}

template <typename PAIRING>
const R1Cowitness<typename PAIRING::Fr>& input()
{
    return TL<R1C<typename PAIRING::Fr>>::singleton()
        ->input();
}

template <typename PAIRING>
const snarklib::R1Witness<typename PAIRING::Fr>& witness()
{
    return TL<R1C<typename PAIRING::Fr>>::singleton()
        ->witness();
}

template <typename PAIRING>
snarklib::PPZK_Proof<PAIRING> proof(
    const snarklib::PPZK_ProvingKey<PAIRING>& key)
{
    return TL<R1C<typename PAIRING::Fr>>::singleton()
        ->proof(key, 0);
}

template <typename PAIRING>
snarklib::PPZK_Proof<PAIRING> proof(
    const snarklib::PPZK_ProvingKey<PAIRING>& key,
    snarklib::ProgressCallback& callback)
{
    return TL<R1C<typename PAIRING::Fr>>::singleton()
        ->proof(key, 0, std::addressof(callback));
}

template <typename PAIRING>
snarklib::PPZK_Proof<PAIRING> proof(
    const snarklib::PPZK_ProvingKey<PAIRING>& key,
    const std::size_t reserveTune,
    snarklib::ProgressCallback& callback)
{
    return TL<R1C<typename PAIRING::Fr>>::singleton()
        ->proof(key, reserveTune, std::addressof(callback));
}

template <typename PAIRING>
snarklib::PPZK_Proof<PAIRING> proof(
    const snarklib::PPZK_Keypair<PAIRING>& keypair)
{
    return proof(keypair.pk());
}

template <typename PAIRING>
snarklib::PPZK_Proof<PAIRING> proof(
    const snarklib::PPZK_Keypair<PAIRING>& keypair,
    snarklib::ProgressCallback& callback)
{
    return proof(keypair.pk(), callback);
}

template <typename PAIRING>
snarklib::PPZK_Proof<PAIRING> proof(
    const snarklib::PPZK_Keypair<PAIRING>& keypair,
    const std::size_t reserveTune,
    snarklib::ProgressCallback& callback)
{
    return proof(keypair.pk(), reserveTune, callback);
}

template <typename PAIRING>
bool verify(
    const snarklib::PPZK_VerificationKey<PAIRING>& key,
    const R1Cowitness<typename PAIRING::Fr>& input,
    const snarklib::PPZK_Proof<PAIRING>& proof)
{
    return TL<R1C<typename PAIRING::Fr>>::singleton()
        ->verify(key, input, proof);
}

template <typename PAIRING>
bool verify(
    const snarklib::PPZK_VerificationKey<PAIRING>& key,
    const R1Cowitness<typename PAIRING::Fr>& input,
    const snarklib::PPZK_Proof<PAIRING>& proof,
    snarklib::ProgressCallback& callback)
{
    return TL<R1C<typename PAIRING::Fr>>::singleton()
        ->verify(key, input, proof, std::addressof(callback));
}

template <typename PAIRING>
bool verify(
    const snarklib::PPZK_Keypair<PAIRING>& keypair,
    const R1Cowitness<typename PAIRING::Fr>& input,
    const snarklib::PPZK_Proof<PAIRING>& proof)
{
    return verify(keypair.vk(), input, proof);
}

template <typename PAIRING>
bool verify(
    const snarklib::PPZK_Keypair<PAIRING>& keypair,
    const R1Cowitness<typename PAIRING::Fr>& input,
    const snarklib::PPZK_Proof<PAIRING>& proof,
    snarklib::ProgressCallback& callback)
{
    return verify(keypair.vk(), input, proof, callback);
}

////////////////////////////////////////////////////////////////////////////////
// terminate circuits, constrain final proof output
//

template <typename FR>
void assert_true(const AST_Var<Alg_bool<FR>>& x) {
    TL<R1C<FR>>::singleton()->setTrue(x->r1Terms()[0]);
}

template <typename FR>
void assert_false(const AST_Var<Alg_bool<FR>>& x) {
    TL<R1C<FR>>::singleton()->setFalse(x->r1Terms()[0]);
}

template <typename FR>
void assert_true(const AST_X<Alg_bool<FR>>& a) {
    assert_true(bool_x<FR>(a));
}

template <typename FR>
void assert_false(const AST_X<Alg_bool<FR>>& a) {
    assert_false(bool_x<FR>(a));
}

} // namespace snarkfront

#endif
