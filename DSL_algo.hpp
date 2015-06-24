#ifndef _SNARKFRONT_DSL_ALGO_HPP_
#define _SNARKFRONT_DSL_ALGO_HPP_

#include <array>
#include <cstdint>
#include <vector>

#include <cryptl/AES.hpp>
#include <cryptl/CipherModes.hpp>
#include <cryptl/Digest.hpp>
#include <cryptl/SHA.hpp>
#include <cryptl/SHA_1.hpp>
#include <cryptl/SHA_224.hpp>
#include <cryptl/SHA_256.hpp>
#include <cryptl/SHA_384.hpp>
#include <cryptl/SHA_512.hpp>
#include <cryptl/SHA_512_224.hpp>
#include <cryptl/SHA_512_256.hpp>

#include <snarkfront/Alg.hpp>
#include <snarkfront/AST.hpp>
#include <snarkfront/BitwiseAST.hpp>
#include <snarkfront/Lazy.hpp>

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// AES typedefs for managed ZKP types
//

template <typename FR> using AES = cryptl::AES_All<
    AST_Var<Alg_uint8<FR>>, AST_Node<Alg_uint8<FR>>, AST_Op<Alg_uint8<FR>>,
    BitwiseAST<Alg_uint8<FR>>>;

template <typename FR> using UNAES = cryptl::UNAES_All<
    AST_Var<Alg_uint8<FR>>, AST_Node<Alg_uint8<FR>>, AST_Op<Alg_uint8<FR>>,
    BitwiseAST<Alg_uint8<FR>>>;

template <typename FR> using AES128 = cryptl::AES_128<
    AST_Var<Alg_uint8<FR>>, AST_Node<Alg_uint8<FR>>, AST_Op<Alg_uint8<FR>>,
    BitwiseAST<Alg_uint8<FR>>>;

template <typename FR> using UNAES128 = cryptl::UNAES_128<
    AST_Var<Alg_uint8<FR>>, AST_Node<Alg_uint8<FR>>, AST_Op<Alg_uint8<FR>>,
    BitwiseAST<Alg_uint8<FR>>>;

template <typename FR> using AES192 = cryptl::AES_192<
    AST_Var<Alg_uint8<FR>>, AST_Node<Alg_uint8<FR>>, AST_Op<Alg_uint8<FR>>,
    BitwiseAST<Alg_uint8<FR>>>;

template <typename FR> using UNAES192 = cryptl::UNAES_192<
    AST_Var<Alg_uint8<FR>>, AST_Node<Alg_uint8<FR>>, AST_Op<Alg_uint8<FR>>,
    BitwiseAST<Alg_uint8<FR>>>;

template <typename FR> using AES256 = cryptl::AES_256<
    AST_Var<Alg_uint8<FR>>, AST_Node<Alg_uint8<FR>>, AST_Op<Alg_uint8<FR>>,
    BitwiseAST<Alg_uint8<FR>>>;

template <typename FR> using UNAES256 = cryptl::UNAES_256<
    AST_Var<Alg_uint8<FR>>, AST_Node<Alg_uint8<FR>>, AST_Op<Alg_uint8<FR>>,
    BitwiseAST<Alg_uint8<FR>>>;

////////////////////////////////////////////////////////////////////////////////
// SHA typedefs for managed ZKP types
//

template <typename FR> using SHA1 = cryptl::SHA_1<
    AST_Var<Alg_uint32<FR>>,
    Lazy<AST_Var<Alg_uint32<FR>>, std::uint32_t>,
    AST_Var<Alg_uint8<FR>>,
    cryptl::SHA_Functions<
        AST_Node<Alg_uint32<FR>>,
        AST_Op<Alg_uint32<FR>>,
        BitwiseAST<Alg_uint32<FR>>>>;

template <typename FR> using SHA224 = cryptl::SHA_224<
    AST_Var<Alg_uint32<FR>>,
    Lazy<AST_Var<Alg_uint32<FR>>, std::uint32_t>,
    AST_Var<Alg_uint8<FR>>,
    cryptl::SHA_Functions<
        AST_Node<Alg_uint32<FR>>,
        AST_Op<Alg_uint32<FR>>,
        BitwiseAST<Alg_uint32<FR>>>>;

template <typename FR> using SHA256 = cryptl::SHA_256<
    AST_Var<Alg_uint32<FR>>,
    Lazy<AST_Var<Alg_uint32<FR>>, std::uint32_t>,
    AST_Var<Alg_uint8<FR>>,
    cryptl::SHA_Functions<
        AST_Node<Alg_uint32<FR>>,
        AST_Op<Alg_uint32<FR>>,
        BitwiseAST<Alg_uint32<FR>>>>;

template <typename FR> using SHA384 = cryptl::SHA_384<
    AST_Var<Alg_uint64<FR>>,
    Lazy<AST_Var<Alg_uint64<FR>>, std::uint64_t>,
    AST_Var<Alg_uint8<FR>>,
    cryptl::SHA_Functions<
        AST_Node<Alg_uint64<FR>>,
        AST_Op<Alg_uint64<FR>>,
        BitwiseAST<Alg_uint64<FR>>>>;

template <typename FR> using SHA512 = cryptl::SHA_512<
    AST_Var<Alg_uint64<FR>>,
    Lazy<AST_Var<Alg_uint64<FR>>, std::uint64_t>,
    AST_Var<Alg_uint8<FR>>,
    cryptl::SHA_Functions<
        AST_Node<Alg_uint64<FR>>,
        AST_Op<Alg_uint64<FR>>,
        BitwiseAST<Alg_uint64<FR>>>>;

template <typename FR> using SHA512_224 = cryptl::SHA_512_224<
    AST_Var<Alg_uint32<FR>>,
    AST_Var<Alg_uint64<FR>>,
    Lazy<AST_Var<Alg_uint64<FR>>, std::uint64_t>,
    AST_Var<Alg_uint8<FR>>,
    cryptl::SHA_Functions<
        AST_Node<Alg_uint64<FR>>,
        AST_Op<Alg_uint64<FR>>,
        BitwiseAST<Alg_uint64<FR>>>,
    Alg_uint32<FR>>;

template <typename FR> using SHA512_256 = cryptl::SHA_512_256<
    AST_Var<Alg_uint32<FR>>,
    AST_Var<Alg_uint64<FR>>,
    Lazy<AST_Var<Alg_uint64<FR>>, std::uint64_t>,
    AST_Var<Alg_uint8<FR>>,
    cryptl::SHA_Functions<
        AST_Node<Alg_uint64<FR>>,
        AST_Op<Alg_uint64<FR>>,
        BitwiseAST<Alg_uint64<FR>>>,
    Alg_uint32<FR>>;

////////////////////////////////////////////////////////////////////////////////
// SHA-256 hash algorithm specializations
// (arises frequently in applications)
//

cryptl::SHA256 H(const std::uint32_t& dummy);

template <std::size_t N>
cryptl::SHA256 H(const std::array<std::uint32_t, N>& dummy) {
    return cryptl::SHA256();
}

cryptl::SHA256 H(const std::vector<std::uint32_t>& dummy);

template <typename FR>
SHA256<FR> H(const AST_Var<Alg_uint32<FR>>& dummy) {
    return SHA256<FR>();
}

template <typename FR, std::size_t N>
SHA256<FR> H(const std::array<AST_Var<Alg_uint32<FR>>, N>& dummy) {
    return SHA256<FR>();
}

template <typename FR>
SHA256<FR> H(const std::vector<AST_Var<Alg_uint32<FR>>>& dummy) {
    return SHA256<FR>();
}

} // namespace snarkfront

#endif
