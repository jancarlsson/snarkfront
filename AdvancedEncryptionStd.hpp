#ifndef _SNARKFRONT_ADVANCED_ENCRYPTION_STD_HPP_
#define _SNARKFRONT_ADVANCED_ENCRYPTION_STD_HPP_

#include <array>

#include <snarkfront/AES_Cipher.hpp>
#include <snarkfront/AES_InvCipher.hpp>
#include <snarkfront/Alg.hpp>
#include <snarkfront/BitwiseAST.hpp>
#include <snarkfront/BitwiseINT.hpp>

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// AES variants
//

template <typename VAR, typename T, typename U, typename BITWISE>
class AES_All
{
public:
    AES_All() = default;

    typedef VAR VarType;
    typedef AES_Cipher<VAR, T, U, BITWISE> Encrypt;
    typedef AES_InvCipher<VAR, T, U, BITWISE> Decrypt;
    typedef Encrypt Algo;
    typedef Decrypt InvAlgo;

    typedef typename Encrypt::BlockType BlockType;
    typedef typename Encrypt::KeyExpansion KeyExpansion;
};

template <typename VAR, typename T, typename U, typename BITWISE>
class UNAES_All
{
public:
    UNAES_All() = default;

    typedef VAR VarType;
    typedef AES_Cipher<VAR, T, U, BITWISE> Encrypt;
    typedef AES_InvCipher<VAR, T, U, BITWISE> Decrypt;
    typedef Decrypt Algo;
    typedef Encrypt InvAlgo;

    typedef typename Decrypt::BlockType BlockType;
    typedef typename Decrypt::KeyExpansion KeyExpansion;
};

template <typename VAR, typename T, typename U, typename BITWISE>
class AES_128
{
public:
    AES_128() = default;

    typedef VAR VarType;
    typedef AES_Cipher<VAR, T, U, BITWISE> Encrypt;
    typedef AES_InvCipher<VAR, T, U, BITWISE> Decrypt;
    typedef Encrypt Algo;
    typedef Decrypt InvAlgo;

    typedef typename Encrypt::BlockType BlockType;
    typedef typename Encrypt::KeyExpansion KeyExpansion;
    typedef typename KeyExpansion::Key128Type KeyType;
    typedef typename KeyExpansion::Schedule128Type ScheduleType;
};

template <typename VAR, typename T, typename U, typename BITWISE>
class UNAES_128
{
public:
    UNAES_128() = default;

    typedef VAR VarType;
    typedef AES_Cipher<VAR, T, U, BITWISE> Encrypt;
    typedef AES_InvCipher<VAR, T, U, BITWISE> Decrypt;
    typedef Decrypt Algo;
    typedef Encrypt InvAlgo;

    typedef typename Decrypt::BlockType BlockType;
    typedef typename Decrypt::KeyExpansion KeyExpansion;
    typedef typename KeyExpansion::Key128Type KeyType;
    typedef typename KeyExpansion::Schedule128Type ScheduleType;
};

template <typename VAR, typename T, typename U, typename BITWISE>
class AES_192
{
public:
    AES_192() = default;

    typedef VAR VarType;
    typedef AES_Cipher<VAR, T, U, BITWISE> Encrypt;
    typedef AES_InvCipher<VAR, T, U, BITWISE> Decrypt;
    typedef Encrypt Algo;
    typedef Decrypt InvAlgo;

    typedef typename Encrypt::BlockType BlockType;
    typedef typename Encrypt::KeyExpansion KeyExpansion;
    typedef typename KeyExpansion::Key192Type KeyType;
    typedef typename KeyExpansion::Schedule192Type ScheduleType;
};

template <typename VAR, typename T, typename U, typename BITWISE>
class UNAES_192
{
public:
    UNAES_192() = default;

    typedef VAR VarType;
    typedef AES_Cipher<VAR, T, U, BITWISE> Encrypt;
    typedef AES_InvCipher<VAR, T, U, BITWISE> Decrypt;
    typedef Decrypt Algo;
    typedef Encrypt InvAlgo;

    typedef typename Decrypt::BlockType BlockType;
    typedef typename Decrypt::KeyExpansion KeyExpansion;
    typedef typename KeyExpansion::Key192Type KeyType;
    typedef typename KeyExpansion::Schedule192Type ScheduleType;
};

template <typename VAR, typename T, typename U, typename BITWISE>
class AES_256
{
public:
    AES_256() = default;

    typedef VAR VarType;
    typedef AES_Cipher<VAR, T, U, BITWISE> Encrypt;
    typedef AES_InvCipher<VAR, T, U, BITWISE> Decrypt;
    typedef Encrypt Algo;
    typedef Decrypt InvAlgo;

    typedef typename Encrypt::BlockType BlockType;
    typedef typename Encrypt::KeyExpansion KeyExpansion;
    typedef typename KeyExpansion::Key256Type KeyType;
    typedef typename KeyExpansion::Schedule256Type ScheduleType;
};

template <typename VAR, typename T, typename U, typename BITWISE>
class UNAES_256
{
public:
    UNAES_256() = default;

    typedef VAR VarType;
    typedef AES_Cipher<VAR, T, U, BITWISE> Encrypt;
    typedef AES_InvCipher<VAR, T, U, BITWISE> Decrypt;
    typedef Decrypt Algo;
    typedef Encrypt InvAlgo;

    typedef typename Decrypt::BlockType BlockType;
    typedef typename Decrypt::KeyExpansion KeyExpansion;
    typedef typename KeyExpansion::Key256Type KeyType;
    typedef typename KeyExpansion::Schedule256Type ScheduleType;
};

////////////////////////////////////////////////////////////////////////////////
// typedefs
//

namespace zk {
    template <typename FR> using
    AES = AES_All<
        AST_Var<Alg_uint8<FR>>, AST_Node<Alg_uint8<FR>>, AST_Op<Alg_uint8<FR>>,
        BitwiseAST<Alg_uint8<FR>>>;

    template <typename FR> using
    UNAES = UNAES_All<
        AST_Var<Alg_uint8<FR>>, AST_Node<Alg_uint8<FR>>, AST_Op<Alg_uint8<FR>>,
        BitwiseAST<Alg_uint8<FR>>>;

    template <typename FR> using
    AES128 = AES_128<
        AST_Var<Alg_uint8<FR>>, AST_Node<Alg_uint8<FR>>, AST_Op<Alg_uint8<FR>>,
        BitwiseAST<Alg_uint8<FR>>>;

    template <typename FR> using
    UNAES128 = UNAES_128<
        AST_Var<Alg_uint8<FR>>, AST_Node<Alg_uint8<FR>>, AST_Op<Alg_uint8<FR>>,
        BitwiseAST<Alg_uint8<FR>>>;

    template <typename FR> using
    AES192 = AES_192<
        AST_Var<Alg_uint8<FR>>, AST_Node<Alg_uint8<FR>>, AST_Op<Alg_uint8<FR>>,
        BitwiseAST<Alg_uint8<FR>>>;

    template <typename FR> using
    UNAES192 = UNAES_192<
        AST_Var<Alg_uint8<FR>>, AST_Node<Alg_uint8<FR>>, AST_Op<Alg_uint8<FR>>,
        BitwiseAST<Alg_uint8<FR>>>;

    template <typename FR> using
    AES256 = AES_256<
        AST_Var<Alg_uint8<FR>>, AST_Node<Alg_uint8<FR>>, AST_Op<Alg_uint8<FR>>,
        BitwiseAST<Alg_uint8<FR>>>;

    template <typename FR> using
    UNAES256 = UNAES_256<
        AST_Var<Alg_uint8<FR>>, AST_Node<Alg_uint8<FR>>, AST_Op<Alg_uint8<FR>>,
        BitwiseAST<Alg_uint8<FR>>>;
} // namespace zk

namespace eval {
    typedef AES_All<
        std::uint8_t, std::uint8_t, std::uint8_t, BitwiseINT<std::uint8_t>>
        AES;

    typedef UNAES_All<
        std::uint8_t, std::uint8_t, std::uint8_t, BitwiseINT<std::uint8_t>>
        UNAES;

    typedef AES_128<
        std::uint8_t, std::uint8_t, std::uint8_t, BitwiseINT<std::uint8_t>>
        AES128;

    typedef UNAES_128<
        std::uint8_t, std::uint8_t, std::uint8_t, BitwiseINT<std::uint8_t>>
        UNAES128;

    typedef AES_192<
        std::uint8_t, std::uint8_t, std::uint8_t, BitwiseINT<std::uint8_t>>
        AES192;

    typedef UNAES_192<
        std::uint8_t, std::uint8_t, std::uint8_t, BitwiseINT<std::uint8_t>>
        UNAES192;

    typedef AES_256<
        std::uint8_t, std::uint8_t, std::uint8_t, BitwiseINT<std::uint8_t>>
        AES256;

    typedef UNAES_256<
        std::uint8_t, std::uint8_t, std::uint8_t, BitwiseINT<std::uint8_t>>
        UNAES256;
} // namespace eval

} // namespace snarkfront

#endif
