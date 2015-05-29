#ifndef _SNARKFRONT_DSL_ALGO_HPP_
#define _SNARKFRONT_DSL_ALGO_HPP_

#include <array>
#include <cstdint>
#include <vector>

#include <snarkfront/DataBuffer.hpp>
#include <snarkfront/DSL_bless.hpp>

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// convenient message digest for data
// (new variables for entire message block)
//

template <typename T>
typename T::DigType digest(T hashAlgo, const DataBufferStream& buf)
{
    auto bufCopy = buf; // need copy as blessing from stream consumes it

    while (! bufCopy.empty()) {
        typename T::MsgType msg;
        bless(msg, bufCopy);
        hashAlgo.msgInput(msg);
    }

    hashAlgo.computeHash();

    return hashAlgo.digest();
}

template <typename T>
typename T::DigType digest(T hashAlgo, const std::string& a)
{
    DataBufferStream buf(a);
    T::padMessage(buf);
    return digest(hashAlgo, buf);
}

template <typename T>
typename T::DigType digest(T hashAlgo, const char* a)
{
    return digest(hashAlgo, std::string(a));
}

template <typename T>
typename T::DigType digest(T hashAlgo, const std::vector<std::uint8_t>& a)
{
    DataBufferStream buf(a);
    T::padMessage(buf);
    return digest(hashAlgo, buf);
}

template <typename T, typename... Args>
typename T::DigType digest(T hashAlgo, const Args... parameterPack)
{
    DataBufferStream buf;
    buf.push(parameterPack...);
    T::padMessage(buf);
    return digest(hashAlgo, buf);
}

////////////////////////////////////////////////////////////////////////////////
// convenient AES block encryption for data
// (new variables for entire message block)
//

template <typename T>
typename T::BlockType cipher(T dummyAES,
                             const std::vector<std::uint8_t>& inOctets,
                             const std::vector<std::uint8_t>& keyOctets)
{
    typename T::BlockType inBlock, outBlock;
    typename T::KeyType keyBlock;
    typename T::ScheduleType scheduleBlock;

    DataBufferStream inBuf(inOctets), keyBuf(keyOctets);
    bless(inBlock, inBuf);
    bless(keyBlock, keyBuf);

    typename T::KeyExpansion keyExpand;
    keyExpand(keyBlock, scheduleBlock);

    typename T::Algo aesAlgo;
    aesAlgo(inBlock, outBlock, scheduleBlock);
    return outBlock;
}

template <typename T>
typename T::BlockType cipher(T dummyAES,
                             const bool inverse,
                             const std::vector<std::uint8_t>& inOctets,
                             const std::vector<std::uint8_t>& keyOctets)
{
    typename T::BlockType inBlock, outBlock;
    typename T::KeyType keyBlock;
    typename T::ScheduleType scheduleBlock;

    DataBufferStream inBuf(inOctets), keyBuf(keyOctets);
    bless(inBlock, inBuf);
    bless(keyBlock, keyBuf);

    typename T::KeyExpansion keyExpand;
    keyExpand(keyBlock, scheduleBlock);

    if (inverse) {
        typename T::InvAlgo aesInvAlgo;
        aesInvAlgo(inBlock, outBlock, scheduleBlock);
    } else {
        typename T::Algo aesAlgo;
        aesAlgo(inBlock, outBlock, scheduleBlock);
    }

    return outBlock;
}

} // namespace snarkfront

#endif
