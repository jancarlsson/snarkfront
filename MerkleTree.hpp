#ifndef _SNARKFRONT_MERKLE_TREE_HPP_
#define _SNARKFRONT_MERKLE_TREE_HPP_

#include <array>
#include <cstdint>
#include <vector>
#include "FoundationDSL.hpp"
#include "PowersOf2.hpp"
#include "SHA_256.hpp"
#include "SHA_512.hpp"

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// authentication path from a binary Merkle tree
//

template <typename HASH, typename BIT>
class MerkleAuthPath
{
public:
    typedef HASH HashType;
    typedef typename HASH::DigType DigType;

    // eval
    MerkleAuthPath(const std::size_t depth)
        : m_depth(depth),
          m_rootPath(depth) // first update initializes hash digests
    {
        m_siblings.reserve(depth);
        m_childBits.reserve(depth);

        for (std::size_t i = 0; i < depth; ++i) {
            m_siblings.emplace_back(zero());
            m_childBits.emplace_back(0);
        }
    }

    // zk from eval
    template <typename OTHER_HASH, typename OTHER_BIT>
    MerkleAuthPath(const MerkleAuthPath<OTHER_HASH, OTHER_BIT>& other)
        : m_depth(other.depth()),
          m_rootPath(other.depth()) // first update initializes hash digests
    {
        m_siblings.reserve(other.depth());
        for (const auto& a : other.siblings()) {
            DigType b;
            bless(b, a);
            m_siblings.emplace_back(b);
        }

        m_childBits.reserve(other.depth());
        for (const auto& a : other.childBits()) {
            BIT b;
            bless(b, a);
            m_childBits.emplace_back(b);
        }
    }

    std::size_t depth() const {
        return m_depth;
    }

    const DigType& rootHash() const {
        return m_rootPath.back();
    }

    // bottom-up order, index 0 is at the leaves of tree
    const std::vector<DigType>& rootPath() const { return m_rootPath; }
    const std::vector<DigType>& siblings() const { return m_siblings; }
    const std::vector<BIT>& childBits() const { return m_childBits; }

    // update hash codes along path back to root
    void updatePath(const DigType& leaf) {
        std::vector<MerkleAuthPath> dummy;
        updatePath(leaf, dummy);
    }

    // update hash codes along path back to root
    void updatePath(const DigType& leaf,
                    std::vector<MerkleAuthPath>& oldPaths)
    {
        // root path overlap
        std::vector<int> overlap;
        overlap.reserve(oldPaths.size());
        for (const auto& a : oldPaths) {
            overlap.push_back(
                matchMSB(m_childBits, a.childBits()));
        }

        HASH hashAlgo;

        auto dig = leaf;

        // ascend tree from leaf to root
        for (std::size_t i = 0; i < m_depth; ++i) {
            hashAlgo.clearMessage();

            const auto& isRightChild = m_childBits[i];
            const auto
                leftDigest = ternary(isRightChild, m_siblings[i], dig),
                rightDigest = ternary(isRightChild, dig, m_siblings[i]);

            hashAlgo.msgInput(leftDigest);
            hashAlgo.msgInput(rightDigest);
            hashAlgo.computeHash();

            dig = m_rootPath[i] = hashAlgo.digest();

            // path length from root to node with the new hash
            const int pathLen = m_depth - 1 - i;

            // update old authentication paths
            for (std::size_t j = 0; j < overlap.size(); ++j) {
                if (pathLen <= overlap[j]) {
                    // update root path hashes
                    oldPaths[j].m_rootPath[i] = dig;

                } else if (pathLen == overlap[j] + 1) {
                    // update sibling hashes
                    oldPaths[j].m_siblings[i + 1] = dig;

                }
            }
        }

        // update old authentication paths
        for (std::size_t j = 0; j < overlap.size(); ++j) {
            if (m_depth - 1 == overlap[j])
                // differ in last bit only, leaf must be right sibling
                oldPaths[j].m_siblings[0] = leaf;
        }
    }

    // just added leaf becomes left sibling
    void leafSibling(const DigType& leaf) {
        m_siblings[0] = leaf;
    }

    // new branch in Merkle tree
    void hashSibling(const std::size_t index)
    {
        m_siblings[index] = m_rootPath[index - 1];

        for (std::size_t i = 0; i < index; ++i)
            m_siblings[i] = zero();
    }

    // returns index of first set bit (right child)
    int incChildBits()
    {
        for (std::size_t i = 0; i < m_depth; ++i) {
            auto& a = m_childBits[i];

            if (bool(0 == a)) {
                // bit is zero, increment to one
                a = 1;
                return i;

            } else {
                // bit is one, increment to zero and carry
                a = 0;
            }
        }

        // increment all ones wraps back to zero with carry
        return -1;
    }

private:
    // note: not called by proof generation
    static DigType zero() {
        return {0};
    }

    const std::size_t m_depth;

    // indices start from 0 at the leaves increasing up to the root
    std::vector<DigType> m_rootPath, m_siblings;

    // next available leaf element
    std::vector<BIT> m_childBits;
};

////////////////////////////////////////////////////////////////////////////////
// Merkle tree (binary)
//

template <typename HASH>
class MerkleTree
{
public:
    typedef HASH HashType;
    typedef typename HASH::DigType DigType;

    // unmanaged (eval namespace)
    MerkleTree(const std::size_t depth)
        : m_depth(depth),
          m_isFull(false),
          m_authPath(depth)
    {}

    // true when number of occupied leaves is 2^depth
    bool isFull() const {
        return m_isFull;
    }

    const MerkleAuthPath<HASH, int>& authPath() const {
        return m_authPath;
    }

    // update hash codes along path back to root
    void updatePath(const DigType& leaf) {
        m_authPath.updatePath(leaf);
    }

    // update hash codes along path back to root
    void updatePath(const DigType& leaf,
                    std::vector<MerkleAuthPath<HASH, int>>& v)
    {
        m_authPath.updatePath(leaf, v);
    }

    // prepare tree for next leaf
    void updateSiblings(const DigType& leaf)
    {
        // counter for next leaf element
        const int firstBit = m_authPath.incChildBits();

        if (-1 == firstBit) {
            // tree is full
            m_isFull = true;
            return;

        } else if (0 == firstBit) {
            // next leaf is right child
            m_authPath.leafSibling(leaf);

        } else {
            // left sibling of new branch in tree
            m_authPath.hashSibling(firstBit);
        }
    }

private:
    const std::size_t m_depth;
    bool m_isFull;

    MerkleAuthPath<HASH, int> m_authPath;
};

////////////////////////////////////////////////////////////////////////////////
// typedefs
//

namespace zk {
    template <typename FR> using MerkleAuthPath_SHA256 = MerkleAuthPath<SHA256<FR>, bool_x<FR>>;
    template <typename FR> using MerkleAuthPath_SHA512 = MerkleAuthPath<SHA512<FR>, bool_x<FR>>;
} // namespace zk

namespace eval {
    typedef MerkleAuthPath<SHA256, int> MerkleAuthPath_SHA256;
    typedef MerkleAuthPath<SHA512, int> MerkleAuthPath_SHA512;
    typedef MerkleTree<SHA256> MerkleTree_SHA256;
    typedef MerkleTree<SHA512> MerkleTree_SHA512;
} // namespace eval

} // namespace snarkfront

#endif
