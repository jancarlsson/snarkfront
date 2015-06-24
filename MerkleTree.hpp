#ifndef _SNARKFRONT_MERKLE_TREE_HPP_
#define _SNARKFRONT_MERKLE_TREE_HPP_

#include <cstdint>
#include <iostream>
#include <istream>
#include <ostream>
#include <vector>

#include <cryptl/SHA_256.hpp>
#include <cryptl/SHA_512.hpp>

#include <snarkfront/MerkleAuthPath.hpp>

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// Merkle tree (binary)
//

template <typename HASH>
class MerkleTree
{
public:
    typedef HASH HashType;
    typedef typename HASH::DigType DigType;

    MerkleTree()
        : m_isFull(true),
          m_authPath(0)
    {}

    // unmanaged (eval namespace)
    MerkleTree(const std::size_t depth)
        : m_isFull(false),
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

    void marshal_out(std::ostream& os) const {
        os << m_isFull << ' ' << m_authPath;
    }

    bool marshal_in(std::istream& is) {
        m_isFull = true; // use as valid flag

        // is full
        bool full = true;
        if (! (is >> full)) return false;

        // space
        char c;
        if (!is.get(c) || (' ' != c)) return false;

        if (! m_authPath.marshal_in(is)) return false;

        m_isFull = full;

        return true;
    }

    void clear() {
        m_isFull = true;
        m_authPath.clear();
    }

    bool empty() const 
    {
        return
            isFull() ||
            authPath().empty();
    }

private:
    bool m_isFull;
    MerkleAuthPath<HASH, int> m_authPath;
};

template <typename HASH>
std::ostream& operator<< (std::ostream& os, const MerkleTree<HASH>& a) {
    a.marshal_out(os);
    return os;
}

template <typename HASH>
std::istream& operator>> (std::istream& is, MerkleTree<HASH>& a) {
    if (! a.marshal_in(is)) a.clear();
    return is;
}

////////////////////////////////////////////////////////////////////////////////
// typedefs
//

typedef MerkleTree<cryptl::SHA256> MerkleTree_SHA256;
typedef MerkleTree<cryptl::SHA512> MerkleTree_SHA512;

} // namespace snarkfront

#endif
