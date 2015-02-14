#ifndef _SNARKFRONT_MERKLE_BUNDLE_HPP_
#define _SNARKFRONT_MERKLE_BUNDLE_HPP_

#include <cstdint>
#include <iostream>
#include <istream>
#include <ostream>
#include <set>
#include <vector>
#include "DSL_utility.hpp"
#include "MerkleAuthPath.hpp"
#include "MerkleTree.hpp"

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// Merkle tree with authentication paths
//

template <typename TREE, typename PATH, typename COUNT>
class MerkleBundle
{
public:
    typedef typename TREE::HashType HashType;
    typedef typename TREE::DigType DigType;
    typedef PATH AuthPath;
    typedef COUNT Count;

    MerkleBundle()
        : m_treeSize(0)
    {}

    MerkleBundle(const std::size_t depth)
        : m_tree(depth),
          m_treeSize(0)
    {}

    bool isFull() const {
        return m_tree.isFull();
    }

    COUNT treeSize() const {
        return m_treeSize;
    }

    const DigType& rootHash() const {
        return m_tree.authPath().rootHash();
    }

    void addLeaf(const DigType& cm, const bool keepPath = true) {
        m_tree.updatePath(cm, m_authPath);

        if (keepPath) {
            m_authLeaf.emplace_back(cm);
            m_authPath.emplace_back(m_tree.authPath());
        }

        m_tree.updateSiblings(cm);

        ++m_treeSize;
    }

    const std::vector<DigType>& authLeaf() const {
        return m_authLeaf;
    }

    const std::vector<PATH>& authPath() const {
        return m_authPath;
    }

    void authGC(const std::set<DigType>& markedLeaf) {
        std::vector<DigType> keepLeaf;
        std::vector<PATH> keepPath;

        for (std::size_t i = 0; i < m_authLeaf.size(); ++i) {
            const auto& cm = m_authLeaf[i];
            if (markedLeaf.count(cm)) {
                keepLeaf.emplace_back(cm);
                keepPath.emplace_back(m_authPath[i]);
            }
        }

        m_authLeaf = keepLeaf;
        m_authPath = keepPath;
    }

    void marshal_out(std::ostream& os) const {
        os << m_tree
           << m_treeSize << std::endl
           << m_authLeaf;

        for (const auto& r : m_authPath)
            os << r;
    }

    bool marshal_in(std::istream& is) {
        if (!m_tree.marshal_in(is) || !(is >> m_treeSize) || !(is >> m_authLeaf))
            return false;

        m_authPath.resize(m_authLeaf.size());
        for (auto& r : m_authPath) {
            if (! r.marshal_in(is)) return false;
        }

        return true;
    }

private:
    TREE m_tree;
    COUNT m_treeSize;

    std::vector<DigType> m_authLeaf;
    std::vector<PATH> m_authPath;
};

template <typename TREE, typename PATH, typename COUNT>
std::ostream& operator<< (std::ostream& os,
                          const MerkleBundle<TREE, PATH, COUNT>& a) {
    a.marshal_out(os);
    return os;
}

template <typename TREE, typename PATH, typename COUNT>
std::istream& operator>> (std::istream& is,
                          MerkleBundle<TREE, PATH, COUNT>& a) {
    a.marshal_in(is);
    return is;
}

////////////////////////////////////////////////////////////////////////////////
// typedefs
//

template <typename COUNT> using
MerkleBundle_SHA256 = MerkleBundle<MerkleTree_SHA256, eval::MerkleAuthPath_SHA256, COUNT>;

template <typename COUNT> using
MerkleBundle_SHA512 = MerkleBundle<MerkleTree_SHA512, eval::MerkleAuthPath_SHA512, COUNT>;

} // namespace snarkfront

#endif
