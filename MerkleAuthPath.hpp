#ifndef _SNARKFRONT_MERKLE_AUTH_PATH_HPP_
#define _SNARKFRONT_MERKLE_AUTH_PATH_HPP_

#include <cstdint>
#include <iostream>
#include <istream>
#include <ostream>
#include <vector>

#include <cryptl/SHA_256.hpp>
#include <cryptl/SHA_512.hpp>

#include <snarkfront/DSL_base.hpp>
#include <snarkfront/DSL_bless.hpp>
#include <snarkfront/DSL_utility.hpp>
#include <snarkfront/PowersOf2.hpp>

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

    MerkleAuthPath()
        : m_depth(0)
    {}

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

    // (eval) return initial path from leaf of specified depth
    MerkleAuthPath leafPath(const std::size_t leaf_depth) const {
        MerkleAuthPath subPath(leaf_depth);
        for (std::size_t i = 0; i < leaf_depth; ++i) {
            subPath.m_rootPath[i] = m_rootPath[i];
            subPath.m_siblings[i] = m_siblings[i];
            subPath.m_childPath[i] = m_childBits[i];
        }
        return subPath;
    }

    // (eval) return subsequent path to root of specified depth
    MerkleAuthPath rootPath(const std::size_t root_depth) const {
        MerkleAuthPath subPath(root_depth);
        const std::size_t leaf_depth = m_depth - root_depth;
        for (std::size_t i = 0; i < root_depth; ++i) {
            subPath.m_rootPath[i] = m_rootPath[i + leaf_depth];
            subPath.m_siblings[i] = m_siblings[i + leaf_depth];
            subPath.m_childPath[i] = m_childBits[i + leaf_depth];
        }
        return subPath;
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

    void marshal_out(std::ostream& os) const {
        os << m_depth << ' '
           << m_rootPath
           << m_siblings;

        const char *ptr = reinterpret_cast<const char*>(m_childBits.data());

        if (snarklib::is_big_endian<int>()) {
            for (std::size_t i = 0; i < m_childBits.size(); ++i) {
                for (int j = sizeof(int) - 1; j >= 0; --j) {
                    os.put(ptr[i * sizeof(int) + j]);
                }
            }

        } else {
            os.write(ptr, m_childBits.size() * sizeof(int));
        }
    }

    bool marshal_in(std::istream& is) {
        m_depth = 0; // use as valid flag

        // depth
        std::size_t len = 0;
        if (!(is >> len) || (0 == len)) return false;

        // consume space
        char c;
        if (!is.get(c) || (' ' != c)) return false;

        m_rootPath.resize(len);
        if (! (is >> m_rootPath)) return false;

        m_siblings.resize(len);
        if (! (is >> m_siblings)) return false;

        m_childBits.resize(len);
        char *ptr = reinterpret_cast<char*>(m_childBits.data());

        if (snarklib::is_big_endian<int>()) {
            for (std::size_t i = 0; i < m_childBits.size(); ++i) {
                for (int j = sizeof(int) - 1; j >= 0; --j) {
                    if (! is.get(ptr[i * sizeof(int) + j])) return false;
                }
            }
        } else {
            if (! is.read(ptr, m_childBits.size() * sizeof(int))) return false;
        }

        m_depth = len;

        return true;
    }

    void clear() {
        m_depth = 0;
        m_rootPath.clear();
        m_siblings.clear();
        m_childBits.clear();
    }

    bool empty() const {
        return
            0 == m_depth ||
            m_rootPath.empty() ||
            m_siblings.empty() ||
            m_childBits.empty();
    }

private:
    // note: not called by proof generation
    static DigType zero() {
        return {0};
    }

    std::size_t m_depth;

    // indices start from 0 at the leaves increasing up to the root
    std::vector<DigType> m_rootPath, m_siblings;

    // next available leaf element
    std::vector<BIT> m_childBits;
};

template <typename HASH, typename BIT>
std::ostream& operator<< (std::ostream& os, const MerkleAuthPath<HASH, BIT>& a) {
    a.marshal_out(os);
    return os;
}

template <typename HASH, typename BIT>
std::istream& operator>> (std::istream& is, MerkleAuthPath<HASH, BIT>& a) {
    if (! a.marshal_in(is)) a.clear();
    return is;
}

////////////////////////////////////////////////////////////////////////////////
// typedefs
//

namespace zk {
    template <typename FR> using MerkleAuthPath_SHA256
    = MerkleAuthPath<SHA256<FR>, bool_x<FR>>;

    template <typename FR> using MerkleAuthPath_SHA512
    = MerkleAuthPath<SHA512<FR>, bool_x<FR>>;
} // namespace zk

namespace eval {
    typedef MerkleAuthPath<cryptl::SHA256, int> MerkleAuthPath_SHA256;
    typedef MerkleAuthPath<cryptl::SHA512, int> MerkleAuthPath_SHA512;
} // namespace eval

} // namespace snarkfront

#endif
