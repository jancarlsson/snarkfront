#ifndef _SNARKFRONT_MERKLE_FOREST_HPP_
#define _SNARKFRONT_MERKLE_FOREST_HPP_

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <istream>
#include <memory>
#include <ostream>
#include <vector>

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// forest of Merkle trees
//

template <template <typename> class BUNDLE, typename COUNT>
class MerkleForest
{
public:
    typedef typename BUNDLE<COUNT>::DigType DigType;
    typedef typename BUNDLE<COUNT>::AuthPath AuthPath;

    MerkleForest()
        : m_forest(1) // start with single tree
    {}

    MerkleForest(const std::size_t depth)
        : m_forest(1, BUNDLE<COUNT>(depth)) // start with single tree
    {}

    // number of trees in the forest
    std::size_t treeCount() const {
        return m_forest.size();
    }

    // return vector of Merkle trees
    const std::vector<BUNDLE<COUNT>>& operator* () const {
        return m_forest;
    }

    // maximum tree size
    std::size_t maxTreeSize() const {
        std::size_t a = 0;

        for (const auto& r : m_forest)
            a = std::max(a, r.treeSize());

        return a;
    }

    // minimum tree size
    std::size_t minTreeSize() const {
        std::size_t a = -1;

        for (const auto& r : m_forest)
            a = std::min(a, r.treeSize());

        return a;
    }

    // remove the small trees
    void treeGC(const std::size_t keepSize) {
        std::vector<BUNDLE<COUNT>> keepForest;

        for (const auto& r : m_forest) {
            if (r.treeSize() >= keepSize)
                keepForest.emplace_back(r);
        }

        m_forest = keepForest;
    }

    // grow forest by one new tree
    // apply lambda to new copy of bundle with matching Merkle tree root digest
    // (collision resistance implies multiple matching trees do not occur)
    bool matchRoot(const DigType& rt,
                   std::function<void (BUNDLE<COUNT>&)> func)
    {
        for (const auto& r : m_forest) {
            if (r.rootHash() == rt) {
                m_forest.emplace_back(r);
                func(m_forest.back());
                return true; // found match
            }
        }

        return false; // no match found
    }

    // find trees with matching leaves in the forest
    // apply lambda to bundles with matching authentication path leaf digests
    // (several trees may have the same leaf commitment)
    void matchLeaf(const DigType& cm,
                   std::function<void (const BUNDLE<COUNT>&, std::size_t)> func)
    {
        for (const auto& r: m_forest) {
            for (std::size_t i = 0; i < r.authLeaf().size(); ++i)
                if (cm == r.authLeaf()[i])
                    func(r, i);
        }
    }

    void marshal_out(std::ostream& os) const {
        os << treeCount() << std::endl;

        for (const auto& r : m_forest)
            os << r;
    }

    bool marshal_in(std::istream& is) {
        std::size_t len = -1;
        if (!(is >> len) || (-1 == len)) return false;

        m_forest.resize(len);
        for (auto& r : m_forest) {
            if (! r.marshal_in(is)) return false;
        }

        return true;
    }

private:
    // forest of Merkle trees with associated authentication path histories
    std::vector<BUNDLE<COUNT>> m_forest;
};

} // namespace snarkfront

#endif
