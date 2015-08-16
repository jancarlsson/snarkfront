#ifndef _SNARKFRONT_NS_SNARKFRONT_HPP_
#define _SNARKFRONT_NS_SNARKFRONT_HPP_

#include <istream>

#include <snarkfront/DSL_base.hpp>
#include <snarkfront/DSL_bless.hpp>

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// namespace as type for algorithm template parameter
//

class NS
{
public:
    // bless
    template <typename T>
    static bool bless(T& x, std::istream& is) {
        return snarkfront::bless(x, is);
    }

    // array comparison (imperative)
    template <typename FR, std::size_t N>
    static AST_X<Alg_bool<FR>> notequal(const std::array<uint8_x<FR>, N>& x,
                                        const std::array<uint8_x<FR>, N>& y) {
        return x != y;
    }

    template <typename FR, std::size_t N>
    static AST_X<Alg_bool<FR>> notequal(const std::array<uint8_x<FR>, N>& x,
                                        const std::array<c_uint8<FR>, N>& y) {
        return x != y;
    }

    template <typename FR, std::size_t N>
    static AST_X<Alg_bool<FR>> notequal(const std::array<c_uint8<FR>, N>& x,
                                        const std::array<uint8_x<FR>, N>& y) {
        return x != y;
    }

    template <typename FR, std::size_t N>
    static AST_X<Alg_bool<FR>> notequal(const std::array<uint32_x<FR>, N>& x,
                                        const std::array<uint32_x<FR>, N>& y) {
        return x != y;
    }

    template <typename FR, std::size_t N>
    static AST_X<Alg_bool<FR>> notequal(const std::array<uint32_x<FR>, N>& x,
                                        const std::array<c_uint32<FR>, N>& y) {
        return x != y;
    }

    template <typename FR, std::size_t N>
    static AST_X<Alg_bool<FR>> notequal(const std::array<c_uint32<FR>, N>& x,
                                        const std::array<uint32_x<FR>, N>& y) {
        return x != y;
    }

    template <typename FR, std::size_t N>
    static AST_X<Alg_bool<FR>> notequal(const std::array<uint64_x<FR>, N>& x,
                                        const std::array<uint64_x<FR>, N>& y) {
        return x != y;
    }

    template <typename FR, std::size_t N>
    static AST_X<Alg_bool<FR>> notequal(const std::array<uint64_x<FR>, N>& x,
                                        const std::array<c_uint64<FR>, N>& y) {
        return x != y;
    }

    template <typename FR, std::size_t N>
    static AST_X<Alg_bool<FR>> notequal(const std::array<c_uint64<FR>, N>& x,
                                        const std::array<uint64_x<FR>, N>& y) {
        return x != y;
    }
};

} // namespace snarkfront

#endif
