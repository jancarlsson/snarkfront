#ifndef _SNARKFRONT_LAZY_HPP_
#define _SNARKFRONT_LAZY_HPP_

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// laziness box, primary purpose is to defer creation of variables
//

template <typename T, typename A>
class Lazy
{
public:
    // not lazy, object already created
    Lazy(const T& a)
        : m_obj(a),
          m_init(true)
    {}

    // lazy, defer object creation until referenced
    Lazy(const A& a)
        : m_arg(a),
          m_init(false)
    {}

    // dereferencing is unboxing
    const T& operator* () {
        if (! m_init) {
            // unboxing
            m_init = true;
            m_obj = T(m_arg);
        }

        return m_obj;
    }

private:
    T m_obj;
    A m_arg;
    bool m_init;
};

} // namespace snarkfront

#endif
