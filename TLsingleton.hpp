#ifndef _SNARKFRONT_TL_SINGLETON_HPP_
#define _SNARKFRONT_TL_SINGLETON_HPP_

#include <memory>

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// templated thread local singleton
// (each thread has its own singleton object)
//

template <typename T>
class TL
{
public:
    ~TL() = default;

    static TL<T>& singleton() {
        thread_local static TL<T> obj;
        return obj;
    }

    T& operator* () {
        return m_value;
    }

    const T& operator* () const {
        return m_value;
    }

    T* operator-> () {
        return std::addressof(m_value);
    }

    const T* operator-> () const {
        return std::addressof(m_value);
    }

private:    
    TL() = default;

    T m_value;
};

} // namespace snarkfront

#endif
