#ifndef _SNARKFRONT_COUNTER_HPP_
#define _SNARKFRONT_COUNTER_HPP_

#include <cstdint>
#include <vector>

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// source of unique ID numbers for constraint variables
//

template <typename T>
class Counter
{
public:
    Counter()
        : m_value(0) // note: prefix increment so zero value can be a
                     // null flag - shift operations introduce zero
                     // bits which are distinguished from dual IDs
    {}

    // return single ID
    T uniqueID() {
        return ++m_value; // prefix increment so starts at 1
    }

    T peekID() const {
        return m_value + 1; // what next value of uniqueID will be
    }

    void reset(const T& a = 0) {
        m_value = a;
    }

private:
    T m_value;
};

} // namespace snarkfront

#endif
