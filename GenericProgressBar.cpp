#include <cassert>
#include <iostream>
#include "GenericProgressBar.hpp"

using namespace std;

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// generic progress bar
//

GenericProgressBar::GenericProgressBar(ostream& os)
    : m_os(os),
      m_width(0)
{}

GenericProgressBar::GenericProgressBar(ostream& os,
                                       const size_t width)
    : m_os(os),
      m_width(width)
{
#ifdef USE_ASSERT
    assert(2 <= width);
#endif
}

void GenericProgressBar::majorSteps(const size_t numberSteps) {
    m_major = numberSteps;
}

void GenericProgressBar::major(const bool newLine) {
    if (newLine) m_os << endl;

    if (0 == m_width) {
        m_os << ".";

    } else {
        m_os << "(" << m_major << ") ";
    }

    --m_major;
    m_minor = 0;
}

size_t GenericProgressBar::minorSteps() {
    return m_width - m_minor;
}

void GenericProgressBar::minor() {
    if (0 != m_width) {
        m_os << ".";
        ++m_minor;
    }
}

} // namespace snarkfront
