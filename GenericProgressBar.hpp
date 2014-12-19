#ifndef _SNARKFRONT_GENERIC_PROGRESS_BAR_HPP_
#define _SNARKFRONT_GENERIC_PROGRESS_BAR_HPP_

#include <cstdint>
#include <ostream>
#include <ProgressCallback.hpp> // snarklib

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// generic progress bar
//

class GenericProgressBar : public snarklib::ProgressCallback
{
public:
    // major callbacks only (ignore any minor callbacks)
    GenericProgressBar(std::ostream& os);

    // major and minor callbacks
    GenericProgressBar(std::ostream& os, const std::size_t width);

    void majorSteps(const std::size_t numberSteps);
    void major(const bool newLine);

    std::size_t minorSteps();
    void minor();

private:
    std::ostream& m_os;
    const std::size_t m_width;
    std::size_t m_major, m_minor;
};

} // namespace snarkfront

#endif
