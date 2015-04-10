#include <sstream>
#include <unistd.h>
#include "Getopt.hpp"

using namespace std;

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// command line handling
//

Getopt::Getopt(int argc, char *argv[],
               const string& string_opts,
               const string& number_opts,
               const string& flag_opts)
    : m_error(false)
{
    stringstream ss;

    // string options
    for (const auto& c : string_opts) {
        m_string_opts.insert(c);
        ss << c << ":";
    }

    // number options
    for (const auto& c : number_opts) {
        m_number_opts.insert(c);
        ss << c << ":";
    }

    // boolean flags
    for (const auto& c : flag_opts) {
        m_flag_opts.insert(c);
        ss << c;
    }

    // pick out arguments unrelated to options and switches
    size_t i = 1;
    while (i < argc) {
        const size_t N = string(argv[i]).size();

        if (N >= 2 && '-' == argv[i][0]) {
            const char c = argv[i][1];

            if (m_string_opts.count(c) || m_number_opts.count(c)) {
                if (N > 2)
                    ++i; // no space between option switch and argument
                else
                    i += 2; // space between option switch and argument

            } else if (m_flag_opts.count(c)) {
                ++i;

            } else {
                m_args.push_back(argv[i]);
                ++i;
            }

        } else {
            m_args.push_back(argv[i]);
            ++i;
        }
    }

    int opt;
    while (-1 != (opt = getopt(argc, argv, ss.str().c_str()))) {
        if (m_string_opts.count(opt)) {
            m_string[opt] = optarg;

        } else if (m_number_opts.count(opt)) {
            stringstream ss(optarg);
            size_t a;
            ss >> a;
            if (!ss)
                m_error = true;
            else
                m_number[opt] = a;

        } else if (m_flag_opts.count(opt)) {
            m_flag.insert(opt);

        } else {
            m_error = true;
        }
    }
}

bool Getopt::operator! () const {
    return m_error;
}

bool Getopt::empty() const {
    return
        m_string.empty() &&
        m_number.empty() &&
        m_flag.empty();
}

bool Getopt::valid(const string& string_opts,
                   const string& number_opts,
                   const string& flag_opts)
{
    for (const auto& c : string_opts)
        if (! m_string.count(c)) return false;

    for (const auto& c : number_opts)
        if (! m_number.count(c)) return false;

    for (const auto& c : flag_opts)
        if (! m_flag.count(c)) return false;

    // all options found
    return true;
}

string Getopt::getString(const char c) {
    return m_string.count(c)
        ? m_string[c]
        : string();
}

size_t Getopt::getNumber(const char c) {
    return m_number.count(c)
        ? m_number[c]
        : -1;
}

bool Getopt::getFlag(const char c) {
    return m_flag.count(c);
}

const std::vector<std::string>& Getopt::getArgs() const {
    return m_args;
}

} // namespace snarkfront
