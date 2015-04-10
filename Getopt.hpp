#ifndef _SNARKFRONT_GETOPT_HPP_
#define _SNARKFRONT_GETOPT_HPP_

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// command line handling
//

class Getopt
{
public:
    Getopt(int argc, char *argv[],
           const std::string& string_opts,
           const std::string& number_opts,
           const std::string& flag_opts);

    bool operator! () const;
    bool empty() const;

    bool valid(const std::string& string_opts,
               const std::string& number_opts,
               const std::string& flag_opts);

    std::string getString(const char c);
    std::size_t getNumber(const char c);
    bool getFlag(const char c);

    const std::vector<std::string>& getArgs() const;

private:
    std::map<int, std::string> m_string;
    std::map<int, std::size_t> m_number;
    std::set<int> m_flag, m_string_opts, m_number_opts, m_flag_opts;
    std::vector<std::string> m_args;

    bool m_error;
};

} // namespace snarkfront

#endif
