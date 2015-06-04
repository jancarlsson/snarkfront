#include <memory>

#include <snarklib/Util.hpp>

#include "snarkfront/Serialize.hpp"

using namespace snarklib;
using namespace std;

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// uint32_t
//

void writeStream(ostream& os, const uint32_t& a) {
    const char *ptr = reinterpret_cast<const char*>(addressof(a));

    if (is_big_endian<int>()) {
        for (int i = sizeof(uint32_t) - 1; i >= 0; --i)
            os.put(ptr[i]);

    } else {
        os.write(ptr, sizeof(uint32_t));
    }
}

bool readStream(istream& is, uint32_t& a) {
    char *ptr = reinterpret_cast<char*>(addressof(a));

    if (is_big_endian<int>()) {
        for (int i = sizeof(uint32_t) - 1; i >= 0; --i)
            if (! is.get(ptr[i])) return false;

    } else {
        if (! is.read(ptr, sizeof(uint32_t))) return false;
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////
// uint64_t
//

void writeStream(ostream& os, const uint64_t& a) {
    const char *ptr = reinterpret_cast<const char*>(addressof(a));

    if (is_big_endian<int>()) {
        for (int i = sizeof(uint64_t) - 1; i >= 0; --i)
            os.put(ptr[i]);

    } else {
        os.write(ptr, sizeof(uint64_t));
    }
}

bool readStream(istream& is, uint64_t& a) {
    char *ptr = reinterpret_cast<char*>(addressof(a));

    if (is_big_endian<int>()) {
        for (int i = sizeof(uint64_t) - 1; i >= 0; --i)
            if (! is.get(ptr[i])) return false;

    } else {
        if (! is.read(ptr, sizeof(uint64_t))) return false;
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////
// string
//

void writeStream(ostream& os, const string& a) {
    // number of octets
    // a single space
    // string text
    os << a.size() << ' ' << a;
}

bool readStream(istream& is, string& a) {
    // number of octets
    size_t len = -1;
    if (!(is >> len) || (-1 == len)) return false;

    // single space
    char c;
    if (!is.get(c) || (' ' != c)) return false;

    // string text
    char buffer[len];
    if (!is.read(buffer, len)) return false;
    a = string(buffer, len);

    // success
    return true;
}

////////////////////////////////////////////////////////////////////////////////
// byte vector
//

void writeStream(ostream& os, const vector<uint8_t>& a) {
    // number of elements followed by a single space
    os << a.size() << ' ';

    // vector elements
    os.write(reinterpret_cast<const char*>(a.data()), a.size());
}

bool readStream(istream& is, vector<uint8_t>& a) {
    // number of elements
    size_t len = -1;
    if (!(is >> len) || (-1 == len)) return false;

    // single space
    char c;
    if (!is.get(c) || (' ' != c)) return false;

    // vector elements
    a.resize(len);
    if (!is.read(reinterpret_cast<char*>(a.data()), len)) return false;

    // success
    return true;
}

////////////////////////////////////////////////////////////////////////////////
// read and write types: vector<uint32_t>     (commitment vector)
//

void writeStream(ostream& os, const vector<uint32_t>& a) {
    // number of elements followed by a single space
    os << a.size() << ' ';

    // vector elements
    for (const auto& b : a)
        writeStream(os, b);
}

bool readStream(istream& is, vector<uint32_t>& a) {
    // number of elements
    size_t len = -1;
    if (!(is >> len) || (-1 == len)) return false;

    // single space
    char c;
    if (!is.get(c) || (' ' != c)) return false;

    // vector elements
    a.resize(len);
    for (std::size_t i = 0; i < len; ++i)
        if (! readStream(is, a[i])) return false;

    // success
    return true;
}

} // namespace snarkfront
