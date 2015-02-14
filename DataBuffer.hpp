#ifndef _SNARKFRONT_DATA_BUFFER_HPP_
#define _SNARKFRONT_DATA_BUFFER_HPP_

#include <array>
#include <climits>
#include <cstdint>
#include <istream>
#include <memory>
#include <ostream>
#include <string>
#include <vector>

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// data buffer
//

template <typename T>
class DataBuffer
{
public:
    DataBuffer() = default;

    template <typename X>
    DataBuffer(X& a) // not const reference for std::ostream
        : m_buf(a)
    {}

    template <typename X, typename U>
    DataBuffer(X& a, const U b) // PrintHex constructor takes two arguments
        : m_buf(a, b)
    {}

    T& operator* () {
        return m_buf;
    }

    const T* operator-> () const {
        return std::addressof(m_buf);
    }

    void push8(const std::uint8_t a) {
        m_buf.pushOctet(a);
    }

    void push32(const std::uint32_t a) {
        push8(a >> 3 * CHAR_BIT);
        push8((a >> 2 * CHAR_BIT) & 0xff);
        push8((a >> CHAR_BIT) & 0xff);
        push8(a & 0xff);
    }

    void push64(const std::uint64_t a) {
        push32(a >> 4 * CHAR_BIT);
        push32(a & 0xffffffff);
    }

    void pushText(const std::string& a) {
        for (const auto& c : a)
            push8(c);
    }

    void push(const std::uint8_t a) { push8(a); }
    void push(const std::uint32_t a) { push32(a); }
    void push(const std::uint64_t a) { push64(a); }
    void push(const std::string& a) { pushText(a); }
    void push(const char* a) { push(std::string(a)); }

    template <typename U, std::size_t N>
    void push(const std::array<U, N>& a) {
        for (const auto& b : a)
            push(b);
    }

    template <typename U>
    void push(const std::vector<U>& a) {
        for (const auto& b : a)
            push(b);
    }

    void push(const DataBuffer& other) {
        for (const auto& a : other->data())
            push8(a);
    }

private:
    T m_buf;
};

// (extract) read from stream into data buffer object
template <typename T>
std::istream& operator>> (std::istream& is, DataBuffer<T>& a) {
    char c;
    while (!is.eof() && !!is.get(c))
        a.push8(c);

    return is;
}

////////////////////////////////////////////////////////////////////////////////
// clear text buffer
//

class ClearText
{
public:
    ClearText() = default;
    ClearText(DataBuffer<ClearText>&);

    void clear();

    void pushOctet(const std::uint8_t);

    const std::vector<std::uint8_t>& data() const;

    bool empty() const;
    std::size_t size() const;
    std::size_t sizeBits() const;

    template <typename T>
    T getWord(std::size_t& index) const {
        T a = 0;

        for (std::size_t i = 0; i < sizeof(T); ++i) {
            a = (a << CHAR_BIT) | m_data[index++];
        }

        return a;
    }

private:
    std::vector<std::uint8_t> m_data;
};

////////////////////////////////////////////////////////////////////////////////
// data buffer stream
//

class DataBufferStream
{
public:
    DataBufferStream();
    DataBufferStream(const DataBufferStream& other) = default;

    template <typename T>
    DataBufferStream(const T& a)
        : DataBufferStream{}
    {
        m_buf.push(a);
    }

    template <typename T>
    void push(const T& a) {
        m_buf.push(a);
    }

    template <typename T, typename... Args>
    void push(const T& a, const Args... parameterPack) {
        push(a);
        push(parameterPack...);
    }

    bool empty() const;

    const std::vector<std::uint8_t>& data() const;

    DataBuffer<ClearText>& operator* ();
    DataBuffer<ClearText>* operator-> ();

    template <typename T>
    T getWord() {
        return m_buf->getWord<T>(m_index);
    }

    template <typename T, std::size_t N>
    std::array<T, N> getArray() {
        std::array<T, N> a;

        for (std::size_t i = 0; i < N; ++i)
            a[i] = getWord<T>();

        return a;
    }

private:
    DataBuffer<ClearText> m_buf;
    std::size_t m_index;
};

// (extract) read from stream into data buffer stream object
std::istream& operator>> (std::istream& is, DataBufferStream& a);

} // namespace snarkfront

#endif
