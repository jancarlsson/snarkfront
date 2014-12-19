#include <cctype>
#include "DataBuffer.hpp"

using namespace std;

namespace snarkfront {

////////////////////////////////////////////////////////////////////////////////
// clear text buffer
//

ClearText::ClearText(DataBuffer<ClearText>& outer)
    : m_data(outer->data())
{}

void ClearText::clear() {
    m_data.clear();
}

void ClearText::pushOctet(const uint8_t a) {
    m_data.push_back(a);
}

const vector<uint8_t>& ClearText::data() const {
    return m_data;
}

bool ClearText::empty() const {
    return m_data.empty();
}

size_t ClearText::size() const {
    return data().size();
}

size_t ClearText::sizeBits() const {
    return size() * CHAR_BIT;
}

////////////////////////////////////////////////////////////////////////////////
// data buffer stream
//

DataBufferStream::DataBufferStream()
    : m_index(0)
{}

bool DataBufferStream::empty() const {
    return m_index == m_buf->size();
}

const vector<uint8_t>& DataBufferStream::data() const {
    return m_buf->data();
}

DataBuffer<ClearText>& DataBufferStream::operator* () {
    return m_buf;
}

DataBuffer<ClearText>* DataBufferStream::operator-> () {
    return addressof(m_buf);
}

istream& operator>> (istream& is, DataBufferStream& a) {
    return is >> *a;
}

} // namespace snarkfront
