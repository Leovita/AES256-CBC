#ifndef AES_PADDING_H
#define AES_PADDING_H

#include <cstdint>
#include <cstddef>
#include <vector>

namespace aes {

// PKCS#7-style: pad value equals the number of bytes added
std::vector<uint8_t> pad(const uint8_t* data, size_t sz);
std::vector<uint8_t> unpad(const std::vector<uint8_t>& data, size_t origSz);

} // namespace aes

#endif // AES_PADDING_H
