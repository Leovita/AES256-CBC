#include "aes_padding.h"
#include <algorithm>

namespace aes {

static constexpr size_t blockSize = 16;

std::vector<uint8_t> pad(const uint8_t* data, size_t sz) {
    size_t padVal = blockSize - (sz % blockSize);
    std::vector<uint8_t> out(sz + padVal, static_cast<uint8_t>(padVal));
    std::copy(data, data + sz, out.begin());
    return out;
}

std::vector<uint8_t> unpad(const std::vector<uint8_t>& data, size_t origSz) {
    std::vector<uint8_t> out(origSz);
    std::copy(data.begin(), data.begin() + origSz, out.begin());
    return out;
}

} // namespace aes
