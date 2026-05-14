#ifndef AES_CIPHER_H
#define AES_CIPHER_H

#include <cstdint>
#include <array>

namespace aes {

void encipher(std::array<uint8_t, 16>& state, const std::array<uint32_t, 60>& expKey);
void decipher(std::array<uint8_t, 16>& state, const std::array<uint32_t, 60>& expKey);

}

#endif // AES_CIPHER_H
