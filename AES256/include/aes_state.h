#ifndef AES_STATE_H
#define AES_STATE_H

#include <cstdint>
#include <array>

namespace aes {

void subBytes(std::array<uint8_t, 16>& state);
void shiftRows(std::array<uint8_t, 16>& state);
void mixColumns(std::array<uint8_t, 16>& state);

void invSubBytes(std::array<uint8_t, 16>& state);
void invShiftRows(std::array<uint8_t, 16>& state);
void invMixColumns(std::array<uint8_t, 16>& state);

} // namespace aes

#endif // AES_STATE_H
