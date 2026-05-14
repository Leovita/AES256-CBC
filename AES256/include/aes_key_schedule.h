#ifndef AES_KEY_SCHEDULE_H
#define AES_KEY_SCHEDULE_H

#include <cstdint>
#include <array>

namespace aes {

static constexpr int Nr     = 14;
static constexpr int Nk     = 8;
static constexpr int Nb     = 4;
static constexpr int RconSz = 7;

// Expands a 256-bit key into 60 round-key words
std::array<uint32_t, 60> expandKey(const std::array<uint8_t, 32>& key);

} // namespace aes

#endif // AES_KEY_SCHEDULE_H
