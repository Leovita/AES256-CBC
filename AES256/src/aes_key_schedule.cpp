#include "aes_key_schedule.h"
#include "aes_tables.h"

namespace aes {

#define RotL32(x,n) (((x) << (n)) | ((x) >> (32 - (n))))

static uint32_t subWord(uint32_t w) {
    uint32_t out = 0;
    uint32_t map = 0xFF;
    for (size_t i = 0; i < 4; i++) {
        uint32_t c = (w & map) >> (i * 8);
        out |= static_cast<uint32_t>(SBox[16 * (c >> 4) + (c & 0xF)]) << (i * 8);
    }
    return out;
}

static std::array<uint32_t, RconSz> buildRcon() {
    std::array<uint32_t, RconSz> rcon{};
    uint32_t rc = 1, rcL = 1;
    for (int i = 0; i < RconSz; i++) {
        rcon[i] = rc << 24;
        rc = rcL < 80 ? 2 * rcL : (2 * rcL) ^ 0x1B;
        rcL = rc;
    }
    return rcon;
}

std::array<uint32_t, 60> expandKey(const std::array<uint8_t, 32>& key) {
    const auto Rcon = buildRcon();
    std::array<uint32_t, 60> expKey{};

    for (int i = 0; i < Nk; i++) {
        expKey[i] = (static_cast<uint32_t>(key[4 * i])     << 24)
                  | (static_cast<uint32_t>(key[4 * i + 1]) << 16)
                  | (static_cast<uint32_t>(key[4 * i + 2]) <<  8)
                  |  static_cast<uint32_t>(key[4 * i + 3]);
    }

    for (int i = Nk; i < Nb * (Nr + 1); i++) {
        uint32_t tmp = expKey[i - 1];
        if (i % Nk == 0)
            tmp = subWord(RotL32(tmp, 8)) ^ Rcon[i / Nk - 1];
        else if (Nk > 6 && i % Nk == 4)
            tmp = subWord(tmp);
        expKey[i] = expKey[i - Nk] ^ tmp;
    }
    return expKey;
}

} // namespace aes
