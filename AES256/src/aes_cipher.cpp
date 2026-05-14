#include "aes_cipher.h"
#include "aes_state.h"
#include "aes_key_schedule.h"

namespace aes {

static void addRoundKey(std::array<uint8_t, 16>& state, const std::array<uint32_t, 60>& expKey, int round) {
    for (int i = 0; i < Nb; i++) {
        uint32_t w = expKey[round * Nb + i];
        state[i * 4 + 0] ^= (w >> 24) & 0xFF;
        state[i * 4 + 1] ^= (w >> 16) & 0xFF;
        state[i * 4 + 2] ^= (w >>  8) & 0xFF;
        state[i * 4 + 3] ^= (w      ) & 0xFF;
    }
}

void encipher(std::array<uint8_t, 16>& state, const std::array<uint32_t, 60>& expKey) {
    addRoundKey(state, expKey, 0);
    for (int i = 1; i < Nr; i++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, expKey, i);
    }
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, expKey, Nr);
}

void decipher(std::array<uint8_t, 16>& state, const std::array<uint32_t, 60>& expKey) {
    addRoundKey(state, expKey, Nr);
    for (int i = Nr - 1; i >= 1; i--) {
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, expKey, i);
        invMixColumns(state);
    }
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, expKey, 0);
}

} // namespace aes
