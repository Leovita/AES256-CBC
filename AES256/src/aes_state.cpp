#include "aes_state.h"
#include "aes_tables.h"
#include "galois.h"

namespace aes {

static constexpr size_t stSz = 16;

void subBytes(std::array<uint8_t, 16>& state) {
    for (size_t i = 0; i < stSz; i++)
        state[i] = SBox[16 * (state[i] >> 4) + (state[i] & 0xF)];
}

void shiftRows(std::array<uint8_t, 16>& state) {
    std::array<uint8_t, 4> fetch;
    for (int i = 1; i < 4; i++) {
        for (int j = 0; j < i; j++) {
            for (size_t k = 0; k < 4; k++)
                fetch[k] = state[i + 4 * k];
            for (size_t k = 0; k < 4; k++)
                state[((i + 4 * k) - 4 + stSz) % stSz] = fetch[k];
        }
    }
}

void mixColumns(std::array<uint8_t, 16>& state) {
    std::array<uint8_t, 4> f;
    for (size_t i = 0; i < 4; i++) {
        size_t idx = i * 4;
        for (size_t j = 0; j < 4; j++) f[j] = state[idx + j];
        state[idx]     = galoisMult(f[0], 2) ^ galoisMult(f[1], 3) ^ f[2]              ^ f[3];
        state[idx + 1] = f[0]                ^ galoisMult(f[1], 2) ^ galoisMult(f[2], 3) ^ f[3];
        state[idx + 2] = f[0]                ^ f[1]                ^ galoisMult(f[2], 2) ^ galoisMult(f[3], 3);
        state[idx + 3] = galoisMult(f[0], 3) ^ f[1]                ^ f[2]              ^ galoisMult(f[3], 2);
    }
}

void invSubBytes(std::array<uint8_t, 16>& state) {
    for (size_t i = 0; i < stSz; i++)
        state[i] = RSBox[16 * (state[i] >> 4) + (state[i] & 0xF)];
}

void invShiftRows(std::array<uint8_t, 16>& state) {
    std::array<uint8_t, 4> fetch;
    for (int i = 1; i < 4; i++) {
        for (int j = 0; j < i; j++) {
            for (size_t k = 0; k < 4; k++)
                fetch[k] = state[i + 4 * k];
            for (size_t k = 0; k < 4; k++)
                state[(i + 4 * k + 4) % stSz] = fetch[k];
        }
    }
}

void invMixColumns(std::array<uint8_t, 16>& state) {
    std::array<uint8_t, 4> f;
    for (size_t i = 0; i < 4; i++) {
        size_t idx = i * 4;
        for (size_t j = 0; j < 4; j++) f[j] = state[idx + j];
        state[idx]     = galoisMultL(f[0], 0x0E) ^ galoisMultL(f[1], 0x0B) ^ galoisMultL(f[2], 0x0D) ^ galoisMultL(f[3], 0x09);
        state[idx + 1] = galoisMultL(f[0], 0x09) ^ galoisMultL(f[1], 0x0E) ^ galoisMultL(f[2], 0x0B) ^ galoisMultL(f[3], 0x0D);
        state[idx + 2] = galoisMultL(f[0], 0x0D) ^ galoisMultL(f[1], 0x09) ^ galoisMultL(f[2], 0x0E) ^ galoisMultL(f[3], 0x0B);
        state[idx + 3] = galoisMultL(f[0], 0x0B) ^ galoisMultL(f[1], 0x0D) ^ galoisMultL(f[2], 0x09) ^ galoisMultL(f[3], 0x0E);
    }
}

} // namespace aes
