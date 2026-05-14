#include "galois.h"

namespace aes {

uint8_t galoisMult(uint8_t a, uint8_t b) {
    assert(b == 2 || b == 3);
    if (b == 2)
        return ((a << 1) ^ ((a & 0x80) ? 0x1B : 0x00));
    return galoisMult(a, 2) ^ a;
}

uint8_t galoisMultL(uint8_t a, uint8_t b) {
    uint8_t p = 0, c, i;
    for (i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        c = a & 0x80;
        a <<= 1;
        if (c) a ^= 0x1B;
        b >>= 1;
    }
    return p;
}

} // namespace aes
