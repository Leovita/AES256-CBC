#ifndef AES_GALOIS_H
#define AES_GALOIS_H

#include <cstdint>
#include <cassert>

namespace aes {

// Fast GF(2^8) multiply — only handles b in {2, 3}
uint8_t galoisMult(uint8_t a, uint8_t b);

// General GF(2^8) multiply with 0x1B reduction (used for b > 3)
uint8_t galoisMultL(uint8_t a, uint8_t b);

} // namespace aes

#endif // AES_GALOIS_H
