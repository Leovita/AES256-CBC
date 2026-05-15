#include "aes256.h"
#include "../tests/kat_gcm.h"
#include <iostream>
#include <string>
#include <cassert>

int main() {
    if (int failures = runKatTests(); failures != 0) {
        std::cerr << "KAT falliti: " << failures << "\n";
        return 1;
    }

    AES256 aes;

    std::string msg = "dasd";
    std::cout << "\nInput:      " << msg << "\n";

    std::string enc = aes.encrypt(msg);
    std::cout << "Encrypted:  " << enc << "\n";

    aes.rotateKey();

    std::string dec = aes.decrypt(enc);
    std::cout << "Decrypted:  " << dec << "\n";

    assert(dec == msg);

    return 0;
}
