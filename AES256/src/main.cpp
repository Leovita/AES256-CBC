#include "aes256.h"
#include <iostream>
#include <string>
#include <cassert>

int main() {
    AES256 aes;

    std::string msg = "dasd";
    std::cout << "\nInput:      " << msg << "\n";

    std::string enc = aes.encrypt(msg);
    std::cout << "Encrypted:  " << enc << "\n";

    std::string dec = aes.decrypt(enc);
    std::cout << "Decrypted:  " << dec << "\n";

    assert(dec == msg);

    return 0;
}
