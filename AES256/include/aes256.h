#pragma once

#include "appSettings.h"
#include "secureStorage.h"

#include <cstdint>
#include <vector>
#include <array>
#include <cstddef>
#include <string>

class AES256 {
public:
    explicit AES256(AppSettings settings = AppSettings::load());

    // genera una nuova chiave, la protegge con DPAPI e la salva su file
    void keyGen();

    // restituisce la chiave corrente come stringa hex
    std::string getKey();

    // plaintext string -> hex ciphertext string
    std::string encrypt(const std::string& plaintext);

    // hex ciphertext string -> plaintext string
    std::string decrypt(const std::string& hexCiphertext);

private:
    SecureKeyStorage storage_;

    std::vector<uint8_t> encryptRaw(const uint8_t* data, size_t sz);
    std::vector<uint8_t> decryptRaw(const std::vector<uint8_t>& in);

	// helpers hex -> string, string -> hex per rappresentare i byte cifrati 
    static std::string          toHex(const std::vector<uint8_t>& v);
    static std::vector<uint8_t> fromHex(const std::string& hex);
};

// --- template headers needed by secureStorage / cipher internals ---
#include "aes_cipher.h"
#include "aes_key_schedule.h"
#include "aes_padding.h"
