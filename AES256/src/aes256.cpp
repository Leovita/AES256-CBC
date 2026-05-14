#include "aes256.h"
#include "aes_cipher.h"
#include "aes_key_schedule.h"
#include "aes_padding.h"

#include <windows.h>
#include <stdexcept>
#include <random>
#include <algorithm>
#include <sstream>
#include <iomanip>

static std::array<uint8_t, 32> toKeyArray(const std::vector<uint8_t>& key) {
    std::array<uint8_t, 32> arr{};
    size_t n = key.size() < 32 ? key.size() : 32;
    std::copy(key.begin(), key.begin() + n, arr.begin());
    return arr;
}

static std::array<uint8_t, 16> loadBlock(const uint8_t* src, size_t available, uint8_t padVal) {
    std::array<uint8_t, 16> block;
    block.fill(padVal);
    size_t n = available < 16 ? available : 16;
    std::copy(src, src + n, block.begin());
    return block;
}

AES256::AES256(AppSettings settings)
    : storage_(settings.keyFilePath, settings.dpapiScope) {
    storage_.loadOrCreateKey();
}

void AES256::keyGen() {
    std::vector<uint8_t> key(32);
    std::random_device rnd;
    std::generate(key.begin(), key.end(), [&] { return static_cast<uint8_t>(rnd()); });

    if (!storage_.protectKey(key)) {
        SecureZeroMemory(key.data(), key.size());
        throw std::runtime_error("AES256: impossibile proteggere la nuova chiave");
    }
    SecureZeroMemory(key.data(), key.size());
}

std::string AES256::getKey() {
    auto key = storage_.unprotectKey();
    std::string hex = toHex(key);
    SecureZeroMemory(key.data(), key.size());
    return hex;
}

std::vector<uint8_t> AES256::encryptRaw(const uint8_t* data, size_t sz) {
    if (!storage_.hasStoredKey())
        throw std::runtime_error("AES256: nessuna chiave salvata. Chiamare keyGen() prima.");

    auto key = storage_.unprotectKey();
    auto expKey = aes::expandKey(toKeyArray(key));
    SecureZeroMemory(key.data(), key.size());

	// genera iv random, non è necessario proteggerlo, ma deve essere unico per ogni cifratura
    std::array<uint8_t, 16> iv;
    std::random_device rd;
    std::uniform_int_distribution<unsigned int> dist(0, 255);
    for (auto& b : iv) b = static_cast<uint8_t>(dist(rd));

    size_t padVal    = 16 - (sz % 16);
    size_t numBlocks = (sz + padVal) / 16;

    // out: [IV 16B][ciphertext blocks]
    std::vector<uint8_t> out(16 + numBlocks * 16);
    std::copy(iv.begin(), iv.end(), out.begin());

    std::array<uint8_t, 16> prev = iv;
    for (size_t i = 0; i < numBlocks; i++) {
        size_t offset    = i * 16;
        size_t available = (offset < sz) ? sz - offset : 0;
        auto block = loadBlock(data + offset, available, static_cast<uint8_t>(padVal));
        for (int j = 0; j < 16; j++) block[j] ^= prev[j];  // CBC XOR
        aes::encipher(block, expKey);
        std::copy(block.begin(), block.end(), out.begin() + 16 + offset);
        prev = block;
    }
    return out;
}

std::vector<uint8_t> AES256::decryptRaw(const std::vector<uint8_t>& in) {
    // Formato atteso: [IV 16B][almeno un blocco dati 16B]
    if (in.size() < 32 || in.size() % 16 != 0)
        throw std::length_error("AES256: dimensione input non valida (minimo 32 byte, multiplo di 16)");

    auto key = storage_.unprotectKey();
    auto expKey = aes::expandKey(toKeyArray(key));
    SecureZeroMemory(key.data(), key.size());

    // Estrai IV (primi 16 byte)
    std::array<uint8_t, 16> prev;
    std::copy(in.begin(), in.begin() + 16, prev.begin());

    size_t numBlocks = (in.size() - 16) / 16;
    std::vector<uint8_t> out(numBlocks * 16);
    for (size_t i = 0; i < numBlocks; i++) {
        size_t offset = 16 + i * 16;
        std::array<uint8_t, 16> block;
        std::copy(in.begin() + offset, in.begin() + offset + 16, block.begin());
        std::array<uint8_t, 16> enc = block;  // salva cipherblock per prossimo XOR
        aes::decipher(block, expKey);
        for (int j = 0; j < 16; j++) block[j] ^= prev[j];  // CBC XOR
        std::copy(block.begin(), block.end(), out.begin() + i * 16);
        prev = enc;
    }

    uint8_t padLen = out.back();
    if (padLen == 0 || padLen > 16)
        throw std::runtime_error("AES256: padding non valido nel testo cifrato");
    out.resize(out.size() - padLen);

    return out;
}

std::string AES256::encrypt(const std::string& plaintext) {
    auto cipherBytes = encryptRaw(
        reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());
    return toHex(cipherBytes);
}

std::string AES256::decrypt(const std::string& hexCiphertext) {
    auto cipherBytes = fromHex(hexCiphertext);
    auto plainBytes  = decryptRaw(cipherBytes);
    return std::string(plainBytes.begin(), plainBytes.end());
}

// hex -> string, string -> hex helpers impl.
std::string AES256::toHex(const std::vector<uint8_t>& v) {
    std::ostringstream oss;
    for (uint8_t b : v)
        oss << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(b);
    return oss.str();
}

std::vector<uint8_t> AES256::fromHex(const std::string& hex) {
    if (hex.size() % 2 != 0)
        throw std::invalid_argument("AES256: stringa hex di lunghezza dispari");

    std::vector<uint8_t> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); i++) {
        unsigned int byte;
        std::istringstream ss(hex.substr(i * 2, 2));
        if (!(ss >> std::hex >> byte))
            throw std::invalid_argument("AES256: carattere hex non valido");
        out[i] = static_cast<uint8_t>(byte);
    }
    return out;
}
