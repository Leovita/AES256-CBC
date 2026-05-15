#include "aes256.h"

#include <windows.h>
#include <bcrypt.h>
#include <stdexcept>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "bcrypt.lib")

// 0xC000A002 = STATUS_AUTH_TAG_MISMATCH (evita conflitti con ntstatus.h)
#ifndef STATUS_AUTH_TAG_MISMATCH
#define STATUS_AUTH_TAG_MISMATCH ((NTSTATUS)0xC000A002L)
#endif

static std::array<uint8_t, 32> toKeyArray(const std::vector<uint8_t>& key) {
    std::array<uint8_t, 32> arr{};
    size_t n = key.size() < 32 ? key.size() : 32;
    std::copy(key.begin(), key.begin() + n, arr.begin());
    return arr;
}

// C2: unico punto di generazione byte casuali crittografici
static void cryptoRandBytes(uint8_t* buf, ULONG len) {
    NTSTATUS st = BCryptGenRandom(nullptr, buf, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(st))
        throw std::runtime_error("AES256: BCryptGenRandom fallito");
}

// RAII per handle CNG — evita leak in caso di eccezione
struct BcryptAlgHandle {
    BCRYPT_ALG_HANDLE h = nullptr;
    ~BcryptAlgHandle() { if (h) BCryptCloseAlgorithmProvider(h, 0); }
};
struct BcryptKeyHandle {
    BCRYPT_KEY_HANDLE h = nullptr;
    ~BcryptKeyHandle() { if (h) BCryptDestroyKey(h); }
};

// C3: apre provider AES-256-GCM (AEAD) — sostituisce CBC puro
static void openGcmAlg(BcryptAlgHandle& alg) {
    NTSTATUS st = BCryptOpenAlgorithmProvider(&alg.h, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(st))
        throw std::runtime_error("AES256: BCryptOpenAlgorithmProvider fallito");
    st = BCryptSetProperty(alg.h, BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
        sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(st))
        throw std::runtime_error("AES256: BCryptSetProperty (GCM) fallito");
}

AES256::AES256(AppSettings settings)
    : storage_(settings.keyFilePath, settings.dpapiScope) {
    storage_.loadOrCreateKey();
}

void AES256::keyGen() {
    std::vector<uint8_t> key(32);
    cryptoRandBytes(key.data(), 32);

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

// Formato output: [version 2B LE][nonce 12B][tag GCM 16B][ciphertext nB]
std::vector<uint8_t> AES256::encryptRaw(const uint8_t* data, size_t sz) {
    if (!storage_.hasStoredKey())
        throw std::runtime_error("AES256: nessuna chiave salvata.");

    auto key = storage_.unprotectKey();
    auto keyArr = toKeyArray(key);
    SecureZeroMemory(key.data(), key.size());

    BcryptAlgHandle alg;
    openGcmAlg(alg);

    BcryptKeyHandle hKey;
    NTSTATUS st = BCryptGenerateSymmetricKey(alg.h, &hKey.h, nullptr, 0, keyArr.data(), 32, 0);
    SecureZeroMemory(keyArr.data(), 32);
    if (!BCRYPT_SUCCESS(st))
        throw std::runtime_error("AES256: BCryptGenerateSymmetricKey fallito");

    std::array<uint8_t, 12> nonce{};
    cryptoRandBytes(nonce.data(), 12);

    std::array<uint8_t, 16> tag{};

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce.data();
    authInfo.cbNonce = 12;
    authInfo.pbTag   = tag.data();
    authInfo.cbTag   = 16;

    ULONG cbResult = 0;
    std::vector<uint8_t> ciphertext(sz);
    st = BCryptEncrypt(hKey.h,
        const_cast<PUCHAR>(data), static_cast<ULONG>(sz),
        &authInfo, nullptr, 0,
        ciphertext.data(), static_cast<ULONG>(sz),
        &cbResult, 0);
    if (!BCRYPT_SUCCESS(st))
        throw std::runtime_error("AES256: BCryptEncrypt fallito");

    uint16_t ver = static_cast<uint16_t>(storage_.getActiveVersion());
    std::vector<uint8_t> out;
    out.reserve(2 + 12 + 16 + cbResult);
    out.push_back(static_cast<uint8_t>(ver & 0xFF));          // version LSB
    out.push_back(static_cast<uint8_t>((ver >> 8) & 0xFF));   // version MSB
    out.insert(out.end(), nonce.begin(), nonce.end());
    out.insert(out.end(), tag.begin(), tag.end());
    out.insert(out.end(), ciphertext.begin(), ciphertext.begin() + cbResult);
    return out;
}

std::vector<uint8_t> AES256::decryptRaw(const std::vector<uint8_t>& in) {
    // minimo: 2 (version) + 12 (nonce) + 16 (tag) = 30
    if (in.size() < 30)
        throw std::length_error("AES256: input troppo corto (minimo 30 byte)");

    uint16_t version = static_cast<uint16_t>(in[0]) | (static_cast<uint16_t>(in[1]) << 8);

    auto key = storage_.unprotectKey(static_cast<int>(version));
    auto keyArr = toKeyArray(key);
	// flush memory heap prima possibile, la chiave è ora in keyArr
    SecureZeroMemory(key.data(), key.size());

    BcryptAlgHandle alg;
    openGcmAlg(alg);

    BcryptKeyHandle hKey;
    NTSTATUS st = BCryptGenerateSymmetricKey(alg.h, &hKey.h, nullptr, 0, keyArr.data(), 32, 0);
    SecureZeroMemory(keyArr.data(), 32);
    if (!BCRYPT_SUCCESS(st))
        throw std::runtime_error("AES256: BCryptGenerateSymmetricKey fallito");

    // nonce: offset 2, tag: offset 14, ciphertext: offset 30
    std::array<uint8_t, 16> tag{};
    std::copy(in.begin() + 14, in.begin() + 30, tag.begin());
    ULONG ctLen = static_cast<ULONG>(in.size() - 30);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = const_cast<PUCHAR>(in.data() + 2);
    authInfo.cbNonce = 12;
    authInfo.pbTag   = tag.data();
    authInfo.cbTag   = 16;

    ULONG cbResult = 0;
    std::vector<uint8_t> out(ctLen);
    st = BCryptDecrypt(hKey.h,
        const_cast<PUCHAR>(in.data() + 30), ctLen,
        &authInfo, nullptr, 0,
        out.data(), ctLen,
        &cbResult, 0);

    if (st == STATUS_AUTH_TAG_MISMATCH)
        throw std::runtime_error("AES256: autenticazione fallita — ciphertext corrotto o manomesso");
    if (!BCRYPT_SUCCESS(st))
        throw std::runtime_error("AES256: BCryptDecrypt fallito");

    out.resize(cbResult);
    return out;
}

int AES256::rotateKey() {
    return storage_.rotateKey();
}

void AES256::importKey(const std::string& hexKey) {
    if (hexKey.size() != 64)
        throw std::invalid_argument("AES256: la chiave deve essere 64 caratteri hex (32 byte / 256 bit)");

    auto key = fromHex(hexKey);

    if (!storage_.protectKey(key)) {
        // svuota registro in heap
        SecureZeroMemory(key.data(), key.size());
        throw std::runtime_error("AES256: impossibile proteggere la chiave importata");
    }
    SecureZeroMemory(key.data(), key.size());
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
