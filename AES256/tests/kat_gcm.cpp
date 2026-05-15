// KAT (Known Answer Tests) per AES-256-GCM
// Vettori NIST SP 800-38D, Appendix B, Test Case 13-16 (chiave 256 bit)
// Testa il primitivo BCrypt direttamente, senza DPAPI o key storage.

#include <windows.h>
#include <bcrypt.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

#ifndef STATUS_AUTH_TAG_MISMATCH
#define STATUS_AUTH_TAG_MISMATCH ((NTSTATUS)0xC000A002L)
#endif

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

static std::vector<uint8_t> fromHex(const char* s) {
    std::vector<uint8_t> out;
    size_t len = strlen(s);
    for (size_t i = 0; i + 1 < len; i += 2) {
        unsigned int b = 0;
        sscanf_s(s + i, "%02x", &b);
        out.push_back(static_cast<uint8_t>(b));
    }
    return out;
}

static std::string toHex(const uint8_t* data, size_t len) {
    std::string out;
    out.reserve(len * 2);
    char buf[3];
    for (size_t i = 0; i < len; i++) {
        snprintf(buf, sizeof(buf), "%02x", data[i]);
        out += buf;
    }
    return out;
}

// ---------------------------------------------------------------------------
// BCrypt AES-256-GCM primitivo
// ---------------------------------------------------------------------------

struct AlgHandle { BCRYPT_ALG_HANDLE h = nullptr; ~AlgHandle() { if (h) BCryptCloseAlgorithmProvider(h, 0); } };
struct KeyHandle { BCRYPT_KEY_HANDLE h = nullptr; ~KeyHandle() { if (h) BCryptDestroyKey(h); } };

struct GcmResult {
    std::vector<uint8_t> ct;
    std::vector<uint8_t> tag;
    bool ok = false;
};

static GcmResult gcmEncrypt(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& pt,
    const std::vector<uint8_t>& aad)
{
    GcmResult res;

    AlgHandle alg;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg.h, BCRYPT_AES_ALGORITHM, nullptr, 0)))
        return res;
    if (!BCRYPT_SUCCESS(BCryptSetProperty(alg.h, BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
        sizeof(BCRYPT_CHAIN_MODE_GCM), 0)))
        return res;

    KeyHandle hKey;
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(alg.h, &hKey.h, nullptr, 0,
        const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0)))
        return res;

    res.tag.resize(16);
    res.ct.resize(pt.empty() ? 1 : pt.size()); // BCrypt richiede almeno 1 byte di output buffer

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce    = const_cast<PUCHAR>(iv.data());
    info.cbNonce    = static_cast<ULONG>(iv.size());
    info.pbTag      = res.tag.data();
    info.cbTag      = 16;
    if (!aad.empty()) {
        info.pbAuthData = const_cast<PUCHAR>(aad.data());
        info.cbAuthData = static_cast<ULONG>(aad.size());
    }

    ULONG cbResult = 0;
    NTSTATUS st = BCryptEncrypt(hKey.h,
        pt.empty() ? nullptr : const_cast<PUCHAR>(pt.data()), static_cast<ULONG>(pt.size()),
        &info, nullptr, 0,
        pt.empty() ? nullptr : res.ct.data(), static_cast<ULONG>(pt.empty() ? 0 : res.ct.size()),
        &cbResult, 0);

    if (!BCRYPT_SUCCESS(st)) return res;
    res.ct.resize(cbResult);
    res.ok = true;
    return res;
}

static bool gcmDecryptVerify(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& ct,
    const std::vector<uint8_t>& aad,
    const std::vector<uint8_t>& tag,
    std::vector<uint8_t>& ptOut)
{
    AlgHandle alg;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg.h, BCRYPT_AES_ALGORITHM, nullptr, 0)))
        return false;
    if (!BCRYPT_SUCCESS(BCryptSetProperty(alg.h, BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
        sizeof(BCRYPT_CHAIN_MODE_GCM), 0)))
        return false;

    KeyHandle hKey;
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(alg.h, &hKey.h, nullptr, 0,
        const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0)))
        return false;

    std::vector<uint8_t> tagCopy = tag;
    ptOut.resize(ct.empty() ? 1 : ct.size());

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce    = const_cast<PUCHAR>(iv.data());
    info.cbNonce    = static_cast<ULONG>(iv.size());
    info.pbTag      = tagCopy.data();
    info.cbTag      = 16;
    if (!aad.empty()) {
        info.pbAuthData = const_cast<PUCHAR>(aad.data());
        info.cbAuthData = static_cast<ULONG>(aad.size());
    }

    ULONG cbResult = 0;
    NTSTATUS st = BCryptDecrypt(hKey.h,
        ct.empty() ? nullptr : const_cast<PUCHAR>(ct.data()), static_cast<ULONG>(ct.size()),
        &info, nullptr, 0,
        ct.empty() ? nullptr : ptOut.data(), static_cast<ULONG>(ct.empty() ? 0 : ptOut.size()),
        &cbResult, 0);

    if (st == STATUS_AUTH_TAG_MISMATCH) { ptOut.clear(); return false; }
    if (!BCRYPT_SUCCESS(st)) return false;
    ptOut.resize(cbResult);
    return true;
}

// ---------------------------------------------------------------------------
// Framework di test minimalista
// ---------------------------------------------------------------------------

static int g_pass = 0, g_fail = 0;

static void check(const char* label, bool cond) {
    if (cond) {
        printf("  [PASS] %s\n", label);
        g_pass++;
    } else {
        printf("  [FAIL] %s\n", label);
        g_fail++;
    }
}

static void runKat(
    const char* name,
    const char* keyHex,
    const char* ivHex,
    const char* ptHex,
    const char* aadHex,
    const char* ctHex,
    const char* tagHex)
{
    printf("\n[%s]\n", name);

    auto key = fromHex(keyHex);
    auto iv  = fromHex(ivHex);
    auto pt  = fromHex(ptHex);
    auto aad = fromHex(aadHex);
    auto expCt  = fromHex(ctHex);
    auto expTag = fromHex(tagHex);

    // --- Encrypt ---
    auto res = gcmEncrypt(key, iv, pt, aad);
    check("encrypt: BCrypt ok", res.ok);
    check("encrypt: ciphertext corretto",
        res.ct.size() == expCt.size() &&
        (expCt.empty() || memcmp(res.ct.data(), expCt.data(), expCt.size()) == 0));
    check("encrypt: tag GCM corretto",
        memcmp(res.tag.data(), expTag.data(), 16) == 0);

    if (!res.ok) return;

    // --- Decrypt con tag autentico ---
    std::vector<uint8_t> ptDec;
    bool decOk = gcmDecryptVerify(key, iv, expCt, aad, expTag, ptDec);
    check("decrypt: tag autentico accettato", decOk);
    check("decrypt: plaintext recuperato",
        decOk && ptDec.size() == pt.size() &&
        (pt.empty() || memcmp(ptDec.data(), pt.data(), pt.size()) == 0));

    // --- Decrypt con tag manomesso (deve fallire) ---
    std::vector<uint8_t> badTag = expTag;
    badTag[0] ^= 0xFF;
    std::vector<uint8_t> ptBad;
    bool tamperRejected = !gcmDecryptVerify(key, iv, expCt, aad, badTag, ptBad);
    check("decrypt: tag manomesso rifiutato", tamperRejected);
}

// ---------------------------------------------------------------------------
// Vettori NIST SP 800-38D, Appendix B — AES-256-GCM
// ---------------------------------------------------------------------------

int runKatTests() {
    printf("=== KAT AES-256-GCM — NIST SP 800-38D Appendix B ===\n");

    // TC13 — chiave e IV all-zero, PT vuoto, nessun AAD
    runKat("TC13",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        "",
        "",
        "",
        "530f8afbc74536b9a963b4f1c4cb738b");

    // TC14 — chiave e IV all-zero, PT = 16 byte zero, nessun AAD
    runKat("TC14",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        "00000000000000000000000000000000",
        "",
        "cea7403d4d606b6e074ec5d3baf39d18",
        "d0d1c8a799996bf0265b98b5d48ab919");

    // TC15 — chiave/IV NIST, PT 60 byte, nessun AAD
    runKat("TC15",
        "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "d9313225f88406e5a55909c5aff5269a"
        "86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525"
        "b16aedf5aa0de657ba637b391aafd255",
        "",
        "522dc1f099567d07f47f37a32a84427d"
        "643a8cdcbfe5c0c97598a2bd2555d1aa"
        "8cb08e48590dbb3da7b08b1056828838"
        "c5f61e6393ba7a0abcc9f662898015ad",
        "b094dac5d93471bdec1a502270e3cc6c");

    // TC16 — stessa chiave/IV, PT troncato a 60 byte, AAD 20 byte
    runKat("TC16",
        "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        "cafebabefacedbaddecaf888",
        "d9313225f88406e5a55909c5aff5269a"
        "86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525"
        "b16aedf5aa0de657ba637b39",
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "522dc1f099567d07f47f37a32a84427d"
        "643a8cdcbfe5c0c97598a2bd2555d1aa"
        "8cb08e48590dbb3da7b08b1056828838"
        "c5f61e6393ba7a0abcc9f662",
        "76fc6ece0f4e1768cddf8853bb2d551b");

    printf("\n=== Risultato: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return g_fail;
}
