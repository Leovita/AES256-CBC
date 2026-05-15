#include "secureStorage.h"

#include "third_party/rapidjson/document.h"
#include "third_party/rapidjson/istreamwrapper.h"

#include <windows.h>
#include <dpapi.h>
#include <bcrypt.h>
#include <aclapi.h>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <filesystem>
#include <chrono>
#include <ctime>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")


namespace {

    // H3: imposta DACL owner-only sul file indicato
    bool restrictFileToOwner(const std::string& path) {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
            return false;

        DWORD dwSize = 0;
        GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwSize);
        std::vector<BYTE> buf(dwSize);
        bool ok = GetTokenInformation(hToken, TokenUser, buf.data(), dwSize, &dwSize) != 0;
        CloseHandle(hToken);
        if (!ok) return false;

        PSID pSid = reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid;

        EXPLICIT_ACCESS ea{};
        ea.grfAccessPermissions = GENERIC_ALL;
        ea.grfAccessMode        = SET_ACCESS;
        ea.grfInheritance       = NO_INHERITANCE;
        ea.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType  = TRUSTEE_IS_USER;
        ea.Trustee.ptstrName    = reinterpret_cast<LPTSTR>(pSid);

        PACL pDacl = nullptr;
        if (SetEntriesInAcl(1, &ea, nullptr, &pDacl) != ERROR_SUCCESS)
            return false;

        // PROTECTED_DACL_SECURITY_INFORMATION rimuove ACE ereditate dalla directory padre
        DWORD result = SetNamedSecurityInfoA(
            const_cast<LPSTR>(path.c_str()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            nullptr, nullptr, pDacl, nullptr);

        LocalFree(pDacl);
        return result == ERROR_SUCCESS;
    }

    // C1: CSPRNG per generazione chiavi
    std::vector<uint8_t> generateRawKey() {
        std::vector<uint8_t> key(32);
        NTSTATUS st = BCryptGenRandom(nullptr, key.data(), 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!BCRYPT_SUCCESS(st))
            throw std::runtime_error("AES256: BCryptGenRandom fallito nella generazione della chiave");
        return key;
    }

    std::string utcNow() {
        auto now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        struct tm tm_utc{};
        gmtime_s(&tm_utc, &t);
        char buf[32];
        strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
        return buf;
    }

} // namespace


// ── path helpers ──────────────────────────────────────────────────────────────

std::string SecureKeyStorage::versionedPath(int version) const {
    namespace fs = std::filesystem;
    fs::path p(m_keyFilePath);
    std::string name = p.stem().string() + "_v" + std::to_string(version) + p.extension().string();
    return (p.parent_path() / name).string();
}

std::string SecureKeyStorage::manifestPath() const {
    return (std::filesystem::path(m_keyFilePath).parent_path() / "key_manifest.json").string();
}


// ── ctor / dtor ───────────────────────────────────────────────────────────────

SecureKeyStorage::SecureKeyStorage(const std::string& keyFilePath, Scope scope)
    : m_keyFilePath(keyFilePath), m_scope(scope) {}

SecureKeyStorage::~SecureKeyStorage() {
    if (!m_encryptedKey.empty())
        SecureZeroMemory(m_encryptedKey.data(), m_encryptedKey.size());
}


// ── manifest ──────────────────────────────────────────────────────────────────

bool SecureKeyStorage::saveManifest() {
    auto dir = std::filesystem::path(manifestPath()).parent_path();
    if (!dir.empty())
        std::filesystem::create_directories(dir);

    std::ostringstream json;
    json << "{\n  \"activeVersion\": " << m_activeVersion << ",\n  \"keys\": [\n";
    for (size_t i = 0; i < m_keyEntries.size(); i++) {
        const auto& e = m_keyEntries[i];
        json << "    {\"version\": " << e.version
             << ", \"createdAt\": \"" << e.createdAt
             << "\", \"status\": \"" << e.status << "\"}";
        if (i + 1 < m_keyEntries.size()) json << ",";
        json << "\n";
    }
    json << "  ]\n}\n";

    std::ofstream file(manifestPath());
    file << json.str();
    if (!file.good()) return false;
    file.close();

    return restrictFileToOwner(manifestPath());
}

bool SecureKeyStorage::loadManifest() {
    std::ifstream file(manifestPath());
    if (!file) return false;

    rapidjson::IStreamWrapper isw(file);
    rapidjson::Document doc;
    doc.ParseStream(isw);
    if (doc.HasParseError() || !doc.IsObject()) return false;

    if (!doc.HasMember("activeVersion") || !doc["activeVersion"].IsInt()) return false;
    m_activeVersion = doc["activeVersion"].GetInt();

    m_keyEntries.clear();
    if (doc.HasMember("keys") && doc["keys"].IsArray()) {
        for (const auto& k : doc["keys"].GetArray()) {
            KeyEntry e;
            e.version   = (k.HasMember("version")   && k["version"].IsInt())     ? k["version"].GetInt()        : 0;
            e.createdAt = (k.HasMember("createdAt")  && k["createdAt"].IsString())? k["createdAt"].GetString()   : "";
            e.status    = (k.HasMember("status")     && k["status"].IsString())   ? k["status"].GetString()      : "unknown";
            m_keyEntries.push_back(e);
        }
    }
    return true;
}


// ── file I/O ──────────────────────────────────────────────────────────────────

bool SecureKeyStorage::saveEncryptedKeyToPath(const std::string& path) {
    auto dir = std::filesystem::path(path).parent_path();
    if (!dir.empty())
        std::filesystem::create_directories(dir);

    std::ofstream file(path, std::ios::binary);
    file.write(reinterpret_cast<const char*>(m_encryptedKey.data()), m_encryptedKey.size());
    if (!file.good()) return false;
    file.close();

    return restrictFileToOwner(path);
}


// ── public API ────────────────────────────────────────────────────────────────

bool SecureKeyStorage::hasStoredKey() const {
    return std::filesystem::exists(manifestPath());
}

void SecureKeyStorage::loadOrCreateKey() {
    if (loadManifest()) return;

    // Prima esecuzione: crea versione 1
    m_activeVersion = 1;
    auto newKey = generateRawKey();
    bool ok = protectKey(newKey);
    SecureZeroMemory(newKey.data(), newKey.size());
    if (!ok)
        throw std::runtime_error("AES256: impossibile proteggere e salvare la chiave AES");
}

bool SecureKeyStorage::protectKey(const std::vector<uint8_t>& plainKey) {
    DATA_BLOB inputBlob;
    inputBlob.pbData = const_cast<BYTE*>(plainKey.data());
    inputBlob.cbData = static_cast<DWORD>(plainKey.size());
    DATA_BLOB outputBlob = { 0 };

    if (!CryptProtectData(&inputBlob, L"AES256-Key", NULL, NULL, NULL,
        static_cast<DWORD>(m_scope), &outputBlob)) {
        return false;
    }

    m_encryptedKey.assign(outputBlob.pbData, outputBlob.pbData + outputBlob.cbData);
    LocalFree(outputBlob.pbData);

    if (!saveEncryptedKeyToPath(versionedPath(m_activeVersion)))
        return false;

    // Aggiorna o inserisce la voce nel manifest per la versione attiva
    bool found = false;
    for (auto& e : m_keyEntries) {
        if (e.version == m_activeVersion) { e.status = "active"; found = true; }
    }
    if (!found)
        m_keyEntries.push_back({ m_activeVersion, utcNow(), "active" });

    return saveManifest();
}

std::vector<uint8_t> SecureKeyStorage::unprotectKey(int version) {
    int v = (version == -1) ? m_activeVersion : version;
    std::string path = versionedPath(v);

    std::ifstream file(path, std::ios::binary);
    if (!file)
        throw std::runtime_error("AES256: chiave versione " + std::to_string(v) + " non trovata in " + path);

    file.seekg(0, std::ios::end);
    size_t size = static_cast<size_t>(file.tellg());
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> encKey(size);
    file.read(reinterpret_cast<char*>(encKey.data()), size);

    DATA_BLOB inputBlob;
    inputBlob.pbData = encKey.data();
    inputBlob.cbData = static_cast<DWORD>(size);
    DATA_BLOB outputBlob = { 0 };

    if (!CryptUnprotectData(&inputBlob, NULL, NULL, NULL, NULL,
        static_cast<DWORD>(m_scope), &outputBlob)) {
        throw std::runtime_error("AES256: CryptUnprotectData fallito per versione " + std::to_string(v));
    }

    std::vector<uint8_t> plainKey(outputBlob.pbData, outputBlob.pbData + outputBlob.cbData);
    SecureZeroMemory(outputBlob.pbData, outputBlob.cbData);
    LocalFree(outputBlob.pbData);
    return plainKey;
}

int SecureKeyStorage::rotateKey() {
    // segna la versione corrente come retired in-memory
    for (auto& e : m_keyEntries) {
        if (e.version == m_activeVersion)
            e.status = "retired";
    }

    int prevVersion  = m_activeVersion;
    m_activeVersion  = prevVersion + 1;

    auto newKey = generateRawKey();
    bool ok = protectKey(newKey);
    SecureZeroMemory(newKey.data(), newKey.size());

    if (!ok) {
        // Rollback in-memory
        m_activeVersion = prevVersion;
        for (auto& e : m_keyEntries) {
            if (e.version == prevVersion)
                e.status = "active";
        }
        throw std::runtime_error("AES256: rotazione chiave fallita");
    }

    return m_activeVersion;
}
