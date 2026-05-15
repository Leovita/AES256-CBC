#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <windows.h>

struct KeyEntry {
    int         version;
    std::string createdAt;
    std::string status;    // "active" | "retired"
};

class SecureKeyStorage {
public:
    enum Scope {
        CurrentUser  = 0,
        LocalMachine = 0x4
    };

    explicit SecureKeyStorage(const std::string& keyFilePath, Scope scope = CurrentUser);
    ~SecureKeyStorage();

    // protegge e salva la chiave attiva con DPAPI
    bool protectKey(const std::vector<uint8_t>& plainKey);

    // decifra la chiave della versione indicata (-1 = versione attiva)
    std::vector<uint8_t> unprotectKey(int version = -1);

    // true se il manifest esiste (almeno una chiave salvata)
    bool hasStoredKey() const;

    // carica il manifest esistente o genera la versione 1
    void loadOrCreateKey();

    // genera una nuova chiave come versione successiva, segna la precedente come "retired"
    // restituisce il numero della nuova versione
    int rotateKey();

    int getActiveVersion() const { return m_activeVersion; }
    std::vector<KeyEntry> getKeyEntries() const { return m_keyEntries; }

    std::string& getKeyFilePath() { return m_keyFilePath; }

private:
    bool saveEncryptedKeyToPath(const std::string& path);
    bool saveManifest();
    bool loadManifest();
    std::string versionedPath(int version) const;
    std::string manifestPath() const;

    std::vector<uint8_t> m_encryptedKey{};
    std::string          m_keyFilePath{};
    Scope                m_scope{ CurrentUser };
    int                  m_activeVersion{ 1 };
    std::vector<KeyEntry> m_keyEntries{};
};
