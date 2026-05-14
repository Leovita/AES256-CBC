#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <windows.h>

class SecureKeyStorage {
public:
	// ci accedi con SecureKeyStorage::CurrentUser 
    // o SecureKeyStorage::LocalMachine
    enum Scope {
        CurrentUser = 0,           // Legata all'utente corrente
        LocalMachine = 0x4         // Legata al computer (richiede admin)
    };

    explicit SecureKeyStorage(const std::string& keyFilePath, Scope scope = CurrentUser);
    ~SecureKeyStorage();

    // protegge e salva la chiave AES su file tramite DPAPI
    bool protectKey(const std::vector<uint8_t>& plainKey);

    // recupera e decifra la chiave AES (decifrata solo in memoria locale, non conservata)
    std::vector<uint8_t> unprotectKey();

    // true se esiste già una chiave protetta salvata
    bool hasStoredKey() const;

    // carica la chiave esistente o ne genera e salva una nuova, restituisce la chiave in chiaro
    std::vector<uint8_t> loadOrCreateKey();

    std::string& getKeyFilePath() { return m_keyFilePath; }

private:
    bool saveToFile();
    bool loadFromFile();

    std::vector<uint8_t> m_encryptedKey{};
    // configurabili in appSettings:
    std::string m_keyFilePath{};
	Scope m_scope{ CurrentUser }; 
};
