#include "secureStorage.h"

#include <windows.h>
#include <dpapi.h>
#include <fstream>
#include <stdexcept>
#include <random>
#include <algorithm>
#include <filesystem>
#include <iostream>

#pragma comment(lib, "crypt32.lib")


namespace {
    DATA_BLOB toDataBlob(const std::vector<uint8_t>& data) {
        DATA_BLOB blob;
        blob.pbData = const_cast<BYTE*>(data.data());
        blob.cbData = static_cast<DWORD>(data.size());
        return blob;
    }

    std::vector<uint8_t> generateRawKey() {
        std::vector<uint8_t> key(32);
        std::random_device rnd;
        std::mt19937 eng{ rnd() };
        std::uniform_int_distribution<int> dist{ 0, 255 };
        std::generate(key.begin(), key.end(), [&] { return static_cast<uint8_t>(dist(eng)); });
        return key;
    }
}

SecureKeyStorage::SecureKeyStorage(const std::string& keyFilePath, Scope scope)
    : m_keyFilePath(keyFilePath), m_scope(scope) {}

SecureKeyStorage::~SecureKeyStorage() {
	// se ce chiave storata, quando oggetto distrutto
    // azzero la memoria usata per contenerla
    if (!m_encryptedKey.empty())
        SecureZeroMemory(m_encryptedKey.data(), m_encryptedKey.size());
}

bool SecureKeyStorage::protectKey(const std::vector<uint8_t>& plainKey) {
    DATA_BLOB inputBlob = toDataBlob(plainKey);
    DATA_BLOB outputBlob = { 0 };

    std::cerr << "Proteggendo chiave AES con DPAPI, scope: "
		<< (m_scope == CurrentUser ? "CurrentUser" : "LocalMachine") << std::endl;

	std::cout << static_cast<DWORD> (m_scope) << std::endl;
	/*
		m_scope viene assiciato a dPapiScope in appSettings, 
        che puo' essere "CurrentUser" (default) o "LocalMachine".
    */
    if (!CryptProtectData(&inputBlob, L"AES256-Key", NULL, NULL, NULL,
        static_cast<DWORD>(m_scope), &outputBlob)) {
        return false;
    }

    m_encryptedKey.assign(outputBlob.pbData, outputBlob.pbData + outputBlob.cbData);
    LocalFree(outputBlob.pbData);

    return saveToFile();
}

std::vector<uint8_t> SecureKeyStorage::unprotectKey() {
    if (m_encryptedKey.empty() && !loadFromFile())
        throw std::runtime_error("AES256: impossibile caricare la chiave cifrata da " + m_keyFilePath);

    DATA_BLOB inputBlob = toDataBlob(m_encryptedKey);
    DATA_BLOB outputBlob = { 0 };

    if (!CryptUnprotectData(&inputBlob, NULL, NULL, NULL, NULL,
        static_cast<DWORD>(m_scope), &outputBlob)) {
        throw std::runtime_error("AES256: CryptUnprotectData fallito");
    }

    std::vector<uint8_t> plainKey(outputBlob.pbData, outputBlob.pbData + outputBlob.cbData);
    SecureZeroMemory(outputBlob.pbData, outputBlob.cbData);
    LocalFree(outputBlob.pbData);

    return plainKey;
}

bool SecureKeyStorage::hasStoredKey() const {
    std::ifstream file(m_keyFilePath, std::ios::binary);
    return file.good();
}

bool SecureKeyStorage::saveToFile() {
	// se il path non esiste lo creo, come definito in appSettings
    auto dir = std::filesystem::path(m_keyFilePath).parent_path();
    if (!dir.empty())
        std::filesystem::create_directories(dir);

    std::ofstream file(m_keyFilePath, std::ios::binary);
    file.write(reinterpret_cast<const char*>(m_encryptedKey.data()), m_encryptedKey.size());
    return file.good();
}

bool SecureKeyStorage::loadFromFile() {
    std::ifstream file(m_keyFilePath, std::ios::binary);
    if (!file) return false;

    file.seekg(0, std::ios::end);
    size_t size = static_cast<size_t>(file.tellg());
    file.seekg(0, std::ios::beg);

    m_encryptedKey.resize(size);
    file.read(reinterpret_cast<char*>(m_encryptedKey.data()), size);
    return file.good();
}

std::vector<uint8_t> SecureKeyStorage::loadOrCreateKey() {
	// se stored key esiste, caricala e restituiscila
    if (hasStoredKey()) {
		std::cerr << "Chiave AES gia' salvata trovata, caricando da " << m_keyFilePath << std::endl;
        return unprotectKey();
    }
    //altrimenti genera una nuova chiave, proteggila e salvala
	std::cerr << "Nessuna chiave AES salvata trovata, generando nuova chiave..." << std::endl;
    auto newKey = generateRawKey();
    if (!protectKey(newKey)) {
        throw std::runtime_error("AES256: impossibile proteggere e salvare la chiave AES");
    }
    return newKey;
}
