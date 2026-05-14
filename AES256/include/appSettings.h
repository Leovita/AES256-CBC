#pragma once

#include "secureStorage.h"
#include <string>

struct AppSettings {
    std::string keyFilePath{ "keys\\aes_key.dat" };
    SecureKeyStorage::Scope dpapiScope{ SecureKeyStorage::CurrentUser };

    /*
        carica appSettings.json dalla stessa directory dell'eseguibile
        se il file manca o il campo e' assente, mantiene il valore di default.

        dpapiScope: "CurrentUser" (default) | "LocalMachine" (richiede admin)
    */
    static AppSettings load(const std::string& jsonPath = "appSettings.json");
};
