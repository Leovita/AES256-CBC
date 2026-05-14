#include "appSettings.h"

#include "third_party/rapidjson/document.h"
#include "third_party/rapidjson/istreamwrapper.h"

#include <fstream>
#include <iostream>
#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#endif

static std::filesystem::path resolveSettingsPath(const std::string& jsonPath) {
    std::filesystem::path p = jsonPath;
    if (!p.is_relative() || std::filesystem::exists(p))
        return p;

#ifdef _WIN32
    char buf[MAX_PATH];
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    std::filesystem::path exeDir = std::filesystem::path(buf).parent_path();
#else
    std::filesystem::path exeDir = std::filesystem::canonical("/proc/self/exe").parent_path();
#endif

    std::filesystem::path candidate = exeDir / p;
    if (std::filesystem::exists(candidate))
        return candidate;

    return p; // fallback: restituisce il path originale (non trovato)
}

AppSettings AppSettings::load(const std::string& jsonPath) {
    AppSettings settings;

    std::filesystem::path resolved = resolveSettingsPath(jsonPath);
    std::cerr << "[AppSettings] cercando: " << resolved << " -> "
        << (std::filesystem::exists(resolved) ? "trovato" : "NON trovato") << "\n";

    std::ifstream file(resolved);
    if (!file)
        return settings;

    rapidjson::IStreamWrapper isw(file);
    rapidjson::Document doc;
    doc.ParseStream(isw);

    if (doc.HasParseError() || !doc.IsObject())
        return settings;

    if (doc.HasMember("keyFilePath") && doc["keyFilePath"].IsString())
        settings.keyFilePath = doc["keyFilePath"].GetString();

    if (doc.HasMember("dpapiScope") && doc["dpapiScope"].IsString()) {
        std::string scope = doc["dpapiScope"].GetString();
        if (scope == "LocalMachine") {
            std::cerr << "[AppSettings] DPAPI scope configurato su LocalMachine (richiede admin)\n";
            settings.dpapiScope = SecureKeyStorage::LocalMachine;
        }
        else {
            std::cerr << "[AppSettings] DPAPI scope configurato su CurrentUser (default)\n";
            settings.dpapiScope = SecureKeyStorage::CurrentUser;
        }
    }

    return settings;
}
