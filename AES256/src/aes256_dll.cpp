#include "aes256_dll.h"
#include "aes256.h"

#include <string>
#include <exception>

thread_local std::string g_lastError;

static void setError(const char* msg) {
    g_lastError = msg ? msg : "errore sconosciuto";
}

void* AES256_Create() {
    try {
        return new AES256();
    } catch (const std::exception& e) {
        setError(e.what());
        return nullptr;
    }
}

void AES256_Destroy(void* handle) {
    delete static_cast<AES256*>(handle);
}

int AES256_KeyGen(void* handle) {
    try {
        static_cast<AES256*>(handle)->keyGen();
        return 0;
    } catch (const std::exception& e) {
        setError(e.what());
        return -1;
    }
}

char* AES256_Encrypt(void* handle, const char* plaintext) {
    if (!handle || !plaintext) {
        setError("handle o plaintext nullo");
        return nullptr;
    }
    try {
        std::string result = static_cast<AES256*>(handle)->encrypt(plaintext);
        char* buf = new char[result.size() + 1];
        std::copy(result.begin(), result.end(), buf);
        buf[result.size()] = '\0';
        return buf;
    } catch (const std::exception& e) {
        setError(e.what());
        return nullptr;
    }
}

char* AES256_Decrypt(void* handle, const char* hexCiphertext) {
    if (!handle || !hexCiphertext) {
        setError("handle o hexCiphertext nullo");
        return nullptr;
    }
    try {
        std::string result = static_cast<AES256*>(handle)->decrypt(hexCiphertext);
        char* buf = new char[result.size() + 1];
        std::copy(result.begin(), result.end(), buf);
        buf[result.size()] = '\0';
        return buf;
    } catch (const std::exception& e) {
        setError(e.what());
        return nullptr;
    }
}

void AES256_Free(char* ptr) {
    delete[] ptr;
}

const char* AES256_LastError() {
    return g_lastError.c_str();
}
