#pragma once

#ifdef AES256_EXPORTS
  #define AES256_API __declspec(dllexport)
#else
  #define AES256_API __declspec(dllimport)
#endif

extern "C" {

    // Crea un'istanza AES256. Ritorna un handle opaco, nullptr su errore.
    AES256_API void* AES256_Create();

    // Distrugge l'istanza e libera la memoria.
    AES256_API void  AES256_Destroy(void* handle);

    // Genera una nuova chiave casuale, la protegge con DPAPI e la salva su file.
    // Ritorna 0 su successo, -1 su errore.
    AES256_API int   AES256_KeyGen(void* handle);

    // Cifra una stringa UTF-8. Ritorna una stringa hex allocata dalla DLL.
    // Il chiamante deve liberare il buffer con AES256_Free().
    // Ritorna nullptr su errore.
    AES256_API char* AES256_Encrypt(void* handle, const char* plaintext);

    // Decifra una stringa hex. Ritorna il plaintext allocato dalla DLL.
    // Il chiamante deve liberare il buffer con AES256_Free().
    // Ritorna nullptr su errore.
    AES256_API char* AES256_Decrypt(void* handle, const char* hexCiphertext);

    // Libera un buffer restituito da AES256_Encrypt o AES256_Decrypt.
    AES256_API void  AES256_Free(char* ptr);

    // Ritorna il messaggio dell'ultimo errore per il thread corrente.
    // Il puntatore e' valido fino alla prossima chiamata sulla stessa DLL nello stesso thread.
    AES256_API const char* AES256_LastError();

}
