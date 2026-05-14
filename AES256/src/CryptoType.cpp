#include <windows.h>
#include <dpapi.h>

/*
* se vuoi proteggere la chiave a livello di macchina,
  invece che a livello di utente, usa la costante a 
  0x4 (CRYPTPROTECT_LOCAL_MACHINE)
  https://stackoverflow.com/questions/19164926/data-protection-api-scope-localmachine-currentuser
*/
namespace Crypto {
    constexpr DWORD LOCAL_MACHINE = 0x4;
    constexpr DWORD CURRENT_USER = 0x0;
}

