/**
 * @file platform_windows.c
 * @brief Windows-specific platform helpers (stub on Linux).
 */
#include "cbae/cbae_error.h"

#ifdef _WIN32
#include <windows.h>
long cbae_win32_cpu_count(void) {
    SYSTEM_INFO si; GetSystemInfo(&si);
    return (long)si.dwNumberOfProcessors;
}
long cbae_win32_page_size(void) {
    SYSTEM_INFO si; GetSystemInfo(&si);
    return (long)si.dwPageSize;
}
#else
typedef int cbae_platform_windows_stub;
#endif
