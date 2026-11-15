/* lib.c - a DLL for test_pe_real: exports by name, by ordinal only, a forwarder and a data export; imports by name from kernel32. */
__declspec(dllimport) unsigned long GetTickCount(void);
__declspec(dllimport) void *GetProcAddress(void *module, const char *name);

int exported_data = 7;
unsigned long uptime(void) { return GetTickCount() / 1000; }
int add(int a, int b) { return a + b; }
void *lookup(void *m) { return GetProcAddress(m, "add"); }
int hidden_by_ordinal(int x) { return x * 2 + exported_data; }
